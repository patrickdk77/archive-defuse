import { crc32 } from './crc32';
import { CheckError, DataError, isIoError, NestedIoError, NestingLimitError, ParseError, StopError, stopsTree, TimeLimitError, UnsupportedError } from './errors';
import { FindingFactory, findingSpec } from './findings';
import { openArchive } from './formats';
import { bufferSink, bufferSource, copyToSink, SpillSink, TempDir } from './io';
import type { Archive, Entry, Kept, Meter, Note, WritePlan } from './model';
import { applyRules, type Decision } from './rules';
import { scoreFindings } from './score';
import { sniffType, typeFromName, typesDisagree } from './sniff';
import {
  type ArchiveDisarmResult,
  type ArchiveFinding,
  type ArchiveInspection,
  type ArchiveOptions,
  ArchiveRisk,
  type ByteSink,
  type ByteSource,
  ArchiveCategory as C,
  type ContainedFile,
  type ContainedFileResult,
  ArchiveDetail as D,
  type DefuseFinding,
  type PluginContext,
} from './types';
import { ZipArchive, type ZipEntry } from './zip';

export const DEFAULT_LIMITS = {
  entries: 10_000,
  decompressedBytes: 512 * 1024 * 1024,
  totalDecompressedBytes: 2 * 1024 * 1024 * 1024,
  compressionRatio: 1000,
  nestingDepth: 10,
  dictionaryBytes: 256 * 1024 * 1024,
};
/** An entry's ratio is checked once it passes this many decoded bytes. */
const RATIO_FLOOR = 1024 * 1024;

/** The key under which archive-defuse hands its run's options to a plugin. No other package can name it. */
export const RUN_OPTIONS = Symbol('archive-defuse run options');

/** A plugin context as archive-defuse makes it. */
export type RunContext = PluginContext & { [RUN_OPTIONS]?: ArchiveOptions };

/** What a plugin kept in the upload, which the check of the output credits to an entry with the same MD5. */
interface Expected {
  result: 'passed' | 'scrubbed';
  plugin: string;
  findings?: DefuseFinding[];
}

/** What one analysis holds open. Whoever starts the run releases it with endRun(), however the run ends. */
interface Run {
  temp: TempDir;
  archive?: Archive<Entry>;
  plan?: WritePlan<Entry>;
  /** Copies plugins kept, which the rewrite reads. */
  held: SpillSink[];
  /** What plugins kept, by MD5, for the check of the output. */
  kept: Map<string, Expected>;
  /** Entries the plan keeps, for the check of the output. */
  entries?: number;
}

async function endRun(run: Run): Promise<void> {
  try {
    for (const s of run.held) await s.dispose();
  } finally {
    await run.temp.cleanup();
  }
}

/** Kinds whose content the rewrite drops whatever their action, so an info override leaves CONTENT_REMOVED. */
const DROPPED_ANYWAY = new Set<string>([D.HiddenData, D.NonFileData, D.ExtraField]);

/**
 * `incomplete` marks a run that could not inspect the whole archive. finish() then rejects it without a score,
 * whatever the actions say, because an override can make the finding that stopped it look harmless.
 */
function finish(findings: DefuseFinding[], options: ArchiveOptions, incomplete: boolean, archive?: Archive<Entry>, isOutput = false): ArchiveInspection {
  const named = archive ? { format: archive.format, entries: archive.entries.length } : {};
  if (incomplete) return { status: 'rejected', score: null, risk: ArchiveRisk.Unknown, findings, ...named };
  const rejected = findings.some(f => f.action === 'reject');
  // In an upload, a plugin rewrite or a metadata strip changes the file, so the output must be written.
  const strippable = findings.some(f => f.action === 'strip' || (!isOutput && (f.detail === D.PluginScrubbed || f.detail === D.Stripped) && f.attachment === undefined));
  // What a plugin decided counts at the weights of the plugin's own findings; the PLUGIN_* findings that record its
  // answer weigh nothing.
  const { score, risk } = scoreFindings(findings, options);
  return { status: rejected ? 'rejected' : strippable ? 'strippable' : 'clean', score, risk, findings, ...named };
}

/** A value from the archive, such as a name, cut to a length a report can carry. */
const clip = (s: string) => (s.length > 4096 ? `${s.slice(0, 4093)}...` : s);
const clipped = (data: Record<string, string | number>) => Object.fromEntries(Object.entries(data).map(([k, v]) => [k, typeof v === 'string' ? clip(v) : v]));

/** Collects findings. Past 200 of one kind, further ones only raise a count, as in pdf-defuse. */
class Findings {
  readonly list: DefuseFinding[] = [];
  private readonly perKey = new Map<string, number>();
  private readonly aggregates = new Map<string, DefuseFinding>();
  constructor(readonly factory: FindingFactory) {}

  push(f: DefuseFinding): void {
    const k = `${f.category}/${f.detail}`;
    const n = (this.perKey.get(k) ?? 0) + 1;
    this.perKey.set(k, n);
    if (n <= 200) {
      this.list.push(f);
      return;
    }
    let agg = this.aggregates.get(k);
    if (!agg) {
      const data = { ...f.data, count: 0 };
      agg = findingSpec(f.category, f.detail)
        ? this.factory.make(f.category as C, f.detail as D, 'additional occurrences', data)
        : { category: f.category, detail: f.detail, description: f.description, action: f.action, location: 'additional occurrences', data, weight: f.weight };
      agg.action = f.action;
      this.aggregates.set(k, agg);
      this.list.push(agg);
    } else if (f.action === 'reject' || (f.action === 'strip' && agg.action === 'info')) agg.action = f.action;
    const data = agg.data;
    if (data) data.count = Number(data.count) + 1;
  }

  emit(category: C, detail: D, location?: string, data?: Record<string, string | number>): ArchiveFinding {
    const f = this.factory.make(category, detail, location && clip(location), data && clipped(data));
    this.push(f);
    return f;
  }

  /** Reports content that goes whatever the overrides say. Its action is strip, or reject when the caller asked for that. */
  removal(category: C, detail: D, location?: string, data?: Record<string, string | number>): ArchiveFinding {
    const f = this.factory.make(category, detail, location, data);
    if (f.action === 'info') f.action = 'strip';
    this.push(f);
    return f;
  }

  has(category: C, detail: D, where?: string): boolean {
    return this.list.some(f => f.category === category && f.detail === detail && (where === undefined || f.data?.where === where));
  }
}

/** Where an entry sits, for findings. */
const locate = (e: Entry, archive: Archive<Entry>) => (e.name === '' && archive.single ? 'compressed content' : e.name === '' && archive.nameless ? `entry ${e.index + 1}` : `entry "${e.name}"`);

/**
 * Throws on an error a plugin threw that stops the whole tree. An I/O error fails this run as one of its own would,
 * so its cause goes up.
 */
function passOn(run: Run, e: unknown): void {
  const code = stopsTree(e);
  if (code === 'DEFUSE_IO') {
    const cause = (e as { cause?: unknown }).cause ?? e;
    run.temp.ioError ??= cause;
    throw cause;
  }
  if (code === 'DEFUSE_LIMIT') throw e;
}

/** Adds findings a plugin reported from inside an entry. A reject inside it means the entry goes, not the archive, so it is recorded as strip. */
function pushContained(out: Findings, found: DefuseFinding[] | undefined, location: string, name: string | undefined): void {
  const label = name || 'unnamed file';
  for (const f of found ?? []) {
    out.push({
      ...f,
      action: f.action === 'reject' ? 'strip' : f.action,
      location: f.location ? `${location} > ${f.location}` : location,
      data: f.data && { ...f.data },
      attachment: f.attachment ? `${label} > ${f.attachment}` : label,
    });
  }
}

interface Settings {
  options: ArchiveOptions;
  depth: number;
  deadline?: number;
  /** In the check of an output: what plugins kept in the upload, by MD5. */
  verify?: Map<string, Expected>;
}

/** The passwords to try on an encrypted entry, in order, with the empty password last. */
export const passwordsOf = (options: ArchiveOptions) => [...(Array.isArray(options.password) ? options.password : options.password === undefined ? [] : [options.password]), ''];

/** The limits of a run, with the defaults filled in. */
export const limitsOf = (options: ArchiveOptions) =>
  ({ ...DEFAULT_LIMITS, ...Object.fromEntries(Object.entries(options.limits ?? {}).filter(([, v]) => v !== undefined)) }) as typeof DEFAULT_LIMITS & { fileSize?: number; timeMs?: number };

/** Where a stop happened: an entry by its name, or a 7z folder or header as the 7z reader names it. */
const stopLocation = (location: string | undefined) => (location === undefined ? undefined : SEVEN_PLACE.test(location) ? location : `entry "${location}"`);
const SEVEN_PLACE = /^(folder [1-9][0-9]*|header)$/;

/** The finding for a limit or a refusal that stopped the run. */
function stopFinding(factory: FindingFactory, e: unknown): ArchiveFinding | undefined {
  if (e instanceof StopError) return factory.make(e.category, e.detail, stopLocation(e.location), e.data);
  if (stopsTree(e) === 'DEFUSE_LIMIT') return factory.make(C.Limit, (e as { limit?: unknown }).limit === 'nesting' ? D.NestingDepth : D.Time);
  // What the xz, lzma and 7z readers throw while they open a file.
  if (e instanceof CheckError) return factory.make(C.Corrupted, D.CheckFailed, undefined, { check: e.check });
  if (e instanceof DataError && e.truncated) return factory.make(C.Corrupted, D.Truncated, undefined, { what: 'structure' });
  if (e instanceof ParseError) return factory.make(C.Corrupted, D.Unparseable, undefined, { reason: e.message.slice(0, 120) });
  if (e instanceof UnsupportedError) return unsupported(factory, e);
  return undefined;
}

/** The finding for a method or a feature of the format this package does not read. */
function unsupported(factory: FindingFactory, e: UnsupportedError, location?: string): ArchiveFinding {
  if (!e.method) return factory.make(C.Compression, D.UnsupportedFeature, location, { reason: String(e.data?.reason ?? e.message).slice(0, 120) });
  return factory.make(C.Compression, D.UnsupportedMethod, location, { method: String(e.data?.method ?? e.message).slice(0, 120) });
}

/**
 * Inspects `source` and leaves what it opens in `run`. It throws an I/O error instead of reporting a verdict on the
 * archive, and a time or nesting limit for the caller to pass up or report.
 */
async function analyze(run: Run, source: ByteSource, s: Settings): Promise<ArchiveInspection> {
  try {
    return await analyzeInner(run, source, s);
  } catch (e) {
    if (run.temp.ioError !== undefined) throw run.temp.ioError;
    if (stopsTree(e) || isIoError(e)) throw e;
    const factory = new FindingFactory(s.options.actionOverrides);
    const f = stopFinding(factory, e) ?? factory.make(C.Corrupted, D.Unparseable, undefined, { reason: String((e as Error)?.message ?? e).slice(0, 120) });
    return finish([f], s.options, true, run.archive);
  }
}

async function analyzeInner(run: Run, source: ByteSource, s: Settings): Promise<ArchiveInspection> {
  const { options, depth, deadline } = s;
  const factory = new FindingFactory(options.actionOverrides);
  const out = new Findings(factory);
  const limits = limitsOf(options);
  if (limits.nestingDepth !== undefined && depth > limits.nestingDepth) throw new NestingLimitError('Nesting limit exceeded');
  const size = await source.size();
  if (limits.fileSize !== undefined && size > limits.fileSize) return finish([factory.make(C.Limit, D.FileSize, undefined, { size })], options, true);
  let archive: Archive<Entry>;
  try {
    archive = await openArchive(source, limits, deadline, passwordsOf(options), { dir: run.temp, threshold: options.memoryThreshold ?? 8 * 1024 * 1024 });
  } catch (e) {
    // A time limit in a nested run stops the whole tree, so it goes up to the container.
    if (depth > 0 && stopsTree(e) === 'DEFUSE_LIMIT') throw e;
    const f = stopFinding(factory, e);
    if (!f) throw e;
    return finish([f], options, true);
  }
  run.archive = archive;
  let incomplete = false;
  const stop = (f: ArchiveFinding) => {
    out.push(f);
    incomplete = true;
  };
  // Findings whose content the writer keeps when they are info, which therefore remove nothing.
  const keptOnInfo = new Set<DefuseFinding>();
  const note = (n: Note, location?: string) => {
    const f = out.emit(n.category, n.detail, location, n.data);
    if (n.keptOnInfo) keptOnInfo.add(f);
  };
  for (const n of archive.notes) note(n, n.location ?? (n.data?.where as string | undefined));
  if (archive.comment !== undefined) out.emit(C.Metadata, D.Comment, 'archive');

  const totals = { decoded: 0 };
  const meterFor = (e: Entry): Meter & { total: number } => makeMeter(e, limits, deadline, totals);
  let decisions: Decision[] = [];
  const kept: Kept<Entry>[] = [];
  try {
    // Symbolic links in a ZIP keep their targets as content, which the link rules need.
    await readLinkTargets(archive, meterFor);
    decisions = applyRules(archive.entries, factory, (c, d, e, data) => out.emit(c, d, locate(e, archive), data), {
      names: !(archive.nameless || (archive.single && archive.entries[0]?.name === '')),
      backslashIsSeparator: archive.format !== 'cab',
    });

    const passwords = passwordsOf(options);
    const threshold = options.memoryThreshold ?? 8 * 1024 * 1024;
    let retained = 0;
    for (const [i, e] of archive.entries.entries()) {
      if (i % 64 === 0 && deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
      const d = decisions[i];
      const loc = locate(e, archive);
      for (const n of e.notes) note(n, n.location ?? loc);
      if (e.comment !== undefined) out.emit(C.Metadata, D.Comment, loc);
      const enc = e.encryption;
      if (enc?.kind === 'zipcrypto') out.emit(C.Encrypted, D.ZipCrypto, loc);
      else if (enc?.kind === 'aes') out.emit(C.Encrypted, enc.bits === 128 ? D.Aes128 : enc.bits === 192 ? D.Aes192 : D.Aes256, loc);
      if (d.remove) continue;
      const hasContent = e.kind === 'file' || e.kind === 'other';
      const hasData = hasContent || e.kind === 'symlink';
      if (hasData && e.method && !e.method.readable && (e.size > 0 || e.compressedSize > 0)) {
        stop(factory.make(C.Compression, D.UnsupportedMethod, loc, { method: e.method.name }));
        continue;
      }
      if (hasData && e.method?.unavailable) {
        stop(factory.make(C.Compression, D.Unavailable, loc, { method: e.method.name }));
        continue;
      }
      let recompress = false;
      if (hasData && e.method?.unusual) recompress = out.emit(C.Compression, D.UnusualMethod, loc, { method: e.method.name }).action === 'strip';
      if (enc?.kind === 'unsupported') {
        stop(factory.make(C.Encrypted, D.Unsupported, loc, { reason: enc.reason }));
        continue;
      }
      if (e.broken) {
        out.removal(C.Corrupted, D.EntryData, loc, { name: e.name, reason: e.broken });
        continue;
      }
      const k: Kept<Entry> = { entry: e, name: d.name, mode: d.mode, recompress, dropCapabilities: d.dropCapabilities };
      // The passwords are tried in order, each only once it opens the entry. A ZipCrypto header can pass for a wrong
      // password, so a password whose data then fails gives way to the next one that opens the entry.
      const tried = new Set<string>();
      const nextPassword = async (): Promise<string | undefined | null> => {
        if (!enc) {
          if (tried.size) return null;
          tried.add('');
          return undefined;
        }
        for (const p of passwords) {
          if (tried.has(p)) continue;
          tried.add(p);
          if (await archive.unlock(e, p)) return p;
        }
        return null;
      };
      let decoded: SpillSink | undefined;
      let failure: DataError | undefined;
      let opened = false;
      for (let password = await nextPassword(); password !== null; password = await nextPassword()) {
        opened = true;
        if (!hasContent) {
          k.password = password;
          break;
        }
        // Read the content, under the limits, into memory or a temporary file.
        decoded = new SpillSink(run.temp, threshold);
        const meter = meterFor(e);
        let crc = 0;
        try {
          for await (const c of archive.read(e, meter, password)) {
            if (enc?.kind === 'aes') crc = crc32(c, crc);
            await decoded.write(c);
          }
          await decoded.close();
          k.password = password;
          if (enc?.kind === 'aes') k.crc = crc;
          failure = undefined;
          break;
        } catch (err) {
          await decoded.dispose();
          decoded = undefined;
          totals.decoded -= meter.total;
          if (err instanceof DataError) {
            failure = err;
            continue;
          }
          if (err instanceof UnsupportedError) {
            stop(unsupported(factory, err, loc));
            break;
          }
          throw err;
        }
      }
      if (!opened) {
        stop(factory.make(C.Encrypted, D.PasswordRequired, loc));
        continue;
      }
      if (!hasContent) {
        kept.push(k);
        continue;
      }
      if (incomplete && !decoded) continue;
      if (!decoded) {
        const reason = failure?.message.slice(0, 120) ?? '';
        if (archive.single) {
          if (failure instanceof CheckError) stop(factory.make(C.Corrupted, D.CheckFailed, loc, { check: failure.check }));
          else if (failure instanceof ParseError && !failure.truncated) stop(factory.make(C.Corrupted, D.Unparseable, loc, { reason }));
          else stop(factory.make(C.Corrupted, failure?.truncated ? D.Truncated : D.DataError, loc, failure?.truncated ? { what: 'compressed stream' } : { reason }));
          continue;
        }
        out.removal(C.Corrupted, D.EntryData, loc, { name: e.name, reason });
        continue;
      }
      if (enc) out.emit(C.Encrypted, k.password === '' ? D.EmptyPassword : D.Decrypted, loc);
      if (decoded.spilled) out.emit(C.Processing, D.MemoryFallback, loc, { part: `Entry "${e.name.slice(0, 60)}"` });
      try {
        const decision = await decideContent(run, s, out, e, loc, decoded, threshold - retained);
        if (!decision.keep) continue;
        if (decision.replacement) {
          k.replacement = decision.replacement;
          if (!decision.replacement.spilled) retained += decision.replacement.length;
        }
        kept.push(k);
      } finally {
        await decoded.dispose();
      }
    }
    for (const n of archive.lateNotes) out.emit(n.category, n.detail, n.location ?? (n.data?.where as string | undefined), n.data);
    // A compressed file whose one file goes leaves nothing to write, so what removed it rejects the file instead, as
    // file-defuse does with an upload it would have to strip whole.
    if (archive.single && !incomplete && !kept.length && archive.entries.length) {
      const loc = locate(archive.entries[0], archive);
      for (const f of out.list) if (f.attachment === undefined && f.location === loc && f.action === 'strip') f.action = 'reject';
    }
  } catch (e) {
    // A time or nesting limit, its own or one a plugin threw, stops the whole tree: a nested run passes it up.
    if (depth > 0 && stopsTree(e) === 'DEFUSE_LIMIT') throw e;
    const f = stopFinding(factory, e);
    if (!f) throw e;
    out.push(f);
    return finish(out.list, options, true, archive);
  }

  // Another end record inside an entry's compressed bytes would come through a copy of them, so that entry is
  // compressed afresh.
  if (factory.strips(C.Structure, D.SeveralEndRecords)) recompressRivals(archive, kept);

  // A hard link goes with the file it links to, and names it by the name the rewrite gives that file.
  const keptIndex = new Map(kept.map(k => [k.entry.index, k]));
  const final = kept.filter(k => {
    if (k.entry.kind !== 'hardlink') return true;
    const to = decisions[k.entry.index].linkIndex;
    const target = to === undefined ? undefined : keptIndex.get(to);
    if (to !== undefined && !target) return false;
    if (target) k.linkTarget = target.name;
    return true;
  });

  if (options.stripMetadata && archive.hasMetadata()) out.emit(C.Metadata, D.Stripped);
  if (!incomplete && out.list.some(f => f.attachment === undefined && DROPPED_ANYWAY.has(f.detail) && f.action === 'info' && !keptOnInfo.has(f))) out.removal(C.Processing, D.ContentRemoved);
  const strips = (c: C, d: D) => factory.strips(c, d);
  run.plan = {
    kept: final,
    stripMetadata: options.stripMetadata === true,
    keepLeading: !strips(C.Structure, D.LeadingBytes) && !(out.has(C.Structure, D.Polyglot, 'before the archive') && strips(C.Structure, D.Polyglot)),
    keepTrailing:
      !strips(C.Structure, D.TrailingBytes) &&
      !(out.list.some(f => f.detail === D.Polyglot && String(f.data?.where ?? '').startsWith('after')) && strips(C.Structure, D.Polyglot)) &&
      !(archive.format === 'tar' && out.has(C.Structure, D.HiddenData) && strips(C.Structure, D.HiddenData)),
    keepExtraFields: !strips(C.Structure, D.ExtraField),
    ratioLimit: limits.compressionRatio,
  };
  run.entries = final.length;
  return finish(out.list, options, incomplete, archive, s.verify !== undefined);
}

/** Reads the targets of symbolic links, which ZIP and 7z keep as their content. */
async function readLinkTargets(archive: Archive<Entry>, meterFor: (e: Entry) => Meter): Promise<void> {
  if (!archive.linkTarget) return;
  for (const e of archive.entries) {
    if (e.kind !== 'symlink' || e.broken) continue;
    try {
      e.linkTarget = await archive.linkTarget(e, meterFor(e));
    } catch (err) {
      if (!(err instanceof DataError)) throw err;
    }
  }
}

/** Marks for compressing afresh the ZIP entries whose stored bytes hold another end record. */
function recompressRivals(archive: Archive<Entry>, kept: Kept<Entry>[]): void {
  if (!(archive instanceof ZipArchive) || !archive.rivals.length) return;
  for (const k of kept) {
    const e = k.entry as ZipEntry;
    if (archive.rivals.some(at => at >= e.dataOffset && at < e.dataOffset + e.compressedSize)) k.recompress = true;
  }
}

/** A meter for one entry: its own decoded size, the run's total, the ratio, and the deadline. */
export function makeMeter(e: Entry, limits: typeof DEFAULT_LIMITS, deadline: number | undefined, totals: { decoded: number }): Meter & { total: number } {
  const meter = {
    total: 0,
    add(decoded: number, compressedSoFar?: number) {
      totals.decoded += decoded - meter.total;
      meter.total = decoded;
      if (deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
      if (decoded > limits.decompressedBytes) throw new StopError(C.Limit, D.DecompressedSize, 'An entry decodes past the limit', { limit: limits.decompressedBytes }, e.name || undefined);
      if (totals.decoded > limits.totalDecompressedBytes) throw new StopError(C.Limit, D.TotalDecompressedSize, 'The entries decode past the limit', { limit: limits.totalDecompressedBytes });
      if (decoded > RATIO_FLOOR && compressedSoFar !== undefined && decoded > Math.max(1, compressedSoFar) * limits.compressionRatio) {
        throw new StopError(C.Limit, D.Ratio, 'An entry decodes past the ratio limit', { limit: limits.compressionRatio }, e.name || undefined);
      }
    },
    time() {
      if (deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
    },
  };
  return meter;
}

/**
 * Shows an entry's content to the file plugins, as pdf-defuse shows an attached file. The first plugin that accepts it
 * decides: 'passed' and 'scrubbed' keep it, with the bytes the plugin wrote when it wrote any, and 'removed', a failure
 * or a scrub that wrote nothing remove it. When no plugin accepts it, ENTRY/NO_PLUGIN decides. In the check of an
 * output the plugins are not asked again: content whose MD5 matches what a plugin kept counts as kept.
 */
async function decideContent(run: Run, s: Settings, out: Findings, e: Entry, loc: string, decoded: SpillSink, room: number): Promise<{ keep: boolean; replacement?: SpillSink }> {
  const name = e.name === '' ? undefined : e.name;
  const hash = decoded.digest();
  const expected = s.verify?.get(hash);
  if (expected) {
    out.emit(C.Entry, expected.result === 'passed' ? D.PluginPassed : D.PluginScrubbed, loc, { plugin: expected.plugin, name: name ?? '' });
    pushContained(out, expected.findings, loc, name);
    return { keep: true };
  }
  const source = decoded.source();
  try {
    const head = await source.read(0, Math.min(1024, decoded.length));
    const sniffed = sniffType(head);
    if (typesDisagree(undefined, name, sniffed)) {
      const f = out.emit(C.Entry, D.TypeMismatch, loc, { name: name ?? '', sniffed: sniffed ?? '', nameType: typeFromName(name) ?? '' });
      if (f.action === 'strip') return { keep: false };
    }
    const file: ContainedFile = { name, sniffedType: sniffed, size: decoded.length, location: loc, depth: s.depth + 1, source };
    const context: RunContext = { depth: file.depth, deadline: s.deadline, [RUN_OPTIONS]: s.options };
    for (const plugin of s.verify ? [] : (s.options.filePlugins ?? [])) {
      try {
        if (!(await plugin.accepts(file))) continue;
      } catch (err) {
        passOn(run, err);
        continue;
      }
      // Copies plugins keep wait for the rewrite, so all of them together stay under one memory threshold.
      const kept = new SpillSink(run.temp, Math.max(0, room));
      const data = { plugin: plugin.name, name: name ?? '' };
      try {
        const answer = await plugin.process(file, kept, context);
        const r: Partial<ContainedFileResult> = typeof answer === 'string' ? { result: answer } : (answer ?? {});
        await kept.close();
        let keep = false;
        if (r.result === 'passed') {
          out.emit(C.Entry, D.PluginPassed, loc, data);
          // Bytes the plugin wrote are the ones kept, such as a document rewritten with nothing removed.
          const passed: Expected = { result: 'passed', plugin: plugin.name, findings: r.outputFindings };
          run.kept.set(hash, passed);
          if (kept.length > 0) run.kept.set(kept.digest(), passed);
          keep = true;
        } else if (r.result === 'scrubbed' && kept.length > 0) {
          out.emit(C.Entry, D.PluginScrubbed, loc, data);
          run.kept.set(kept.digest(), { result: 'scrubbed', plugin: plugin.name, findings: r.outputFindings });
          keep = true;
        } else out.removal(C.Entry, r.result === 'removed' ? D.PluginRemoved : D.PluginFailed, loc, data);
        pushContained(out, r.findings, loc, name);
        if (keep && kept.length > 0) {
          run.held.push(kept);
          return { keep, replacement: kept };
        }
        await kept.dispose();
        return { keep };
      } catch (err) {
        await kept.dispose();
        passOn(run, err);
        out.removal(C.Entry, D.PluginFailed, loc, data);
        return { keep: false };
      }
    }
    const f = out.emit(C.Entry, D.NoPlugin, loc, { name: name ?? '', sniffed: sniffed ?? '' });
    return { keep: f.action !== 'strip' };
  } finally {
    await source.close?.();
  }
}

async function closeSource(source: ByteSource): Promise<void> {
  try {
    await source.close?.();
  } catch {
    /* ignore */
  }
}

function rethrowOrReject(e: unknown, options: ArchiveOptions): ArchiveInspection {
  const f = stopFinding(new FindingFactory(options.actionOverrides), e);
  if (!f) throw e;
  return finish([f], options, true);
}

const newRun = (options: ArchiveOptions): Run => ({ temp: new TempDir(options.tempDir), held: [], kept: new Map() });

/** Inspects an archive without changing it. The source is closed when the run ends. */
export async function inspectArchiveSource(source: ByteSource, options: ArchiveOptions = {}): Promise<ArchiveInspection> {
  const run = newRun(options);
  const deadline = options.limits?.timeMs !== undefined ? Date.now() + options.limits.timeMs : undefined;
  try {
    return await analyze(run, source, { options, depth: 0, deadline }).catch(e => rethrowOrReject(e, options));
  } finally {
    await closeSource(source);
    await endRun(run);
  }
}

/** Copies to the caller's sink. On failure it aborts the sink instead of closing it, so a partial copy does not look whole. */
async function deliver(from: ByteSource, sink: ByteSink): Promise<void> {
  try {
    await copyToSink(from, sink);
  } catch (e) {
    try {
      await sink.abort?.(e);
    } catch {
      /* the copy's error is the one to report */
    }
    throw e;
  }
  await sink.close();
}

/**
 * Writes a defused copy of `source` to `sink`. Nothing reaches the sink unless the output passes inspection. The
 * source is closed when the run ends.
 */
export async function disarmArchiveSource(source: ByteSource, sink: ByteSink, options: ArchiveOptions = {}): Promise<ArchiveDisarmResult> {
  return disarmAtDepth(source, sink, options, 0);
}

/** Internal entry that carries the nesting depth for archives inside other files, and the deadline they share with the upload. */
export async function disarmAtDepth(
  source: ByteSource,
  sink: ByteSink,
  options: ArchiveOptions,
  depth: number,
  deadline = options.limits?.timeMs !== undefined ? Date.now() + options.limits.timeMs : undefined,
): Promise<ArchiveDisarmResult> {
  const run = newRun(options);
  let input = source;
  try {
    let before: ArchiveInspection;
    try {
      // A caller's source can change between reads, so analysis and the rewrite read one snapshot. A nested archive's
      // source already belongs to the container, and analysis rejects a file over the size limit unread.
      const fileSize = options.limits?.fileSize;
      if (depth === 0 && (fileSize === undefined || (await source.size()) <= fileSize)) {
        const snapshot = new SpillSink(run.temp, options.memoryThreshold ?? 8 * 1024 * 1024);
        try {
          await copyToSink(source, snapshot, () => {
            if (deadline !== undefined && Date.now() > deadline) throw new TimeLimitError('Time limit exceeded');
          });
        } finally {
          await snapshot.close();
        }
        input = snapshot.source();
      }
      before = await analyze(run, input, { options, depth, deadline });
    } catch (e) {
      if (depth > 0 && stopsTree(e) === 'DEFUSE_LIMIT') throw e;
      before = rethrowOrReject(e, options);
    }
    const archive = run.archive;
    const plan = run.plan;
    if (before.status === 'rejected' || !archive || !plan) return { status: 'rejected', before, removed: [] };
    const factory = new FindingFactory(options.actionOverrides);
    // The rewrite goes to memory up to the threshold and to a temporary file past it, so the many small archives of a
    // nested tree do not each make a file.
    const out = new SpillSink(run.temp, options.memoryThreshold ?? 8 * 1024 * 1024);
    const limits = limitsOf(options);
    try {
      // The rewrite decodes the entries again under the same limits for each entry. The total is not counted again,
      // since an entry compressed afresh can be decoded twice.
      await archive.write(plan, out, {
        meter: () => makeMeter({ index: 0, name: '', kind: 'file', size: 0, compressedSize: 0, notes: [] }, { ...limits, totalDecompressedBytes: Number.POSITIVE_INFINITY }, deadline, { decoded: 0 }),
        temp: run.temp,
        threshold: options.memoryThreshold ?? 8 * 1024 * 1024,
      });
    } catch (e) {
      await out.close().catch(() => {
        // The write's failure, handled below, is the one that counts.
      });
      if (run.temp.ioError !== undefined) throw run.temp.ioError;
      if (isIoError(e)) throw e;
      if (stopsTree(e) === 'DEFUSE_LIMIT') {
        if (depth > 0) throw e;
        const lf = factory.make(C.Limit, (e as { limit?: unknown }).limit === 'nesting' ? D.NestingDepth : D.Time);
        return { status: 'rejected', before: { ...before, status: 'rejected', score: null, risk: ArchiveRisk.Unknown, findings: [...before.findings, lf] }, removed: [] };
      }
      before.findings.push(factory.make(C.Processing, D.VerificationFailed, undefined, { reasons: `write failed: ${String((e as Error)?.message ?? e).slice(0, 100)}` }));
      before.status = 'rejected';
      return { status: 'rejected', before, removed: [] };
    }
    await out.close();
    if (run.temp.ioError !== undefined) throw run.temp.ioError;
    const verifyOptions: ArchiveOptions = {
      actionOverrides: options.actionOverrides,
      scoreWeights: options.scoreWeights,
      scoreBands: options.scoreBands,
      tempDir: options.tempDir,
      memoryThreshold: options.memoryThreshold,
      limits: { ...options.limits, fileSize: undefined, timeMs: undefined },
    };
    const outSource = out.source();
    try {
      const check = newRun(verifyOptions);
      let after: ArchiveInspection;
      let entries: number | undefined;
      try {
        after = await analyze(check, outSource, { options: verifyOptions, depth, deadline, verify: run.kept });
        entries = check.entries;
      } finally {
        await endRun(check);
      }
      const reasons = after.findings.filter(f => f.action !== 'info').map(f => `${f.category}/${f.detail}`);
      // A check that stopped early verified nothing, even when the caller overrode the finding that stopped it to info.
      if (after.status === 'rejected' && !reasons.length) reasons.push('the output check stopped early');
      if (entries !== run.entries) reasons.push(`entries ${run.entries} -> ${entries}`);
      if (reasons.length) {
        before.findings.push(factory.make(C.Processing, D.VerificationFailed, undefined, { reasons: [...new Set(reasons)].slice(0, 10).join(', ') }));
        before.status = 'rejected';
        return { status: 'rejected', before, removed: [] };
      }
      await deliver(outSource, sink);
      return { status: before.status === 'clean' ? 'clean' : 'defused', before, after, removed: before.findings.filter(f => f.action === 'strip') };
    } finally {
      await closeSource(outSource);
    }
  } catch (e) {
    // A nested archive's I/O error fails the upload's run too, instead of counting as a failed plugin.
    if (depth > 0 && (isIoError(e) || (e !== undefined && e === run.temp.ioError))) throw new NestedIoError(e);
    throw e;
  } finally {
    if (input !== source) await closeSource(input);
    // A nested archive's source belongs to the container that found it.
    if (depth === 0) await closeSource(source);
    await endRun(run);
  }
}

/** Inspects archive bytes. */
export async function inspectArchive(bytes: Uint8Array, options: ArchiveOptions = {}): Promise<ArchiveInspection> {
  return inspectArchiveSource(bufferSource(bytes), options);
}

/** Defuses archive bytes. `bytes` holds the output unless the archive was rejected. */
export async function disarmArchive(bytes: Uint8Array, options: ArchiveOptions = {}): Promise<ArchiveDisarmResult & { bytes?: Uint8Array }> {
  const sink = bufferSink();
  const result = await disarmArchiveSource(bufferSource(bytes), sink, options);
  return result.status === 'rejected' ? result : { ...result, bytes: sink.result() };
}
