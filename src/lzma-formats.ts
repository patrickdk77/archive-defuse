// The formats that came from lzma-defuse when it merged into this package: 7z, xz and .lzma. The readers and writers
// are lzma-defuse's; these classes put them behind the Archive interface the engine drives, so 7z entries go through
// the same rules and plugins as ZIP and tar entries.

import { type AloneInfo, readAlone } from './alone';
import { CHECK_CRC64 } from './checks';
import { DataError } from './errors';
import { type Reader as ByteReader, Reader, SpillSink } from './io';
import { detectLzmaFormat, SEVENZIP_SEARCH } from './lzma-sniff';
import { type Content, passesRatio, type SevenOut, WRITABLE_CHECKS, writeAlone, writeSevenZip, writeXz } from './lzma-writers';
import { type Archive, contentOf, type Entry, type EntryKind, type Kept, type Meter, type Note, sizeOf, type WriteContext, type WritePlan } from './model';
import { openSevenZip, type SevenArchive, type SevenEntry, SevenReader, unixMode } from './seven';
import { sniffType } from './sniff';
import type { Limits, StreamCounter } from './stream-meter';
import { type ByteSink, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';
import { readXz, type XzInfo } from './xz';

/** Notes of one kind as one note with a count, so a file of a million xz streams does not make a million findings. */
function grouped(notes: Note[]): Note[] {
  const groups = new Map<string, Note[]>();
  for (const n of notes) {
    const k = `${n.category}/${n.detail}`;
    const g = groups.get(k) ?? [];
    g.push(n);
    groups.set(k, g);
  }
  return [...groups.values()].map(g => (g.length > 1 ? { ...g[0], data: { ...g[0].data, count: g.length } } : g[0]));
}

/**
 * Notes a ZIP end record that a ZIP reader would find from the end of the file, and a PDF header in the first 1024
 * bytes, where a PDF reader takes one. `trailingAt` is where data after the format's own structures starts.
 */
async function otherReaders(reader: ByteReader, start: number, trailingAt: number | undefined, notes: Note[]): Promise<void> {
  const size = reader.size;
  const last = await reader.read(Math.max(0, size - 65_557), Math.min(size, 65_557));
  for (let i = last.length - 22; i >= 0; i--) {
    if (last[i] === 0x50 && last[i + 1] === 0x4b && last[i + 2] === 0x05 && last[i + 3] === 0x06 && i + 22 + (last[i + 20] | (last[i + 21] << 8)) === last.length) {
      const at = size - last.length + i;
      notes.push({
        category: C.Structure,
        detail: D.Polyglot,
        data: { type: 'application/zip', where: trailingAt !== undefined && at >= trailingAt ? 'after the archive' : 'at the end of the file' },
      });
      break;
    }
  }
  const first = await reader.read(start, 1024);
  if (Buffer.from(first.buffer, first.byteOffset, first.byteLength).toString('latin1').includes('%PDF-')) {
    notes.push({ category: C.Structure, detail: D.Polyglot, data: { type: 'application/pdf', where: 'in the first 1024 bytes' } });
  }
}

/** Notes data after the format's own structures, and what it reads as. */
async function trailing(reader: ByteReader, at: number | undefined, notes: Note[]): Promise<void> {
  if (at === undefined || at >= reader.size) return;
  notes.push({ category: C.Structure, detail: D.TrailingBytes, data: { bytes: reader.size - at } });
  const type = sniffType(await reader.read(at, Math.min(1024, reader.size - at)));
  if (type !== undefined) notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'after the archive' } });
}

/** Copies a range of the source to the sink. */
async function copyRange(reader: ByteReader, sink: ByteSink, from: number, to: number, time: () => void): Promise<void> {
  for await (const c of reader.chunks(from, to - from)) {
    time();
    await sink.write(c);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// 7z

export interface SevenZipEntry extends Entry {
  seven: SevenEntry;
}

const KINDS: Record<SevenEntry['kind'], EntryKind> = { file: 'file', dir: 'directory', symlink: 'symlink', device: 'device', fifo: 'fifo', socket: 'socket' };

/** No system takes a link target longer than PATH_MAX, 4096 bytes on Linux. */
const MAX_LINK = 4096;

/** `s` with each lone surrogate, which no file system name holds, read as U+FFFD, as a UTF-16 decoder reads it. */
function wellFormed(s: string): string {
  let out = '';
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0xd800 || c > 0xdfff) continue;
    const next = s.charCodeAt(i + 1);
    if (c <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) {
      i++;
      continue;
    }
    out += `${s.slice(from, i)}\ufffd`;
    from = i + 1;
  }
  return from === 0 ? s : out + s.slice(from);
}

export class SevenZipArchive implements Archive<SevenZipEntry> {
  readonly format = '7z';
  readonly single = false;
  readonly nameless: boolean;
  readonly lateNotes: Note[] = [];
  readonly entries: SevenZipEntry[];
  private readonly contents: SevenReader;

  private constructor(
    private readonly reader: ByteReader,
    private readonly seven: SevenArchive,
    readonly notes: Note[],
    private readonly passwords: string[],
    env: ConstructorParameters<typeof SevenReader>[0],
  ) {
    this.contents = new SevenReader(env, seven);
    this.nameless = seven.entries.length > 0 && seven.entries.every(s => s.info.name === undefined);
    this.entries = seven.entries.map(s => {
      const kind = KINDS[s.kind];
      const raw = s.info.name ?? '';
      const name = wellFormed(raw);
      const entryNotes: Note[] = name === raw ? [] : [{ category: C.Name, detail: D.Encoding, data: { name } }];
      const folder = s.folder === undefined ? undefined : seven.streams?.folders[s.folder];
      const encrypted = folder?.coders.some(c => c.method === '06f10701') === true;
      const full = unixMode(s.info.attrib);
      return {
        index: s.index,
        name: kind === 'directory' && name !== '' && !name.endsWith('/') ? `${name}/` : name,
        kind,
        mode: full === undefined ? undefined : full & 0o7777,
        size: s.size,
        compressedSize: 0,
        encryption: encrypted ? { kind: 'aes', bits: 256 } : undefined,
        notes: entryNotes,
        anti: s.info.anti === true,
        seven: s,
      };
    });
  }

  static async open(source: ByteSource, limits: Limits, deadline: number | undefined, passwords: string[]): Promise<SevenZipArchive> {
    const size = await source.size();
    const reader = new Reader(source, size);
    const found = detectLzmaFormat(await reader.read(0, Math.min(size, SEVENZIP_SEARCH)));
    if (found?.format !== '7z') throw new DataError('no 7z signature header');
    const env = { source, reader, size, limits, totals: { decoded: 0, compressed: 0 }, deadline, passwords };
    const seven = await openSevenZip(env, found.offset);
    const notes: Note[] = grouped(seven.notes);
    if (seven.headerEncrypted) notes.push({ category: C.Encrypted, detail: D.Header });
    if (found.offset > 0) {
      notes.push({ category: C.Structure, detail: D.LeadingBytes, data: { bytes: found.offset } });
      const type = sniffType(await reader.read(0, Math.min(found.offset, 1024)));
      if (type !== undefined) notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'before the archive' } });
    }
    await trailing(reader, seven.trailingAt, notes);
    await otherReaders(reader, found.offset, seven.trailingAt, notes);
    return new SevenZipArchive(reader, seven, notes, passwords, env);
  }

  hasMetadata(): boolean {
    return this.seven.entries.some(e => e.info.ctime || e.info.atime || e.info.mtime);
  }

  async unlock(e: SevenZipEntry, password: string): Promise<boolean> {
    return this.contents.unlock(e.seven, password);
  }

  async *read(e: SevenZipEntry, meter: Meter, password?: string): AsyncGenerator<Uint8Array> {
    let total = 0;
    for await (const c of this.contents.content(e.seven, password)) {
      total += c.length;
      meter.add(total);
      yield c;
    }
  }

  /** A symbolic link's target, which a 7z archive keeps as the link's content. */
  async linkTarget(e: SevenZipEntry, meter: Meter): Promise<string | undefined> {
    // A Windows reparse point holds a reparse buffer, not a path, so where it leads cannot be read as a path.
    if (e.size > MAX_LINK || unixMode(e.seven.info.attrib) === undefined) return undefined;
    let password: string | undefined;
    if (e.encryption) {
      for (const p of this.passwords) {
        if (await this.unlock(e, p)) {
          password = p;
          break;
        }
      }
      if (password === undefined) return undefined;
    }
    const parts: Uint8Array[] = [];
    for await (const c of this.read(e, meter, password)) parts.push(c);
    return Buffer.concat(parts).toString('utf8');
  }

  async write(plan: WritePlan<SevenZipEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    const time = () => context.meter().time();
    if (plan.keepLeading && this.seven.offset > 0) await copyRange(this.reader, sink, 0, this.seven.offset, time);
    const out: SevenOut[] = plan.kept.map(k => this.out(k, plan, context));
    await writeSevenZip(out, sink, context.temp, context.threshold, time, plan.ratioLimit);
    await this.contents.close();
    const end = this.seven.trailingAt;
    if (plan.keepTrailing && end !== undefined) await copyRange(this.reader, sink, end, this.reader.size, time);
  }

  /** One kept entry as the writer takes it, with its name and permissions as the rules left them. */
  private out(k: Kept<SevenZipEntry>, plan: WritePlan<SevenZipEntry>, context: WriteContext): SevenOut {
    const info = k.entry.seven.info;
    const dir = k.entry.kind === 'directory';
    let attrib = info.attrib;
    const full = unixMode(attrib);
    if (full !== undefined && attrib !== undefined) {
      const mode = ((full & ~0o7777) | ((k.mode ?? full) & 0o7777)) & 0xffff;
      attrib = ((attrib & 0xffff) | (mode << 16)) >>> 0;
    }
    const size = sizeOf(k);
    const content: Content | undefined = dir || size === 0 ? undefined : { size, chunks: () => contentOf(this, k, context) };
    const name = dir && k.name.endsWith('/') ? k.name.slice(0, -1) : k.name;
    const o: SevenOut = { name: info.name === undefined ? undefined : name, dir, attrib, content };
    if (!plan.stripMetadata) {
      o.ctime = info.ctime;
      o.atime = info.atime;
      o.mtime = info.mtime;
    }
    return o;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// xz and .lzma

/** The engine's meter in the shape the xz and .lzma readers count through: decoded bytes against compressed ones. */
function counter(meter: Meter): StreamCounter {
  let decoded = 0;
  let compressed = 0;
  return {
    get decoded() {
      return decoded;
    },
    get compressed() {
      return compressed;
    },
    tick: () => meter.time(),
    packed: n => {
      compressed += n;
    },
    add: n => {
      decoded += n;
      meter.add(decoded, compressed);
    },
  };
}

interface LzmaSingleEntry extends Entry {
  decoded?: number;
}

/** A file that compresses one file: its one entry has no name, and its content goes to the plugins like any other. */
abstract class LzmaSingle implements Archive<LzmaSingleEntry> {
  abstract readonly format: 'xz' | 'lzma';
  readonly single = true;
  readonly notes: Note[] = [];
  readonly lateNotes: Note[] = [];
  readonly entries: LzmaSingleEntry[];
  /** Set once the entry has been read: where data after the stream starts, when the file goes on. */
  protected trailingAt?: number;
  /** Set once the entry has been read and nothing about the stream needs writing again: it can be copied as it is. */
  protected copyable = false;

  constructor(
    protected readonly reader: ByteReader,
    protected readonly limits: Limits,
  ) {
    this.entries = [{ index: 0, name: '', kind: 'file', size: 0, compressedSize: reader.size, notes: [] }];
  }

  async unlock(): Promise<boolean> {
    return false;
  }

  hasMetadata(): boolean {
    return false;
  }

  abstract read(e: LzmaSingleEntry, meter: Meter): AsyncGenerator<Uint8Array>;

  /** Writes `content` in the format. With `store`, a format that can store data uncompressed does. */
  protected abstract encode(content: ByteSource | undefined, sink: ByteSink, time: () => void, store: boolean): Promise<void>;

  /** True when encode() can store data uncompressed. */
  protected readonly canStore: boolean = false;

  /** Notes what the read found besides the content, and whether the stream can be copied as it is. */
  protected async finishRead(e: LzmaSingleEntry, total: number, notes: Note[], oneStream: boolean, trailingAt: number | undefined): Promise<void> {
    e.decoded = total;
    e.size = total;
    this.trailingAt = trailingAt;
    this.lateNotes.length = 0;
    this.lateNotes.push(...grouped(notes));
    await trailing(this.reader, trailingAt, this.lateNotes);
    await otherReaders(this.reader, 0, trailingAt, this.lateNotes);
    this.copyable = oneStream && this.lateNotes.length === 0;
  }

  async write(plan: WritePlan<LzmaSingleEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    const time = () => context.meter().time();
    const k = plan.kept[0];
    const end = this.trailingAt ?? this.reader.size;
    if (k && !k.replacement && !k.recompress && this.copyable) await copyRange(this.reader, sink, 0, end, time);
    else await this.writeContent(k, sink, context, time, plan.ratioLimit);
    if (plan.keepTrailing && this.trailingAt !== undefined) await copyRange(this.reader, sink, this.trailingAt, this.reader.size, time);
  }

  private async writeContent(k: Kept<LzmaSingleEntry> | undefined, sink: ByteSink, context: WriteContext, time: () => void, ratioLimit: number): Promise<void> {
    if (!k) return this.encode(undefined, sink, time, false);
    // The writer reads the content by offset, so content that is not a plugin's copy is decoded again into memory or
    // a temporary file first.
    const decoded = k.replacement ? undefined : new SpillSink(context.temp, context.threshold);
    const encoded = new SpillSink(context.temp, context.threshold);
    try {
      if (decoded) {
        for await (const c of contentOf(this, k, context)) await decoded.write(c);
        await decoded.close();
      }
      const content = (decoded ?? k.replacement)?.source();
      if (!content) throw new Error('No content to write');
      try {
        await this.encode(content, encoded, time, false);
        await encoded.close();
        const size = await content.size();
        // Content compressed past the ratio limit is stored where the format can store, so the output reads under the
        // same limit.
        if (this.canStore && passesRatio(size, encoded.length, ratioLimit)) await this.encode(content, sink, time, true);
        else for await (const c of encoded.read()) await sink.write(c);
      } finally {
        await content.close?.();
      }
    } finally {
      await encoded.dispose();
      await decoded?.dispose();
    }
  }
}

export class XzArchive extends LzmaSingle {
  readonly format = 'xz';
  /** The check the rewrite writes: the one every stream used when this package can compute it, else CRC64. */
  private checkId = CHECK_CRC64;

  static async open(source: ByteSource, limits: Limits): Promise<XzArchive> {
    return new XzArchive(new Reader(source, await source.size()), limits);
  }

  async *read(e: LzmaSingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    const info: XzInfo = { streams: 0, checks: [], notes: [] };
    let total = 0;
    for await (const c of readXz({ reader: this.reader, size: this.reader.size, limits: this.limits, meter: counter(meter) }, info)) {
      total += c.length;
      yield c;
    }
    const notes = [...info.notes];
    if (info.streams > 1) notes.push({ category: C.Structure, detail: D.MultipleStreams, data: { count: info.streams } });
    const checks = new Set(info.checks);
    const only = checks.size === 1 ? [...checks][0] : undefined;
    this.checkId = only !== undefined && WRITABLE_CHECKS.has(only) ? only : CHECK_CRC64;
    await this.finishRead(e, total, notes, info.streams === 1, info.trailingAt);
  }

  protected override readonly canStore = true;

  protected encode(content: ByteSource | undefined, sink: ByteSink, time: () => void, store: boolean): Promise<void> {
    return writeXz(content, this.checkId, sink, time, store);
  }
}

export class LzmaArchive extends LzmaSingle {
  readonly format = 'lzma';

  static async open(source: ByteSource, limits: Limits): Promise<LzmaArchive> {
    return new LzmaArchive(new Reader(source, await source.size()), limits);
  }

  async *read(e: LzmaSingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    const info: AloneInfo = { notes: [] };
    let total = 0;
    for await (const c of readAlone({ reader: this.reader, size: this.reader.size, limits: this.limits, meter: counter(meter) }, info)) {
      total += c.length;
      yield c;
    }
    await this.finishRead(e, total, info.notes, true, info.trailingAt);
  }

  protected encode(content: ByteSource | undefined, sink: ByteSink, time: () => void): Promise<void> {
    return writeAlone(content, sink, time);
  }
}
