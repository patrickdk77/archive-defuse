// Making archives and compressed files from scratch, for callers who use this package as an archive library: ZIP,
// tar on its own or compressed, 7z, and the formats that compress one file. The writers are the ones the rewrite uses.
import { PassThrough, type Readable } from 'node:stream';
import { bzip2 } from './bzip2';
import { brotliEncode, deflateRaw } from './codecs';
import { crc32 } from './crc32';
import { bufferSink, SpillSink, TempDir, writableSink } from './io';
import { type Content, passesRatio, type SevenOut, writeAlone, writeSevenZip, writeXz } from './lzma-writers';
import { nameDetails } from './rules';
import { asciiFallback, BLOCK, header, paxRecord, RECORD, split } from './tar';
import { type ByteSink, type ByteSource, ArchiveDetail as D } from './types';
import { type Written, ZipOutput } from './zip-writer';
import { zstdEncode } from './zstd';

/** What an entry holds: bytes, text written as UTF-8, or a stream such as a Node Readable. */
export type PackData = Uint8Array | string | AsyncIterable<Uint8Array | string>;

/** One file, folder or symbolic link to put in an archive. */
export interface PackEntry {
  /** The path inside the archive, with "/" between folders. A name that ends in "/" is a folder. */
  name: string;
  /** Defaults to 'directory' for a name that ends in "/", 'symlink' when `linkTarget` is set, and 'file' otherwise. */
  kind?: 'file' | 'directory' | 'symlink';
  /**
   * The content of a file, or a function that returns it, which is called when the entry is written. A function lets
   * a caller open a stream only when its turn comes.
   */
  data?: PackData | (() => PackData | Promise<PackData>);
  /** The target of a symbolic link. */
  linkTarget?: string;
  /** Permission bits. Defaults to 0644 for a file and 0755 for a folder. */
  mode?: number;
  /** Defaults to `PackOptions.mtime`. */
  mtime?: Date;
  /** ZIP only: store the file without compression, as the `mimetype` entry of an ODF document needs. */
  store?: boolean;
}

/** The archive formats `createArchive` writes. */
export type PackFormat = 'zip' | 'tar' | 'tar.gz' | 'tar.bz2' | 'tar.zst' | 'tar.xz' | '7z';

/** The formats that compress one file, which `compress` writes. */
export type CompressFormat = 'gzip' | 'bzip2' | 'zstd' | 'brotli' | 'xz' | 'lzma';

export interface PackOptions {
  /**
   * Compression level: 0 to 9 for ZIP deflate and gzip (default 6), 1 to 9 for bzip2 (default 9). The other formats
   * have one level.
   */
  level?: number;
  /** The time of entries that give none. Defaults to the time the call starts. */
  mtime?: Date;
  /** ZIP: the archive's comment. */
  comment?: string;
  /**
   * ZIP and 7z: a file that would compress past this many bytes per compressed byte is stored instead, so the archive
   * reads under the same `limits.compressionRatio` when this package inspects it. Default 1,000, the reading default.
   */
  ratioLimit?: number;
  /** Folder for temporary files. Defaults to `os.tmpdir()`. */
  tempDir?: string;
  /**
   * Bytes of one entry held in memory before a temporary file takes over, default 8 MiB. ZIP, tar and 7z need an
   * entry's size before its data, so an entry given as a stream is read into memory or a temporary file first.
   */
  memoryThreshold?: number;
  /** Stops the work when aborted: the sink is aborted and the call throws the signal's reason. */
  signal?: AbortSignal;
}

/** Thrown for an entry this package will not write, before anything of the entry is written. */
export class PackError extends Error {}

const enc = new TextEncoder();
/** The reading default of `limits.compressionRatio`. */
const DEFAULT_RATIO = 1000;
const toBytes = (c: Uint8Array | string) => (typeof c === 'string' ? enc.encode(c) : c);

/** Throws the signal's reason once the work is to stop. */
type Check = () => void;

/** `chunks`, with `check` before each one, so an aborted signal stops a long read. */
async function* checked(chunks: AsyncIterable<Uint8Array>, check: Check): AsyncGenerator<Uint8Array> {
  for await (const c of chunks) {
    check();
    yield c;
  }
}

/** The content of an entry as chunks of bytes. */
async function* chunksOf(data: PackData | undefined): AsyncGenerator<Uint8Array> {
  if (data === undefined) return;
  if (typeof data === 'string' || data instanceof Uint8Array) {
    const b = toBytes(data);
    if (b.length) yield b;
    return;
  }
  for await (const c of data) {
    const b = toBytes(c);
    if (b.length) yield b;
  }
}

/** One entry with its kind settled and its name checked. */
interface Settled {
  name: string;
  kind: 'file' | 'directory' | 'symlink';
  entry: PackEntry;
  mode: number;
  mtime: Date;
}

/** Why `createArchive` refuses a name, for each name rule of the inspection that changes a name. */
const REFUSED: Partial<Record<D, string>> = {
  [D.Empty]: 'is empty',
  [D.DriveLetter]: 'starts with a drive letter',
  [D.Absolute]: 'is an absolute path',
  [D.Traversal]: 'has a ".." part',
  [D.EmptySegment]: 'has an empty or "." part',
  [D.Backslash]: 'holds a backslash, which Windows reads as a folder separator',
  [D.ControlCharacter]: 'holds a control character or a character that reorders text',
  [D.WindowsReserved]: 'has a part Windows cannot create as written',
};

/**
 * Characters that Windows turns into a slash, a backslash, a colon or a dot when a program that uses the ANSI file
 * calls converts a name with best fit. Taken from Microsoft's best-fit tables at unicode.org for code pages 874, 932,
 * 936, 949, 950 and 1250 to 1258. The yen sign is a backslash in code page 932, the won sign in 949, and the acute
 * accent a slash in 1253.
 */
const BEST_FIT: Record<string, string> = {
  '\u00a5': '\\',
  '\u20a9': '\\',
  '\u2216': '\\',
  '\uff3c': '\\',
  '\u00b4': '/',
  '\u2044': '/',
  '\u2215': '/',
  '\uff0f': '/',
  '\u0589': ':',
  '\u2236': ':',
  '\uff1a': ':',
  '\uff0e': '.',
};
const BEST_FIT_CHARS = /[\u00a5\u20a9\u2216\uff3c\u00b4\u2044\u2215\uff0f\u0589\u2236\uff1a\uff0e]/g;
/** The rules whose break lets an extractor write outside its folder. */
const ESCAPES = [D.DriveLetter, D.Absolute, D.Traversal];

/**
 * Settles an entry's kind and checks its name. The name must pass the inspection's name rules, so the archive passes
 * this package's own inspection: no ".." part, no absolute path or drive letter, no empty or "." part, no backslash,
 * control character or part Windows cannot create. It must also not leave its folder once NFKC normalization or
 * Windows best fit has changed it, as "\uff0e\uff0e/x" becomes "../x".
 */
function settle(entry: PackEntry, options: PackOptions, now: Date): Settled {
  const raw = entry.name;
  if (typeof raw !== 'string' || raw === '' || raw === '/') throw new PackError('An entry needs a name');
  if (raw.includes('\0')) throw new PackError(`Entry name ${JSON.stringify(raw)} holds a NUL`);
  const kind = entry.kind ?? (raw.endsWith('/') ? 'directory' : entry.linkTarget !== undefined ? 'symlink' : 'file');
  if (kind === 'symlink' && entry.linkTarget === undefined) throw new PackError(`Symbolic link ${JSON.stringify(raw)} needs a linkTarget`);
  const name = kind === 'directory' ? (raw.endsWith('/') ? raw : `${raw}/`) : raw.replace(/\/+$/, '');
  for (const detail of nameDetails(name, true)) {
    const why = REFUSED[detail];
    if (why) throw new PackError(`Entry name ${JSON.stringify(raw)} ${why}`);
  }
  const folds: Array<[string, string]> = [
    [name.normalize('NFKC'), 'NFKC normalization'],
    [name.replace(BEST_FIT_CHARS, c => BEST_FIT[c]), 'Windows best fit'],
  ];
  for (const [folded, how] of folds) {
    if (folded !== name && nameDetails(folded, true).some(d => ESCAPES.includes(d))) throw new PackError(`Entry name ${JSON.stringify(raw)} leaves its folder after ${how}`);
  }
  return { name, kind, entry, mode: (entry.mode ?? (kind === 'directory' ? 0o755 : kind === 'symlink' ? 0o777 : 0o644)) & 0o7777, mtime: entry.mtime ?? options.mtime ?? now };
}

/** The content of a settled entry: a file's data, a link's target, or nothing for a folder. */
async function contentOf(s: Settled): Promise<AsyncGenerator<Uint8Array>> {
  if (s.kind === 'directory') return chunksOf(undefined);
  if (s.kind === 'symlink') return chunksOf(s.entry.linkTarget);
  const d = s.entry.data;
  return chunksOf(typeof d === 'function' ? await d() : d);
}

/** Reads an entry's content into memory or a temporary file, counting its CRC-32. */
async function spillOf(s: Settled, temp: TempDir, threshold: number, check: Check): Promise<{ spill: SpillSink; crc: number }> {
  const spill = new SpillSink(temp, threshold);
  let crc = 0;
  try {
    for await (const c of checked(await contentOf(s), check)) {
      crc = crc32(c, crc);
      await spill.write(c);
    }
    await spill.close();
  } catch (e) {
    await spill.dispose();
    throw e;
  }
  return { spill, crc };
}

const isAscii = (s: string) => /^[\x20-\x7e]*$/.test(s);

// ---------------------------------------------------------------------------------------------------------------
// ZIP

/** A date as the DOS time and date of a ZIP header, local time, clamped to the years DOS can hold. */
function dosTime(d: Date): { time: number; date: number } {
  const year = Math.min(2107, Math.max(1980, d.getFullYear()));
  return {
    time: (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1),
    date: ((year - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate(),
  };
}

const ZIP_TYPE_BITS = { file: 0o100000, directory: 0o040000, symlink: 0o120000 };

async function writeZipEntries(entries: AsyncIterable<Settled>, sink: ByteSink, options: PackOptions, temp: TempDir, check: Check): Promise<void> {
  const out = new ZipOutput(sink);
  const threshold = options.memoryThreshold ?? 8 * 1024 * 1024;
  const level = options.level ?? 6;
  for await (const s of entries) {
    const { time, date } = dosTime(s.mtime);
    const info: Written = {
      name: enc.encode(s.name),
      flags: isAscii(s.name) ? 0 : 0x0800,
      method: 0,
      versionNeeded: s.kind === 'directory' ? 20 : 10,
      versionMadeBy: (3 << 8) | 30,
      externalAttr: (((ZIP_TYPE_BITS[s.kind] | s.mode) << 16) >>> 0) | (s.kind === 'directory' ? 0x10 : 0),
      internalAttr: 0,
      time,
      date,
      crc: 0,
      compressedSize: 0,
      size: 0,
      extras: new Uint8Array(0),
      comment: new Uint8Array(0),
    };
    if (s.kind === 'directory') {
      await out.entry(info, () => chunksOf(undefined), s.name);
      continue;
    }
    // The content is read once, into memory or a temporary file, and deflated from there, so it can be stored instead
    // when deflate gains nothing or passes the ratio limit.
    const { spill: raw, crc } = await spillOf(s, temp, threshold, check);
    const deflated = new SpillSink(temp, threshold);
    try {
      let stored = s.kind === 'symlink' || s.entry.store === true || level === 0 || raw.length === 0;
      if (!stored) {
        for await (const c of deflateRaw(checked(raw.read(), check), level)) await deflated.write(c);
        await deflated.close();
        stored = deflated.length >= raw.length || passesRatio(raw.length, deflated.length, options.ratioLimit ?? DEFAULT_RATIO);
      }
      info.method = stored ? 0 : 8;
      info.versionNeeded = stored ? 10 : 20;
      info.crc = crc;
      info.size = raw.length;
      info.compressedSize = stored ? raw.length : deflated.length;
      await out.entry(info, () => checked(stored ? raw.read() : deflated.read(), check), s.name);
    } finally {
      await deflated.dispose();
      await raw.dispose();
    }
  }
  await out.end(enc.encode(options.comment ?? ''));
}

// ---------------------------------------------------------------------------------------------------------------
// tar

const TAR_TYPES = { file: '0', directory: '5', symlink: '2' };

async function* tarChunks(entries: AsyncIterable<Settled>, options: PackOptions, temp: TempDir, check: Check): AsyncGenerator<Uint8Array> {
  const threshold = options.memoryThreshold ?? 8 * 1024 * 1024;
  let written = 0;
  const pad = (n: number) => Buffer.alloc((BLOCK - (n % BLOCK)) % BLOCK);
  for await (const s of entries) {
    const { spill } = s.kind === 'file' ? await spillOf(s, temp, threshold, check) : { spill: undefined };
    try {
      const size = spill?.length ?? 0;
      const link = s.kind === 'symlink' ? (s.entry.linkTarget ?? '') : '';
      const mtime = Math.floor(s.mtime.getTime() / 1000);
      // What the ustar header cannot hold goes in a pax header before it.
      const records: Buffer[] = [];
      const parts = split(s.name);
      if (!parts) records.push(paxRecord('path', Buffer.from(s.name, 'utf8')));
      const linkFits = isAscii(link) && link.length <= 100;
      if (!linkFits) records.push(paxRecord('linkpath', Buffer.from(link, 'utf8')));
      if (size > 0o77777777777) records.push(paxRecord('size', Buffer.from(String(size))));
      const timeFits = mtime >= 0 && mtime <= 0o77777777777;
      if (!timeFits) records.push(paxRecord('mtime', Buffer.from(String(mtime))));
      if (records.length) {
        const body = Buffer.concat(records);
        const h = header({
          name: Buffer.from('././@PaxHeader'),
          mode: 0o644,
          uid: 0,
          gid: 0,
          size: body.length,
          mtime: 0,
          typeflag: 'x',
          linkname: Buffer.alloc(0),
          uname: '',
          gname: '',
          prefix: Buffer.alloc(0),
          devmajor: 0,
          devminor: 0,
        });
        yield h;
        yield body;
        yield pad(body.length);
        written += h.length + body.length + pad(body.length).length;
      }
      const h = header({
        name: parts?.name ?? asciiFallback(s.name),
        prefix: parts?.prefix ?? Buffer.alloc(0),
        mode: s.mode,
        uid: 0,
        gid: 0,
        size: size > 0o77777777777 ? 0 : size,
        mtime: timeFits ? mtime : 0,
        typeflag: TAR_TYPES[s.kind],
        linkname: linkFits ? Buffer.from(link, 'latin1') : asciiFallback(link),
        uname: '',
        gname: '',
        devmajor: 0,
        devminor: 0,
      });
      yield h;
      written += h.length;
      if (spill) {
        yield* checked(spill.read(), check);
        const p = pad(size);
        if (p.length) yield p;
        written += size + p.length;
      }
    } finally {
      await spill?.dispose();
    }
  }
  const end = Buffer.alloc(2 * BLOCK);
  yield end;
  written += end.length;
  const tail = (RECORD - (written % RECORD)) % RECORD;
  if (tail) yield Buffer.alloc(tail);
}

// ---------------------------------------------------------------------------------------------------------------
// 7z

/** A date as a Windows FILETIME: 100-nanosecond intervals since 1601, little-endian. */
function fileTime(d: Date): Uint8Array {
  const t = BigInt(d.getTime() + 11_644_473_600_000) * 10_000n;
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(t < 0n ? 0n : t);
  return b;
}

async function writeSevenEntries(entries: AsyncIterable<Settled>, sink: ByteSink, options: PackOptions, temp: TempDir, check: Check): Promise<void> {
  const threshold = options.memoryThreshold ?? 8 * 1024 * 1024;
  const spills: SpillSink[] = [];
  const out: SevenOut[] = [];
  try {
    // 7z writes its header after the data, from every entry, so each entry is read before any is written.
    let held = 0;
    for await (const s of entries) {
      const dir = s.kind === 'directory';
      let content: Content | undefined;
      if (!dir) {
        const { spill } = await spillOf(s, temp, Math.max(0, threshold - held), check);
        spills.push(spill);
        if (!spill.spilled) held += spill.length;
        content = { size: spill.length, chunks: () => spill.read() };
      }
      const typeBits = dir ? 0o040000 : s.kind === 'symlink' ? 0o120000 : 0o100000;
      // The Unix mode sits in the high 16 bits, with 0x8000 to say it is there, as p7zip writes it.
      const attrib = (((typeBits | s.mode) << 16) | 0x8000 | (dir ? 0x10 : 0x20)) >>> 0;
      out.push({ name: dir ? s.name.slice(0, -1) : s.name, dir, attrib, mtime: fileTime(s.mtime), content });
    }
    await writeSevenZip(out, sink, temp, threshold, check, options.ratioLimit ?? DEFAULT_RATIO);
  } finally {
    for (const s of spills) await s.dispose();
  }
}

// ---------------------------------------------------------------------------------------------------------------
// One compressed stream

/** A gzip member around raw deflate, with the CRC-32 and size after it. */
async function* gzipOf(chunks: AsyncIterable<Uint8Array>, level: number, mtime: Date): AsyncGenerator<Uint8Array> {
  const head = Buffer.from([0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255]);
  head.writeUInt32LE(Math.max(0, Math.min(0xffffffff, Math.floor(mtime.getTime() / 1000))), 4);
  yield head;
  let crc = 0;
  let size = 0;
  async function* tally(): AsyncGenerator<Uint8Array> {
    for await (const c of chunks) {
      crc = crc32(c, crc);
      size += c.length;
      yield c;
    }
  }
  yield* deflateRaw(tally(), level);
  const tail = Buffer.alloc(8);
  tail.writeUInt32LE(crc >>> 0, 0);
  tail.writeUInt32LE(size % 2 ** 32, 4);
  yield tail;
}

/** xz and .lzma need the content by offset, or its size first, so it is read into memory or a temporary file. */
async function* lzmaOf(format: 'xz' | 'lzma', chunks: AsyncIterable<Uint8Array>, options: PackOptions, temp: TempDir, check: Check): AsyncGenerator<Uint8Array> {
  const spill = new SpillSink(temp, options.memoryThreshold ?? 8 * 1024 * 1024);
  try {
    for await (const c of checked(chunks, check)) await spill.write(c);
    await spill.close();
    const source: ByteSource | undefined = spill.length ? spill.source() : undefined;
    // The writers write to a sink, so their output goes to memory or a temporary file and then out.
    const encoded = new SpillSink(temp, options.memoryThreshold ?? 8 * 1024 * 1024);
    try {
      try {
        if (format === 'xz') await writeXz(source, 4, encoded, check);
        else await writeAlone(source, encoded, check);
      } finally {
        await source?.close?.();
      }
      await encoded.close();
      yield* checked(encoded.read(), check);
    } finally {
      await encoded.dispose();
    }
  } finally {
    await spill.dispose();
  }
}

function compressChunks(format: CompressFormat, input: AsyncIterable<Uint8Array>, options: PackOptions, temp: TempDir, now: Date, check: Check): AsyncIterable<Uint8Array> {
  const chunks = checked(input, check);
  switch (format) {
    case 'gzip':
      return gzipOf(chunks, options.level ?? 6, options.mtime ?? now);
    case 'bzip2':
      return bzip2(chunks, options.level ?? 9);
    case 'zstd':
      return zstdEncode(chunks);
    case 'brotli':
      return brotliEncode(chunks);
    case 'xz':
    case 'lzma':
      return lzmaOf(format, chunks, options, temp, check);
    default:
      throw new PackError(`Unknown format ${String(format)}`);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The calls

const ARCHIVE_FORMATS = new Set<PackFormat>(['zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.zst', 'tar.xz', '7z']);
const TAR_COMPRESSION: Record<string, CompressFormat> = { 'tar.gz': 'gzip', 'tar.bz2': 'bzip2', 'tar.zst': 'zstd', 'tar.xz': 'xz' };

/** Copies chunks to the sink, then closes it. On failure it aborts the sink, so a partial output never looks whole. */
async function deliver(produce: () => Promise<void>, sink: ByteSink): Promise<void> {
  try {
    await produce();
  } catch (e) {
    try {
      await sink.abort?.(e);
    } catch {
      // The write's error is the one to report.
    }
    throw e;
  }
  await sink.close();
}

/**
 * Writes an archive of `entries`, in their order, to `sink`, then closes it. Entries can come as a list or as an async
 * iterable, and each file's content as bytes, text or a stream. When anything fails, such as an entry's stream, the
 * sink is aborted instead of closed and the error is thrown.
 */
export async function createArchive(format: PackFormat, entries: Iterable<PackEntry> | AsyncIterable<PackEntry>, sink: ByteSink, options: PackOptions = {}): Promise<void> {
  if (!ARCHIVE_FORMATS.has(format)) throw new PackError(`Unknown archive format ${String(format)}`);
  const now = new Date();
  const temp = new TempDir(options.tempDir);
  const check = () => options.signal?.throwIfAborted();
  async function* settled(): AsyncGenerator<Settled> {
    for await (const e of entries) {
      check();
      yield settle(e, options, now);
    }
  }
  try {
    await deliver(async () => {
      check();
      if (format === 'zip') return writeZipEntries(settled(), sink, options, temp, check);
      if (format === '7z') return writeSevenEntries(settled(), sink, options, temp, check);
      const tar = tarChunks(settled(), options, temp, check);
      const method = TAR_COMPRESSION[format];
      for await (const c of method ? compressChunks(method, tar, options, temp, now, check) : tar) await sink.write(c);
    }, sink);
  } finally {
    await temp.cleanup();
  }
}

/**
 * Runs `write` into a Node Readable. An error destroys the stream, so a consumer never takes a partial output as whole.
 * A consumer that destroys the stream before its end, or the caller's signal, stops the work.
 */
function readableOf(write: (sink: ByteSink, signal: AbortSignal) => Promise<void>, signal?: AbortSignal): Readable {
  const out = new PassThrough();
  const controller = new AbortController();
  const stop = () => controller.abort(signal?.reason);
  if (signal?.aborted) stop();
  else signal?.addEventListener('abort', stop, { once: true });
  out.on('close', () => {
    if (!controller.signal.aborted) controller.abort(out.errored ?? new Error('The output stream closed before all data was written'));
  });
  write(writableSink(out), controller.signal)
    .catch(e => {
      if (!out.destroyed) out.destroy(e instanceof Error ? e : new Error(String(e)));
    })
    .finally(() => signal?.removeEventListener('abort', stop));
  return out;
}

/** `createArchive` as a Node Readable, to pipe to a file, an HTTP response or an upload. */
export function createArchiveStream(format: PackFormat, entries: Iterable<PackEntry> | AsyncIterable<PackEntry>, options: PackOptions = {}): Readable {
  return readableOf((sink, signal) => createArchive(format, entries, sink, { ...options, signal }), options.signal);
}

/** `createArchive` into memory. */
export async function createArchiveBytes(format: PackFormat, entries: Iterable<PackEntry> | AsyncIterable<PackEntry>, options: PackOptions = {}): Promise<Uint8Array> {
  const sink = bufferSink();
  await createArchive(format, entries, sink, options);
  return sink.result();
}

/** Compresses `data` as one stream of `format` to `sink`, then closes it. */
export async function compressTo(format: CompressFormat, data: PackData, sink: ByteSink, options: PackOptions = {}): Promise<void> {
  const temp = new TempDir(options.tempDir);
  const check = () => options.signal?.throwIfAborted();
  try {
    await deliver(async () => {
      check();
      for await (const c of compressChunks(format, chunksOf(data), options, temp, new Date(), check)) await sink.write(c);
    }, sink);
  } finally {
    await temp.cleanup();
  }
}

/** `compressTo` as a Node Readable. */
export function compressStream(format: CompressFormat, data: PackData, options: PackOptions = {}): Readable {
  return readableOf((sink, signal) => compressTo(format, data, sink, { ...options, signal }), options.signal);
}

/** `compressTo` into memory. */
export async function compress(format: CompressFormat, data: PackData, options: PackOptions = {}): Promise<Uint8Array> {
  const sink = bufferSink();
  await compressTo(format, data, sink, options);
  return sink.result();
}
