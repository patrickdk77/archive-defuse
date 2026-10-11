import { type AesProps, deriveKey } from './aes7z';
import { type Chunks, checkFolder, decodeFolder, type FolderEnv, isAes } from './coders';
import { crc32 } from './crc32';
import { CheckError, DataError, ParseError, StopError, stopsTree, UnsupportedError } from './errors';
import type { Reader } from './io';
import type { Note } from './model';
import { type FileInfo, type Folder, Nid, parseEncodedHeader, parseHeader, parseStartHeader, type StartHeader, type StreamsInfo } from './sevenzip';
import type { Limits, StreamCounter as Meter, Totals } from './stream-meter';
import { Meter as StreamMeter } from './stream-meter';
import { type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';

/** What kind of thing an entry is. */
export type EntryKind = 'file' | 'dir' | 'symlink' | 'device' | 'fifo' | 'socket';

/** One entry of a 7z archive. */
export interface SevenEntry {
  index: number;
  info: FileInfo;
  kind: EntryKind;
  /** Decoded size the header declares. */
  size: number;
  crc?: number;
  /** The folder the entry's data sits in, if it has data. */
  folder?: number;
  /** Where the entry's data starts in its folder's output. */
  start: number;
}

/** A byte range of the file and what it holds, for finding the bytes no structure covers. */
interface Span {
  start: number;
  end: number;
  what: string;
}

export interface SevenArchive {
  /** Where the signature header starts: above 0 when other data comes first. */
  offset: number;
  entries: SevenEntry[];
  streams?: StreamsInfo;
  notes: Note[];
  /** The header was encrypted and a password opened it. */
  headerEncrypted: boolean;
  /** Offset of the first byte after the last structure, when the file goes on past it. */
  trailingAt?: number;
  /** Absolute offset of each packed stream. */
  packOffsets: number[];
  /** Index of each folder's first packed stream. */
  folderPack: number[];
}

export interface SevenEnv {
  source: ByteSource;
  reader: Reader;
  size: number;
  limits: Limits;
  totals: Totals;
  deadline?: number;
  /** Passwords to try, in order. */
  passwords: string[];
}

const S_IFMT = 0xf000;
const UNIX_EXTENSION = 0x8000;
const FILE_ATTRIBUTE_DIRECTORY = 0x10;
const FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

/** The Unix mode stored in the high 16 bits of the attributes, when the low bits say one is there. */
export function unixMode(attrib: number | undefined): number | undefined {
  return attrib !== undefined && attrib & UNIX_EXTENSION ? attrib >>> 16 : undefined;
}

function kindOf(f: FileInfo): EntryKind {
  const mode = unixMode(f.attrib);
  if (mode !== undefined) {
    switch (mode & S_IFMT) {
      case 0xa000:
        return 'symlink';
      case 0x2000:
      case 0x6000:
        return 'device';
      case 0x1000:
        return 'fifo';
      case 0xc000:
        return 'socket';
      case 0x4000:
        return 'dir';
      default:
        break;
    }
  }
  if (f.attrib !== undefined && f.attrib & FILE_ATTRIBUTE_REPARSE_POINT) return 'symlink';
  if (!f.hasStream && !f.emptyFile && !f.anti) return 'dir';
  if (f.attrib !== undefined && f.attrib & FILE_ATTRIBUTE_DIRECTORY && !f.hasStream) return 'dir';
  return 'file';
}

const keyCache = new WeakMap<object, Map<string, Buffer>>();

function folderEnv(env: SevenEnv, meter: Meter, password: string | undefined): FolderEnv {
  let cache = keyCache.get(env);
  if (!cache) {
    cache = new Map();
    keyCache.set(env, cache);
  }
  const keys = cache;
  return {
    source: env.source,
    deadline: env.deadline,
    onPacked: n => meter.packed(n),
    key(props: AesProps): Buffer {
      if (password === undefined) throw new DataError('no password to try');
      const id = `${password}\0${Buffer.from(props.salt).toString('hex')}\0${props.numCyclesPower}`;
      let k = keys.get(id);
      if (!k) {
        k = deriveKey(password, props, env.deadline);
        keys.set(id, k);
      }
      return k;
    },
  };
}

/** Collects a stream into memory, up to `max` bytes. */
async function collect(chunks: Chunks, max: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  let n = 0;
  for await (const c of chunks) {
    n += c.length;
    if (n > max) throw new DataError('the stream decodes to more than its declared size');
    parts.push(c);
  }
  return Buffer.concat(parts);
}

const isEncrypted = (f: Folder) => f.coders.some(isAes);

/** Turns a folder check's limit into the stop it causes. */
function folderLimits(env: SevenEnv, folder: Folder, location: string): void {
  const over = checkFolder(folder, { decompressedBytes: env.limits.totalDecompressedBytes, dictionaryBytes: env.limits.dictionaryBytes });
  if (!over) return;
  if (over.limit === 'dictionary') throw new StopError(C.Limit, D.DictionarySize, 'Dictionary size limit exceeded', { limit: env.limits.dictionaryBytes, dictionary: over.value }, location);
  throw new StopError(C.Limit, D.TotalDecompressedSize, 'Total decompressed size limit exceeded', { limit: env.limits.totalDecompressedBytes, declared: over.value }, location);
}

/** Decodes an encoded header, trying each password on an encrypted one. */
async function decodeHeaderStreams(env: SevenEnv, info: StreamsInfo, base: number): Promise<{ bytes: Uint8Array; encrypted: boolean; spans: Span[] }> {
  if (info.folders.length !== 1) throw new ParseError('an encoded header has other than one folder');
  const folder = info.folders[0];
  folderLimits(env, folder, 'header');
  const size = folder.unpackSizes[folder.mainOut];
  if (size > env.limits.decompressedBytes) throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: env.limits.decompressedBytes, declared: size }, 'header');
  const offsets: number[] = [];
  let at = base + info.packPos;
  for (const s of info.packSizes) {
    offsets.push(at);
    at += s;
  }
  if (at > env.size) throw new DataError('the encoded header lies past the end of the file', true);
  const spans = offsets.map((o, i) => ({ start: o, end: o + info.packSizes[i], what: 'encoded header' }));
  const encrypted = isEncrypted(folder);
  const tries: Array<string | undefined> = encrypted ? env.passwords : [undefined];
  let lastError: unknown;
  for (const password of tries) {
    const meter = new StreamMeter(env.limits, env.totals, env.deadline, true, 'header');
    try {
      const chunks = decodeFolder(folder, offsets, info.packSizes, folderEnv(env, meter, password));
      const bytes = await collect(meterChunks(chunks, meter), size);
      if (folder.crc !== undefined && crc32(bytes) !== folder.crc) throw new CheckError('the encoded header CRC32 does not match', 'encoded header CRC32');
      if (bytes[0] !== Nid.Header) throw new ParseError('the decoded header does not start with kHeader');
      return { bytes, encrypted, spans };
    } catch (e) {
      if (!encrypted || e instanceof StopError || e instanceof UnsupportedError || stopsTree(e)) throw e;
      lastError = e;
    }
  }
  if (encrypted) throw new StopError(C.Encrypted, D.PasswordRequired, 'No password opens the header', undefined, 'header');
  throw lastError;
}

async function* meterChunks(chunks: Chunks, meter: Meter): AsyncGenerator<Uint8Array> {
  for await (const c of chunks) {
    meter.add(c.length);
    yield c;
  }
}

/**
 * Reads a 7z archive's signature and headers, decoding an encoded header, and checks that its structures fit the file
 * and each other. `offset` is where the signature was found.
 */
export async function openSevenZip(env: SevenEnv, offset: number): Promise<SevenArchive> {
  const notes: Note[] = [];
  const sig = await env.reader.read(offset, 32);
  if (sig.length < 32) throw new DataError('the file ends in its signature header', true);
  if (sig[6] !== 0) throw new UnsupportedError(`7z format version ${sig[6]}.${sig[7]}`, false, { reason: `format version ${sig[6]}.${sig[7]}` });
  const storedStart = new DataView(sig.buffer, sig.byteOffset, 32).getUint32(8, true);
  const base = offset + 32;
  if (!sig.subarray(8, 32).every(b => b === 0)) {
    if (crc32(sig.subarray(12, 32)) !== storedStart) throw new CheckError('the start header CRC32 does not match', 'start header CRC32');
    return openWith(env, offset, parseStartHeader(sig), notes);
  }
  // An empty start header: each place a header may start near the end is tried, the nearest to the end first.
  // A place that is not the header can claim any count or size, so a limit fails that place, not the file. When no
  // place works, the failure of the one nearest the end is reported.
  let failure: unknown;
  for (const start of await headerCandidates(env, base)) {
    try {
      const found = await openWith(env, offset, start, [{ category: C.Structure, detail: D.EmptyStartHeader }]);
      // An empty header parses anywhere, so a found one must hold data and files, as Commons Compress requires.
      if (found.streams && found.streams.packSizes.length > 0 && found.entries.length > 0) return found;
      failure ??= new ParseError('the header found at the end of the file holds no data');
    } catch (e) {
      if (!(e instanceof DataError || e instanceof UnsupportedError || e instanceof StopError)) throw e;
      failure ??= e;
    }
  }
  throw failure ?? new CheckError('the start header is empty and no header is found at the end of the file', 'start header CRC32');
}

/** Reads the headers an intact or recovered start header points to. */
async function openWith(env: SevenEnv, offset: number, start: StartHeader, notes: Note[]): Promise<SevenArchive> {
  const base = offset + 32;
  const spans: Span[] = [{ start: offset, end: base, what: 'signature header' }];
  const archive: SevenArchive = { offset, entries: [], notes, headerEncrypted: false, packOffsets: [], folderPack: [] };
  if (start.nextHeaderSize === 0) {
    finishSpans(env, archive, spans, base);
    return archive;
  }
  const headerStart = base + start.nextHeaderOffset;
  const headerEnd = headerStart + start.nextHeaderSize;
  if (headerEnd > env.size) throw new DataError('the header lies past the end of the file', true);
  if (start.nextHeaderSize > env.limits.decompressedBytes) {
    throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: env.limits.decompressedBytes, declared: start.nextHeaderSize }, 'header');
  }
  spans.push({ start: headerStart, end: headerEnd, what: 'header' });
  let headerBytes = await env.reader.read(headerStart, start.nextHeaderSize);
  if (crc32(headerBytes) !== start.nextHeaderCrc) throw new CheckError('the next header CRC32 does not match', 'next header CRC32');
  if (headerBytes[0] === Nid.EncodedHeader) {
    const decoded = await decodeHeaderStreams(env, parseEncodedHeader(headerBytes), base);
    headerBytes = decoded.bytes;
    archive.headerEncrypted = decoded.encrypted;
    spans.push(...decoded.spans);
  }
  const header = parseHeader(headerBytes, env.limits.entries, n => {
    throw new StopError(C.Limit, D.EntryCount, 'Entry count limit exceeded', { limit: env.limits.entries, entries: n });
  });
  for (const u of header.unknown) notes.push({ category: C.Structure, detail: D.UnknownProperty, data: { property: u } });
  const streams = header.streams;
  archive.streams = streams;
  // Packed streams, and which folder starts where.
  if (streams) {
    let at = base + streams.packPos;
    for (const s of streams.packSizes) {
      archive.packOffsets.push(at);
      spans.push({ start: at, end: at + s, what: 'packed stream' });
      at += s;
    }
    if (at > env.size) throw new DataError('packed streams lie past the end of the file', true);
    let next = 0;
    for (const f of streams.folders) {
      archive.folderPack.push(next);
      next += f.packedStreams.length;
    }
    if (next > streams.packSizes.length) throw new ParseError('the folders read more packed streams than the archive has');
  }
  // Entries and the substreams that hold their data.
  const subCount = streams ? streams.subSizes.length : 0;
  const withData = header.files.filter(f => f.hasStream).length;
  if (withData !== subCount) throw new ParseError('the number of files with data does not match the streams that hold it');
  let sub = 0;
  let folder = 0;
  let inFolder = 0;
  let folderAt = 0;
  for (const [index, info] of header.files.entries()) {
    const entry: SevenEntry = { index, info, kind: kindOf(info), size: 0, start: 0 };
    if (info.hasStream && streams) {
      while (inFolder >= streams.numUnpackStreams[folder]) {
        folder++;
        inFolder = 0;
        folderAt = 0;
      }
      entry.folder = folder;
      entry.size = streams.subSizes[sub];
      entry.crc = streams.subCrcs[sub];
      entry.start = folderAt;
      folderAt += entry.size;
      sub++;
      inFolder++;
    }
    archive.entries.push(entry);
  }
  if (streams) {
    streams.folders.forEach((f, i) => {
      folderLimits(env, f, `folder ${i + 1}`);
    });
    const total = streams.folders.reduce((sum, f) => sum + f.unpackSizes[f.mainOut], 0);
    if (total > env.limits.totalDecompressedBytes) {
      throw new StopError(C.Limit, D.TotalDecompressedSize, 'Total decompressed size limit exceeded', { limit: env.limits.totalDecompressedBytes, declared: total });
    }
  }
  for (const e of archive.entries) {
    if (e.size > env.limits.decompressedBytes) {
      throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: env.limits.decompressedBytes, declared: e.size }, e.info.name);
    }
  }
  finishSpans(env, archive, spans, base);
  return archive;
}

/** How far from the end a header is looked for when the start header is empty, as Commons Compress looks. */
const RECOVERY_WINDOW = 1024 * 1024;
/** How many places in that window are tried at most. */
const RECOVERY_TRIES = 256;

/**
 * Where the header of an archive whose start header is all zeros may start, as an interrupted write leaves it:
 * each kEncodedHeader followed by kPackInfo, and each kHeader followed by kMainStreamsInfo, in the last 1 MiB, the
 * nearest to the end first, each taken to run to the end of the file. 7-Zip's FORMAT_7Z_RECOVERY looks for these
 * pairs, and Commons Compress looks as far back.
 */
async function headerCandidates(env: SevenEnv, base: number): Promise<StartHeader[]> {
  const n = Math.min(RECOVERY_WINDOW, env.size - base);
  const tail = await env.reader.read(env.size - n, n);
  const out: StartHeader[] = [];
  for (let i = n - 1; i >= 0 && out.length < RECOVERY_TRIES; i--) {
    if ((tail[i] === Nid.EncodedHeader && tail[i + 1] === Nid.PackInfo) || (tail[i] === Nid.Header && tail[i + 1] === Nid.MainStreamsInfo)) {
      out.push({ minorVersion: 0, nextHeaderOffset: env.size - n + i - base, nextHeaderSize: n - i, nextHeaderCrc: crc32(tail.subarray(i)) });
    }
  }
  return out;
}

/** Notes overlapping structures, bytes between them and bytes after the last one. */
function finishSpans(env: SevenEnv, archive: SevenArchive, spans: Span[], base: number): void {
  const sorted = spans.filter(s => s.end > s.start).sort((a, b) => a.start - b.start || a.end - b.end);
  let end = archive.offset;
  let hidden = 0;
  let overlap = false;
  for (const s of sorted) {
    if (s.start < end) overlap = true;
    else hidden += s.start - end;
    end = Math.max(end, s.end);
  }
  if (overlap) archive.notes.push({ category: C.Structure, detail: D.Overlap });
  if (hidden > 0) archive.notes.push({ category: C.Structure, detail: D.HiddenData, data: { bytes: hidden } });
  end = Math.max(end, base);
  if (end < env.size) archive.trailingAt = end;
}

/** Reads a folder's output a stretch at a time, so each entry takes its own bytes. */
class FolderCursor {
  private it?: AsyncIterator<Uint8Array>;
  private buf: Uint8Array = new Uint8Array(0);
  private pos = 0;
  /** Bytes of the folder's output taken so far. */
  taken = 0;
  /** Why the folder stopped decoding, once it has. */
  failed?: unknown;
  constructor(private readonly chunks: Chunks) {}

  private async more(): Promise<boolean> {
    this.it ??= this.chunks[Symbol.asyncIterator]();
    const r = await this.it.next();
    if (r.done) return false;
    this.buf = r.value;
    this.pos = 0;
    return true;
  }

  /** The next `n` bytes. A failure stays with the cursor, and every later call throws it too. */
  async *take(n: number): AsyncGenerator<Uint8Array> {
    if (this.failed !== undefined) throw this.failed;
    let left = n;
    try {
      while (left > 0) {
        if (this.pos >= this.buf.length && !(await this.more())) throw new DataError('the folder decodes to less than its entries need', true);
        const k = Math.min(left, this.buf.length - this.pos);
        const part = this.buf.subarray(this.pos, this.pos + k);
        this.pos += k;
        this.taken += k;
        left -= k;
        yield part;
      }
    } catch (e) {
      if (!(e instanceof StopError) && !stopsTree(e)) this.failed = e;
      throw e;
    }
  }

  async close(): Promise<void> {
    await this.it?.return?.();
  }
}

/** Decoding of one folder for its entries: the password that opened it and the cursor over its output. */
interface OpenFolder {
  index: number;
  cursor: FolderCursor;
  meter: Meter;
  /** A password opened the folder's encryption. */
  decrypted: boolean;
  password?: string;
}

/**
 * True when `password` opens an encrypted folder: the folder decodes under it up to the end of its first entry with a
 * CRC, and that entry matches its CRC. A folder with no CRC to check opens when its first entry, or its first 64 KiB,
 * decodes. The trial counts toward no total.
 */
async function opensFolder(env: SevenEnv, archive: SevenArchive, f: number, password: string): Promise<boolean> {
  const streams = archive.streams;
  if (!streams) return false;
  const folder = streams.folders[f];
  const first = archive.entries.find(e => e.folder === f && e.size > 0 && e.crc !== undefined) ?? archive.entries.find(e => e.folder === f && e.size > 0);
  const skip = first ? archive.entries.filter(e => e.folder === f && e.index < first.index).reduce((n, e) => n + e.size, 0) : 0;
  const want = first ? skip + first.size : Math.min(folder.unpackSizes[folder.mainOut], 1 << 16);
  const meter = new StreamMeter(env.limits, { decoded: 0, compressed: 0 }, env.deadline, false, `folder ${f + 1}`);
  const cursor = new FolderCursor(meterChunks(decodeFolder(folder, packOffsetsOf(archive, f), packSizesOf(archive, f), folderEnv(env, meter, password)), meter));
  try {
    let crc = 0;
    let at = 0;
    for await (const c of cursor.take(want)) {
      if (at + c.length > skip) crc = crc32(c.subarray(Math.max(0, skip - at)), crc);
      at += c.length;
    }
    return !first || first.crc === undefined || crc === first.crc;
  } catch (e) {
    if (e instanceof StopError || e instanceof UnsupportedError || stopsTree(e)) throw e;
    return false;
  } finally {
    await cursor.close();
  }
}

function packOffsetsOf(archive: SevenArchive, f: number): number[] {
  const n = archive.streams?.folders[f].packedStreams.length ?? 0;
  return archive.packOffsets.slice(archive.folderPack[f], archive.folderPack[f] + n);
}

function packSizesOf(archive: SevenArchive, f: number): number[] {
  const n = archive.streams?.folders[f].packedStreams.length ?? 0;
  return archive.streams?.packSizes.slice(archive.folderPack[f], archive.folderPack[f] + n) ?? [];
}

/**
 * The content of each entry, decoded folder by folder. Entries of one folder read in order share one decode; an entry
 * before the last one read starts the folder again.
 */
export class SevenReader {
  private open?: OpenFolder;
  /**
   * The password that opened each encrypted folder. A folder opens with one password, the first the engine tries that
   * opens it, so an entry that fails its CRC never sends the reader back to the start of the folder with another.
   */
  private readonly chosen = new Map<number, string>();
  /** Passwords that did not open a folder, by folder and password. */
  private readonly refused = new Set<string>();
  constructor(
    private readonly env: SevenEnv,
    private readonly archive: SevenArchive,
  ) {}

  /** True when the folder of `entry` is not encrypted, or `password` opens it. */
  async unlock(entry: SevenEntry, password: string): Promise<boolean> {
    const f = entry.folder;
    const folder = f === undefined ? undefined : this.archive.streams?.folders[f];
    if (f === undefined || !folder || !isEncrypted(folder)) return true;
    const chosen = this.chosen.get(f);
    if (chosen !== undefined) return chosen === password;
    const key = `${f}\0${password}`;
    if (this.refused.has(key)) return false;
    if (await opensFolder(this.env, this.archive, f, password)) {
      this.chosen.set(f, password);
      return true;
    }
    this.refused.add(key);
    return false;
  }

  private async folder(f: number, password: string | undefined): Promise<OpenFolder> {
    if (this.open?.index === f && this.open.password === password) return this.open;
    await this.open?.cursor.close();
    this.open = undefined;
    const streams = this.archive.streams;
    if (!streams) throw new ParseError('an entry has data but the archive has no streams');
    const folder = streams.folders[f];
    const encrypted = isEncrypted(folder);
    if (encrypted && password === undefined) throw new StopError(C.Encrypted, D.PasswordRequired, 'No password opens the folder', undefined, `folder ${f + 1}`);
    // Each decode of a folder counts its own ratio. The folders' declared sizes were checked against the totals when
    // the archive opened, and a decode stops at them.
    const meter = new StreamMeter(this.env.limits, { decoded: 0, compressed: 0 }, this.env.deadline, false, `folder ${f + 1}`);
    const chunks = decodeFolder(folder, packOffsetsOf(this.archive, f), packSizesOf(this.archive, f), folderEnv(this.env, meter, encrypted ? password : undefined));
    this.open = { index: f, cursor: new FolderCursor(meterChunks(chunks, meter)), meter, decrypted: encrypted, password };
    return this.open;
  }

  /** The decoded content of an entry with data. It throws when the folder cannot decode it or its CRC does not match. */
  async *content(entry: SevenEntry, password?: string): AsyncGenerator<Uint8Array> {
    if (entry.folder === undefined) return;
    let open = await this.folder(entry.folder, password);
    if (open.cursor.taken > entry.start) {
      await this.close();
      open = await this.folder(entry.folder, password);
    }
    // Bytes of earlier entries nobody read are skipped.
    if (open.cursor.taken < entry.start) for await (const _ of open.cursor.take(entry.start - open.cursor.taken));
    let crc = 0;
    for await (const c of open.cursor.take(entry.size)) {
      crc = crc32(c, crc);
      yield c;
    }
    if (entry.crc !== undefined && crc !== entry.crc) throw new CheckError('the entry CRC32 does not match', 'CRC32');
  }

  async close(): Promise<void> {
    await this.open?.cursor.close();
    this.open = undefined;
  }
}
