// Copied from office-defuse src/zip.ts. Changed: a header that only one reader would take differently becomes a note
// for the engine instead of a refusal, so the rewrite can settle it. The reader picks among several end records,
// follows a central directory whose offsets are shifted, decodes names in CP437 and from the Unicode path field, reads
// symbolic links, devices and permissions from Unix attributes, opens ZipCrypto and WinZip AES entries, and decodes
// bzip2 and zstd entries besides stored and deflated ones. Name rules and duplicate names moved to the engine.
import { bunzip2 } from './bzip2';
import { type Consumed, inflateRaw, through, zstdDecompressor } from './codecs';
import { crc32 } from './crc32';
import { checkTime, DataError, StopError } from './errors';
import { inflate64 } from './inflate64';
import type { TempDir } from './io';
import type { Limits } from './stream-meter';
import { zipLzma, zipXz } from './zip-lzma';

/** The LZMA dictionary limit's default, for a reader opened without the run's limits. */
const DEFAULT_DICTIONARY = 256 * 1024 * 1024;

import { Reader } from './io';
import type { Archive, Encryption, Entry, EntryKind, Meter, Method, Note, WriteContext, WritePlan } from './model';
import { cp437, isAscii, utf8OrUndefined } from './names';
import { sniffType } from './sniff';
import { type ByteSink, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';
import { METADATA_EXTRAS, writeZip } from './zip-writer';
import { AES_SALT, aesAuthentic, aesBits, aesDecrypt, aesKeys, passwordBytes, zipCryptoDecrypt, zipCryptoOpens } from './zipcrypt';

const SIG_LOCAL = 0x04034b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_END = 0x06054b50;
const SIG_END64 = 0x06064b50;
const SIG_LOCATOR64 = 0x07064b50;
const SIG_DESCRIPTOR = 0x08074b50;
const MAX16 = 0xffff;
const MAX32 = 0xffffffff;
const UNKNOWN64 = 0xffffffffffffffffn;
/** The end record is 22 bytes and its comment at most 65,535. */
const END_SEARCH = 22 + MAX16;
/** Flags whose meaning a local header and the central directory must agree on: encryption, data descriptor, strong encryption, UTF-8 names and an encrypted directory. */
const FLAG_MASK = 0x0001 | 0x0008 | 0x0040 | 0x0800 | 0x2000;
/** A symbolic link's target is read whole before the rules run, so it has to be short. */
const MAX_LINK = 4096;
/** Hidden data is searched for local headers up to this many bytes. */
const HIDDEN_SCAN = 64 * 1024 * 1024;

/** Extra field records the rewrite replaces with its own: ZIP64 sizes, Unicode names and comments, and AES. */
const STRUCTURAL_EXTRAS = new Set([0x0001, 0x7075, 0x6375, 0x9901]);

export interface ZipLimits {
  entries: number;
  decompressedBytes: number;
  totalDecompressedBytes: number;
  compressionRatio: number;
}

/** One record of an extra field. */
export interface ExtraRecord {
  id: number;
  data: Uint8Array;
  /** A times or owners record that does not have its documented layout. */
  malformed?: boolean;
}

export interface ZipEntry extends Entry {
  rawName: Uint8Array;
  flags: number;
  /** The method field of the headers: 99 for AES. */
  storedMethod: number;
  /** The method the data is compressed with, inside any encryption. */
  methodCode: number;
  versionMadeBy: number;
  externalAttr: number;
  internalAttr: number;
  dosTime: number;
  dosDate: number;
  crc: number;
  localOffset: number;
  dataOffset: number;
  /** Where the entry ends, after any data descriptor. */
  end: number;
  /** Central directory extra records, apart from the ones the rewrite replaces. */
  extras: ExtraRecord[];
  /** The entry's comment as stored. */
  commentBytes: Uint8Array;
  /** WinZip AES: 1 for AE-1, which keeps the CRC, 2 for AE-2, which does not. */
  aesVersion?: number;
  aesStrength?: number;
}

class Bytes {
  private readonly view: DataView;
  constructor(readonly b: Uint8Array) {
    this.view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  }
  u16(at: number): number {
    return this.view.getUint16(at, true);
  }
  u32(at: number): number {
    return this.view.getUint32(at, true);
  }
  /** An 8-byte value as it is, for comparing bytes that may not be a 64-bit field at all. */
  big(at: number): bigint {
    return this.view.getBigUint64(at, true);
  }
  /** An 8-byte value, or undefined when it does not fit a JavaScript number exactly. */
  u64(at: number): number | undefined {
    const v = this.big(at);
    return v > BigInt(Number.MAX_SAFE_INTEGER) ? undefined : Number(v);
  }
}

const unparseable = (reason: string): never => {
  throw new StopError(C.Corrupted, D.Unparseable, reason, { reason });
};

/** Splits an extra field block into records. A block that does not split exactly keeps the records before the fault. */
function parseExtra(extra: Uint8Array): { records: ExtraRecord[]; malformed?: string } {
  const records: ExtraRecord[] = [];
  const b = new Bytes(extra);
  const seen = new Set<number>();
  let p = 0;
  while (p < extra.length) {
    if (p + 4 > extra.length) return { records, malformed: 'an extra field block ends inside a record header' };
    const id = b.u16(p);
    const len = b.u16(p + 2);
    if (p + 4 + len > extra.length) return { records, malformed: 'an extra field record runs past its block' };
    if (seen.has(id)) return { records, malformed: `extra field 0x${id.toString(16).padStart(4, '0')} appears twice` };
    seen.add(id);
    records.push({ id, data: extra.subarray(p + 4, p + 4 + len) });
    p += 4 + len;
  }
  return { records };
}

const hex = (id: number) => `0x${id.toString(16).padStart(4, '0')}`;

/** The names of the times and owners records, for findings. */
const METADATA_NAMES: Record<number, string> = {
  21589: 'extended timestamp',
  10: 'NTFS times',
  22613: 'old Info-ZIP Unix',
  30805: 'Info-ZIP Unix owners',
  30837: 'Info-ZIP new Unix owners',
};

const setBits = (v: number) => (v & 1) + ((v >> 1) & 1) + ((v >> 2) & 1);

/**
 * Why a times or owners record from the central directory does not have the layout Info-ZIP's extrafld.txt gives
 * it, or undefined when it does. The rewrite copies these records into its own headers, so one that a reader could
 * read past its end is not kept.
 */
function metadataFault(r: ExtraRecord): string | undefined {
  const d = r.data;
  const n = d.length;
  switch (r.id) {
    case 0x5455: {
      // A flags byte, then the times its low three bits name. The central version may hold the modification time alone.
      if (n === 0) return 'it has no flags byte';
      if ((n - 1) % 4 !== 0 || (n - 1) / 4 > setBits(d[0] & 7)) return `its ${n} bytes do not fit the times its flags name`;
      if (d[0] & 1 && n < 5) return 'its flags name a modification time it does not hold';
      return undefined;
    }
    case 0x000a: {
      // Four reserved bytes, then tagged attributes. Tag 1 holds three 8-byte times.
      if (n < 4) return 'it ends inside its reserved bytes';
      const b = new Bytes(d);
      for (let p = 4; p < n; ) {
        if (p + 4 > n) return 'it ends inside an attribute header';
        const tag = b.u16(p);
        const size = b.u16(p + 2);
        if (p + 4 + size > n) return `attribute ${tag} runs past the record`;
        if (tag === 1 && size !== 24) return `its times attribute has ${size} bytes, not 24`;
        p += 4 + size;
      }
      return undefined;
    }
    case 0x5855:
      // Access and modification times, then a user and a group ID only in a local header.
      return n === 8 || n === 12 ? undefined : `it has ${n} bytes, not 8 or 12`;
    case 0x7855:
      // Empty in the central directory, a 2-byte user and group ID in a local header.
      return n === 0 || n === 4 ? undefined : `it has ${n} bytes, not 0 or 4`;
    case 0x7875: {
      // A version, then a user ID and a group ID, each after its size. An empty record only flags that they exist.
      if (n === 0) return undefined;
      if (d[0] !== 1) return `it is version ${d[0]}, and only version 1 is defined`;
      if (n < 2 || n < 3 + d[1]) return 'it ends inside its user ID';
      return 3 + d[1] + d[2 + d[1]] === n ? undefined : 'its ID sizes do not add up to its length';
    }
    default:
      return undefined;
  }
}

/** The method a ZIP entry's data uses, by its number. */
function methodOf(code: number): Method {
  switch (code) {
    case 0:
      return { name: 'stored', readable: true, unusual: false };
    case 8:
      return { name: 'deflate', readable: true, unusual: false };
    case 9:
      return { name: 'deflate64', readable: true, unusual: true };
    case 12:
      return { name: 'bzip2', readable: true, unusual: true };
    case 14:
      return { name: 'lzma', readable: true, unusual: true };
    case 95:
      return { name: 'xz', readable: true, unusual: true };
    case 93:
      return { name: 'zstd', readable: true, unusual: true, unavailable: zstdDecompressor === undefined };
    default: {
      const names: Record<number, string> = {
        1: 'shrink',
        2: 'reduce',
        3: 'reduce',
        4: 'reduce',
        5: 'reduce',
        6: 'implode',
        10: 'PKWARE implode',
        14: 'LZMA',
        18: 'IBM TERSE',
        19: 'IBM LZ77',
        20: 'zstd (old number)',
        94: 'MP3',
        95: 'XZ',
        96: 'JPEG',
        97: 'WavPack',
        98: 'PPMd',
      };
      return { name: names[code] ?? `method ${code}`, readable: false, unusual: true };
    }
  }
}

const S_IFMT = 0o170000;

/** What an entry is, from its name and, for entries made on Unix, the file type in its attributes. */
function kindOf(name: string, versionMadeBy: number, externalAttr: number): { kind: EntryKind; mode?: number; typeCode?: string } {
  const host = versionMadeBy >>> 8;
  const unixMode = externalAttr >>> 16;
  if (host === 3 && unixMode !== 0) {
    const type = unixMode & S_IFMT;
    const mode = unixMode & 0o7777;
    if (name.endsWith('/') || type === 0o040000) return { kind: 'directory', mode };
    if (type === 0o120000) return { kind: 'symlink', mode };
    if (type === 0o020000 || type === 0o060000) return { kind: 'device', mode, typeCode: type === 0o020000 ? 'character device' : 'block device' };
    if (type === 0o010000) return { kind: 'fifo', mode };
    if (type === 0o140000) return { kind: 'socket', mode };
    if (type === 0o100000 || type === 0) return { kind: 'file', mode };
    return { kind: 'other', mode, typeCode: `Unix file type 0o${type.toString(8)}` };
  }
  if (name.endsWith('/') || (externalAttr & 0x10) !== 0) return { kind: 'directory' };
  return { kind: 'file' };
}

/** Decodes a name: UTF-8 under the flag, ASCII as it is, and anything else as CP437 or UTF-8, which readers pick differently. */
function decodeName(raw: Uint8Array, flags: number): { name: string; ambiguous: boolean } {
  if (flags & 0x0800) {
    const u = utf8OrUndefined(raw);
    return u === undefined ? { name: Buffer.from(raw).toString('utf8'), ambiguous: true } : { name: u, ambiguous: false };
  }
  if (isAscii(raw)) return { name: Buffer.from(raw).toString('latin1'), ambiguous: false };
  // Without the flag the format says CP437, but many writers put UTF-8 there and many readers take it.
  return { name: utf8OrUndefined(raw) ?? cp437(raw), ambiguous: true };
}

/**
 * The Info-ZIP Unicode path or comment field: version 1, the CRC-32 of the header's own bytes, then UTF-8. Returns
 * the text when the CRC matches, `stale` when the field belongs to other bytes, and nothing for a field it cannot read.
 */
function unicodeField(field: Uint8Array | undefined, headerBytes: Uint8Array): { text?: string; stale?: boolean } {
  if (!field || field.length < 5 || field[0] !== 1) return {};
  const text = utf8OrUndefined(field.subarray(5));
  if (text === undefined) return { stale: true };
  if (new Bytes(field).u32(1) !== crc32(headerBytes)) return { stale: true };
  return { text };
}

interface EndRecord {
  /** Offset of the end record. */
  at: number;
  commentLength: number;
  count: number;
  countOnDisk: number;
  disk: number;
  dirDisk: number;
  dirSize: number;
  dirOffset: number;
  /** Where the central directory ends: the ZIP64 end record when there is one, else the end record. */
  dirEnd: number;
  /** Where the central directory actually starts, which differs from dirOffset when the offsets are shifted. */
  dirStart?: number;
  /** How the end record and its ZIP64 records disagree, when they do. */
  disagree?: string;
}

/**
 * Reads the end record at `at`, with its ZIP64 records. Returns undefined when the bytes there cannot be an end record
 * whose directory exists. A ZIP64 record that contradicts the end record throws, since no reading of it is safe.
 */
async function endRecordAt(reader: Reader, size: number, at: number): Promise<EndRecord | undefined> {
  const r = new Bytes(await reader.read(at, 22));
  if (r.b.length < 22 || r.u32(0) !== SIG_END) return undefined;
  const short: EndRecord = {
    at,
    commentLength: r.u16(20),
    disk: r.u16(4),
    dirDisk: r.u16(6),
    countOnDisk: r.u16(8),
    count: r.u16(10),
    dirSize: r.u32(12),
    dirOffset: r.u32(16),
    dirEnd: at,
  };
  // The directory sits where the end record says, or, in an archive that had data put in front of it, right before
  // the end record, where readers that correct the offsets look.
  const sigAt = async (p: number) => p >= 0 && p + 4 <= size && new Bytes(await reader.read(p, 4)).u32(0) === SIG_CENTRAL;
  const locate = async (e: EndRecord): Promise<EndRecord | undefined> => {
    if (e.count === 0 && e.dirSize === 0) e.dirStart = e.dirEnd;
    else if (e.dirOffset + e.dirSize <= e.dirEnd && (await sigAt(e.dirOffset))) e.dirStart = e.dirOffset;
    else if (e.dirEnd - e.dirSize >= 0 && (await sigAt(e.dirEnd - e.dirSize))) e.dirStart = e.dirEnd - e.dirSize;
    else return undefined;
    return e;
  };
  const locatorAt = at - 20;
  const locator = new Bytes(locatorAt >= 0 ? await reader.read(locatorAt, 20) : new Uint8Array(0));
  if (locator.b.length !== 20 || locator.u32(0) !== SIG_LOCATOR64) {
    if (short.dirSize === MAX32 || short.dirOffset === MAX32) return undefined;
    return locate(short);
  }
  if (locator.u32(4) !== 0 || locator.u32(16) > 1) throw new StopError(C.Structure, D.MultiVolume, 'The ZIP64 locator names another disk');
  // A locator that leads to no ZIP64 end record leaves readers that ignore it with the end record's own values.
  const fallback = async () => {
    if (short.dirSize === MAX32 || short.dirOffset === MAX32) return undefined;
    const found = await locate(short);
    if (found) found.disagree = 'a ZIP64 locator leads to no ZIP64 end record';
    return found;
  };
  const z = locator.u64(8);
  if (z === undefined || z + 56 > locatorAt) return fallback();
  const rec = new Bytes(await reader.read(z, 56));
  if (rec.u32(0) !== SIG_END64) return fallback();
  const len = rec.u64(4);
  if (len === undefined || z + 12 + len !== locatorAt) return fallback();
  const values = [rec.u32(16), rec.u32(20), rec.u64(24), rec.u64(32), rec.u64(40), rec.u64(48)];
  if (values.some(v => v === undefined)) return unparseable('a ZIP64 end record holds a value beyond any file this reader can hold');
  const [disk, dirDisk, countOnDisk, count, dirSize, dirOffset] = values as number[];
  const long: EndRecord = { at, commentLength: short.commentLength, disk, dirDisk, countOnDisk, count, dirSize, dirOffset, dirEnd: z };
  // A field the end record does not leave to the ZIP64 record and gives otherwise splits readers: some take the ZIP64
  // record whenever it is there, and others only for the fields at their maximum.
  const split = (a: number, max: number, b: number) => a !== max && a !== b;
  const disagree =
    split(short.disk, MAX16, disk) ||
    split(short.dirDisk, MAX16, dirDisk) ||
    split(short.countOnDisk, MAX16, countOnDisk) ||
    split(short.count, MAX16, count) ||
    split(short.dirSize, MAX32, dirSize) ||
    split(short.dirOffset, MAX32, dirOffset);
  const found = (await locate(long)) ?? (disagree ? await locate({ ...short, dirEnd: z }) : undefined);
  if (found && disagree) found.disagree = 'the end record and the ZIP64 end record give different values';
  return found;
}

/** What the archive's bytes outside every entry and header hold. */
interface Coverage {
  leading: number;
  hidden: number;
  localHeaders: number;
  overlap: number;
}

/**
 * A ZIP archive read from its central directory, with every local header checked against it. Reading an entry
 * decrypts and decodes it in chunks and checks its size and CRC.
 */
export class ZipArchive implements Archive<ZipEntry> {
  readonly format = 'zip';
  readonly single = false;
  readonly lateNotes: Note[] = [];
  comment?: string;

  private constructor(
    readonly reader: Reader,
    readonly entries: ZipEntry[],
    readonly notes: Note[],
    /** Where the archive starts in the file: the first local header, or the directory when there is none. */
    readonly start: number,
    /** Where the archive ends: after the end record's comment. */
    readonly end: number,
    readonly commentBytes: Uint8Array,
    /** Where the other end records that lead to a directory sit, which an entry's data can hold. */
    readonly rivals: number[] = [],
  ) {
    if (commentBytes.length) this.comment = Buffer.from(commentBytes).toString('latin1');
  }

  /** What LZMA and XZ entries need from the run: its limits, and a temporary folder for an XZ entry's bytes. */
  decoders?: { temp: TempDir; threshold: number; limits: Limits };

  static async open(source: ByteSource, limits: ZipLimits, deadline?: number): Promise<ZipArchive> {
    const size = await source.size();
    const reader = new Reader(source, size);
    const notes: Note[] = [];
    if (size < 22) unparseable('the file is too short to be a ZIP archive');
    const tailStart = Math.max(0, size - END_SEARCH);
    const tail = new Bytes(await reader.read(tailStart, size - tailStart));
    // Every end signature in the last 64 KiB, last first, since that is the one a reader scanning backwards takes.
    const found: EndRecord[] = [];
    for (let p = tail.b.length - 22; p >= 0; p--) {
      if (tail.b[p] !== 0x50 || tail.u32(p) !== SIG_END) continue;
      checkTime(deadline);
      const e = await endRecordAt(reader, size, tailStart + p);
      if (e) found.push(e);
    }
    // The last end record whose comment fits in the file is the archive. Another one whose comment ends exactly at the
    // end of the file, and that leads to a directory, is one that readers checking the comment length can take instead.
    const end = found.find(e => e.at + 22 + e.commentLength <= size) ?? found[0];
    if (!end) {
      // A file that starts with the spanning marker and has no end record is the first part of a split archive.
      const head = await reader.read(0, 4);
      if (new Bytes(head).b.length === 4 && new Bytes(head).u32(0) === SIG_DESCRIPTOR) throw new StopError(C.Structure, D.MultiVolume, 'The first part of a split archive');
      return unparseable('no end of central directory record that leads to a central directory');
    }
    const rivals = found.filter(e => e !== end && e.at + 22 + e.commentLength === size);
    if (rivals.length) notes.push({ category: C.Structure, detail: D.SeveralEndRecords, data: { records: rivals.length + 1 } });
    if (end.disagree) notes.push({ category: C.Structure, detail: D.HeaderMismatch, data: { what: end.disagree } });
    let archiveEnd = end.at + 22 + end.commentLength;
    if (archiveEnd > size) {
      notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: "the end record's comment runs past the end of the file" } });
      archiveEnd = size;
    }
    const commentBytes = (await reader.read(end.at + 22, archiveEnd - end.at - 22)).slice();
    if (end.disk !== 0 || end.dirDisk !== 0) throw new StopError(C.Structure, D.MultiVolume, 'The archive spans several disks');
    const dirStart = end.dirStart ?? end.dirOffset;
    const shift = dirStart - end.dirOffset;
    if (shift !== 0) notes.push({ category: C.Structure, detail: D.OffsetShift, data: { bytes: shift } });
    if (end.count > limits.entries) throw new StopError(C.Limit, D.EntryCount, `${end.count} entries`, { entries: end.count, limit: limits.entries });

    const entries: ZipEntry[] = [];
    let total = 0;
    let pos = dirStart;
    while (pos + 46 <= end.dirEnd) {
      if (entries.length % 256 === 0) checkTime(deadline);
      const h = new Bytes(await reader.read(pos, 46));
      if (h.u32(0) !== SIG_CENTRAL) break;
      const nameLength = h.u16(28);
      const extraLength = h.u16(30);
      const commentLength = h.u16(32);
      const recordEnd = pos + 46 + nameLength + extraLength + commentLength;
      if (recordEnd > end.dirEnd) unparseable('a central directory header runs past the directory');
      if (entries.length >= limits.entries) throw new StopError(C.Limit, D.EntryCount, 'Too many entries', { limit: limits.entries });
      const body = await reader.read(pos + 46, nameLength + extraLength + commentLength);
      const entry = ZipArchive.central(
        entries.length,
        h,
        body.subarray(0, nameLength).slice(),
        body.subarray(nameLength, nameLength + extraLength),
        body.subarray(nameLength + extraLength).slice(),
        shift,
      );
      // A broken entry's sizes mean nothing, and the entry is removed unread.
      if (entry.broken) {
        entries.push(entry);
        pos = recordEnd;
        continue;
      }
      if (entry.size > limits.decompressedBytes)
        throw new StopError(C.Limit, D.DecompressedSize, `${entry.name} declares ${entry.size} bytes`, { size: entry.size, limit: limits.decompressedBytes }, entry.name);
      total += entry.size;
      if (total > limits.totalDecompressedBytes) throw new StopError(C.Limit, D.TotalDecompressedSize, 'The entries declare too many bytes', { limit: limits.totalDecompressedBytes });
      if (entry.size > 1024 * 1024 && entry.size > entry.compressedSize * limits.compressionRatio) {
        throw new StopError(C.Limit, D.Ratio, `${entry.name} declares a ratio past the limit`, { size: entry.size, compressedSize: entry.compressedSize, limit: limits.compressionRatio }, entry.name);
      }
      entries.push(entry);
      pos = recordEnd;
    }
    // Readers that go by the count, by the directory size or by the entries they find can each see other entries.
    if (entries.length !== end.count || pos !== end.dirEnd || end.countOnDisk !== end.count || dirStart + end.dirSize !== end.dirEnd) {
      notes.push({ category: C.Structure, detail: D.HeaderMismatch, data: { what: 'the end record and the central directory disagree on the entries' } });
    }

    for (const [i, e] of entries.entries()) {
      if (i % 256 === 0) checkTime(deadline);
      if (!e.broken) await ZipArchive.checkLocal(reader, e, dirStart);
    }

    const cover = await ZipArchive.coverage(reader, entries, dirStart, deadline);
    const start = cover.leading;
    if (cover.leading > 0) {
      notes.push({ category: C.Structure, detail: D.LeadingBytes, data: { bytes: cover.leading } });
      const type = sniffType(await reader.read(0, Math.min(1024, cover.leading)));
      if (type !== undefined) notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'before the archive' } });
    }
    if (cover.hidden > 0) notes.push({ category: C.Structure, detail: D.HiddenData, data: { bytes: cover.hidden, localHeaders: cover.localHeaders } });
    if (cover.overlap > 0) notes.push({ category: C.Structure, detail: D.Overlap, data: { entries: cover.overlap } });
    if (archiveEnd < size) {
      notes.push({ category: C.Structure, detail: D.TrailingBytes, data: { bytes: size - archiveEnd } });
      const type = sniffType(await reader.read(archiveEnd, Math.min(1024, size - archiveEnd)));
      if (type !== undefined) notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'after the archive' } });
    }
    return new ZipArchive(
      reader,
      entries,
      notes,
      start,
      archiveEnd,
      commentBytes,
      rivals.map(r => r.at),
    );
  }

  /** One entry from its central directory header. */
  private static central(index: number, h: Bytes, rawName: Uint8Array, extra: Uint8Array, commentBytes: Uint8Array, shift: number): ZipEntry {
    const flags = h.u16(8);
    const storedMethod = h.u16(10);
    const versionMadeBy = h.u16(4);
    const externalAttr = h.u32(38);
    const notes: Note[] = [];
    const decoded = decodeName(rawName, flags);
    let name = decoded.name;
    const parsed = parseExtra(extra);
    const byId = new Map(parsed.records.map(r => [r.id, r.data]));
    const up = unicodeField(byId.get(0x7075), rawName);
    if (up.text !== undefined && up.text !== name) {
      // The field exists to give a name the header could not, so it differs from a non-ASCII header by design.
      if (!decoded.ambiguous) notes.push({ category: C.Name, detail: D.UnicodePath, data: { name, unicodeName: up.text } });
      name = up.text;
    } else if (up.stale) notes.push({ category: C.Name, detail: D.UnicodePath, data: { name, reason: 'the field belongs to another name' } });
    if (decoded.ambiguous) notes.push({ category: C.Name, detail: D.Encoding, data: { name } });
    const comment = unicodeField(byId.get(0x6375), commentBytes).text ?? (commentBytes.length ? decodeName(commentBytes, flags).name : undefined);
    if (parsed.malformed) notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: 'a malformed extra field', reason: parsed.malformed } });
    const extras = parsed.records.filter(r => !STRUCTURAL_EXTRAS.has(r.id));
    for (const r of extras) {
      if (!METADATA_EXTRAS.has(r.id)) {
        notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: `extra field ${hex(r.id)}` }, keptOnInfo: true });
        continue;
      }
      const fault = metadataFault(r);
      if (fault === undefined) continue;
      r.malformed = true;
      notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: `a malformed ${METADATA_NAMES[r.id]} field`, reason: fault }, keptOnInfo: true });
    }

    const e: ZipEntry = {
      index,
      name,
      rawName,
      kind: 'file',
      size: h.u32(24),
      compressedSize: h.u32(20),
      notes,
      flags,
      storedMethod,
      methodCode: storedMethod,
      versionMadeBy,
      externalAttr,
      internalAttr: h.u16(36),
      dosTime: h.u16(12),
      dosDate: h.u16(14),
      crc: h.u32(16),
      localOffset: h.u32(42),
      dataOffset: 0,
      end: 0,
      extras,
      commentBytes,
      comment,
    };
    const k = kindOf(name, versionMadeBy, externalAttr);
    e.kind = k.kind;
    if (k.mode !== undefined) e.mode = k.mode;
    if (k.typeCode !== undefined) e.typeCode = k.typeCode;

    // ZIP64 values the header defers to its extra field, in the order the format fixes.
    const disk = h.u16(34);
    const want = [e.size === MAX32, e.compressedSize === MAX32, e.localOffset === MAX32, disk === MAX16];
    const length = (want[0] ? 8 : 0) + (want[1] ? 8 : 0) + (want[2] ? 8 : 0) + (want[3] ? 4 : 0);
    const z = byId.get(0x0001);
    if (length > 0) {
      if (!z || z.length < length) e.broken = 'a field at its maximum has no ZIP64 value behind it';
      else {
        const b = new Bytes(z);
        let p = 0;
        const next = () => {
          const v = b.u64(p);
          p += 8;
          if (v === undefined) e.broken = 'a ZIP64 value beyond any file this reader can hold';
          return v ?? 0;
        };
        if (want[0]) e.size = next();
        if (want[1]) e.compressedSize = next();
        if (want[2]) e.localOffset = next();
        if (want[3] && b.u32(p) !== 0) throw new StopError(C.Structure, D.MultiVolume, 'An entry starts on another disk');
        if (z.length > length) notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'a ZIP64 extra field holds more values than its header defers to it' } });
      }
    } else if (disk !== 0) throw new StopError(C.Structure, D.MultiVolume, 'An entry starts on another disk');
    e.localOffset += shift;

    e.encryption = ZipArchive.encryption(e, byId.get(0x9901));
    e.method = methodOf(e.methodCode);
    if (e.kind === 'directory' && e.size > 0) notes.push({ category: C.Structure, detail: D.NonFileData, data: { name, bytes: e.size } });
    if (e.methodCode === 0 && !e.encryption && e.size !== e.compressedSize) e.broken ??= 'a stored entry has two different sizes';
    return e;
  }

  /** The encryption an entry uses, from its flags and its AES field, which also gives the method inside. */
  private static encryption(e: ZipEntry, aes: Uint8Array | undefined): Encryption | undefined {
    if (e.flags & 0x2000) return { kind: 'unsupported', reason: 'an encrypted central directory' };
    if (!(e.flags & 0x0001)) return undefined;
    if (e.flags & 0x0040) return { kind: 'unsupported', reason: 'PKWARE strong encryption' };
    if (e.storedMethod !== 99) return { kind: 'zipcrypto' };
    if (!aes || aes.length < 7) return { kind: 'unsupported', reason: 'an AES entry without its AES field' };
    const b = new Bytes(aes);
    const version = b.u16(0);
    const bits = aesBits(aes[4]);
    if ((version !== 1 && version !== 2) || aes[2] !== 0x41 || aes[3] !== 0x45 || bits === undefined) return { kind: 'unsupported', reason: 'an AES field of an unknown version' };
    e.aesVersion = version;
    e.aesStrength = aes[4];
    e.methodCode = b.u16(5);
    return { kind: 'aes', bits };
  }

  /** Checks a local header and any data descriptor against the central directory, and fills in where the entry's data and the entry end. */
  private static async checkLocal(reader: Reader, e: ZipEntry, dirStart: number): Promise<void> {
    const mismatch = (what: string) => e.notes.push({ category: C.Structure, detail: D.HeaderMismatch, data: { name: e.name, what } });
    if (e.localOffset < 0 || e.localOffset + 30 > reader.size) {
      e.broken = 'its local header lies outside the file';
      return;
    }
    const h = new Bytes(await reader.read(e.localOffset, 30));
    if (h.u32(0) !== SIG_LOCAL) {
      e.broken = 'no local header where the central directory points';
      return;
    }
    const flags = h.u16(6);
    const nameLength = h.u16(26);
    const extraLength = h.u16(28);
    e.dataOffset = e.localOffset + 30 + nameLength + extraLength;
    if (e.dataOffset + e.compressedSize > reader.size) {
      e.broken = 'its data runs past the end of the file';
      return;
    }
    const rest = await reader.read(e.localOffset + 30, nameLength + extraLength);
    if (Buffer.compare(rest.subarray(0, nameLength), e.rawName) !== 0) mismatch('the local header names another file');
    if ((flags & FLAG_MASK) !== (e.flags & FLAG_MASK)) mismatch('the local header has other flags');
    if (h.u16(8) !== e.storedMethod) mismatch('the local header gives another compression method');
    const parsed = parseExtra(rest.subarray(nameLength));
    if (parsed.malformed) e.notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: 'a malformed local extra field', reason: parsed.malformed } });
    const local = new Map(parsed.records.map(r => [r.id, r.data]));
    for (const r of parsed.records) {
      if (!STRUCTURAL_EXTRAS.has(r.id) && !METADATA_EXTRAS.has(r.id) && !e.extras.some(x => x.id === r.id)) {
        e.notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: `local extra field ${hex(r.id)}` } });
      }
    }
    const lp = unicodeField(local.get(0x7075), e.rawName);
    if (lp.text !== undefined && lp.text !== e.name) mismatch("the local header's Unicode path names another file");
    let size: number | undefined = h.u32(22);
    let compressedSize: number | undefined = h.u32(18);
    const z = local.get(0x0001);
    if (z && z.length >= 16) {
      const b = new Bytes(z);
      // A writer that streams the entry does not know its sizes yet. It sets the data descriptor flag and may fill
      // the ZIP64 sizes with ones, which then mean what zero means: the data descriptor has them.
      const wide = (at: number) => (e.flags & 0x0008 && b.big(at) === UNKNOWN64 ? 0 : b.u64(at));
      const ws = wide(0);
      const wc = wide(8);
      if ((size !== MAX32 && size !== 0 && size !== ws) || (compressedSize !== MAX32 && compressedSize !== 0 && compressedSize !== wc))
        mismatch('the local header and its ZIP64 field give other sizes');
      size = ws;
      compressedSize = wc;
    } else if (z) mismatch('the local ZIP64 field is too short');
    const crc = h.u32(14);
    if (e.flags & 0x0008) {
      // With a data descriptor the local fields may be zero. Any that are set must agree.
      if (crc !== 0 && crc !== e.crc) mismatch('the local header gives another CRC');
      if (size !== 0 && size !== e.size) mismatch('the local header gives another size');
      if (compressedSize !== 0 && compressedSize !== e.compressedSize) mismatch('the local header gives another compressed size');
    } else if (crc !== e.crc || size !== e.size || compressedSize !== e.compressedSize) {
      mismatch('the local header gives another CRC or size');
    }
    const dataEnd = e.dataOffset + e.compressedSize;
    e.end = dataEnd;
    if (!(e.flags & 0x0008)) return;
    const d = new Bytes(await reader.read(dataEnd, Math.max(0, Math.min(24, reader.size - dataEnd))));
    let p = 0;
    if (d.b.length >= 8 && d.u32(0) === SIG_DESCRIPTOR && d.u32(4) === e.crc) p = 4;
    if (d.b.length < p + 12 || d.u32(p) !== e.crc) {
      mismatch('the data descriptor gives another CRC');
      return;
    }
    // The format says eight-byte sizes go with a ZIP64 field. Either width is accepted when its values agree; the
    // coverage check then sees any bytes the other reading would leave over. Past a narrow descriptor the wide reading
    // takes in the next header's signature, so it compares the bytes without demanding that they fit a number.
    const wide = d.b.length >= p + 20 && d.big(p + 4) === BigInt(e.compressedSize) && d.big(p + 12) === BigInt(e.size);
    const narrow = d.u32(p + 4) === e.compressedSize && d.u32(p + 8) === e.size;
    if (z ? wide : narrow) e.end = dataEnd + p + (z ? 20 : 12);
    else if (z ? narrow : wide) e.end = dataEnd + p + (z ? 12 : 20);
    else mismatch('the data descriptor gives other sizes');
    if (e.end > dirStart && dataEnd <= dirStart) e.end = dirStart;
  }

  /** Bytes before the first entry, bytes between entries and the directory that belong to none, and entries that share bytes. */
  private static async coverage(reader: Reader, entries: ZipEntry[], dirStart: number, deadline: number | undefined): Promise<Coverage> {
    const placed = entries.filter(e => !e.broken).sort((a, b) => a.localOffset - b.localOffset || a.index - b.index);
    const gaps: Array<[number, number]> = [];
    let covered = -1;
    let leading = 0;
    let overlap = 0;
    for (const e of placed) {
      if (covered < 0) {
        leading = e.localOffset;
        covered = e.localOffset;
      }
      if (e.localOffset < covered) overlap++;
      else if (e.localOffset > covered) gaps.push([covered, e.localOffset]);
      covered = Math.max(covered, e.end);
    }
    if (covered < 0) {
      leading = dirStart;
      covered = dirStart;
    }
    if (covered > dirStart) overlap++;
    else if (covered < dirStart) gaps.push([covered, dirStart]);
    let hidden = 0;
    let localHeaders = 0;
    let scanned = 0;
    for (const [from, to] of gaps) {
      hidden += to - from;
      // A local header in hidden data is an entry a streaming reader extracts and a directory reader never sees.
      for (let at = from; at < to && scanned < HIDDEN_SCAN; at += 65536) {
        checkTime(deadline);
        const b = await reader.read(at, Math.min(65536 + 3, to - at));
        scanned += b.length;
        for (let i = 0; i + 4 <= b.length && i < 65536; i++) if (b[i] === 0x50 && b[i + 1] === 0x4b && b[i + 2] === 3 && b[i + 3] === 4) localHeaders++;
      }
    }
    return { leading, hidden, localHeaders, overlap };
  }

  hasMetadata(): boolean {
    return this.commentBytes.length > 0 || this.entries.some(e => e.commentBytes.length > 0 || e.dosTime !== 0 || e.dosDate !== 0x21 || e.extras.some(r => METADATA_EXTRAS.has(r.id)));
  }

  /** Reads a symbolic link's target, which a ZIP stores as the entry's content. */
  async linkTarget(e: ZipEntry, meter: Meter): Promise<string | undefined> {
    if (e.size > MAX_LINK || e.encryption || !e.method?.readable || e.method.unavailable) return undefined;
    const parts: Uint8Array[] = [];
    for await (const c of this.read(e, meter)) parts.push(c);
    return Buffer.concat(parts).toString('utf8');
  }

  /** The stored bytes of an entry. */
  raw(e: ZipEntry): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(e.dataOffset, e.compressedSize);
  }

  /** The bytes before the archive and after it. */
  leading(): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(0, this.start);
  }
  trailing(): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(this.end, this.reader.size - this.end);
  }

  /** The 12-byte ZipCrypto header's check byte: the CRC's high byte, or the time's with a data descriptor. */
  private checkByte(e: ZipEntry): number {
    return e.flags & 0x0008 ? (e.dosTime >>> 8) & 0xff : e.crc >>> 24;
  }

  async unlock(e: ZipEntry, password: string): Promise<boolean> {
    const enc = e.encryption;
    if (!enc || enc.kind === 'unsupported') return false;
    if (enc.kind === 'zipcrypto') {
      if (e.compressedSize < 12) return false;
      const header = await this.reader.read(e.dataOffset, 12);
      return passwordBytes(password).some(p => zipCryptoOpens(header, p, this.checkByte(e)));
    }
    const salt = AES_SALT[e.aesStrength ?? 0];
    if (e.compressedSize < salt + 12) return false;
    const head = await this.reader.read(e.dataOffset, salt + 2);
    for (const p of passwordBytes(password)) {
      const keys = aesKeys(p, head.subarray(0, salt), enc.bits);
      if (Buffer.compare(keys.verifier, head.subarray(salt, salt + 2)) !== 0) continue;
      const mac = await this.reader.read(e.dataOffset + e.compressedSize - 10, 10);
      if (await aesAuthentic(this.reader.chunks(e.dataOffset + salt + 2, e.compressedSize - salt - 12), keys.hmacKey, mac)) return true;
    }
    return false;
  }

  /** The entry's compressed bytes without their encryption, for a rewrite that copies them. Their length comes from `plainLength`. */
  async *plain(e: ZipEntry, password?: string): AsyncGenerator<Uint8Array> {
    const enc = e.encryption;
    if (!enc) {
      yield* this.raw(e);
      return;
    }
    if (enc.kind === 'unsupported' || password === undefined) throw new DataError('The entry is encrypted');
    if (enc.kind === 'zipcrypto') {
      const header = await this.reader.read(e.dataOffset, 12);
      const p = passwordBytes(password).find(b => zipCryptoOpens(header, b, this.checkByte(e)));
      if (!p) throw new DataError('The password does not open the entry');
      yield* zipCryptoDecrypt(this.raw(e), p);
      return;
    }
    const salt = AES_SALT[e.aesStrength ?? 0];
    const head = await this.reader.read(e.dataOffset, salt + 2);
    const p = passwordBytes(password).find(b => Buffer.compare(aesKeys(b, head.subarray(0, salt), enc.bits).verifier, head.subarray(salt)) === 0);
    if (!p) throw new DataError('The password does not open the entry');
    const mac = await this.reader.read(e.dataOffset + e.compressedSize - 10, 10);
    yield* aesDecrypt(this.reader.chunks(e.dataOffset + salt + 2, e.compressedSize - salt - 12), aesKeys(p, head.subarray(0, salt), enc.bits), mac);
  }

  /** The length of what plain() yields. */
  plainLength(e: ZipEntry): number {
    if (!e.encryption) return e.compressedSize;
    if (e.encryption.kind === 'zipcrypto') return e.compressedSize - 12;
    return e.compressedSize - AES_SALT[e.aesStrength ?? 0] - 12;
  }

  /** The entry's content in chunks. Its size, its CRC unless AE-2 leaves it out, and the compressed bytes used must all agree with the central directory. */
  async *read(e: ZipEntry, meter: Meter, password?: string): AsyncGenerator<Uint8Array> {
    if (e.broken) throw new DataError(e.broken);
    const compressed = this.plainLength(e);
    const consumed: Consumed = { bytes: 0 };
    async function* timed(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
      for await (const c of chunks) {
        meter.time();
        yield c;
      }
    }
    const input = timed(this.plain(e, password));
    let out: AsyncIterable<Uint8Array>;
    if (e.methodCode === 0) {
      out = input;
    } else if (e.methodCode === 8) out = inflateRaw(input, consumed);
    else if (e.methodCode === 9) out = inflate64(input, consumed);
    else if (e.methodCode === 14) out = zipLzma(input, e.size, consumed, this.decoders?.limits.dictionaryBytes ?? DEFAULT_DICTIONARY);
    else if (e.methodCode === 95) {
      if (!this.decoders) throw new DataError('an XZ entry needs a temporary folder, which this run has none of');
      out = zipXz(input, consumed, meter, this.decoders.temp, this.decoders.threshold, this.decoders.limits);
    } else if (e.methodCode === 12) {
      const info = { streams: [], trailing: 0, trailingZeros: true };
      out = bunzip2(input, info, false, consumed);
    } else if (e.methodCode === 93) {
      const make = zstdDecompressor;
      if (!make) throw new DataError('This Node has no zstd');
      out = through(make(), input, consumed);
    } else throw new DataError(`compression method ${e.methodCode}`);
    let crc = 0;
    let total = 0;
    for await (const c of out) {
      total += c.length;
      if (total > e.size) throw new DataError('it decodes past its declared size');
      meter.add(total, e.methodCode === 0 ? total : consumed.bytes);
      crc = crc32(c, crc);
      yield c;
    }
    if (e.methodCode !== 0 && consumed.bytes !== compressed) throw new DataError('its compressed data ends before its compressed size', consumed.bytes < compressed);
    if (total !== e.size) throw new DataError(`it decodes to ${total} bytes, not ${e.size}`, true);
    // AE-2 leaves the CRC out, since the authentication code covers the data.
    if (crc !== e.crc && e.aesVersion !== 2) throw new DataError('it does not match its CRC');
  }

  write(plan: WritePlan<ZipEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    return writeZip(this, plan, sink, context);
  }
}

/** True when the file ends in what may be a ZIP archive: an end record signature in the last 64 KiB. */
export async function hasZipEnd(source: ByteSource): Promise<boolean> {
  const size = await source.size();
  if (size < 22) return false;
  const start = Math.max(0, size - END_SEARCH);
  const tail = await source.read(start, size - start);
  for (let p = tail.length - 22; p >= 0; p--) if (tail[p] === 0x50 && tail[p + 1] === 0x4b && tail[p + 2] === 5 && tail[p + 3] === 6) return true;
  return false;
}
