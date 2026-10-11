// tar archives: v7, ustar, star, GNU (long names, long links, old sparse files) and POSIX pax (extended and global
// headers, sparse files 0.0, 0.1 and 1.0). The writer writes ustar headers, with pax records for what they cannot hold.
import { checkTime, DataError, StopError } from './errors';
import { Reader } from './io';
import type { Archive, Entry, EntryKind, Kept, Meter, Note, WriteContext, WritePlan } from './model';
import { contentOf, sizeOf } from './model';
import { isAscii, utf8OrUndefined } from './names';
import { isTarHeader, sniffType } from './sniff';
import { type ByteSink, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';

export const BLOCK = 512;
/** GNU tar's default record: the archive is padded with zeros to a multiple of it. */
export const RECORD = 20 * BLOCK;
/** The most a pax header, a long name or a sparse map may hold. */
const MAX_META = 8 * 1024 * 1024;
/** The most regions a sparse map may list. */
const MAX_REGIONS = 500_000;
/** Further headers after the end of the archive are searched for up to this many bytes. */
const HIDDEN_SCAN = 64 * 1024 * 1024;

/** A pax record kept as written: its key, and its value's bytes. */
export interface PaxRecord {
  key: string;
  value: Buffer;
}

export interface TarEntry extends Entry {
  headerOffset: number;
  dataOffset: number;
  /** Bytes of data the archive stores for the entry. For a sparse file, the data segments without the holes. */
  stored: number;
  typeflag: string;
  uid: number;
  gid: number;
  uname: string;
  gname: string;
  mtime: number;
  devmajor: number;
  devminor: number;
  /** Pax records the rewrite keeps as they are: extended attributes, access and change times, vendor records. */
  pax: PaxRecord[];
  /** A sparse file's data segments, as offset and length in the whole file. */
  sparse?: Array<[number, number]>;
  /** Bytes at the start of the data that hold a pax 1.0 sparse map. */
  sparseMapBytes?: number;
}

const cstr = (b: Uint8Array, at: number, length: number) => {
  const end = b.subarray(at, at + length).indexOf(0);
  return b.subarray(at, end < 0 ? at + length : at + end);
};

/**
 * A numeric field: octal digits after any spaces or NULs, up to a space or NUL, or GNU's base-256 with the top bit of
 * the first byte set. Undefined when the field holds anything else or a value beyond a safe integer.
 */
export function numeric(b: Uint8Array, at: number, length: number): number | undefined {
  if (b[at] & 0x80) {
    // Base-256, two's complement, with the top bit as the marker. 0xff marks a negative value.
    const negative = b[at] === 0xff;
    let v = negative ? -1n : 0n;
    for (let i = 0; i < length; i++) v = (v << 8n) | BigInt(i === 0 ? (negative ? 0xff : b[at] & 0x7f) : b[at + i]);
    if (v > BigInt(Number.MAX_SAFE_INTEGER) || v < BigInt(Number.MIN_SAFE_INTEGER)) return undefined;
    return Number(v);
  }
  let i = at;
  const end = at + length;
  while (i < end && (b[i] === 0x20 || b[i] === 0)) i++;
  let v = 0;
  let digits = 0;
  for (; i < end && b[i] >= 0x30 && b[i] <= 0x37; i++, digits++) {
    v = v * 8 + (b[i] - 0x30);
    if (v > Number.MAX_SAFE_INTEGER) return undefined;
  }
  for (; i < end; i++) if (b[i] !== 0x20 && b[i] !== 0) return undefined;
  return digits === 0 ? 0 : v;
}

/** Parses pax records, "<length> <key>=<value>\n". Returns them in order, with the reason for any fault that stopped it. */
export function parsePax(data: Uint8Array): { records: PaxRecord[]; malformed?: string } {
  const records: PaxRecord[] = [];
  let p = 0;
  while (p < data.length) {
    // A trailing run of NULs pads the last block.
    if (data[p] === 0) break;
    const space = data.indexOf(0x20, p);
    if (space < 0 || space - p > 20) return { records, malformed: 'a pax record has no length' };
    const lenText = Buffer.from(data.subarray(p, space)).toString('latin1');
    if (!/^[1-9][0-9]*$/.test(lenText)) return { records, malformed: 'a pax record has no length' };
    const len = Number(lenText);
    if (p + len > data.length || data[p + len - 1] !== 0x0a) return { records, malformed: 'a pax record runs past its header' };
    const body = data.subarray(space + 1, p + len - 1);
    const eq = body.indexOf(0x3d);
    if (eq <= 0) return { records, malformed: 'a pax record has no key' };
    const key = utf8OrUndefined(body.subarray(0, eq));
    if (key === undefined) return { records, malformed: 'a pax key is not UTF-8' };
    records.push({ key, value: Buffer.from(body.subarray(eq + 1)) });
    p += len;
  }
  return { records };
}

/** Keys the reader turns into header fields. Every other record is kept as it is. */
const STRUCTURAL = new Set(['path', 'linkpath', 'size', 'uid', 'gid', 'uname', 'gname', 'mtime', 'hdrcharset']);
const isStructural = (key: string) => STRUCTURAL.has(key) || key.startsWith('GNU.sparse.');
const CAPABILITY = /^(SCHILY|LIBARCHIVE)\.xattr\.security\.capability$/;

/** A name or a link target from bytes: UTF-8 when valid, and Latin-1 otherwise, which no reader agrees on. */
function text(bytes: Uint8Array, notes: Note[], name?: string): string {
  const u = utf8OrUndefined(bytes);
  if (u !== undefined) return u;
  notes.push({ category: C.Name, detail: D.Encoding, data: { name: name ?? Buffer.from(bytes).toString('latin1') } });
  return Buffer.from(bytes).toString('latin1');
}

/** True for a name that leaves the extraction folder: absolute, with a drive letter, or with a ".." part. */
const unsafePath = (p: string) => /^[/\\]/.test(p) || /^[a-zA-Z]:/.test(p) || p.split(/[/\\]/).includes('..');

const kinds: Record<string, EntryKind> = { '0': 'file', '\0': 'file', '7': 'file', '1': 'hardlink', '2': 'symlink', '3': 'device', '4': 'device', '5': 'directory', '6': 'fifo', D: 'directory' };

interface Pending {
  pax: PaxRecord[];
  longName?: Uint8Array;
  longLink?: Uint8Array;
}

/** A tar archive read header by header. */
export class TarArchive implements Archive<TarEntry> {
  readonly format = 'tar';
  readonly single = false;
  readonly lateNotes: Note[] = [];
  comment?: string;

  private constructor(
    readonly reader: Reader,
    readonly entries: TarEntry[],
    readonly notes: Note[],
    /** Where the end-of-archive blocks start, or the archive's data ends. */
    readonly end: number,
    /** Where the data after the archive starts. */
    readonly trailingStart: number,
    /** The volume label, from a GNU 'V' header. */
    readonly label?: string,
  ) {}

  static async open(source: ByteSource, limits: { entries: number; decompressedBytes: number; totalDecompressedBytes: number }, deadline?: number): Promise<TarArchive> {
    const size = await source.size();
    const reader = new Reader(source, size);
    const notes: Note[] = [];
    const entries: TarEntry[] = [];
    let global: PaxRecord[] = [];
    let pending: Pending = { pax: [] };
    let pos = 0;
    let total = 0;
    let comment: string | undefined;
    let label: string | undefined;
    let end = -1;
    let trailingStart = size;
    let headers = 0;
    const meta = async (at: number, length: number, what: string) => {
      if (length > MAX_META) throw new StopError(C.Corrupted, D.Unparseable, `A ${what} is too large`, { reason: `a ${what} of ${length} bytes` });
      if (at + length > size) throw new StopError(C.Corrupted, D.Truncated, 'The archive ends inside a header', { what: what });
      return Buffer.from(await reader.read(at, length));
    };
    for (;;) {
      if (headers++ % 256 === 0) checkTime(deadline);
      if (pos + BLOCK > size) {
        // The archive ends without its two zero blocks.
        if (entries.length || pending.pax.length || pending.longName) notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'the archive has no end-of-archive blocks' } });
        end = Math.min(pos, size);
        trailingStart = end;
        break;
      }
      const block = await reader.read(pos, BLOCK);
      if (block.every(b => b === 0)) {
        end = pos;
        // Two zero blocks end the archive. Readers that stop at the first one and readers that go on past a lone one
        // see different archives, so what follows the first is data after the archive either way.
        const next = pos + BLOCK + BLOCK <= size ? await reader.read(pos + BLOCK, BLOCK) : undefined;
        trailingStart = next?.every(b => b === 0) ? pos + 2 * BLOCK : Math.min(size, pos + BLOCK);
        break;
      }
      if (!isTarHeader(block)) {
        if (pos === 0) throw new StopError(C.Corrupted, D.Unparseable, 'Not a tar archive', { reason: 'no tar header at the start' });
        // A damaged header with more headers after it hides entries from some readers and not others.
        if (await TarArchive.headerAfter(reader, pos + BLOCK, deadline))
          throw new StopError(C.Corrupted, D.Unparseable, 'A damaged header', { reason: 'a damaged header in the middle of the archive' });
        notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'the archive has no end-of-archive blocks' } });
        end = pos;
        trailingStart = pos;
        break;
      }
      const typeflag = String.fromCharCode(block[156]);
      const ustar = Buffer.from(block.subarray(257, 263)).toString('latin1');
      const posix = ustar === 'ustar\0';
      const star = posix && Buffer.from(block.subarray(508, 512)).toString('latin1') === 'tar\0';
      const entryNotes: Note[] = [];
      const num = (at: number, length: number, field: string) => {
        const v = numeric(block, at, length);
        if (v === undefined) entryNotes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: `a ${field} field that is not a number` } });
        return v ?? 0;
      };
      const sizeField = numeric(block, 124, 12);
      if (sizeField === undefined || sizeField < 0) throw new StopError(C.Corrupted, D.Unparseable, 'A header has no valid size', { reason: 'a header without a valid size' });
      const dataOffset = pos + BLOCK;
      // Extended headers and long names describe the next header.
      if (typeflag === 'x' || typeflag === 'X' || typeflag === 'g') {
        const parsed = parsePax(await meta(dataOffset, sizeField, 'pax header'));
        if (parsed.malformed) notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: parsed.malformed } });
        if (typeflag === 'g') {
          // Later global records replace earlier ones of the same key.
          const keys = new Set(parsed.records.map(r => r.key));
          global = [...global.filter(r => !keys.has(r.key)), ...parsed.records];
          const c = parsed.records.find(r => r.key === 'comment');
          if (c) comment = c.value.toString('utf8');
        } else pending.pax.push(...parsed.records);
        pos = dataOffset + Math.ceil(sizeField / BLOCK) * BLOCK;
        continue;
      }
      if (typeflag === 'L' || typeflag === 'K') {
        const value = cstr(await meta(dataOffset, sizeField, 'long name'), 0, sizeField);
        if (typeflag === 'L') pending.longName = value;
        else pending.longLink = value;
        pos = dataOffset + Math.ceil(sizeField / BLOCK) * BLOCK;
        continue;
      }
      if (typeflag === 'M') throw new StopError(C.Structure, D.MultiVolume, 'A GNU multi-volume continuation');
      if (typeflag === 'V') {
        label = Buffer.from(cstr(block, 0, 100)).toString('latin1');
        pos = dataOffset + Math.ceil(sizeField / BLOCK) * BLOCK;
        continue;
      }
      // The records that apply: global ones, then this entry's own, the later winning.
      const records = [...global.filter(g => !pending.pax.some(r => r.key === g.key)), ...pending.pax];
      const last = (key: string) => {
        let found: PaxRecord | undefined;
        for (const r of records) if (r.key === key) found = r;
        return found;
      };
      const binary = last('hdrcharset')?.value.toString('latin1') === 'BINARY';
      const paxText = (key: string) => {
        const r = last(key);
        if (r === undefined) return undefined;
        // GNU tar, bsdtar and Python cut a pax value at its first NUL, so this reader does as well, and says so.
        const nul = r.value.indexOf(0);
        if (nul >= 0) entryNotes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: `the pax ${key} holds a NUL byte, which readers cut at or keep` } });
        const value = nul >= 0 ? r.value.subarray(0, nul) : r.value;
        return binary ? text(value, entryNotes) : value.toString('utf8');
      };
      const paxNumber = (key: string) => {
        const v = paxText(key);
        if (v === undefined) return undefined;
        if (!/^-?[0-9]+(\.[0-9]*)?$/.test(v)) {
          entryNotes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: `a pax ${key} that is not a number` } });
          return undefined;
        }
        const n = Math.floor(Number(v));
        return Number.isSafeInteger(n) ? n : undefined;
      };

      const owner = (v: number, field: string) => {
        if (v >= 0) return v;
        entryNotes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: `a negative ${field}` } });
        return 0;
      };
      const headerName = cstr(block, 0, 100);
      const prefix = posix ? cstr(block, 345, star ? 131 : 155) : new Uint8Array(0);
      const fallbackName = prefix.length ? Buffer.concat([prefix, Buffer.from('/'), headerName]) : Buffer.from(headerName);
      const plainName = pending.longName ?? fallbackName;
      let name = paxText('path') ?? text(plainName, entryNotes);
      const linkBytes = pending.longLink ?? cstr(block, 157, 100);
      const linkTarget = paxText('linkpath') ?? text(linkBytes, entryNotes);
      // Readers without pax or GNU support take the names in the header itself.
      const plain = text(fallbackName, []);
      if (plain !== name && unsafePath(plain) && !unsafePath(name)) {
        entryNotes.push({ category: C.Structure, detail: D.HeaderMismatch, data: { name, what: `readers without pax or GNU long names see the name ${plain}` } });
      }
      const paxSize = paxNumber('size');
      // The header's own size field holds the size too unless it cannot: readers without pax support go by it, and
      // a size that differs from the pax record's makes them read the archive another way.
      const fieldCannotHold = paxSize !== undefined && paxSize > 0o77777777777 && (sizeField === 0 || sizeField === 0o77777777777 || (block[124] & 0x80) !== 0);
      if (paxSize !== undefined && paxSize !== sizeField && !fieldCannotHold) {
        notes.push({ category: C.Structure, detail: D.HeaderMismatch, data: { name, what: 'the pax size and the header size differ' } });
      }
      const stored = paxSize ?? sizeField;
      if (stored < 0) throw new StopError(C.Corrupted, D.Unparseable, 'A negative size', { reason: 'a negative pax size' });
      let kind: EntryKind = kinds[typeflag] ?? 'other';
      // A v7 header marks a directory by the slash alone.
      if (kind === 'file' && (typeflag === '\0' || typeflag === '0') && name.endsWith('/')) kind = 'directory';
      if (kind === 'directory' && !name.endsWith('/')) name += '/';
      const e: TarEntry = {
        index: entries.length,
        name,
        kind,
        mode: num(100, 8, 'mode') & 0o7777,
        size: kind === 'file' || kind === 'other' ? stored : 0,
        compressedSize: stored,
        notes: entryNotes,
        headerOffset: pos,
        dataOffset,
        stored,
        typeflag,
        uid: owner(paxNumber('uid') ?? num(108, 8, 'uid'), 'uid'),
        gid: owner(paxNumber('gid') ?? num(116, 8, 'gid'), 'gid'),
        uname: paxText('uname') ?? Buffer.from(cstr(block, 265, 32)).toString('latin1'),
        gname: paxText('gname') ?? Buffer.from(cstr(block, 297, 32)).toString('latin1'),
        mtime: paxNumber('mtime') ?? num(136, 12, 'mtime'),
        devmajor: posix || ustar === 'ustar ' ? num(329, 8, 'devmajor') : 0,
        devminor: posix || ustar === 'ustar ' ? num(337, 8, 'devminor') : 0,
        // Global records apply to every entry after them, so each entry keeps its own copy. A global comment is the archive's.
        pax: records.filter(r => !isStructural(r.key) && !(r.key === 'comment' && global.includes(r))),
      };
      if (kind === 'symlink' || kind === 'hardlink') e.linkTarget = linkTarget;
      if (kind === 'other') e.typeCode = `tar type ${JSON.stringify(typeflag)}`;
      if (kind === 'device') e.typeCode = typeflag === '3' ? 'character device' : 'block device';
      const ownComment = pending.pax.find(r => r.key === 'comment');
      if (ownComment) e.comment = ownComment.value.toString('utf8');
      const caps = e.pax.filter(r => CAPABILITY.test(r.key)).map(r => r.key);
      if (caps.length) e.capabilities = caps;
      if (typeflag === 'S' || records.some(r => r.key.startsWith('GNU.sparse.'))) await TarArchive.sparse(reader, e, block, records, paxText, pos);
      if (e.dataOffset + stored > size) throw new StopError(C.Corrupted, D.Truncated, 'The archive ends inside an entry', { what: 'entry' }, e.name);
      if (kind !== 'file' && kind !== 'other' && stored > 0) entryNotes.push({ category: C.Structure, detail: D.NonFileData, data: { name, bytes: stored } });
      if (entries.length >= limits.entries) throw new StopError(C.Limit, D.EntryCount, 'Too many entries', { limit: limits.entries });
      if (e.size > limits.decompressedBytes) throw new StopError(C.Limit, D.DecompressedSize, `${name} has ${e.size} bytes`, { size: e.size, limit: limits.decompressedBytes }, name);
      total += e.size;
      if (total > limits.totalDecompressedBytes) throw new StopError(C.Limit, D.TotalDecompressedSize, 'The entries hold too many bytes', { limit: limits.totalDecompressedBytes });
      entries.push(e);
      pending = { pax: [] };
      pos = e.dataOffset + Math.ceil(stored / BLOCK) * BLOCK;
      // The last block of an entry's data may be cut short at the end of the file. Readers that pad it and readers
      // that stop see the same entry, so only the end-of-archive check notes it.
      if (pos > size) pos = size;
    }

    // Data after the end of the archive. GNU tar pads with zeros to a whole record, which is not data.
    if (trailingStart < size) {
      let nonZero = false;
      for (let at = trailingStart; at < size && !nonZero; at += 65536) {
        checkTime(deadline);
        if ((await reader.read(at, Math.min(65536, size - at))).some(b => b !== 0)) nonZero = true;
      }
      if (nonZero) {
        notes.push({ category: C.Structure, detail: D.TrailingBytes, data: { bytes: size - trailingStart } });
        const first = await TarArchive.firstNonZero(reader, trailingStart);
        const type = sniffType(await reader.read(first, Math.min(1024, size - first)));
        // More tar after the end is hidden entries, which HIDDEN_DATA reports, not a second format.
        if (type !== undefined && type !== 'application/x-tar') notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'after the archive' } });
        if (await TarArchive.headerAfter(reader, trailingStart, deadline))
          notes.push({ category: C.Structure, detail: D.HiddenData, data: { reason: 'tar headers after the end of the archive, which some readers go on to read' } });
      }
    }
    const archive = new TarArchive(reader, entries, notes, end, trailingStart, label);
    if (comment !== undefined) archive.comment = comment;
    return archive;
  }

  /** The offset of the first byte that is not zero, from `from`. */
  private static async firstNonZero(reader: Reader, from: number): Promise<number> {
    for (let at = from; at < reader.size; at += 65536) {
      const b = await reader.read(at, Math.min(65536, reader.size - at));
      const i = b.findIndex(x => x !== 0);
      if (i >= 0) return at + i;
    }
    return reader.size;
  }

  /** True when a tar header sits at a block boundary from `from` on. */
  private static async headerAfter(reader: Reader, from: number, deadline: number | undefined): Promise<boolean> {
    const start = Math.ceil(from / BLOCK) * BLOCK;
    for (let at = start; at + BLOCK <= reader.size && at - start < HIDDEN_SCAN; at += BLOCK) {
      if ((at - start) % (256 * BLOCK) === 0) checkTime(deadline);
      if (isTarHeader(await reader.read(at, BLOCK))) return true;
    }
    return false;
  }

  /** Reads a sparse file's map: GNU's old header and its extensions, or pax 0.0, 0.1 or 1.0. */
  private static async sparse(
    reader: Reader,
    e: TarEntry,
    block: Uint8Array,
    records: Array<{ key: string; value: Buffer }>,
    paxText: (key: string) => string | undefined,
    pos: number,
  ): Promise<void> {
    const map: Array<[number, number]> = [];
    const bad = (reason: string): never => {
      throw new StopError(C.Corrupted, D.Unparseable, 'A sparse map that does not read', { reason }, e.name);
    };
    let realSize: number | undefined;
    if (e.typeflag === 'S') {
      const take = (b: Uint8Array, start: number, count: number) => {
        for (let i = 0; i < count; i++) {
          const o = numeric(b, start + i * 24, 12);
          const n = numeric(b, start + i * 24 + 12, 12);
          if (o === undefined || n === undefined) bad('a sparse entry that is not a number');
          if (b[start + i * 24] === 0 && n === 0 && o === 0) continue;
          map.push([o ?? 0, n ?? 0]);
        }
      };
      take(block, 386, 4);
      realSize = numeric(block, 483, 12);
      let extended = block[482] !== 0;
      let at = pos + BLOCK;
      while (extended) {
        if (map.length > MAX_REGIONS || at + BLOCK > reader.size) bad('a sparse map that does not end');
        const ext = await reader.read(at, BLOCK);
        take(ext, 0, 21);
        extended = ext[504] !== 0;
        at += BLOCK;
      }
      // The extension blocks come before the data.
      e.dataOffset = at;
    } else {
      const major = paxText('GNU.sparse.major');
      if (major === '1') {
        realSize = Number(paxText('GNU.sparse.realsize'));
        const name = paxText('GNU.sparse.name');
        if (name !== undefined) e.name = name;
        // The map heads the data, as decimal lines, padded to a block: the number of regions, then an offset and a
        // length for each. The lines are read block by block, and what follows the last one is padding.
        const numbers: number[] = [];
        let at = e.dataOffset;
        let carry = '';
        const wanted = () => (numbers.length ? 1 + 2 * numbers[0] : 1);
        while (numbers.length < wanted()) {
          if (at - e.dataOffset >= MAX_META || at + BLOCK > e.dataOffset + e.stored) bad('a sparse map that does not end');
          const lines = (carry + Buffer.from(await reader.read(at, BLOCK)).toString('latin1')).split('\n');
          at += BLOCK;
          carry = lines.pop() ?? '';
          for (const line of lines) {
            if (numbers.length >= wanted()) break;
            if (!/^[0-9]{1,20}$/.test(line)) bad('a sparse map line that is not a number');
            numbers.push(Number(line));
            if (numbers.length === 1 && numbers[0] > MAX_REGIONS) bad('a sparse map with too many regions');
          }
          if (numbers.length < wanted() && carry.length > 64) bad('a sparse map line that is not a number');
        }
        for (let i = 0; i < numbers[0]; i++) map.push([numbers[1 + 2 * i], numbers[2 + 2 * i]]);
        e.sparseMapBytes = at - e.dataOffset;
      } else if (paxText('GNU.sparse.map') !== undefined) {
        realSize = Number(paxText('GNU.sparse.size'));
        const nums = (paxText('GNU.sparse.map') ?? '').split(',');
        if (nums.length > 2 * MAX_REGIONS) bad('a sparse map with too many regions');
        if (nums.length % 2 !== 0 || nums.some(n => !/^[0-9]+$/.test(n))) bad('a sparse map that does not read');
        for (let i = 0; i + 1 < nums.length; i += 2) map.push([Number(nums[i]), Number(nums[i + 1])]);
        const name = paxText('GNU.sparse.name');
        if (name !== undefined) e.name = name;
      } else {
        realSize = Number(paxText('GNU.sparse.size'));
        let offset: number | undefined;
        for (const r of records) {
          if (r.key === 'GNU.sparse.offset') offset = Number(r.value.toString('latin1'));
          else if (r.key === 'GNU.sparse.numbytes') {
            if (offset === undefined) bad('a sparse length without an offset');
            map.push([offset ?? 0, Number(r.value.toString('latin1'))]);
            offset = undefined;
          }
        }
      }
    }
    if (realSize === undefined || !Number.isSafeInteger(realSize) || realSize < 0) bad('a sparse file without a valid size');
    let covered = 0;
    let data = 0;
    for (const [o, n] of map) {
      if (!Number.isSafeInteger(o) || !Number.isSafeInteger(n) || o < covered || o + n > (realSize ?? 0)) bad('sparse segments out of order or past the file');
      covered = o + n;
      data += n;
    }
    if (data !== e.stored - (e.sparseMapBytes ?? 0)) bad('sparse segments that do not add up to the data');
    e.sparse = map;
    e.size = realSize ?? 0;
    e.kind = 'file';
  }

  async unlock(): Promise<boolean> {
    return false;
  }

  hasMetadata(): boolean {
    return this.label !== undefined || this.comment !== undefined || this.entries.some(e => e.uid !== 0 || e.gid !== 0 || e.mtime !== 0 || e.uname !== '' || e.gname !== '' || e.pax.length > 0);
  }

  /** The entry's stored data. */
  raw(e: TarEntry): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(e.dataOffset, e.stored);
  }

  async *read(e: TarEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    if (e.broken) throw new DataError(e.broken);
    if (!e.sparse) {
      let total = 0;
      for await (const c of this.raw(e)) {
        total += c.length;
        meter.add(total, total);
        yield c;
      }
      if (total !== e.stored) throw new DataError('the archive ends inside the entry', true);
      return;
    }
    // A sparse file: zeros in the holes, the stored segments in between.
    let at = e.dataOffset + (e.sparseMapBytes ?? 0);
    let out = 0;
    const zeros = Buffer.alloc(65536);
    const hole = async function* (length: number) {
      for (let left = length; left > 0; left -= zeros.length) {
        const n = Math.min(left, zeros.length);
        out += n;
        // The holes are the size the header declared, which the limits already checked, so they count as stored.
        meter.add(out, out);
        yield zeros.subarray(0, n);
      }
    };
    for (const [o, n] of e.sparse) {
      yield* hole(o - out);
      for await (const c of this.reader.chunks(at, n)) {
        out += c.length;
        meter.add(out, out);
        yield c;
      }
      at += n;
    }
    yield* hole(e.size - out);
  }

  write(plan: WritePlan<TarEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    return writeTar(this, plan, sink, context);
  }

  trailing(): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(this.trailingStart, this.reader.size - this.trailingStart);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The writer.

/** One pax record, whose length counts its own digits. */
export function paxRecord(key: string, value: Buffer): Buffer {
  const body = Buffer.concat([Buffer.from(` ${key}=`, 'utf8'), value, Buffer.from('\n')]);
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return Buffer.concat([Buffer.from(String(len)), body]);
}

const octalField = (v: number, width: number) => `${v.toString(8).padStart(width - 1, '0')}\0`;

/** A header block. */
export function header(f: {
  name: Buffer;
  mode: number;
  uid: number;
  gid: number;
  size: number;
  mtime: number;
  typeflag: string;
  linkname: Buffer;
  uname: string;
  gname: string;
  prefix: Buffer;
  devmajor: number;
  devminor: number;
}): Buffer {
  const b = Buffer.alloc(BLOCK);
  f.name.copy(b, 0, 0, 100);
  b.write(octalField(f.mode, 8), 100, 'latin1');
  b.write(octalField(f.uid, 8), 108, 'latin1');
  b.write(octalField(f.gid, 8), 116, 'latin1');
  b.write(octalField(f.size, 12), 124, 'latin1');
  b.write(octalField(f.mtime, 12), 136, 'latin1');
  b.write('        ', 148, 'latin1');
  b.write(f.typeflag, 156, 'latin1');
  f.linkname.copy(b, 157, 0, 100);
  b.write('ustar\x0000', 257, 'latin1');
  b.write(f.uname.slice(0, 32), 265, 'latin1');
  b.write(f.gname.slice(0, 32), 297, 'latin1');
  b.write(octalField(f.devmajor, 8), 329, 'latin1');
  b.write(octalField(f.devminor, 8), 337, 'latin1');
  f.prefix.copy(b, 345, 0, 155);
  let sum = 0;
  for (const x of b) sum += x;
  b.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return b;
}

/** A name in ASCII for the header itself, for readers without pax support. The pax record holds the real one. */
export const asciiFallback = (s: string) => Buffer.from(s.replace(/[^\x20-\x7e]/g, '_').slice(0, 100), 'latin1');

/** The name split across the ustar prefix and name fields, or undefined when it does not fit. */
export function split(name: string): { prefix: Buffer; name: Buffer } | undefined {
  if (!/^[\x20-\x7e]*$/.test(name)) return undefined;
  if (name.length <= 100) return { prefix: Buffer.alloc(0), name: Buffer.from(name, 'latin1') };
  for (let i = name.length - 1; i > 0; i--) {
    if (name[i] !== '/') continue;
    if (i <= 155 && name.length - i - 1 <= 100 && name.length - i - 1 > 0) return { prefix: Buffer.from(name.slice(0, i), 'latin1'), name: Buffer.from(name.slice(i + 1), 'latin1') };
  }
  return undefined;
}

const typeflagFor = (e: TarEntry): string => {
  if (e.kind === 'directory') return '5';
  if (e.kind === 'file') return e.typeflag === '7' ? '7' : '0';
  if (e.kind === 'other') return e.typeflag;
  if (e.kind === 'hardlink') return '1';
  if (e.kind === 'symlink') return '2';
  if (e.kind === 'fifo') return '6';
  return e.typeflag === '4' ? '4' : '3';
};

async function writeTar(tar: TarArchive, plan: WritePlan<TarEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
  let written = 0;
  const put = async (b: Uint8Array) => {
    await sink.write(b);
    written += b.length;
  };
  const meta = !plan.stripMetadata;
  if (meta && tar.label !== undefined) {
    await put(
      header({
        name: Buffer.from(tar.label.slice(0, 100), 'latin1'),
        mode: 0,
        uid: 0,
        gid: 0,
        size: 0,
        mtime: 0,
        typeflag: 'V',
        linkname: Buffer.alloc(0),
        uname: '',
        gname: '',
        prefix: Buffer.alloc(0),
        devmajor: 0,
        devminor: 0,
      }),
    );
  }
  if (meta && tar.comment !== undefined) await writePax(put, 'g', [paxRecord('comment', Buffer.from(tar.comment, 'utf8'))]);
  for (const k of plan.kept) {
    context.meter().time();
    await writeEntry(tar, k, plan, put, context);
  }
  await put(Buffer.alloc(2 * BLOCK));
  const pad = (RECORD - (written % RECORD)) % RECORD;
  if (pad) await put(Buffer.alloc(pad));
  if (plan.keepTrailing) for await (const c of tar.trailing()) await put(c);
}

async function writePax(put: (b: Uint8Array) => Promise<void>, typeflag: 'x' | 'g', records: Buffer[]): Promise<void> {
  const body = Buffer.concat(records);
  await put(
    header({
      name: Buffer.from(typeflag === 'g' ? 'pax_global_header' : '././@PaxHeader'),
      mode: 0o644,
      uid: 0,
      gid: 0,
      size: body.length,
      mtime: 0,
      typeflag,
      linkname: Buffer.alloc(0),
      uname: '',
      gname: '',
      prefix: Buffer.alloc(0),
      devmajor: 0,
      devminor: 0,
    }),
  );
  await put(body);
  const pad = (BLOCK - (body.length % BLOCK)) % BLOCK;
  if (pad) await put(Buffer.alloc(pad));
}

async function writeEntry(tar: TarArchive, k: Kept<TarEntry>, plan: WritePlan<TarEntry>, put: (b: Uint8Array) => Promise<void>, context: WriteContext): Promise<void> {
  const e = k.entry;
  const meta = !plan.stripMetadata;
  const records: Buffer[] = [];
  const name = e.kind === 'directory' && !k.name.endsWith('/') ? `${k.name}/` : k.name;
  const parts = split(name);
  if (!parts) records.push(paxRecord('path', Buffer.from(name, 'utf8')));
  const link = k.linkTarget ?? e.linkTarget ?? '';
  const linkFits = /^[\x20-\x7e]*$/.test(link) && link.length <= 100;
  if (!linkFits) records.push(paxRecord('linkpath', Buffer.from(link, 'utf8')));
  const hasData = e.kind === 'file' || e.kind === 'other';
  const size = hasData ? sizeOf(k) : 0;
  if (size > 0o77777777777) records.push(paxRecord('size', Buffer.from(String(size))));
  const uid = meta ? e.uid : 0;
  const gid = meta ? e.gid : 0;
  const uname = meta ? e.uname : '';
  const gname = meta ? e.gname : '';
  const mtime = meta ? e.mtime : 0;
  const idFits = (v: number) => v >= 0 && v <= 0o7777777;
  if (!idFits(uid)) records.push(paxRecord('uid', Buffer.from(String(uid))));
  if (!idFits(gid)) records.push(paxRecord('gid', Buffer.from(String(gid))));
  const nameFits = (s: string) => /^[\x20-\x7e]*$/.test(s) && s.length <= 32;
  if (!nameFits(uname)) records.push(paxRecord('uname', Buffer.from(uname, 'utf8')));
  if (!nameFits(gname)) records.push(paxRecord('gname', Buffer.from(gname, 'utf8')));
  const timeFits = mtime >= 0 && mtime <= 0o77777777777;
  if (!timeFits) records.push(paxRecord('mtime', Buffer.from(String(mtime))));
  if (meta) for (const r of e.pax) if (!(k.dropCapabilities && CAPABILITY.test(r.key))) records.push(paxRecord(r.key, r.value));
  if (records.length) await writePax(put, 'x', records);
  await put(
    header({
      name: parts?.name ?? asciiFallback(name),
      prefix: parts?.prefix ?? Buffer.alloc(0),
      mode: k.mode ?? (e.kind === 'directory' ? 0o755 : 0o644),
      uid: idFits(uid) ? uid : 0,
      gid: idFits(gid) ? gid : 0,
      size: size > 0o77777777777 ? 0 : size,
      mtime: timeFits ? mtime : 0,
      typeflag: typeflagFor(e),
      linkname: linkFits ? Buffer.from(link, 'latin1') : asciiFallback(link),
      uname: nameFits(uname) ? uname : '',
      gname: nameFits(gname) ? gname : '',
      devmajor: e.kind === 'device' ? e.devmajor : 0,
      devminor: e.kind === 'device' ? e.devminor : 0,
    }),
  );
  if (!hasData) return;
  let n = 0;
  const chunks = k.replacement || e.sparse ? contentOf(tar, k, context) : tar.raw(e);
  for await (const c of chunks) {
    context.meter().time();
    n += c.length;
    await put(c);
  }
  if (n !== size) throw new Error(`Entry ${k.name} has ${n} bytes, not ${size}`);
  const pad = (BLOCK - (size % BLOCK)) % BLOCK;
  if (pad) await put(Buffer.alloc(pad));
}

export const isTar = (head: Uint8Array) => head.length >= BLOCK && isTarHeader(head.subarray(0, BLOCK)) && isAscii(head.subarray(257, 262));
