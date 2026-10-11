import { ParseError, UnsupportedError } from './errors';

/** Property IDs of the 7z header. */
export enum Nid {
  End = 0x00,
  Header = 0x01,
  ArchiveProperties = 0x02,
  AdditionalStreamsInfo = 0x03,
  MainStreamsInfo = 0x04,
  FilesInfo = 0x05,
  PackInfo = 0x06,
  UnpackInfo = 0x07,
  SubStreamsInfo = 0x08,
  Size = 0x09,
  Crc = 0x0a,
  Folder = 0x0b,
  CodersUnpackSize = 0x0c,
  NumUnpackStream = 0x0d,
  EmptyStream = 0x0e,
  EmptyFile = 0x0f,
  Anti = 0x10,
  Name = 0x11,
  CTime = 0x12,
  ATime = 0x13,
  MTime = 0x14,
  WinAttributes = 0x15,
  Comment = 0x16,
  EncodedHeader = 0x17,
  StartPos = 0x18,
  Dummy = 0x19,
}

/** One coder of a folder. */
export interface Coder {
  /** The method ID in hex, such as "030101" for LZMA. */
  method: string;
  numIn: number;
  numOut: number;
  props: Uint8Array;
}

/** A folder: coders joined by bind pairs, fed by packed streams. */
export interface Folder {
  coders: Coder[];
  /** Coder in-stream `inIndex` reads coder out-stream `outIndex`. */
  bindPairs: Array<{ inIndex: number; outIndex: number }>;
  /** The in-streams that read packed streams, in the order of the folder's packed streams. */
  packedStreams: number[];
  /** Decoded size of every coder out-stream. */
  unpackSizes: number[];
  /** CRC of the folder's main output, when stored. */
  crc?: number;
  /** The out-stream that is the folder's output: the one no bind pair reads. */
  mainOut: number;
}

export interface StreamsInfo {
  /** Offset of the first packed stream, from the end of the signature header. */
  packPos: number;
  packSizes: number[];
  folders: Folder[];
  /** Per folder, how many files its output holds. */
  numUnpackStreams: number[];
  /** Per substream, in folder order: its size and CRC. */
  subSizes: number[];
  subCrcs: Array<number | undefined>;
}

/** One file entry as the header describes it. */
export interface FileInfo {
  name?: string;
  hasStream: boolean;
  /** For an entry without a stream: an empty file rather than a directory. */
  emptyFile: boolean;
  anti: boolean;
  attrib?: number;
  ctime?: Uint8Array;
  atime?: Uint8Array;
  mtime?: Uint8Array;
}

export interface Header {
  streams?: StreamsInfo;
  files: FileInfo[];
  /** Header properties this package does not keep, by name. */
  unknown: string[];
}

/** What a file declares at its start. */
export interface StartHeader {
  nextHeaderOffset: number;
  nextHeaderSize: number;
  nextHeaderCrc: number;
  minorVersion: number;
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER;

/** Reads the numbers, bit vectors and digests of a 7z header. */
export class HeaderReader {
  pos = 0;
  constructor(readonly buf: Uint8Array) {}

  get remaining(): number {
    return this.buf.length - this.pos;
  }

  byte(): number {
    if (this.pos >= this.buf.length) throw new ParseError('the header ends early');
    return this.buf[this.pos++];
  }

  /** A property ID, read as a 7z number, so an ID can take more than one byte. Any large one is unknown. */
  id(): number {
    return Math.min(this.raw(), MAX_SAFE);
  }

  bytes(n: number): Uint8Array {
    if (n > this.remaining) throw new ParseError('the header ends early');
    const b = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return b;
  }

  /** A 7z number: the first byte's leading one bits count the bytes that follow, which hold the low bits. */
  private raw(): number {
    const first = this.byte();
    let mask = 0x80;
    let value = 0;
    for (let i = 0; i < 8; i++) {
      if ((first & mask) === 0) return value + (first & (mask - 1)) * 2 ** (8 * i);
      value += this.byte() * 2 ** (8 * i);
      mask >>>= 1;
    }
    return value;
  }

  /** A 7z number used as a size, a count or an index. */
  number(): number {
    const value = this.raw();
    if (value > MAX_SAFE) throw new ParseError('a header number is too large');
    return value;
  }

  /** A number used as a count of things that each take at least `unit` bytes of what is left. */
  count(unit: number, max = MAX_SAFE): number {
    const n = this.number();
    if (n > max || n * unit > this.remaining) throw new ParseError('a header count is larger than the header');
    return n;
  }

  uint32(): number {
    const b = this.bytes(4);
    return (b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)) >>> 0;
  }

  bits(n: number): boolean[] {
    const out: boolean[] = [];
    let mask = 0;
    let cur = 0;
    for (let i = 0; i < n; i++) {
      if (mask === 0) {
        cur = this.byte();
        mask = 0x80;
      }
      out.push((cur & mask) !== 0);
      mask >>>= 1;
    }
    return out;
  }

  /** A byte that says all are defined, or a bit vector that says which. */
  defined(n: number): boolean[] {
    const all = this.byte();
    return all ? new Array<boolean>(n).fill(true) : this.bits(n);
  }

  digests(n: number): Array<number | undefined> {
    const defined = this.defined(n);
    return defined.map(d => (d ? this.uint32() : undefined));
  }
}

const hex = (b: Uint8Array) => Buffer.from(b).toString('hex');

/** Reads the 20 bytes after the signature, version and CRC. */
export function parseStartHeader(b: Uint8Array): StartHeader {
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const u64 = (at: number) => {
    const v = view.getUint32(at, true) + view.getUint32(at + 4, true) * 2 ** 32;
    if (v > MAX_SAFE) throw new ParseError('the start header holds an offset beyond any file');
    return v;
  };
  return { minorVersion: b[7], nextHeaderOffset: u64(12), nextHeaderSize: u64(20), nextHeaderCrc: view.getUint32(28, true) };
}

/** At most 64 coders, and 64 streams, in a folder: more than any chain of 7z methods needs. */
const MAX_FOLDER_STREAMS = 64;

function readFolder(r: HeaderReader): Omit<Folder, 'unpackSizes' | 'crc' | 'mainOut'> {
  const numCoders = r.count(2, MAX_FOLDER_STREAMS);
  if (numCoders === 0) throw new ParseError('a folder has no coders');
  const coders: Coder[] = [];
  let totalIn = 0;
  let totalOut = 0;
  for (let i = 0; i < numCoders; i++) {
    const flags = r.byte();
    if (flags & 0x80) throw new UnsupportedError('alternative coder methods', false, { reason: 'alternative coder methods' });
    const idSize = flags & 0x0f;
    // A method ID is a big-endian number, so leading zero bytes add nothing, and an ID of no bytes is 0, which is Copy.
    const method = hex(r.bytes(idSize)).replace(/^(00)+/, '') || '00';
    let numIn = 1;
    let numOut = 1;
    if (flags & 0x10) {
      numIn = r.count(0, MAX_FOLDER_STREAMS);
      numOut = r.count(0, MAX_FOLDER_STREAMS);
    }
    const props = flags & 0x20 ? r.bytes(r.count(1)).slice() : new Uint8Array(0);
    coders.push({ method, numIn, numOut, props });
    totalIn += numIn;
    totalOut += numOut;
  }
  if (totalOut === 0 || totalIn > MAX_FOLDER_STREAMS || totalOut > MAX_FOLDER_STREAMS) throw new ParseError('a folder has an invalid number of streams');
  const bindPairs: Folder['bindPairs'] = [];
  for (let i = 0; i < totalOut - 1; i++) {
    const inIndex = r.number();
    const outIndex = r.number();
    if (inIndex >= totalIn || outIndex >= totalOut) throw new ParseError('a bind pair names a stream the folder does not have');
    bindPairs.push({ inIndex, outIndex });
  }
  const numPacked = totalIn - bindPairs.length;
  if (numPacked < 1) throw new ParseError('a folder reads no packed stream');
  const packedStreams: number[] = [];
  if (numPacked === 1) {
    for (let i = 0; i < totalIn; i++) {
      if (!bindPairs.some(bp => bp.inIndex === i)) {
        packedStreams.push(i);
        break;
      }
    }
  } else {
    for (let i = 0; i < numPacked; i++) {
      const index = r.number();
      if (index >= totalIn) throw new ParseError('a packed stream index names a stream the folder does not have');
      packedStreams.push(index);
    }
  }
  if (packedStreams.length !== numPacked) throw new ParseError('the folder binds every input');
  // Every in-stream gets exactly one source, and no out-stream feeds two in-streams.
  const inUsed = new Set<number>([...bindPairs.map(bp => bp.inIndex), ...packedStreams]);
  const outUsed = new Set<number>(bindPairs.map(bp => bp.outIndex));
  if (inUsed.size !== totalIn || outUsed.size !== bindPairs.length) throw new ParseError('the folder joins its streams inconsistently');
  return { coders, bindPairs, packedStreams };
}

/** The coder that owns a global in- or out-stream index, and the stream's index within that coder. */
export function coderOf(folder: Folder, index: number, side: 'in' | 'out'): { coder: number; local: number } {
  let base = 0;
  for (let c = 0; c < folder.coders.length; c++) {
    const n = side === 'in' ? folder.coders[c].numIn : folder.coders[c].numOut;
    if (index < base + n) return { coder: c, local: index - base };
    base += n;
  }
  throw new ParseError('a stream index is out of range');
}

/** The first global in- or out-stream index of coder `c`. */
export function firstStream(folder: Folder, c: number, side: 'in' | 'out'): number {
  let base = 0;
  for (let i = 0; i < c; i++) base += side === 'in' ? folder.coders[i].numIn : folder.coders[i].numOut;
  return base;
}

/**
 * Throws when following the bind pairs from the main output loops back on itself, or leaves a coder unreached. The
 * walk visits each coder once at most, so a crafted folder cannot make it run long.
 */
function checkAcyclic(folder: Folder): void {
  const visiting = new Set<number>();
  const reached = new Set<number>();
  const visit = (c: number, depth: number) => {
    if (depth > MAX_FOLDER_STREAMS || visiting.has(c) || reached.has(c)) throw new ParseError('the folder binds its coders in a loop');
    visiting.add(c);
    reached.add(c);
    const first = firstStream(folder, c, 'in');
    for (let i = 0; i < folder.coders[c].numIn; i++) {
      const bp = folder.bindPairs.find(p => p.inIndex === first + i);
      if (bp) visit(coderOf(folder, bp.outIndex, 'out').coder, depth + 1);
    }
    visiting.delete(c);
  };
  visit(coderOf(folder, folder.mainOut, 'out').coder, 0);
  if (reached.size !== folder.coders.length) throw new ParseError('a coder of the folder feeds nothing the folder outputs');
}

/**
 * Reads a streams info. `maxEntries` caps the substreams, each of which is a file, before anything is allocated for
 * them; `tooMany` reports a count over it.
 */
export function readStreamsInfo(r: HeaderReader, maxEntries = MAX_SAFE, tooMany?: (n: number) => never): StreamsInfo {
  const info: StreamsInfo = { packPos: 0, packSizes: [], folders: [], numUnpackStreams: [], subSizes: [], subCrcs: [] };
  let id = r.id();
  if (id === Nid.PackInfo) {
    info.packPos = r.number();
    const numPack = r.count(1);
    for (;;) {
      id = r.id();
      if (id === Nid.End) break;
      if (id === Nid.Size) for (let i = 0; i < numPack; i++) info.packSizes.push(r.number());
      else if (id === Nid.Crc) r.digests(numPack);
      else throw new ParseError(`unexpected property ${id} in the pack info`);
    }
    if (info.packSizes.length !== numPack) throw new ParseError('the pack info has no sizes');
    id = r.id();
  }
  if (id === Nid.UnpackInfo) {
    if (r.id() !== Nid.Folder) throw new ParseError('the unpack info does not start with its folders');
    const numFolders = r.count(3);
    if (r.byte() !== 0) throw new UnsupportedError('folders stored outside the header', false, { reason: 'folders stored outside the header' });
    const raw: Array<ReturnType<typeof readFolder>> = [];
    for (let i = 0; i < numFolders; i++) raw.push(readFolder(r));
    if (r.id() !== Nid.CodersUnpackSize) throw new ParseError('the unpack info has no sizes');
    for (const f of raw) {
      const totalOut = f.coders.reduce((s, c) => s + c.numOut, 0);
      const unpackSizes: number[] = [];
      for (let i = 0; i < totalOut; i++) unpackSizes.push(r.number());
      let mainOut = -1;
      for (let i = 0; i < totalOut; i++) if (!f.bindPairs.some(bp => bp.outIndex === i)) mainOut = i;
      const folder: Folder = { ...f, unpackSizes, mainOut };
      checkAcyclic(folder);
      info.folders.push(folder);
    }
    for (;;) {
      id = r.id();
      if (id === Nid.End) break;
      if (id === Nid.Crc) {
        const crcs = r.digests(numFolders);
        crcs.forEach((c, i) => {
          if (c !== undefined) info.folders[i].crc = c;
        });
      } else throw new ParseError(`unexpected property ${id} in the unpack info`);
    }
    id = r.id();
  }
  // Without substream info, each folder holds one file.
  info.numUnpackStreams = info.folders.map(() => 1);
  if (id === Nid.SubStreamsInfo) {
    id = r.id();
    if (id === Nid.NumUnpackStream) {
      info.numUnpackStreams = info.folders.map(() => r.number());
      id = r.id();
    }
    const total = info.numUnpackStreams.reduce((s, n) => s + n, 0);
    if (total > maxEntries) tooMany?.(total);
    if (total > maxEntries || total > r.remaining * 8 + info.folders.length) throw new ParseError('the substream count is larger than the header');
    const sizes: number[] = [];
    const hasSizes = id === Nid.Size;
    for (let f = 0; f < info.folders.length; f++) {
      const n = info.numUnpackStreams[f];
      if (n === 0) continue;
      const folder = info.folders[f];
      const folderSize = folder.unpackSizes[folder.mainOut];
      let sum = 0;
      for (let i = 0; i < n - 1; i++) {
        const s = hasSizes ? r.number() : 0;
        sizes.push(s);
        sum += s;
      }
      if (sum > folderSize) throw new ParseError('substream sizes add up to more than their folder');
      sizes.push(folderSize - sum);
    }
    if (hasSizes) id = r.id();
    info.subSizes = sizes;
    // A folder with one substream and a CRC of its own already gives that substream's CRC. The digests list the rest.
    const crcs: Array<number | undefined> = [];
    const open: number[] = [];
    for (let f = 0; f < info.folders.length; f++) {
      const n = info.numUnpackStreams[f];
      if (n === 1 && info.folders[f].crc !== undefined) crcs.push(info.folders[f].crc);
      else
        for (let i = 0; i < n; i++) {
          open.push(crcs.length);
          crcs.push(undefined);
        }
    }
    while (id !== Nid.End) {
      if (id !== Nid.Crc) throw new ParseError(`unexpected property ${id} in the substream info`);
      const read = r.digests(open.length);
      open.forEach((at, k) => {
        crcs[at] = read[k];
      });
      id = r.id();
    }
    info.subCrcs = crcs;
    id = r.id();
  } else {
    info.subSizes = info.folders.map(f => f.unpackSizes[f.mainOut]);
    info.subCrcs = info.folders.map(f => f.crc);
  }
  if (id !== Nid.End) throw new ParseError(`unexpected property ${id} in the streams info`);
  return info;
}

/** Names of the properties this package drops, for the finding that reports them. */
const PROPERTY_NAMES: Record<number, string> = {
  [Nid.Comment]: 'comment',
  [Nid.StartPos]: 'start positions',
  [Nid.ArchiveProperties]: 'archive properties',
};

function readFiles(r: HeaderReader, header: Header, maxEntries: number, tooMany: (n: number) => never): void {
  const numFiles = r.number();
  if (numFiles > maxEntries) tooMany(numFiles);
  if (numFiles > r.remaining * 8 + 1) throw new ParseError('the file count is larger than the header');
  const files: FileInfo[] = [];
  for (let i = 0; i < numFiles; i++) files.push({ hasStream: true, emptyFile: false, anti: false });
  let emptyStreams: number[] = [];
  const seenTypes = new Set<number>();
  for (;;) {
    const type = r.id();
    if (type === Nid.End) break;
    // A property given twice would leave the entries described two ways, so the header is refused.
    if (type !== Nid.Dummy && seenTypes.has(type)) throw new ParseError(`file property ${type} appears twice`);
    seenTypes.add(type);
    const size = r.number();
    if (size > r.remaining) throw new ParseError('a file property is larger than the header');
    const sub = new HeaderReader(r.bytes(size));
    switch (type) {
      case Nid.EmptyStream: {
        const bits = sub.bits(numFiles);
        emptyStreams = [];
        bits.forEach((b, i) => {
          files[i].hasStream = !b;
          if (b) emptyStreams.push(i);
        });
        break;
      }
      case Nid.EmptyFile:
        sub.bits(emptyStreams.length).forEach((b, k) => {
          files[emptyStreams[k]].emptyFile = b;
        });
        break;
      case Nid.Anti:
        sub.bits(emptyStreams.length).forEach((b, k) => {
          files[emptyStreams[k]].anti = b;
        });
        break;
      case Nid.Name: {
        if (sub.byte() !== 0) throw new UnsupportedError('names stored outside the header', false, { reason: 'names stored outside the header' });
        const body = sub.bytes(sub.remaining);
        let at = 0;
        for (const f of files) {
          let end = at;
          while (end + 1 < body.length && (body[end] | body[end + 1]) !== 0) end += 2;
          if (end + 1 >= body.length) throw new ParseError('a file name is not terminated');
          const units = new Uint16Array(body.buffer.slice(body.byteOffset + at, body.byteOffset + end));
          // As stored, lone surrogates included, so the name rules see what an extractor would.
          let name = '';
          for (let k = 0; k < units.length; k += 4096) name += String.fromCharCode(...units.subarray(k, k + 4096));
          f.name = name;
          at = end + 2;
        }
        // The names fill their property exactly, so a NUL inside one cannot shift the rest.
        if (at !== body.length) throw new ParseError('the names do not fill their property');
        break;
      }
      case Nid.CTime:
      case Nid.ATime:
      case Nid.MTime: {
        const defined = sub.defined(numFiles);
        if (sub.byte() !== 0) throw new UnsupportedError('times stored outside the header', false, { reason: 'times stored outside the header' });
        defined.forEach((d, i) => {
          if (!d) return;
          const t = sub.bytes(8).slice();
          if (type === Nid.CTime) files[i].ctime = t;
          else if (type === Nid.ATime) files[i].atime = t;
          else files[i].mtime = t;
        });
        break;
      }
      case Nid.WinAttributes: {
        const defined = sub.defined(numFiles);
        if (sub.byte() !== 0) throw new UnsupportedError('attributes stored outside the header', false, { reason: 'attributes stored outside the header' });
        defined.forEach((d, i) => {
          if (d) files[i].attrib = sub.uint32();
        });
        break;
      }
      case Nid.Dummy:
        // Padding 7-Zip writes to align what follows.
        break;
      default:
        header.unknown.push(PROPERTY_NAMES[type] ?? `property ${type}`);
    }
  }
  header.files = files;
}

/**
 * Reads a plain header, starting after its kHeader byte. `maxEntries` stops a file count over the limit before
 * anything is allocated for it.
 */
export function parseHeader(buf: Uint8Array, maxEntries: number, tooMany: (n: number) => never): Header {
  const r = new HeaderReader(buf);
  if (r.id() !== Nid.Header) throw new ParseError('the header does not start with kHeader');
  const header: Header = { files: [], unknown: [] };
  let id = r.id();
  if (id === Nid.ArchiveProperties) {
    for (;;) {
      const type = r.id();
      if (type === Nid.End) break;
      r.bytes(r.number());
    }
    header.unknown.push(PROPERTY_NAMES[Nid.ArchiveProperties]);
    id = r.id();
  }
  if (id === Nid.AdditionalStreamsInfo) throw new UnsupportedError('additional streams', false, { reason: 'additional streams' });
  if (id === Nid.MainStreamsInfo) {
    header.streams = readStreamsInfo(r, maxEntries, tooMany);
    id = r.id();
  }
  if (id === Nid.FilesInfo) {
    readFiles(r, header, maxEntries, tooMany);
    id = r.id();
  }
  if (id !== Nid.End) throw new ParseError(`unexpected property ${id} in the header`);
  return header;
}

/** Reads an encoded header's streams info, starting after its kEncodedHeader byte. */
export function parseEncodedHeader(buf: Uint8Array): StreamsInfo {
  const r = new HeaderReader(buf);
  if (r.id() !== Nid.EncodedHeader) throw new ParseError('the header is not encoded');
  return readStreamsInfo(r);
}
