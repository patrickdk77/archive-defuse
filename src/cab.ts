// Microsoft cabinets with stored and MSZIP folders. MSZIP is deflate in blocks of up to 32 KiB, each a whole deflate
// stream that may refer back into the block before it, which Node's zlib takes as a preset dictionary. LZX and Quantum
// folders cannot be decoded here, and a cabinet that continues into another file cannot be read whole.
import * as zlib from 'node:zlib';
import { checkTime, DataError, StopError } from './errors';
import { Reader, SpillSink } from './io';
import { type Archive, contentOf, type Entry, type Kept, type Meter, type Method, type Note, type WriteContext, type WritePlan } from './model';
import { cp437, isAscii, utf8OrUndefined } from './names';
import { sniffType } from './sniff';
import { type ByteSink, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';

const BLOCK = 32768;
const NAME_IS_UTF = 0x80;

/** The cabinet checksum: the data's 32-bit little-endian words XORed together, with an odd tail taken high byte first. */
export function cabChecksum(b: Uint8Array, seed = 0): number {
  let csum = seed >>> 0;
  const words = Math.floor(b.length / 4);
  for (let i = 0; i < words; i++) csum = (csum ^ (b[i * 4] | (b[i * 4 + 1] << 8) | (b[i * 4 + 2] << 16) | (b[i * 4 + 3] << 24))) >>> 0;
  let ul = 0;
  const p = words * 4;
  const rest = b.length % 4;
  if (rest === 3) ul = (b[p] << 16) | (b[p + 1] << 8) | b[p + 2];
  else if (rest === 2) ul = (b[p] << 8) | b[p + 1];
  else if (rest === 1) ul = b[p];
  return (csum ^ ul) >>> 0;
}

interface DataBlock {
  /** Offset of the block header. */
  at: number;
  checksum: number;
  compressed: number;
  uncompressed: number;
  /** Offset of the block's data, after its reserved area. */
  dataAt: number;
}

interface Folder {
  index: number;
  start: number;
  blocks: DataBlock[];
  /** The low four bits: 0 stored, 1 MSZIP, 2 Quantum, 3 LZX. */
  type: number;
  typeCompress: number;
  uncompressed: number;
  /** Bytes the folder's blocks take, headers included. */
  bytes: number;
}

export interface CabEntry extends Entry {
  folder: number;
  offset: number;
  date: number;
  time: number;
  attribs: number;
}

/** Where the decoder of one folder stands, so files read in order do not decode the folder again from its start. */
interface Cursor {
  folder: number;
  block: number;
  /** Uncompressed offset of the start of `data`. */
  base: number;
  data: Buffer;
  /** The previous block's output, MSZIP's dictionary for the next. */
  window: Buffer;
  /** Compressed bytes decoded so far. */
  consumed: number;
}

const methodOf = (type: number): Method => {
  if (type === 0) return { name: 'stored', readable: true, unusual: false };
  if (type === 1) return { name: 'MSZIP', readable: true, unusual: false };
  return { name: type === 2 ? 'Quantum' : type === 3 ? 'LZX' : `cabinet method ${type}`, readable: false, unusual: true };
};

export class CabArchive implements Archive<CabEntry> {
  readonly format = 'cab';
  readonly single = false;
  readonly lateNotes: Note[] = [];
  private cursor?: Cursor;

  private constructor(
    readonly reader: Reader,
    readonly entries: CabEntry[],
    readonly notes: Note[],
    readonly folders: Folder[],
    readonly setId: number,
    readonly cabinetIndex: number,
    /** The end of the cabinet, as its header gives it. */
    readonly end: number,
    /** Bytes of reserved area each data block carries. */
    readonly blockReserve: number,
  ) {}

  static async open(source: ByteSource, limits: { entries: number; decompressedBytes: number; totalDecompressedBytes: number }, deadline?: number): Promise<CabArchive> {
    const size = await source.size();
    const reader = new Reader(source, size);
    const notes: Note[] = [];
    const h = Buffer.from(await reader.read(0, 36));
    if (h.length < 36 || h.toString('latin1', 0, 4) !== 'MSCF') throw new StopError(C.Corrupted, D.Unparseable, 'Not a cabinet', { reason: 'no cabinet header' });
    const cbCabinet = h.readUInt32LE(8);
    const coffFiles = h.readUInt32LE(16);
    const cFolders = h.readUInt16LE(26);
    const cFiles = h.readUInt16LE(28);
    const flags = h.readUInt16LE(30);
    if (h[25] !== 1) throw new StopError(C.Corrupted, D.Unparseable, 'A cabinet version this package does not read', { reason: `cabinet version ${h[25]}.${h[24]}` });
    if (flags & 0x0003) throw new StopError(C.Structure, D.MultiVolume, 'The cabinet continues in another file');
    // Readers go by the tables, so a cabinet size past the end of the file only matters if a block runs past it.
    if (cbCabinet > size) notes.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'the cabinet header gives a size past the end of the file' } });
    const end = Math.min(cbCabinet, size);
    if (cFiles > limits.entries) throw new StopError(C.Limit, D.EntryCount, `${cFiles} files`, { entries: cFiles, limit: limits.entries });
    let p = 36;
    let headerReserve = 0;
    let folderReserve = 0;
    let blockReserve = 0;
    if (flags & 0x0004) {
      const r = Buffer.from(await reader.read(36, 4));
      headerReserve = r.readUInt16LE(0);
      folderReserve = r[2];
      blockReserve = r[3];
      p = 40 + headerReserve;
      if (headerReserve || folderReserve || blockReserve) notes.push({ category: C.Structure, detail: D.ExtraField, data: { field: 'reserved areas in the cabinet' } });
    }
    // Spans the cabinet's parts take, to find bytes no part covers.
    const spans: Array<[number, number]> = [[0, p]];
    const folders: Folder[] = [];
    for (let i = 0; i < cFolders; i++) {
      const f = Buffer.from(await reader.read(p, 8));
      if (f.length < 8) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside the folder table', { what: 'folder table' });
      folders.push({ index: i, start: f.readUInt32LE(0), blocks: [], typeCompress: f.readUInt16LE(6), type: f.readUInt16LE(6) & 0x0f, uncompressed: 0, bytes: 0 });
      spans.push([p, p + 8 + folderReserve]);
      p += 8 + folderReserve;
      const count = f.readUInt16LE(4);
      let at = folders[i].start;
      for (let b = 0; b < count; b++) {
        if (b % 256 === 0) checkTime(deadline);
        const d = Buffer.from(await reader.read(at, 8));
        if (d.length < 8) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a data block', { what: 'data block' });
        const block: DataBlock = { at, checksum: d.readUInt32LE(0), compressed: d.readUInt16LE(4), uncompressed: d.readUInt16LE(6), dataAt: at + 8 + blockReserve };
        if (block.dataAt + block.compressed > end) throw new StopError(C.Corrupted, D.Truncated, 'A data block runs past the cabinet', { what: 'data block' });
        if (block.uncompressed > BLOCK) throw new StopError(C.Corrupted, D.Unparseable, 'A data block is larger than 32 KiB', { reason: 'a data block larger than 32 KiB' });
        folders[i].blocks.push(block);
        folders[i].uncompressed += block.uncompressed;
        spans.push([at, block.dataAt + block.compressed]);
        at = block.dataAt + block.compressed;
      }
      folders[i].bytes = at - folders[i].start;
    }
    const entries: CabEntry[] = [];
    p = coffFiles;
    let total = 0;
    for (let i = 0; i < cFiles; i++) {
      if (i % 256 === 0) checkTime(deadline);
      const f = Buffer.from(await reader.read(p, 16 + 256));
      if (f.length < 17) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside the file table', { what: 'file table' });
      const nul = f.indexOf(0, 16);
      if (nul < 0) throw new StopError(C.Corrupted, D.Unparseable, 'A file name without an end', { reason: 'a file name longer than 256 bytes' });
      const raw = f.subarray(16, nul);
      const attribs = f.readUInt16LE(14);
      const entryNotes: Note[] = [];
      let name: string;
      if (attribs & NAME_IS_UTF) {
        const u = utf8OrUndefined(raw);
        name = u ?? raw.toString('utf8');
        if (u === undefined) entryNotes.push({ category: C.Name, detail: D.Encoding, data: { name } });
      } else if (isAscii(raw)) name = raw.toString('latin1');
      else {
        name = utf8OrUndefined(raw) ?? cp437(raw);
        entryNotes.push({ category: C.Name, detail: D.Encoding, data: { name } });
      }
      // A cabinet separates folders with backslashes, and Windows takes a slash the same way.
      name = name.replace(/\\/g, '/');
      const folderIndex = f.readUInt16LE(8);
      if (folderIndex >= 0xfffd) throw new StopError(C.Structure, D.MultiVolume, 'A file continues in another cabinet');
      const e: CabEntry = {
        index: i,
        name,
        kind: 'file',
        size: f.readUInt32LE(0),
        compressedSize: 0,
        notes: entryNotes,
        folder: folderIndex,
        offset: f.readUInt32LE(4),
        date: f.readUInt16LE(10),
        time: f.readUInt16LE(12),
        attribs,
      };
      const folder = folders[folderIndex];
      if (!folder) e.broken = 'it names a folder the cabinet does not have';
      else {
        e.method = methodOf(folder.type);
        if (e.offset + e.size > folder.uncompressed) e.broken = 'it runs past the end of its folder';
        else e.compressedSize = Math.round((folder.bytes * e.size) / Math.max(1, folder.uncompressed));
      }
      if (e.size > limits.decompressedBytes) throw new StopError(C.Limit, D.DecompressedSize, `${name} declares ${e.size} bytes`, { size: e.size, limit: limits.decompressedBytes }, name);
      total += e.size;
      if (total > limits.totalDecompressedBytes) throw new StopError(C.Limit, D.TotalDecompressedSize, 'The files declare too many bytes', { limit: limits.totalDecompressedBytes });
      entries.push(e);
      spans.push([p, p + 16 + raw.length + 1]);
      p += 16 + raw.length + 1;
    }
    // Bytes of the cabinet no header, table or block covers, and parts of folders no file covers.
    spans.sort((a, b) => a[0] - b[0]);
    let covered = 0;
    let hidden = 0;
    let overlap = false;
    for (const [s, e] of spans) {
      if (s > covered) hidden += s - covered;
      else if (s < covered) overlap = true;
      covered = Math.max(covered, e);
    }
    if (covered < end) hidden += end - covered;
    for (const folder of folders) {
      const ranges = entries.filter(e => e.folder === folder.index && !e.broken).map(e => [e.offset, e.offset + e.size] as [number, number]);
      ranges.sort((a, b) => a[0] - b[0]);
      let at = 0;
      for (const [s, e] of ranges) {
        if (s > at) hidden += s - at;
        else if (s < at && e > s) overlap = true;
        at = Math.max(at, e);
      }
      if (folder.type <= 1 && at < folder.uncompressed) hidden += folder.uncompressed - at;
    }
    if (hidden > 0) notes.push({ category: C.Structure, detail: D.HiddenData, data: { bytes: hidden } });
    if (overlap) notes.push({ category: C.Structure, detail: D.Overlap });
    if (cbCabinet < size) {
      notes.push({ category: C.Structure, detail: D.TrailingBytes, data: { bytes: size - cbCabinet } });
      const type = sniffType(await reader.read(cbCabinet, Math.min(1024, size - cbCabinet)));
      if (type !== undefined) notes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'after the cabinet' } });
    }
    return new CabArchive(reader, entries, notes, folders, h.readUInt16LE(32), h.readUInt16LE(34), end, blockReserve);
  }

  async unlock(): Promise<boolean> {
    return false;
  }

  hasMetadata(): boolean {
    return this.entries.some(e => e.date !== 0x21 || e.time !== 0);
  }

  /** Decodes the next block of the cursor's folder. */
  private async decodeBlock(c: Cursor): Promise<void> {
    const folder = this.folders[c.folder];
    const block = folder.blocks[c.block];
    if (!block) throw new DataError('the folder ends before the file does', true);
    const data = Buffer.from(await this.reader.read(block.dataAt, block.compressed));
    if (block.checksum !== 0) {
      const head = Buffer.alloc(4);
      head.writeUInt16LE(block.compressed, 0);
      head.writeUInt16LE(block.uncompressed, 2);
      if (cabChecksum(head, cabChecksum(data)) !== block.checksum) throw new DataError('a data block does not match its checksum');
    }
    let out: Buffer;
    if (folder.type === 0) {
      if (block.compressed !== block.uncompressed) throw new DataError('a stored block has two different sizes');
      out = data;
    } else {
      if (data[0] !== 0x43 || data[1] !== 0x4b) throw new DataError('an MSZIP block without its signature');
      try {
        const r = zlib.inflateRawSync(data.subarray(2), { dictionary: c.window.length ? c.window : undefined, maxOutputLength: BLOCK, info: true }) as unknown as {
          buffer: Buffer;
          engine: { bytesWritten: number };
        };
        out = r.buffer;
        if (r.engine.bytesWritten !== data.length - 2) throw new DataError('an MSZIP block holds data after its deflate stream');
      } catch (err) {
        if (err instanceof DataError) throw err;
        throw new DataError(`an MSZIP block does not decode: ${(err as Error).message}`);
      }
    }
    if (out.length !== block.uncompressed) throw new DataError('a data block decodes to another size than it gives');
    c.window = out.length >= BLOCK ? out : Buffer.concat([c.window, out]).subarray(-BLOCK);
    c.base += c.data.length;
    c.data = out;
    c.block++;
    c.consumed += block.compressed;
  }

  async *read(e: CabEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    if (e.broken) throw new DataError(e.broken);
    const folder = this.folders[e.folder];
    if (folder.type > 1) throw new DataError(`folder method ${folder.type}`);
    let c = this.cursor;
    if (!c || c.folder !== e.folder || c.base > e.offset) {
      c = { folder: e.folder, block: 0, base: 0, data: Buffer.alloc(0), window: Buffer.alloc(0), consumed: 0 };
      this.cursor = c;
    }
    const startConsumed = c.consumed;
    let at = e.offset;
    const end = e.offset + e.size;
    let total = 0;
    while (at < end) {
      while (at >= c.base + c.data.length) {
        meter.time();
        await this.decodeBlock(c);
      }
      const piece = c.data.subarray(at - c.base, Math.min(c.data.length, end - c.base));
      at += piece.length;
      total += piece.length;
      meter.add(total, Math.max(1, c.consumed - startConsumed));
      yield piece;
    }
  }

  write(plan: WritePlan<CabEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    return writeCab(this, plan, sink, context);
  }

  trailing(): AsyncGenerator<Uint8Array> {
    return this.reader.chunks(this.end, this.reader.size - this.end);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// The writer.

interface OutFolder {
  typeCompress: number;
  blocks: number;
  /** The folder's data blocks, headers included, as they go into the cabinet. */
  data: SpillSink | { copy: Folder };
  bytes: number;
  files: Array<{ k: Kept<CabEntry>; offset: number; size: number }>;
}

/** True when a folder's blocks can be copied: every file in it is kept with its own bytes, and nothing else is in it. */
function copyable(cab: CabArchive, folder: Folder, kept: Kept<CabEntry>[], plan: WritePlan<CabEntry>): boolean {
  if (cab.blockReserve !== 0) return false;
  const all = cab.entries.filter(e => e.folder === folder.index);
  const mine = kept.filter(k => k.entry.folder === folder.index);
  if (mine.length !== all.length || mine.some(k => k.replacement || k.recompress)) return false;
  // Bytes of the folder that no file covers go with the HIDDEN_DATA finding unless it is info.
  const ranges = all.map(e => [e.offset, e.offset + e.size]).sort((a, b) => a[0] - b[0]);
  let at = 0;
  for (const [s, e] of ranges) {
    if (s !== at) return plan.keepExtraFields && false;
    at = e;
  }
  return at === folder.uncompressed;
}

async function writeCab(cab: CabArchive, plan: WritePlan<CabEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
  const out: OutFolder[] = [];
  const spills: SpillSink[] = [];
  try {
    const byFolder = new Map<number, Kept<CabEntry>[]>();
    for (const k of plan.kept) byFolder.set(k.entry.folder, [...(byFolder.get(k.entry.folder) ?? []), k]);
    for (const [index, kept] of byFolder) {
      const folder = cab.folders[index];
      if (copyable(cab, folder, kept, plan)) {
        out.push({
          typeCompress: folder.typeCompress,
          blocks: folder.blocks.length,
          data: { copy: folder },
          bytes: folder.bytes,
          files: kept.map(k => ({ k, offset: k.entry.offset, size: k.entry.size })),
        });
        continue;
      }
      // The folder is built again from the content of the files it keeps, in blocks of 32 KiB.
      const spill = new SpillSink(context.temp, context.threshold);
      spills.push(spill);
      const files: OutFolder['files'] = [];
      let offset = 0;
      let pending = Buffer.alloc(0);
      let blocks = 0;
      const mszip = folder.type === 1;
      const flush = async (b: Buffer) => {
        const data = mszip ? Buffer.concat([Buffer.from('CK'), zlib.deflateRawSync(b)]) : b;
        const head = Buffer.alloc(8);
        head.writeUInt16LE(data.length, 4);
        head.writeUInt16LE(b.length, 6);
        head.writeUInt32LE(cabChecksum(head.subarray(4, 8), cabChecksum(data)), 0);
        await spill.write(head);
        await spill.write(data);
        blocks++;
      };
      for (const k of kept) {
        let size = 0;
        for await (const c of contentOf(cab, k, context)) {
          context.meter().time();
          size += c.length;
          pending = Buffer.concat([pending, c]);
          while (pending.length >= BLOCK) {
            await flush(pending.subarray(0, BLOCK));
            pending = pending.subarray(BLOCK);
          }
        }
        files.push({ k, offset, size });
        offset += size;
      }
      if (pending.length) await flush(pending);
      await spill.close();
      if (blocks > 0xffff) throw new Error('A folder needs more than 65,535 data blocks');
      out.push({ typeCompress: mszip ? 1 : 0, blocks, data: spill, bytes: spill.length, files });
    }
    const names = out.flatMap(f => f.files.map(x => Buffer.from(x.k.name.replace(/\//g, '\\'), 'utf8')));
    const filesBytes = names.reduce((sum, name) => sum + 16 + name.length + 1, 0);
    const coffFiles = 36 + out.length * 8;
    let dataAt = coffFiles + filesBytes;
    const starts = out.map(f => {
      const s = dataAt;
      dataAt += f.bytes;
      return s;
    });
    const header = Buffer.alloc(36);
    header.write('MSCF', 0, 'latin1');
    header.writeUInt32LE(dataAt, 8);
    header.writeUInt32LE(coffFiles, 16);
    header[24] = 3;
    header[25] = 1;
    header.writeUInt16LE(out.length, 26);
    header.writeUInt16LE(names.length, 28);
    header.writeUInt16LE(0, 30);
    header.writeUInt16LE(cab.setId, 32);
    header.writeUInt16LE(cab.cabinetIndex, 34);
    await sink.write(header);
    for (const [i, f] of out.entries()) {
      const b = Buffer.alloc(8);
      b.writeUInt32LE(starts[i], 0);
      b.writeUInt16LE(f.blocks, 4);
      b.writeUInt16LE(f.typeCompress, 6);
      await sink.write(b);
    }
    let n = 0;
    for (const [i, f] of out.entries()) {
      for (const x of f.files) {
        const e = x.k.entry;
        const name = names[n++];
        const b = Buffer.alloc(16);
        b.writeUInt32LE(x.size, 0);
        b.writeUInt32LE(x.offset, 4);
        b.writeUInt16LE(i, 8);
        b.writeUInt16LE(plan.stripMetadata ? 0x21 : e.date, 10);
        b.writeUInt16LE(plan.stripMetadata ? 0 : e.time, 12);
        b.writeUInt16LE((e.attribs & ~NAME_IS_UTF) | (isAscii(name) ? 0 : NAME_IS_UTF), 14);
        await sink.write(Buffer.concat([b, name, Buffer.alloc(1)]));
      }
    }
    for (const f of out) {
      if ('copy' in f.data) {
        for await (const c of cab.reader.chunks(f.data.copy.start, f.data.copy.bytes)) await sink.write(c);
      } else for await (const c of f.data.read()) await sink.write(c);
    }
    if (plan.keepTrailing) for await (const c of cab.trailing()) await sink.write(c);
  } finally {
    for (const s of spills) await s.dispose();
  }
}

export const isCab = (b: Uint8Array) => b.length >= 8 && Buffer.from(b.subarray(0, 8)).toString('latin1') === 'MSCF\0\0\0\0';
