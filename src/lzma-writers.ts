import { CHECK_CRC32, CHECK_CRC64, CHECK_NONE, CHECK_SHA256, checkSize, makeCheck } from './checks';
import { crc32 } from './crc32';
import { LC, LP, LZMA2_DICT_PROP, Lzma2ChunkWriter, PB, PROPS_BYTE, RawLzmaEncoder } from './encoder';
import { SpillSink, type TempDir } from './io';
import { SEVENZIP_MAGIC, XZ_MAGIC } from './lzma-sniff';
import { Nid } from './sevenzip';
import type { ByteSink, ByteSource } from './types';

/** Bytes at the start of a file other readers search for their signatures, such as PDF's header. */
const SIGNATURE_WINDOW = 1024;
/** A stream's ratio counts once it passes this many decoded bytes, as the readers count it. */
const RATIO_FLOOR = 1024 * 1024;

/** True when data compressed this far would pass the ratio limit, so the writer stores it instead. */
export const passesRatio = (size: number, packed: number, ratioLimit: number) => size > RATIO_FLOOR && size > packed * ratioLimit;

async function* chunksOf(source: ByteSource, size: number, step: number, time: () => void): AsyncGenerator<Uint8Array> {
  for (let pos = 0; pos < size; pos += step) {
    time();
    const b = await source.read(pos, Math.min(step, size - pos));
    if (b.length !== Math.min(step, size - pos)) throw Object.assign(new Error('A temporary file returned fewer bytes than it holds'), { code: 'EIO' });
    yield b;
  }
}

/** Content to write: its size, known before it is read, and its bytes, read once. */
export interface Content {
  size: number;
  chunks(): AsyncIterable<Uint8Array>;
}

/** The bytes of `content` in pieces of at most `step`, checked to add up to its size. */
async function* piecesOf(content: Content, step: number, time: () => void): AsyncGenerator<Uint8Array> {
  let n = 0;
  for await (const c of content.chunks()) {
    for (let at = 0; at < c.length; at += step) {
      time();
      const piece = c.subarray(at, Math.min(c.length, at + step));
      n += piece.length;
      if (n > content.size) throw new Error('An entry holds more bytes than its size');
      yield piece;
    }
  }
  if (n !== content.size) throw new Error('An entry holds fewer bytes than its size');
}

const le32 = (v: number) => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0, 0);
  return b;
};
const le64 = (v: number) => {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(v % 2 ** 32, 0);
  b.writeUInt32LE(Math.floor(v / 2 ** 32), 4);
  return b;
};

/** An xz variable-length integer. */
function vli(v: number): Uint8Array {
  const out: number[] = [];
  let n = v;
  while (n >= 0x80) {
    out.push((n % 0x80) | 0x80);
    n = Math.floor(n / 0x80);
  }
  out.push(n);
  return Uint8Array.from(out);
}

/** The check IDs this package writes, the ones it can compute. */
export const WRITABLE_CHECKS = new Set([CHECK_NONE, CHECK_CRC32, CHECK_CRC64, CHECK_SHA256]);

/**
 * Writes `content` as a single-stream xz file with one LZMA2 block, or no block when it is empty. The block's chunks
 * come from Lzma2ChunkWriter. Chunks that would start within the first 1024 bytes of the file stay compressed.
 */
export async function writeXz(content: ByteSource | undefined, checkId: number, sink: ByteSink, time: () => void, store = false): Promise<void> {
  const flags = Uint8Array.of(0, checkId);
  let out = 0;
  const put = async (b: Uint8Array) => {
    out += b.length;
    await sink.write(b);
  };
  await put(Buffer.concat([Uint8Array.from(XZ_MAGIC), flags, le32(crc32(flags))]));
  const size = content ? await content.size() : 0;
  const records: Array<{ unpadded: number; uncompressed: number }> = [];
  if (content && size > 0) {
    // One filter, no sizes: size byte, flags, LZMA2's ID, props size, props, padding, CRC32.
    const blockHeader = Buffer.alloc(12);
    blockHeader.set([2, 0x00, 0x21, 0x01, LZMA2_DICT_PROP]);
    blockHeader.writeUInt32LE(crc32(blockHeader.subarray(0, 8)), 8);
    await put(blockHeader);
    const writer = new Lzma2ChunkWriter();
    const check = makeCheck(checkId);
    let compressed = 0;
    let pos = 0;
    while (pos < size) {
      time();
      const force = out < SIGNATURE_WINDOW;
      const piece = await content.read(pos, Math.min(force ? 1 << 15 : 1 << 16, size - pos));
      if (piece.length === 0) throw Object.assign(new Error('A temporary file returned fewer bytes than it holds'), { code: 'EIO' });
      check?.update(piece);
      const chunk = writer.chunk(piece, force, store);
      compressed += chunk.length;
      await put(chunk);
      pos += piece.length;
    }
    await put(Uint8Array.of(0x00));
    compressed += 1;
    const padding = (4 - ((12 + compressed) % 4)) % 4;
    await put(Buffer.alloc(padding));
    await put(check ? check.digest() : new Uint8Array(0));
    records.push({ unpadded: 12 + compressed + checkSize(checkId), uncompressed: size });
  }
  const indexBody = Buffer.concat([Uint8Array.of(0x00), vli(records.length), ...records.flatMap(r => [vli(r.unpadded), vli(r.uncompressed)])]);
  const index = Buffer.concat([indexBody, Buffer.alloc((4 - (indexBody.length % 4)) % 4)]);
  await put(Buffer.concat([index, le32(crc32(index))]));
  const footerBody = Buffer.concat([le32((index.length + 4) / 4 - 1), flags]);
  await put(Buffer.concat([le32(crc32(footerBody)), footerBody, Uint8Array.of(0x59, 0x5a)]));
}

/** Writes `content` as an .lzma file with its size in the header and no end marker. */
export async function writeAlone(content: ByteSource | undefined, sink: ByteSink, time: () => void): Promise<void> {
  const size = content ? await content.size() : 0;
  const encoder = new RawLzmaEncoder(size);
  const header = Buffer.alloc(13);
  header[0] = PROPS_BYTE;
  header.writeUInt32LE(encoder.dictSize, 1);
  le64(size).copy(header, 5);
  await sink.write(header);
  if (content) for await (const b of chunksOf(content, size, 1 << 16, time)) await sink.write(encoder.write(b));
  await sink.write(encoder.finish());
}

/** One entry of a 7z archive to write. */
export interface SevenOut {
  /** Absent for an entry of an archive that stores no names. */
  name?: string;
  dir: boolean;
  attrib?: number;
  ctime?: Uint8Array;
  atime?: Uint8Array;
  mtime?: Uint8Array;
  /** The content of a file. Empty or absent for an empty file. */
  content?: Content;
}

/** A 7z number. */
function num(v: number): Uint8Array {
  if (v < 0x80) return Uint8Array.of(v);
  const bytes: number[] = [];
  let n = v;
  for (let i = 0; i < 8; i++) {
    bytes.push(n % 256);
    n = Math.floor(n / 256);
  }
  // Fewest extra bytes such that what is left fits in the first byte's free bits.
  for (let extra = 1; extra <= 8; extra++) {
    const high = Math.floor(v / 2 ** (8 * extra));
    if (extra === 8 || high < 2 ** (7 - extra)) {
      const mask = (0xff << (8 - extra)) & 0xff;
      return Uint8Array.from([mask | (extra === 8 ? 0 : high), ...bytes.slice(0, extra)]);
    }
  }
  throw new RangeError('A 7z number too large to write');
}

function bitVector(bits: boolean[]): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  bits.forEach((b, i) => {
    if (b) out[i >> 3] |= 0x80 >> (i & 7);
  });
  return out;
}

/** A property of the files info: its ID, size and body. */
const property = (id: number, body: Uint8Array) => Buffer.concat([Uint8Array.of(id), num(body.length), body]);

/** Times or attributes that may be missing for some entries: the all-defined byte or the vector, then external 0. */
function definedValues(values: Array<Uint8Array | undefined>): Uint8Array | undefined {
  if (!values.some(v => v !== undefined)) return undefined;
  const all = values.every(v => v !== undefined);
  const head = all ? Uint8Array.of(1) : Buffer.concat([Uint8Array.of(0), bitVector(values.map(v => v !== undefined))]);
  return Buffer.concat([head, Uint8Array.of(0), ...values.filter((v): v is Uint8Array => v !== undefined)]);
}

/**
 * Writes a 7z archive: one LZMA folder per file with content, compressed by lzma1's encoder at its preset 1, a plain
 * header with the names, empty files and directories, attributes and the times given, and CRCs of every file.
 */
export async function writeSevenZip(entries: SevenOut[], sink: ByteSink, temp: TempDir, memoryThreshold: number, time: () => void, ratioLimit = Number.POSITIVE_INFINITY): Promise<void> {
  if (entries.length === 0) {
    const start = Buffer.alloc(20);
    await sink.write(Buffer.concat([Uint8Array.from(SEVENZIP_MAGIC), Uint8Array.of(0, 4), le32(crc32(start)), start]));
    return;
  }
  const packed = new SpillSink(temp, memoryThreshold);
  try {
    const folders: Array<{ packSize: number; unpackSize: number; crc: number; dict: number; stored: boolean }> = [];
    try {
      for (const e of entries) {
        const size = e.content ? e.content.size : 0;
        if (e.dir || !e.content || size === 0) continue;
        const encoder = new RawLzmaEncoder(size);
        let crc = 0;
        const one = new SpillSink(temp, memoryThreshold);
        try {
          for await (const b of piecesOf(e.content, 1 << 16, time)) {
            crc = crc32(b, crc);
            await one.write(encoder.write(b));
          }
          await one.write(encoder.finish());
          await one.close();
          // A file LZMA would compress past the ratio limit is stored, so the output reads under the same limit.
          const stored = passesRatio(size, one.length, ratioLimit);
          if (stored) for await (const b of piecesOf(e.content, 1 << 16, time)) await packed.write(b);
          else for await (const b of one.read()) await packed.write(b);
          folders.push({ packSize: stored ? size : one.length, unpackSize: size, crc, dict: encoder.dictSize, stored });
        } finally {
          await one.dispose();
        }
      }
    } finally {
      await packed.close();
    }
    const parts: Uint8Array[] = [Uint8Array.of(Nid.Header)];
    if (folders.length) {
      parts.push(Uint8Array.of(Nid.MainStreamsInfo, Nid.PackInfo), num(0), num(folders.length), Uint8Array.of(Nid.Size));
      for (const f of folders) parts.push(num(f.packSize));
      parts.push(Uint8Array.of(Nid.End, Nid.UnpackInfo, Nid.Folder), num(folders.length), Uint8Array.of(0));
      for (const f of folders) {
        if (f.stored) {
          // One coder: ID size 1 and no properties, Copy.
          parts.push(num(1), Uint8Array.of(0x01, 0x00));
          continue;
        }
        // One coder: ID size 3 with properties, LZMA, five bytes of properties.
        const props = Buffer.concat([Uint8Array.of((PB * 5 + LP) * 9 + LC), le32(f.dict)]);
        parts.push(num(1), Uint8Array.of(0x23, 0x03, 0x01, 0x01), num(props.length), props);
      }
      parts.push(Uint8Array.of(Nid.CodersUnpackSize));
      for (const f of folders) parts.push(num(f.unpackSize));
      parts.push(Uint8Array.of(Nid.End, Nid.SubStreamsInfo, Nid.Crc, 1));
      for (const f of folders) parts.push(le32(f.crc));
      parts.push(Uint8Array.of(Nid.End, Nid.End));
    }
    const sizes = entries.map(e => (e.dir || !e.content ? 0 : e.content.size));
    const empty = entries.map((e, i) => e.dir || sizes[i] === 0);
    const props: Uint8Array[] = [];
    if (empty.some(Boolean)) {
      props.push(property(Nid.EmptyStream, bitVector(empty)));
      const emptyFiles = entries.filter((_, i) => empty[i]).map(e => !e.dir);
      if (emptyFiles.some(Boolean)) props.push(property(Nid.EmptyFile, bitVector(emptyFiles)));
    }
    if (entries.some(e => e.name !== undefined)) {
      const names = Buffer.concat([Uint8Array.of(0), ...entries.map(e => Buffer.from(`${e.name ?? ''}\0`, 'utf16le'))]);
      props.push(property(Nid.Name, names));
    }
    for (const [id, key] of [
      [Nid.CTime, 'ctime'],
      [Nid.ATime, 'atime'],
      [Nid.MTime, 'mtime'],
    ] as const) {
      const body = definedValues(entries.map(e => e[key]));
      if (body) props.push(property(id, body));
    }
    const attribs = definedValues(entries.map(e => (e.attrib === undefined ? undefined : le32(e.attrib))));
    if (attribs) props.push(property(Nid.WinAttributes, attribs));
    parts.push(Uint8Array.of(Nid.FilesInfo), num(entries.length), ...props, Uint8Array.of(Nid.End, Nid.End));
    const header = Buffer.concat(parts);
    const start = Buffer.concat([le64(packed.length), le64(header.length), le32(crc32(header))]);
    await sink.write(Buffer.concat([Uint8Array.from(SEVENZIP_MAGIC), Uint8Array.of(0, 4), le32(crc32(start)), start]));
    for await (const b of packed.read()) await sink.write(b);
    await sink.write(header);
  } finally {
    await packed.dispose();
  }
}
