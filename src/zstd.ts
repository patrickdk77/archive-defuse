// zstd frames. The frame and block headers are read here, so the size of every frame is known without decoding it.
// Decoding is Node's, and a Node without zstd reads none.
import * as zlib from 'node:zlib';
import { through, zstdCompressor } from './codecs';
import { DataError, UnsupportedError } from './errors';

const MAGIC = 0xfd2fb528;
const MAX_BLOCK = 128 * 1024;
/** zstd decoders refuse a larger window unless told to allow it, and so does Node's. */
const MAX_WINDOW = 2 ** 27;

export interface ZstdFrame {
  start: number;
  end: number;
  /** A skippable frame, whose content every decoder ignores. */
  skippable: boolean;
  /** Decompressed size, when the frame header gives it. */
  contentSize?: number;
}

export interface ZstdLayout {
  frames: ZstdFrame[];
  /** Bytes after the last frame that start no frame. */
  trailing: number;
  trailingZeros: boolean;
}

type Read = (offset: number, length: number) => Promise<Uint8Array>;

const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
export const isZstdMagic = (b: Uint8Array) => b.length >= 4 && (u32(b, 0) === MAGIC || (u32(b, 0) & 0xfffffff0) === 0x184d2a50);

/**
 * Walks the frames in [start, end). With `single`, the data must be one frame or more and nothing else, as in a
 * ZIP entry, and anything that is not a frame is an error. Otherwise the walk stops at the first bytes that are not a
 * frame, which count as trailing data.
 */
export async function zstdLayout(read: Read, start: number, end: number, single: boolean, check: () => void): Promise<ZstdLayout> {
  const frames: ZstdFrame[] = [];
  let pos = start;
  while (pos < end) {
    check();
    const head = await read(pos, Math.min(18, end - pos));
    if (head.length < 4 || !isZstdMagic(head)) {
      if (single || frames.length === 0) throw new DataError('Data that is not a zstd frame');
      break;
    }
    if (u32(head, 0) !== MAGIC) {
      if (head.length < 8) throw new DataError('A skippable zstd frame ends early', true);
      const frameEnd = pos + 8 + u32(head, 4);
      if (frameEnd > end) throw new DataError('A skippable zstd frame ends early', true);
      frames.push({ start: pos, end: frameEnd, skippable: true });
      pos = frameEnd;
      continue;
    }
    const fhd = head[4];
    if (fhd === undefined) throw new DataError('A zstd frame header ends early', true);
    if (fhd & 0x08) throw new DataError('A zstd frame header sets its reserved bit');
    const fcsFlag = fhd >> 6;
    const singleSegment = (fhd >> 5) & 1;
    const checksum = (fhd >> 2) & 1;
    const dictFlag = fhd & 3;
    let p = 5;
    let window = 0;
    if (!singleSegment) {
      const wd = head[p++];
      const base = 2 ** (10 + (wd >> 3));
      window = base + (base / 8) * (wd & 7);
    }
    const dictBytes = [0, 1, 2, 4][dictFlag];
    let dictId = 0;
    for (let i = 0; i < dictBytes; i++) dictId += head[p + i] * 2 ** (8 * i);
    p += dictBytes;
    const fcsBytes = [singleSegment ? 1 : 0, 2, 4, 8][fcsFlag];
    if (p + fcsBytes > head.length) throw new DataError('A zstd frame header ends early', true);
    let contentSize: number | undefined;
    if (fcsBytes) {
      contentSize = 0;
      for (let i = 0; i < fcsBytes; i++) contentSize += head[p + i] * 2 ** (8 * i);
      if (fcsBytes === 2) contentSize += 256;
    }
    p += fcsBytes;
    if (singleSegment) window = contentSize ?? 0;
    if (dictId !== 0) throw new UnsupportedError('A zstd frame needs a dictionary');
    if (window > MAX_WINDOW) throw new UnsupportedError(`A zstd frame needs a ${window}-byte window, more than decoders allow by default`);
    const blockMax = Math.min(MAX_BLOCK, Math.max(window, 1));
    let at = pos + p;
    for (;;) {
      check();
      const bh = await read(at, 3);
      if (bh.length < 3) throw new DataError('A zstd frame ends early', true);
      const h = bh[0] | (bh[1] << 8) | (bh[2] << 16);
      const type = (h >> 1) & 3;
      const size = h >> 3;
      if (type === 3) throw new DataError('A zstd block of the reserved type');
      if (type !== 1 && size > blockMax) throw new DataError('A zstd block is larger than its frame allows');
      at += 3 + (type === 1 ? 1 : size);
      if (at > end) throw new DataError('A zstd frame ends early', true);
      if (h & 1) break;
    }
    if (checksum) at += 4;
    if (at > end) throw new DataError('A zstd frame ends early', true);
    frames.push({ start: pos, end: at, skippable: false, contentSize });
    pos = at;
  }
  let trailing = 0;
  let zeros = true;
  for (let at = pos; at < end; at += 65536) {
    const b = await read(at, Math.min(65536, end - at));
    trailing += b.length;
    if (zeros && b.some(x => x !== 0)) zeros = false;
  }
  return { frames, trailing, trailingZeros: zeros };
}

/** Compresses `chunks` as one zstd frame with a content checksum. */
export function zstdEncode(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  const make = zstdCompressor;
  const checksumFlag = (zlib.constants as unknown as Record<string, number | undefined>).ZSTD_c_checksumFlag;
  if (!make || checksumFlag === undefined) throw new UnsupportedError('This Node has no zstd');
  return through(make({ params: { [checksumFlag]: 1 } }), chunks);
}
