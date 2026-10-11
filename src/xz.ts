import { CHECK_CRC32, CHECK_CRC64, CHECK_NONE, CHECK_SHA256, checkName, checkSize, makeCheck } from './checks';
import { Lzma2Feeder, lzma2DictSize } from './coders';
import { crc32 } from './crc32';
import { CheckError, DataError, ParseError, StopError, UnsupportedError } from './errors';
import { type BranchFilter, DeltaStream, SimpleFilterStream, type Transform } from './filters';
import type { Reader } from './io';
import { XZ_MAGIC } from './lzma-sniff';
import { effectiveDictSize } from './lzma1-stream';
import type { Note } from './model';
import type { Limits, StreamCounter as Meter } from './stream-meter';
import { ArchiveCategory as C, ArchiveDetail as D } from './types';

/** What reading an xz file found out, beyond its content. */
export interface XzInfo {
  streams: number;
  /** The check ID of each stream. */
  checks: number[];
  notes: Note[];
  /** Offset of the first byte that is not part of a stream or its padding, when the file goes on past the last stream. */
  trailingAt?: number;
}

const BRANCH_IDS: Record<number, BranchFilter> = { 4: 'x86', 5: 'powerpc', 6: 'ia64', 7: 'arm', 8: 'armthumb', 9: 'sparc', 10: 'arm64', 11: 'riscv' };
const FILTER_LZMA2 = 0x21;
const FILTER_DELTA = 0x03;

/** A variable-length integer of xz: 7 bits per byte, low first, at most 9 bytes and no unneeded zero byte at the end. */
function vli(b: Uint8Array, at: number): { value: number; next: number } {
  let value = 0;
  for (let i = 0; i < 9; i++) {
    if (at + i >= b.length) throw new ParseError('a number runs past its field');
    const byte = b[at + i];
    value += (byte & 0x7f) * 2 ** (7 * i);
    if ((byte & 0x80) === 0) {
      if (byte === 0 && i > 0) throw new ParseError('a number is written with an unneeded zero byte');
      return { value, next: at + i + 1 };
    }
  }
  throw new ParseError('a number is longer than nine bytes');
}

/** Reads bytes one at a time from a reader. */
class ByteStream {
  private buf: Uint8Array = new Uint8Array(0);
  private bufAt = 0;
  constructor(
    private readonly reader: Reader,
    public pos: number,
  ) {}
  async byte(): Promise<number> {
    if (this.pos >= this.bufAt + this.buf.length) {
      this.buf = await this.reader.read(this.pos, 65536);
      this.bufAt = this.pos;
      if (this.buf.length === 0) throw new DataError('the index ends past the end of the file', true);
    }
    const b = this.buf[this.pos - this.bufAt];
    this.pos++;
    return b;
  }
  async vli(): Promise<number> {
    let value = 0;
    for (let i = 0; i < 9; i++) {
      const byte = await this.byte();
      value += (byte & 0x7f) * 2 ** (7 * i);
      if ((byte & 0x80) === 0) {
        if (byte === 0 && i > 0) throw new ParseError('a number is written with an unneeded zero byte');
        return value;
      }
    }
    throw new ParseError('a number is longer than nine bytes');
  }
}

async function exact(reader: Reader, pos: number, n: number, what: string): Promise<Uint8Array> {
  const b = await reader.read(pos, n);
  if (b.length < n) throw new DataError(`the ${what} ends past the end of the file`, true);
  return b;
}

const u32 = (b: Uint8Array, at: number) => (b[at] | (b[at + 1] << 8) | (b[at + 2] << 16) | (b[at + 3] << 24)) >>> 0;
const isMagic = (b: Uint8Array) => b.length >= 6 && XZ_MAGIC.every((x, i) => b[i] === x);

interface BlockHeader {
  size: number;
  compressed?: number;
  uncompressed?: number;
  dict: number;
  /** The filters before LZMA2, in the order the file lists them. */
  filters: Array<{ kind: 'delta'; distance: number } | { kind: BranchFilter; start: number }>;
}

function parseBlockHeader(h: Uint8Array): BlockHeader {
  const size = h.length;
  if (crc32(h.subarray(0, size - 4)) !== u32(h, size - 4)) throw new CheckError('the block header CRC32 does not match', 'block header CRC32');
  const flags = h[1];
  if (flags & 0x3c) throw new UnsupportedError('reserved block flags', false, { reason: 'reserved block header flags' });
  const end = size - 4;
  let q = 2;
  let compressed: number | undefined;
  let uncompressed: number | undefined;
  const field = (what: string) => {
    if (q >= end) throw new ParseError(`the block header ends in its ${what}`);
    const r = vli(h.subarray(0, end), q);
    q = r.next;
    return r.value;
  };
  if (flags & 0x40) {
    compressed = field('compressed size');
    if (compressed === 0) throw new ParseError('a block declares a compressed size of zero');
  }
  if (flags & 0x80) uncompressed = field('uncompressed size');
  const raw: Array<{ id: number; props: Uint8Array }> = [];
  for (let k = 0; k < (flags & 3) + 1; k++) {
    const id = field('filter flags');
    const propsSize = field('filter flags');
    if (q + propsSize > end) throw new ParseError('the block header ends in its filter flags');
    raw.push({ id, props: h.slice(q, q + propsSize) });
    q += propsSize;
  }
  for (let i = q; i < end; i++) {
    if (h[i] !== 0) throw new UnsupportedError('block header padding that is not zero', false, { reason: 'a block header field this package does not know' });
  }
  const last = raw[raw.length - 1];
  const known = (id: number) => id === FILTER_LZMA2 || id === FILTER_DELTA || BRANCH_IDS[id] !== undefined;
  for (const f of raw) {
    if (!known(f.id)) throw new UnsupportedError(`xz filter 0x${f.id.toString(16)}`, true, { method: `filter 0x${f.id.toString(16)}` });
  }
  if (last.id !== FILTER_LZMA2) throw new UnsupportedError('a filter chain that does not end in LZMA2', false, { reason: 'a filter chain that does not end in LZMA2' });
  if (raw.slice(0, -1).some(f => f.id === FILTER_LZMA2)) throw new UnsupportedError('LZMA2 before the last filter', false, { reason: 'LZMA2 before the last filter' });
  const dict = last.props.length === 1 ? lzma2DictSize(last.props[0]) : undefined;
  if (dict === undefined) throw new ParseError('invalid LZMA2 properties');
  const filters: BlockHeader['filters'] = raw.slice(0, -1).map(f => {
    if (f.id === FILTER_DELTA) {
      if (f.props.length !== 1) throw new ParseError('invalid delta filter properties');
      return { kind: 'delta' as const, distance: f.props[0] + 1 };
    }
    if (f.props.length !== 0 && f.props.length !== 4) throw new ParseError('invalid branch filter properties');
    return { kind: BRANCH_IDS[f.id], start: f.props.length === 4 ? u32(f.props, 0) : 0 };
  });
  return { size, compressed, uncompressed, dict, filters };
}

/** What reading an xz file needs from the run. */
export interface XzEnv {
  reader: Reader;
  size: number;
  limits: Limits;
  meter: Meter;
}

/**
 * Decodes an xz file and yields its content: every block of every stream, in order. Stream padding, the index and the
 * footers are checked against what the blocks held. What can be fixed by writing the file again goes to `info.notes`;
 * what cannot throws.
 */
export async function* readXz(env: XzEnv, info: XzInfo): AsyncGenerator<Uint8Array> {
  const { reader, size, meter } = env;
  let pos = 0;
  for (;;) {
    // Stream header. Bytes after a stream that do not start the magic are trailing data, however few; bytes that do
    // start it are a stream cut short.
    const header = await reader.read(pos, 12);
    const magic = header.length >= 6 ? isMagic(header) : header.every((b, i) => b === XZ_MAGIC[i]);
    if (!magic) {
      if (info.streams === 0) throw new ParseError('the file does not start with an xz stream');
      info.trailingAt = pos;
      return;
    }
    if (header.length < 12) throw new DataError('the stream header ends past the end of the file', true);
    const location = info.streams === 0 ? undefined : `stream ${info.streams + 1}`;
    if (crc32(header.subarray(6, 8)) !== u32(header, 8)) throw new CheckError('the stream header CRC32 does not match', 'stream header CRC32');
    if (header[6] !== 0 || (header[7] & 0xf0) !== 0) throw new UnsupportedError('reserved stream flags', false, { reason: 'reserved stream flags' });
    const checkId = header[7] & 0x0f;
    const cSize = checkSize(checkId);
    if (checkId === CHECK_NONE) info.notes.push({ category: C.Structure, detail: D.NoCheck, location });
    else if (checkId !== CHECK_CRC32 && checkId !== CHECK_CRC64 && checkId !== CHECK_SHA256) {
      info.notes.push({ category: C.Structure, detail: D.UnknownCheck, location, data: { check: checkName(checkId) } });
    }
    info.checks.push(checkId);
    info.streams++;
    meter.tick();
    pos += 12;
    // Blocks
    const blocks: Array<{ unpadded: number; uncompressed: number }> = [];
    for (;;) {
      const first = await exact(reader, pos, 1, 'block header');
      if (first[0] === 0x00) break;
      const blockLoc = `${location ? `${location}, ` : ''}block ${blocks.length + 1}`;
      const headerSize = (first[0] + 1) * 4;
      const h = await exact(reader, pos, headerSize, 'block header');
      const bh = parseBlockHeader(h);
      if (bh.uncompressed !== undefined && bh.uncompressed > env.limits.decompressedBytes) {
        throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: env.limits.decompressedBytes, declared: bh.uncompressed }, blockLoc);
      }
      const dictNeed = effectiveDictSize(bh.dict, bh.uncompressed);
      if (dictNeed > env.limits.dictionaryBytes) {
        throw new StopError(C.Limit, D.DictionarySize, 'Dictionary size limit exceeded', { limit: env.limits.dictionaryBytes, dictionary: dictNeed }, blockLoc);
      }
      const dataStart = pos + headerSize;
      const dataEnd = bh.compressed !== undefined ? dataStart + bh.compressed : size;
      if (dataEnd > size) throw new DataError('a block declares more compressed data than the file holds', true);
      // Decoding runs LZMA2 first, then the other filters from the last listed to the first.
      const transforms: Transform[] = bh.filters.map(f => (f.kind === 'delta' ? new DeltaStream(f.distance) : new SimpleFilterStream(f.kind, f.start))).reverse();
      const check = makeCheck(checkId);
      const feeder = new Lzma2Feeder(bh.dict);
      let uncompressed = 0;
      const emit = (chunk: Uint8Array, from: number): Uint8Array => {
        let d = chunk;
        for (let k = from; k < transforms.length && d.length; k++) d = transforms[k].push(d);
        return d;
      };
      let p = dataStart;
      while (!feeder.ended) {
        if (p >= dataEnd)
          throw new DataError(bh.compressed !== undefined ? 'the LZMA2 data does not end within the compressed size its block declares' : 'the LZMA2 data ends past the end of the file', true);
        const chunk = await reader.read(p, Math.min(65536, dataEnd - p));
        let used = 0;
        while (used < chunk.length && !feeder.ended) {
          const n = feeder.push(chunk.subarray(used, used + 4096));
          used += n;
          meter.packed(n);
          for (const out of feeder.take()) {
            const d = emit(out, 0);
            if (!d.length) continue;
            check?.update(d);
            uncompressed += d.length;
            meter.add(d.length);
            yield d;
          }
        }
        p += used;
      }
      for (let k = 0; k < transforms.length; k++) {
        const d = emit(transforms[k].end(), k + 1);
        if (!d.length) continue;
        check?.update(d);
        uncompressed += d.length;
        meter.add(d.length);
        yield d;
      }
      const compressed = p - dataStart;
      if (bh.compressed !== undefined && bh.compressed !== compressed) {
        info.notes.push({ category: C.Structure, detail: D.SizeMismatch, location: blockLoc, data: { reason: 'compressed size of a block', declared: bh.compressed, actual: compressed } });
      }
      if (bh.uncompressed !== undefined && bh.uncompressed !== uncompressed) {
        info.notes.push({ category: C.Structure, detail: D.SizeMismatch, location: blockLoc, data: { reason: 'uncompressed size of a block', declared: bh.uncompressed, actual: uncompressed } });
      }
      const padding = (4 - ((headerSize + compressed) % 4)) % 4;
      const tail = await exact(reader, p, padding + cSize, 'block');
      if (tail.subarray(0, padding).some(b => b !== 0)) info.notes.push({ category: C.Structure, detail: D.BadPadding, location: blockLoc, data: { reason: 'block padding that is not zero' } });
      if (check) {
        const want = check.digest();
        const got = tail.subarray(padding);
        if (want.some((b, i) => b !== got[i])) throw new CheckError(`the ${checkName(checkId)} of a block does not match`, checkName(checkId));
      }
      blocks.push({ unpadded: headerSize + compressed + cSize, uncompressed });
      pos = p + padding + cSize;
    }
    // Index
    const index = new ByteStream(reader, pos);
    await index.byte();
    const count = await index.vli();
    if (count * 2 > size - index.pos) throw new DataError('the index lists more blocks than the file can hold', true);
    let mismatch: string | undefined;
    if (count !== blocks.length) mismatch = 'the number of blocks';
    for (let i = 0; i < count; i++) {
      const unpadded = await index.vli();
      const uncompressed = await index.vli();
      if (unpadded === 0) mismatch ??= 'an unpadded size of zero';
      const b = blocks[i];
      if (b && b.unpadded !== unpadded) mismatch ??= 'the unpadded size of a block';
      if (b && b.uncompressed !== uncompressed) mismatch ??= 'the uncompressed size of a block';
    }
    let padBad = false;
    while ((index.pos - pos) % 4 !== 0) if ((await index.byte()) !== 0) padBad = true;
    let indexCrc = 0;
    for (let at = pos; at < index.pos; at += 65536) indexCrc = crc32(await exact(reader, at, Math.min(65536, index.pos - at), 'index'), indexCrc);
    const stored = await exact(reader, index.pos, 4, 'index');
    if (u32(stored, 0) !== indexCrc) throw new CheckError('the index CRC32 does not match', 'index CRC32');
    if (padBad) info.notes.push({ category: C.Structure, detail: D.BadPadding, location, data: { reason: 'index padding that is not zero' } });
    if (mismatch) info.notes.push({ category: C.Structure, detail: D.IndexMismatch, location, data: { reason: mismatch } });
    const indexSize = index.pos + 4 - pos;
    pos += indexSize;
    // Stream footer
    const footer = await exact(reader, pos, 12, 'stream footer');
    if (footer[10] !== 0x59 || footer[11] !== 0x5a) throw new ParseError('the stream footer has no magic bytes');
    if (crc32(footer.subarray(4, 10)) !== u32(footer, 0)) throw new CheckError('the stream footer CRC32 does not match', 'stream footer CRC32');
    if ((u32(footer, 4) + 1) * 4 !== indexSize) info.notes.push({ category: C.Structure, detail: D.IndexMismatch, location, data: { reason: 'the index size in the stream footer' } });
    if (footer[8] !== header[6] || footer[9] !== header[7]) info.notes.push({ category: C.Structure, detail: D.HeaderMismatch, location });
    pos += 12;
    // Stream padding, then the next stream or the end.
    let zeros = 0;
    for (;;) {
      const b = await reader.read(pos + zeros, 4096);
      let k = 0;
      while (k < b.length && b[k] === 0) k++;
      zeros += k;
      if (k < b.length || b.length === 0) break;
    }
    if (zeros > 0) {
      const next = await reader.read(pos + zeros, 6);
      const atEnd = pos + zeros === size;
      if (atEnd || isMagic(next)) {
        if (zeros % 4 === 0) info.notes.push({ category: C.Structure, detail: D.StreamPadding, data: { bytes: zeros } });
        else info.notes.push({ category: C.Structure, detail: D.BadPadding, data: { reason: 'stream padding that is not a multiple of four bytes', bytes: zeros } });
      } else {
        info.trailingAt = pos;
        return;
      }
    }
    pos += zeros;
    if (pos >= size) return;
  }
}
