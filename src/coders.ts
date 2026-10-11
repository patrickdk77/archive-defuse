import { pipeline, Readable } from 'node:stream';
import * as zlib from 'node:zlib';
import { type AesProps, decryptAes, parseAesProps } from './aes7z';
import { decodeBcj2 } from './bcj2';
import { bunzip2 } from './bzip2';
import { checkTime, DataError, ParseError, UnsupportedError } from './errors';
import { type BranchFilter, DeltaStream, SimpleFilterStream, type Transform } from './filters';
import { inflate64 } from './inflate64';
import { Lzma2Decoder } from './lzma1/lzma2-decoder';
import { concat, decodeProps, effectiveDictSize, Lzma1Stream } from './lzma1-stream';
import { type Coder, coderOf, type Folder, firstStream } from './sevenzip';
import type { ByteSource } from './types';

export type Chunks = AsyncIterable<Uint8Array>;

/** Bytes of LZMA1 input decoded per step. LZMA1 decodes to at most about 7,000 times its input. */
const LZMA1_SLICE = 1024;
/** Bytes of packed data read from the source at a time. */
const READ_SIZE = 1 << 16;

/** LZMA2's dictionary size from its properties byte, or undefined for a byte above 40. */
export function lzma2DictSize(p: number): number | undefined {
  if (p > 40) return undefined;
  return p === 40 ? 0xffffffff : (2 | (p & 1)) * 2 ** (Math.floor(p / 2) + 11);
}

/** Turns an error from lzma1's decoders into a data error. Anything else, such as a limit, passes unchanged. */
export function lzmaError(e: unknown): unknown {
  if (e instanceof DataError) return e;
  const message = String((e as Error)?.message ?? e);
  if (message === 'Truncated input') return new DataError('the data ends before its end', true);
  if (/^Corrupted input: /.test(message)) return new DataError(message.replace(/^Corrupted input: /, ''));
  return e;
}

/**
 * Feeds raw LZMA2 data to lzma1's decoder one chunk at a time. A chunk decodes to at most 2 MiB, so one step never
 * holds more however small the chunks are made. It also tells where the data ends, which an xz block needs.
 */
export class Lzma2Feeder {
  private readonly dec: Lzma2Decoder;
  private readonly out: Uint8Array[] = [];
  private pend: Uint8Array = new Uint8Array(0);
  /** The end marker has been fed. */
  ended = false;
  /** Input bytes used, up to and including the end marker. */
  consumed = 0;

  constructor(dictSize: number) {
    this.dec = new Lzma2Decoder(Math.max(dictSize, 4096), chunk => this.out.push(chunk.slice()));
  }

  /** The size of the chunk that starts with `pend`, once its header is there. */
  private chunkSize(): number | undefined {
    const p = this.pend;
    if (p.length < 1) return undefined;
    const control = p[0];
    if (control === 0x00 || (control > 0x02 && control < 0x80)) return 1;
    if (control < 0x80) return p.length < 3 ? undefined : 3 + ((p[1] << 8) | p[2]) + 1;
    const header = control >= 0xc0 ? 6 : 5;
    return p.length < 5 ? undefined : header + ((p[3] << 8) | p[4]) + 1;
  }

  /** Feeds `chunk` and returns how many of its bytes were used, fewer than all once the end marker is in. */
  push(chunk: Uint8Array): number {
    let used = 0;
    while (used < chunk.length && !this.ended) {
      const size = this.chunkSize();
      const want = size === undefined ? (this.pend.length < 1 ? 1 : this.pend[0] >= 0x80 ? 5 : 3) : size;
      const take = Math.min(want - this.pend.length, chunk.length - used);
      this.pend = concat(this.pend, chunk.slice(used, used + take));
      used += take;
      const whole = this.chunkSize();
      if (whole !== undefined && this.pend.length === whole) {
        const bytes = this.pend;
        this.pend = new Uint8Array(0);
        try {
          this.dec.write(bytes);
        } catch (e) {
          throw lzmaError(e);
        }
        if (bytes[0] === 0x00) this.ended = true;
      }
    }
    this.consumed += used;
    return used;
  }

  /** Decoded bytes waiting to be taken. */
  take(): Uint8Array[] {
    return this.out.splice(0);
  }

  end(): void {
    if (!this.ended) throw new DataError('the LZMA2 data ends before its end marker', true);
  }
}

/** Bytes of a packed stream handed on at a time, so the count of compressed bytes follows what the coders took. */
const PACK_SLICE = 4096;

/** Reads `size` bytes of `source` from `offset`, reporting each piece as it is handed on. */
async function* packStream(source: ByteSource, offset: number, size: number, onRead: (n: number) => void, deadline: number | undefined): AsyncGenerator<Uint8Array> {
  for (let pos = 0; pos < size; ) {
    checkTime(deadline);
    const want = Math.min(READ_SIZE, size - pos);
    const b = await source.read(offset + pos, want);
    if (b.length === 0) throw new DataError('a packed stream ends past the end of the file', true);
    for (let k = 0; k < b.length; k += PACK_SLICE) {
      const piece = b.subarray(k, k + PACK_SLICE);
      onRead(piece.length);
      yield piece;
    }
    pos += b.length;
  }
}

async function* lzma1Decode(input: Chunks, props: Uint8Array, size: number, deadline: number | undefined): AsyncGenerator<Uint8Array> {
  if (props.length < 5) throw new DataError('LZMA properties are cut short');
  const dictSize = props[1] + props[2] * 2 ** 8 + props[3] * 2 ** 16 + props[4] * 2 ** 24;
  const out: Uint8Array[] = [];
  const dec = new Lzma1Stream(decodeProps(props[0], dictSize), size, chunk => out.push(chunk.slice()), false);
  for await (const chunk of input) {
    for (let p = 0; p < chunk.length && !dec.done; p += LZMA1_SLICE) {
      dec.write(chunk.subarray(p, p + LZMA1_SLICE));
      checkTime(deadline);
      for (const c of out.splice(0)) yield c;
    }
    if (dec.done) break;
  }
  dec.end();
  for (const c of out.splice(0)) yield c;
}

async function* lzma2Decode(input: Chunks, props: Uint8Array, deadline: number | undefined): AsyncGenerator<Uint8Array> {
  const dict = props.length === 1 ? lzma2DictSize(props[0]) : undefined;
  if (dict === undefined) throw new DataError('invalid LZMA2 properties');
  const feeder = new Lzma2Feeder(dict);
  for await (const chunk of input) {
    for (let used = 0; used < chunk.length && !feeder.ended; ) {
      used += feeder.push(chunk.subarray(used, used + READ_SIZE));
      checkTime(deadline);
      for (const c of feeder.take()) yield c;
    }
    if (feeder.ended) break;
  }
  feeder.end();
}

async function* transform(input: Chunks, t: Transform): AsyncGenerator<Uint8Array> {
  for await (const chunk of input) {
    // The transform changes its input in place, and the chunk may be a view of bytes someone else holds. A Buffer's
    // slice() is such a view too, so the copy is made explicitly.
    const out = t.push(new Uint8Array(chunk));
    if (out.length) yield out;
  }
  const rest = t.end();
  if (rest.length) yield rest;
}

/** Inflates raw Deflate data through Node's zlib. */
async function* inflate(input: Chunks): AsyncGenerator<Uint8Array> {
  const src = Readable.from(input);
  const z = zlib.createInflateRaw();
  let failure: unknown;
  pipeline(src, z, e => {
    if (e) failure ??= e;
  });
  try {
    for await (const chunk of z) yield chunk as Buffer;
  } catch (e) {
    // zlib's own errors carry a Z_ code. Anything else, such as a limit or bad data before the inflate, passes unchanged.
    const code = (e as { code?: unknown })?.code;
    if (typeof code === 'string' && code.startsWith('Z_')) throw new DataError(`Deflate data does not inflate: ${String((e as Error).message)}`);
    throw e;
  } finally {
    src.destroy();
    z.destroy();
  }
  if (failure !== undefined) throw failure;
}

/** Yields exactly `size` bytes of `input`, and stops reading it there. */
async function* exactly(input: Chunks, size: number): AsyncGenerator<Uint8Array> {
  let n = 0;
  if (size > 0) {
    for await (const chunk of input) {
      const room = size - n;
      if (chunk.length >= room) {
        if (room > 0) yield chunk.subarray(0, room);
        n = size;
        break;
      }
      n += chunk.length;
      yield chunk;
    }
  }
  if (n < size) throw new DataError('a coder decodes to less than its declared size', true);
}

/** What one kind of coder needs. */
interface Method {
  name: string;
  numIn: number;
  branch?: BranchFilter;
}

const METHODS: Record<string, Method> = {
  '00': { name: 'Copy', numIn: 1 },
  '03': { name: 'Delta', numIn: 1 },
  '04': { name: 'BCJ', numIn: 1, branch: 'x86' },
  '03030103': { name: 'BCJ', numIn: 1, branch: 'x86' },
  '05': { name: 'PPC', numIn: 1, branch: 'powerpc' },
  '03030205': { name: 'PPC', numIn: 1, branch: 'powerpc' },
  '06': { name: 'IA64', numIn: 1, branch: 'ia64' },
  '03030401': { name: 'IA64', numIn: 1, branch: 'ia64' },
  '07': { name: 'ARM', numIn: 1, branch: 'arm' },
  '03030501': { name: 'ARM', numIn: 1, branch: 'arm' },
  '08': { name: 'ARMT', numIn: 1, branch: 'armthumb' },
  '03030701': { name: 'ARMT', numIn: 1, branch: 'armthumb' },
  '09': { name: 'SPARC', numIn: 1, branch: 'sparc' },
  '03030805': { name: 'SPARC', numIn: 1, branch: 'sparc' },
  '0a': { name: 'ARM64', numIn: 1, branch: 'arm64' },
  '0b': { name: 'RISCV', numIn: 1, branch: 'riscv' },
  '0303011b': { name: 'BCJ2', numIn: 4 },
  '030101': { name: 'LZMA', numIn: 1 },
  '21': { name: 'LZMA2', numIn: 1 },
  '040108': { name: 'Deflate', numIn: 1 },
  '040109': { name: 'Deflate64', numIn: 1 },
  '040202': { name: 'BZip2', numIn: 1 },
  '06f10701': { name: '7zAES', numIn: 1 },
};

/** Names of methods this package knows but does not decode, for the finding. */
const UNSUPPORTED: Record<string, string> = {
  '030401': 'PPMd',
  '04f71101': 'Zstandard',
  '04f71102': 'Brotli',
  '04f71104': 'LZ4',
  '04f71105': 'LZ5',
  '04f71106': 'Lizard',
  '04f71107': 'Fast LZMA2',
  '03030601': 'M68',
  '03030301': 'Alpha',
  '020302': 'Swap2',
  '020304': 'Swap4',
};

export const methodName = (id: string) => METHODS[id]?.name ?? UNSUPPORTED[id] ?? `method ${id}`;

export const isAes = (c: Coder) => c.method === '06f10701';

/** The limits checked before a folder is decoded. */
export interface FolderLimits {
  decompressedBytes: number;
  dictionaryBytes: number;
}

/**
 * Checks that every coder of `folder` is one this package decodes, with valid properties, and that no coder's output
 * and no dictionary goes over the limits. Returns the dictionary or size that went over, for the caller's finding.
 */
export function checkFolder(folder: Folder, limits: FolderLimits): { limit: 'decompressed' | 'dictionary'; value: number } | undefined {
  // The coders of a folder decode together, so their dictionaries and probability tables count together.
  let memory = 0;
  for (let c = 0; c < folder.coders.length; c++) {
    const coder = folder.coders[c];
    const m = METHODS[coder.method];
    if (!m) throw new UnsupportedError(`7z method ${methodName(coder.method)}`, true, { method: methodName(coder.method) });
    if (coder.numIn !== m.numIn || coder.numOut !== 1) throw new ParseError(`the ${m.name} coder has the wrong number of streams`);
    const size = folder.unpackSizes[firstStream(folder, c, 'out')];
    if (size > limits.decompressedBytes) return { limit: 'decompressed', value: size };
    if (coder.method === '030101') {
      if (coder.props.length < 5) throw new ParseError('LZMA properties are cut short');
      const p = decodeProps(coder.props[0], 0);
      const dict = coder.props[1] + coder.props[2] * 2 ** 8 + coder.props[3] * 2 ** 16 + coder.props[4] * 2 ** 24;
      memory += effectiveDictSize(dict, size) + 2 * 0x300 * 2 ** (p.lc + p.lp);
      if (memory > limits.dictionaryBytes) return { limit: 'dictionary', value: memory };
    } else if (coder.method === '21') {
      const dict = coder.props.length === 1 ? lzma2DictSize(coder.props[0]) : undefined;
      if (dict === undefined) throw new ParseError('invalid LZMA2 properties');
      memory += effectiveDictSize(dict, size);
      if (memory > limits.dictionaryBytes) return { limit: 'dictionary', value: memory };
    } else if (coder.method === '03') {
      if (coder.props.length !== 1) throw new ParseError('invalid Delta properties');
    } else if (m.branch && coder.props.length !== 0 && coder.props.length !== 4) {
      throw new ParseError(`invalid ${m.name} properties`);
    } else if (isAes(coder)) parseAesProps(coder.props);
  }
  return undefined;
}

/** What decoding a folder needs from the run. */
export interface FolderEnv {
  source: ByteSource;
  deadline?: number;
  /** Called with each count of packed bytes read. */
  onPacked(n: number): void;
  /** The key for a 7zAES coder, from the password being tried. */
  key(props: AesProps): Buffer;
}

function runCoder(coder: Coder, inputs: Chunks[], size: number, env: FolderEnv): Chunks {
  const m = METHODS[coder.method];
  const start = coder.props.length === 4 ? (coder.props[0] | (coder.props[1] << 8) | (coder.props[2] << 16) | (coder.props[3] << 24)) >>> 0 : 0;
  if (m.branch) return transform(inputs[0], new SimpleFilterStream(m.branch, start));
  switch (coder.method) {
    case '00':
      return inputs[0];
    case '03':
      return transform(inputs[0], new DeltaStream(coder.props[0] + 1));
    case '0303011b':
      return decodeBcj2(inputs[0], inputs[1], inputs[2], inputs[3], size);
    case '030101':
      return lzma1Decode(inputs[0], coder.props, size, env.deadline);
    case '21':
      return lzma2Decode(inputs[0], coder.props, env.deadline);
    case '040108':
      return inflate(inputs[0]);
    case '040109':
      return inflate64(inputs[0], undefined, env.deadline);
    case '040202':
      // Streams after the first decode too instead of failing the folder. The folder's declared size bounds the output.
      return bunzip2(inputs[0], { streams: [], trailing: 0, trailingZeros: true }, true);
    default: {
      const props = parseAesProps(coder.props);
      return decryptAes(inputs[0], env.key(props), props.iv);
    }
  }
}

/**
 * Decodes a folder checked with checkFolder: its main output, exactly as long as declared. `packOffsets` are the
 * absolute offsets of the folder's packed streams.
 */
export function decodeFolder(folder: Folder, packOffsets: number[], packSizes: number[], env: FolderEnv): Chunks {
  const outStream = (outIndex: number): Chunks => {
    const { coder: c } = coderOf(folder, outIndex, 'out');
    const coder = folder.coders[c];
    const first = firstStream(folder, c, 'in');
    const inputs: Chunks[] = [];
    for (let i = 0; i < coder.numIn; i++) {
      const inIndex = first + i;
      const bp = folder.bindPairs.find(p => p.inIndex === inIndex);
      if (bp) inputs.push(outStream(bp.outIndex));
      else {
        const k = folder.packedStreams.indexOf(inIndex);
        inputs.push(packStream(env.source, packOffsets[k], packSizes[k], env.onPacked, env.deadline));
      }
    }
    const size = folder.unpackSizes[outIndex];
    return exactly(runCoder(coder, inputs, size, env), size);
  };
  return outStream(folder.mainOut);
}
