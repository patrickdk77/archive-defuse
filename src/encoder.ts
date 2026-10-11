import { HC4 } from './lzma1/hc4';
import { MATCH_LEN_MAX } from './lzma1/lzma-coder';
import type { LzmaEncoder } from './lzma1/lzma-encoder';
import { FAST_EXTRA_SIZE_AFTER, FAST_EXTRA_SIZE_BEFORE, LzmaEncoderFast } from './lzma1/lzma-encoder-fast';
import { RangeEncoder } from './lzma1/range-encoder';

/** lc, lp and pb of everything this package encodes: lzma1's defaults, and xz's. */
export const LC = 3;
export const LP = 0;
export const PB = 2;
/** The properties byte of an LZMA header or 7z coder for LC, LP and PB. */
export const PROPS_BYTE = (PB * 5 + LP) * 9 + LC;

/** lzma1's preset 1: the fast encoder with the hash chain match finder and a 1 MiB dictionary. */
const DICT_SIZE = 1 << 20;
const NICE_LEN = 128;
const DEPTH = 8;

/**
 * The smallest dictionary that covers `size` bytes, at most 1 MiB and at least 4 KiB, rounded up to 2^n or 2^n +
 * 2^(n-1) as decoders of the .lzma format expect.
 */
export function fitDictSize(size: number): number {
  for (let n = 12; n < 20; ++n) {
    if (2 ** n >= size) return 2 ** n;
    if (2 ** n + 2 ** (n - 1) >= size) return 2 ** n + 2 ** (n - 1);
  }
  return DICT_SIZE;
}

function makeEncoder(rc: RangeEncoder, dictSize: number, inputSize: number | undefined): LzmaEncoder {
  const lz = new HC4({
    dictSize,
    extraSizeBefore: FAST_EXTRA_SIZE_BEFORE,
    extraSizeAfter: FAST_EXTRA_SIZE_AFTER,
    niceLen: NICE_LEN,
    matchLenMax: MATCH_LEN_MAX,
    depthLimit: DEPTH,
    inputSize,
  });
  return new LzmaEncoderFast(rc, lz, { lc: LC, lp: LP, pb: PB, dictSize, niceLen: NICE_LEN });
}

/**
 * Encodes raw LZMA data of a known size, without an end marker, with lzma1's encoder at its preset 1. The output is
 * the range coder's bytes, as a 7z LZMA coder and the data of an .lzma file hold them.
 */
export class RawLzmaEncoder {
  private rc: RangeEncoder;
  private readonly lzma: LzmaEncoder;
  readonly dictSize: number;

  /** `size` is the input's whole length, or undefined to encode pieces with restart(). */
  constructor(size: number | undefined, dictSize = size === undefined ? DICT_SIZE : fitDictSize(size)) {
    this.dictSize = dictSize;
    this.rc = new RangeEncoder(size === undefined ? 1 << 16 : Math.min(size >>> 1, 1 << 20) + 64);
    this.lzma = makeEncoder(this.rc, dictSize, size);
  }

  /** Encodes `input` and returns the bytes ready so far. */
  write(input: Uint8Array): Uint8Array {
    const lz = this.lzma.lz;
    for (let off = 0; off < input.length; ) {
      off += lz.fillWindow(input, off, input.length - off);
      this.lzma.encode();
    }
    return this.rc.take();
  }

  /** Encodes what is left and returns the last bytes. */
  finish(): Uint8Array {
    this.lzma.lz.setFinishing();
    this.lzma.encode();
    return this.rc.finish();
  }

  /** Starts an independent input with the same encoder, whose tables need no new allocation. */
  restart(): void {
    this.rc = new RangeEncoder(1 << 16);
    this.lzma.restart(this.rc);
  }
}

/** The largest data of one LZMA2 chunk, compressed or stored. */
const CHUNK_MAX = 1 << 16;
/** Dictionary of the LZMA2 chunks below: every chunk resets it, and no chunk holds more than this. */
export const LZMA2_DICT_SIZE = CHUNK_MAX;
/** The LZMA2 properties byte for LZMA2_DICT_SIZE: (2 | (p & 1)) << (p / 2 + 11) is 64 KiB for 8. */
export const LZMA2_DICT_PROP = 8;

/**
 * Writes raw LZMA2 data as independent chunks of at most 64 KiB, each compressed by the LZMA1 encoder above, or
 * stored when that does not make it smaller. Every chunk resets the dictionary and the state, which LZMA2 allows, so
 * the encoder needs no knowledge of LZMA2. `forceCompressed` keeps a chunk compressed even when that is larger, so the
 * stored bytes of the content do not show at the start of a file, where other readers look for their own signatures.
 */
export class Lzma2ChunkWriter {
  private readonly encoder = new RawLzmaEncoder(undefined, LZMA2_DICT_SIZE);
  private used = false;

  /** The chunks for one piece of at most 64 KiB. With `store`, a piece not forced compressed is stored as it is. */
  chunk(piece: Uint8Array, forceCompressed: boolean, store = false): Uint8Array {
    if (piece.length === 0 || piece.length > CHUNK_MAX) throw new RangeError('An LZMA2 piece must hold 1 to 65536 bytes');
    const u = piece.length - 1;
    if (store && !forceCompressed) return Buffer.concat([Uint8Array.of(0x01, (u >>> 8) & 0xff, u & 0xff), piece]);
    if (this.used) this.encoder.restart();
    this.used = true;
    const packed = Buffer.concat([this.encoder.write(piece), this.encoder.finish()]);
    if (packed.length <= CHUNK_MAX && (packed.length < piece.length || forceCompressed)) {
      const c = packed.length - 1;
      const head = Uint8Array.of(0xe0 | (u >>> 16), (u >>> 8) & 0xff, u & 0xff, (c >>> 8) & 0xff, c & 0xff, PROPS_BYTE);
      return Buffer.concat([head, packed]);
    }
    return Buffer.concat([Uint8Array.of(0x01, (u >>> 8) & 0xff, u & 0xff), piece]);
  }
}
