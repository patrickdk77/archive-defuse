// Copied from lzma1 (Apache-2.0, Copyright Filip Seman) and changed for lzma-defuse. NOTICE in this folder lists the changes.
/**
 * Decoder for raw LZMA2 data, the chunked format inside `.xz` blocks and
 * 7z LZMA2 entries. LZMA2 has no header of its own. The container stores
 * the dictionary size.
 *
 * Each chunk starts with a control byte:
 *
 * | control   | chunk                                                  |
 * | --------- | ------------------------------------------------------ |
 * | 0x00      | end of the data                                        |
 * | 0x01      | uncompressed, dictionary reset                         |
 * | 0x02      | uncompressed, no reset                                 |
 * | 0x80-0x9F | LZMA, no reset                                         |
 * | 0xA0-0xBF | LZMA, state reset                                      |
 * | 0xC0-0xDF | LZMA, state reset and new properties                   |
 * | 0xE0-0xFF | LZMA, dictionary reset, state reset and new properties |
 *
 * The sizes follow as big-endian values minus one, then the data:
 *
 * | bytes | uncompressed chunk | LZMA chunk                                 |
 * | ----- | ------------------ | ------------------------------------------ |
 * | 1-2   | size               | uncompressed size, bits 0-15; bits 16-20   |
 * |       |                    | are the low 5 bits of the control byte     |
 * | 3-4   |                    | compressed size                            |
 * | 5     |                    | `(pb * 5 + lp) * 9 + lc`, 0xC0 and up      |
 *
 * The first chunk has to reset the dictionary, and after a dictionary reset
 * the next LZMA chunk has to set properties. Every LZMA chunk starts a new
 * range coder, and LZMA2 doesn't use the end marker of the LZMA layer.
 *
 * Input may arrive in pieces. The decoder copies uncompressed chunks as
 * they arrive and decodes an LZMA chunk once its compressed data, at most
 * 64 KiB, is complete.
 *
 * Ported from XZ for Java (0BSD) by Lasse Collin and Igor Pavlov.
 */

import { LzDecoder } from './lz-decoder';
import { LzmaDecoder } from './lzma-decoder';
import { RangeDecoderFromBuffer } from './range-decoder';

const COMPRESSED_SIZE_MAX = 1 << 16;

/**
 * Upper bound of input bytes a single symbol can consume. The value of
 * `INPUT_MARGIN` in lzma1's alone-decoder.ts, which lzma-defuse does not carry.
 */
const INPUT_MARGIN = 64;

/** Largest chunk header: control byte, two sizes and the properties. */
const CHUNK_HEADER_SIZE_MAX = 6;

export class Lzma2Decoder {
  private readonly lz: LzDecoder;
  private readonly rc = new RangeDecoderFromBuffer();
  private lzma: LzmaDecoder | null = null;

  private uncompressedSize = 0;
  private compressedSize = 0;
  private isLzmaChunk = false;

  private needDictReset = true;
  private needProps = true;
  private endReached = false;

  /**
   * Bytes decoded since the last dictionary reset. LZMA's position bits
   * come from it. XZ for Java reads it from the dictionary
   * (`lz.getPos()`); `LzmaDecoder` counts it in `outPos`.
   */
  private outPos = 0;
  /** Header of the next chunk, collected until it is complete. */
  private readonly header = new Uint8Array(CHUNK_HEADER_SIZE_MAX);
  private headerPos = 0;
  /**
   * Compressed data of the current LZMA chunk, collected until it is
   * complete. `INPUT_MARGIN` bytes after the data leave room for corrupt
   * input, which can make the decoder read past it.
   */
  private readonly inBuf = new Uint8Array(COMPRESSED_SIZE_MAX + INPUT_MARGIN);
  private inPos = 0;

  /**
   * @param dictSize Dictionary size in bytes
   * @param sink Receives decompressed data. The chunk is only valid during
   *        the call.
   */
  constructor(dictSize: number, sink: (chunk: Uint8Array) => void) {
    this.lz = new LzDecoder(dictSize, sink);
  }

  /**
   * Approximate memory needed to decode, in KiB, as XZ for Java's
   * `LZMA2InputStream.getMemoryUsage` computes it.
   */
  static getMemoryUsage(dictSize: number): number {
    // The base state is around 30-40 KiB (probabilities etc.), the range
    // decoder needs COMPRESSED_SIZE_MAX bytes for buffering, and the LZ
    // decoder needs a dictionary buffer.
    return 40 + COMPRESSED_SIZE_MAX / 1024 + Math.floor(getDictSize(dictSize) / 1024);
  }

  /** Decodes as much of `input` as possible. */
  write(input: Uint8Array): void {
    let pos = 0;

    while (pos < input.length && !this.endReached) {
      if (this.uncompressedSize === 0) {
        pos = this.readChunkHeader(input, pos);
        continue;
      }

      if (!this.isLzmaChunk) {
        const copySize = Math.min(this.uncompressedSize, input.length - pos);
        this.lz.copyUncompressed(input, pos, copySize);
        pos += copySize;
        this.outPos += copySize;
        this.uncompressedSize -= copySize;
      } else {
        const copySize = Math.min(this.compressedSize - this.inPos, input.length - pos);
        this.inBuf.set(input.subarray(pos, pos + copySize), this.inPos);
        pos += copySize;
        this.inPos += copySize;

        if (this.inPos === this.compressedSize) {
          this.decodeLzmaChunk();
        }
      }

      this.lz.flush();
    }
  }

  /** Throws if the data ended before its end marker. */
  end(): void {
    if (!this.endReached) {
      throw new Error('Truncated input');
    }
  }

  /** Collects the chunk header and decodes it once it is complete. */
  private readChunkHeader(input: Uint8Array, start: number): number {
    const header = this.header;
    let pos = start;
    header[this.headerPos++] = input[pos++];

    const size = chunkHeaderSize(header[0]);
    const copySize = Math.min(size - this.headerPos, input.length - pos);
    header.set(input.subarray(pos, pos + copySize), this.headerPos);
    this.headerPos += copySize;

    if (this.headerPos === size) {
      this.headerPos = 0;
      this.decodeChunkHeader();
    }

    return pos + copySize;
  }

  private decodeChunkHeader(): void {
    const header = this.header;
    const control = header[0];

    if (control === 0x00) {
      this.endReached = true;
      return;
    }

    if (control >= 0xe0 || control === 0x01) {
      this.needProps = true;
      this.needDictReset = false;
      this.lz.reset();
      this.outPos = 0;
    } else if (this.needDictReset) {
      throw new Error("Corrupted input: the first LZMA2 chunk doesn't reset the dictionary");
    }

    if (control >= 0x80) {
      this.isLzmaChunk = true;

      this.uncompressedSize = (control & 0x1f) << 16;
      this.uncompressedSize += readUnsignedShort(header, 1) + 1;

      // XZ for Java reads the compressed data here; `write` collects
      // it instead.
      this.compressedSize = readUnsignedShort(header, 3) + 1;
      this.inPos = 0;

      if (control >= 0xc0) {
        this.needProps = false;
        this.decodeProps(header[5]);
      } else if (this.needProps) {
        throw new Error('Corrupted input: LZMA2 chunk without properties');
      } else if (control >= 0xa0) {
        this.currentLzma().reset();
      }
    } else if (control > 0x02) {
      throw new Error('Corrupted input: invalid LZMA2 control byte');
    } else {
      this.isLzmaChunk = false;
      this.uncompressedSize = readUnsignedShort(header, 1) + 1;
    }
  }

  private decodeProps(byte: number): void {
    let props = byte;
    if (props > (4 * 5 + 4) * 9 + 8) {
      throw new Error('Corrupted input: invalid LZMA2 properties');
    }

    const pb = (props / (9 * 5)) | 0;
    props -= pb * 9 * 5;
    const lp = (props / 9) | 0;
    const lc = props - lp * 9;

    if (lc + lp > 4) {
      throw new Error('Corrupted input: invalid LZMA2 properties');
    }

    this.lzma = new LzmaDecoder(this.lz, this.rc, lc, lp, pb);
  }

  /** The LZMA decoder of the last properties, which a chunk without properties continues. */
  private currentLzma(): LzmaDecoder {
    if (this.lzma === null) throw new Error('Corrupted input: LZMA2 chunk without properties');
    return this.lzma;
  }

  private decodeLzmaChunk(): void {
    const lzma = this.currentLzma();
    const outLimit = this.outPos + this.uncompressedSize;

    this.rc.prepareInputBuffer(this.inBuf, this.compressedSize);
    lzma.outPos = this.outPos;
    lzma.decode(outLimit, this.compressedSize);

    // Decoding stops before the chunk's size when it reads past the
    // chunk's data or decodes an end marker. XZ for Java throws in both
    // cases. A match that would cross the chunk's end throws in
    // `decode`, which XZ for Java detects with `lz.hasPending()`.
    if (lzma.outPos !== outLimit || !this.rc.isFinished()) {
      throw new Error("Corrupted input: LZMA2 chunk doesn't match its sizes");
    }

    this.outPos = outLimit;
    this.uncompressedSize = 0;
  }
}

/** Size of the chunk header that starts with `control`. */
function chunkHeaderSize(control: number): number {
  if (control >= 0xc0) {
    return 6;
  }
  if (control >= 0x80) {
    return 5;
  }
  if (control === 0x01 || control === 0x02) {
    return 3;
  }

  // The end marker, or an invalid control byte, which throws
  return 1;
}

function readUnsignedShort(bytes: Uint8Array, pos: number): number {
  return (bytes[pos] << 8) | bytes[pos + 1];
}

/**
 * Dictionary size rounded up to a multiple of 16, as XZ for Java allocates
 * it, so the memory needed matches its numbers.
 */
function getDictSize(dictSize: number): number {
  // Not `(dictSize + 15) & ~15`, which turns sizes of 2 GiB and up negative.
  return Math.ceil(dictSize / 16) * 16;
}
