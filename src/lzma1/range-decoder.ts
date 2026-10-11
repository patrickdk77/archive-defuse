// Copied from lzma1 (Apache-2.0, Copyright Filip Seman) and changed for lzma-defuse. NOTICE in this folder lists the changes.
/** Number of bytes the range decoder reads on initialization. */
export const RANGE_DECODER_INIT_SIZE = 5;

/**
 * Range decoder reading from an in-memory byte array.
 *
 * `range` and `code` are unsigned 32-bit values stored in regular numbers,
 * so plain `<` comparisons are unsigned.
 *
 * The LZMA decoder loop (`LzmaDecoder.decode`) does the decoding steps
 * inline with the state in local variables, which is why the state fields
 * are public. `range-coder_test.ts` has the reference implementations.
 */
export class RangeDecoder {
  range = 0;
  code = 0;
  input: Uint8Array = new Uint8Array(0);
  /** Position of the next unread input byte. */
  pos = 0;

  /** Reads the initial bytes from `input` starting at `pos`. */
  init(input: Uint8Array, pos: number): void {
    this.setInput(input, pos);

    if (this.readByte() !== 0x00) {
      throw new Error('Corrupted input: invalid range coder header');
    }

    this.range = 0xffffffff;
    this.code = 0;
    for (let i = 1; i < RANGE_DECODER_INIT_SIZE; ++i) {
      this.code = ((this.code << 8) | this.readByte()) >>> 0;
    }

    if (this.code === this.range) {
      throw new Error('Corrupted input: invalid range coder header');
    }
  }

  /** Continues decoding from a different buffer (used when streaming). */
  setInput(input: Uint8Array, pos: number): void {
    this.input = input;
    this.pos = pos;
  }

  /** True when the encoder's flush bytes have been consumed exactly. */
  isFinished(): boolean {
    return this.code === 0;
  }

  private readByte(): number {
    if (this.pos >= this.input.length) {
      throw new Error('Truncated input');
    }
    return this.input[this.pos++];
  }
}

/**
 * Range decoder for one LZMA2 chunk. Every LZMA chunk starts a new range
 * coder, and its compressed data is complete in the buffer before decoding
 * starts, so the data ends at a known position.
 *
 * Ported from XZ for Java (0BSD) by Lasse Collin and Igor Pavlov.
 */
export class RangeDecoderFromBuffer extends RangeDecoder {
  /** Position after the chunk's compressed data. */
  private end = 0;

  /** Starts decoding the `len` bytes of chunk data at the start of `input`. */
  prepareInputBuffer(input: Uint8Array, len: number): void {
    if (len < RANGE_DECODER_INIT_SIZE) {
      throw new Error('Corrupted input: LZMA2 chunk is too short');
    }

    this.init(input, 0);
    this.end = len;
  }

  /** True when the chunk's data has been consumed exactly. */
  override isFinished(): boolean {
    return this.pos === this.end && this.code === 0;
  }
}
