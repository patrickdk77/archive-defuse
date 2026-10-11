import { DataError } from './errors';

/** Reads an async stream of chunks byte by byte or a chunk at a time. */
export class PullReader {
  private readonly it: AsyncIterator<Uint8Array>;
  private buf: Uint8Array = new Uint8Array(0);
  private pos = 0;
  private ended = false;
  constructor(source: AsyncIterable<Uint8Array>) {
    this.it = source[Symbol.asyncIterator]();
  }

  /** The unread part of the current chunk, after fetching one if it is used up. Empty at the end of the stream. */
  async peek(): Promise<Uint8Array> {
    while (this.pos >= this.buf.length && !this.ended) {
      const r = await this.it.next();
      if (r.done) this.ended = true;
      else {
        this.buf = r.value;
        this.pos = 0;
      }
    }
    return this.buf.subarray(this.pos);
  }

  skip(n: number): void {
    this.pos += n;
  }

  /** The next byte. Throws at the end of the stream. */
  async byte(): Promise<number> {
    const b = await this.peek();
    if (b.length === 0) throw new DataError('a BCJ2 stream ends early', true);
    this.pos++;
    return b[0];
  }

  /** Stops reading the stream. */
  async close(): Promise<void> {
    await this.it.return?.();
  }
}

const TOP = 1 << 24;
const isJ = (b0: number, b1: number) => (b1 & 0xfe) === 0xe8 || (b0 === 0x0f && (b1 & 0xf0) === 0x80);

/**
 * Decodes 7-Zip's BCJ2 filter, which moves the targets of x86 calls and jumps into streams of their own. The main
 * stream holds the code, the call and jump streams the big-endian absolute targets, and a range coder stream says
 * which E8, E9 and Jcc opcodes were converted. This follows Bcj2_Decode of the LZMA SDK 9.20 (public domain).
 */
export async function* decodeBcj2(
  main: AsyncIterable<Uint8Array>,
  call: AsyncIterable<Uint8Array>,
  jump: AsyncIterable<Uint8Array>,
  rcStream: AsyncIterable<Uint8Array>,
  outSize: number,
): AsyncGenerator<Uint8Array> {
  const m = new PullReader(main);
  const c = new PullReader(call);
  const j = new PullReader(jump);
  const r = new PullReader(rcStream);
  try {
    const probs = new Uint16Array(256 + 2).fill(1024);
    let range = 0xffffffff;
    let code = 0;
    for (let i = 0; i < 5; i++) code = ((code << 8) | (await r.byte())) >>> 0;
    let prevByte = 0;
    let outPos = 0;
    const out = new Uint8Array(1 << 16);
    let o = 0;
    const flush = () => {
      const chunk = out.slice(0, o);
      o = 0;
      return chunk;
    };
    while (outPos < outSize) {
      // Copy from the main stream up to and including the next opcode that may have been converted.
      const chunk = await m.peek();
      if (chunk.length === 0) break;
      let i = 0;
      let found = false;
      const limit = Math.min(chunk.length, outSize - outPos);
      while (i < limit) {
        const b = chunk[i++];
        out[o++] = b;
        outPos++;
        if (o === out.length) yield flush();
        if (isJ(prevByte, b)) {
          found = true;
          break;
        }
        prevByte = b;
      }
      m.skip(i);
      if (!found || outPos === outSize) continue;
      const b = chunk[i - 1];
      const index = b === 0xe8 ? prevByte : b === 0xe9 ? 256 : 257;
      const prob = probs[index];
      const bound = (range >>> 11) * prob;
      let converted: boolean;
      if (code < bound) {
        range = bound;
        probs[index] = prob + ((2048 - prob) >>> 5);
        converted = false;
      } else {
        range = (range - bound) >>> 0;
        code = (code - bound) >>> 0;
        probs[index] = prob - (prob >>> 5);
        converted = true;
      }
      if (range < TOP) {
        range = (range << 8) >>> 0;
        code = ((code << 8) | (await r.byte())) >>> 0;
      }
      if (!converted) {
        prevByte = b;
        continue;
      }
      const from = b === 0xe8 ? c : j;
      let src = 0;
      for (let k = 0; k < 4; k++) src = ((src << 8) | (await from.byte())) >>> 0;
      const dest = (src - (outPos + 4)) >>> 0;
      for (let k = 0; k < 4 && outPos < outSize; k++) {
        out[o++] = (dest >>> (8 * k)) & 0xff;
        outPos++;
        if (o === out.length) yield flush();
      }
      prevByte = dest >>> 24;
    }
    if (o > 0) yield flush();
    if (outPos !== outSize) throw new DataError('the BCJ2 main stream ends early', true);
  } finally {
    await Promise.all([m.close(), c.close(), j.close(), r.close()]);
  }
}
