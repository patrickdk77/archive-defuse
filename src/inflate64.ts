/*
 * Deflate64 ("enhanced deflate": ZIP method 9, 7z coder 040109) decoder.
 *
 * Deflate64 is RFC 1951 with three changes. The constants below were checked against zlib 1.3.1
 * contrib/infback9/inftree9.c (tables lbase, lext, dbase, dext) and contrib/infback9/infback9.c (WSIZE 65536):
 * - the window is 65,536 bytes;
 * - length code 285 is base 3 with 16 extra bits (lext 144 = 128 + 16), not a fixed 258;
 * - distance codes 30 and 31 are valid, base 32,769 and 49,153, each with 14 extra bits (dext 142 = 128 + 14).
 * Literal/length codes 286 and 287 stay invalid (inftree9.c marks them with lext 203 and 77).
 *
 * Huffman code checks follow zlib 1.3.1 inftrees.c inflate_table(): an over-subscribed set of lengths is always an
 * error; an incomplete set is an error for the code-length code and for any code whose longest length is over one
 * bit ("if (left > 0 && (type == CODES || max != 1)) return -1"), so the one incomplete code allowed is a single
 * code of length 1. A distance code with no lengths at all is allowed (inftrees.c "no symbols to code at all") and
 * fails only if a distance is decoded with it. infback9.c additionally requires a length for symbol 256 and at most
 * 286 literal/length codes.
 */
import type { Consumed } from './codecs';
import { checkTime, DataError } from './errors';

const WINDOW = 65536;
const MAXBITS = 15;
const FAST = 9;

/** Base and extra bits of literal/length codes 257..285. */
const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16];
/** Base and extra bits of distance codes 0..31. */
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14];
const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/** Which code a set of lengths describes; the incomplete-code rules differ. */
type Kind = 'codes' | 'lens' | 'dists';

/** A canonical Huffman code: counts per length, symbols by (length, value), and a 9-bit lookup for short codes. */
class Huffman {
  readonly count = new Uint16Array(MAXBITS + 1);
  readonly symbol = new Uint16Array(288);
  /** (symbol << 4) | length for codes of at most FAST bits, 0 otherwise. */
  readonly fast = new Int32Array(1 << FAST);
  maxLen = 0;
}

const offs = new Uint16Array(MAXBITS + 2);

/** Builds `h` from `n` lengths at `lens[at]`. Returns an error message, or undefined. Work is bounded by 288 + 512. */
function build(h: Huffman, lens: Uint8Array, at: number, n: number, kind: Kind): string | undefined {
  const count = h.count;
  count.fill(0);
  for (let i = 0; i < n; i++) count[lens[at + i]]++;
  let max = MAXBITS;
  while (max >= 1 && count[max] === 0) max--;
  h.maxLen = max;
  h.fast.fill(0);
  if (max === 0) return kind === 'dists' ? undefined : 'no codes';
  let left = 1;
  for (let len = 1; len <= MAXBITS; len++) {
    left = (left << 1) - count[len];
    if (left < 0) return 'over-subscribed code';
  }
  if (left > 0 && (kind === 'codes' || max !== 1)) return 'incomplete code';
  count[0] = 0;
  offs[1] = 0;
  for (let len = 1; len < MAXBITS; len++) offs[len + 1] = offs[len] + count[len];
  for (let i = 0; i < n; i++) {
    const len = lens[at + i];
    if (len !== 0) h.symbol[offs[len]++] = i;
  }
  // Canonical codes in symbol order: the first code of each length, then reversed into the LSB-first lookup.
  let code = 0;
  let index = 0;
  for (let len = 1; len <= FAST && len <= max; len++) {
    for (let k = 0; k < count[len]; k++) {
      let rev = 0;
      for (let b = 0; b < len; b++) rev |= ((code >>> b) & 1) << (len - 1 - b);
      const entry = (h.symbol[index + k] << 4) | len;
      for (let j = rev; j < 1 << FAST; j += 1 << len) h.fast[j] = entry;
      code++;
    }
    index += count[len];
    code <<= 1;
  }
  return undefined;
}

/** Result of a decode or bit read that needs input the current chunk does not have. */
const NEED = -2;
/** Result of decoding bits that are no code. */
const INVALID = -1;

const fixedLen = new Huffman();
const fixedDist = new Huffman();
{
  const l = new Uint8Array(320);
  l.fill(8, 0, 144);
  l.fill(9, 144, 256);
  l.fill(7, 256, 280);
  l.fill(8, 280, 288);
  l.fill(5, 288, 320);
  build(fixedLen, l, 0, 288, 'lens');
  build(fixedDist, l, 288, 32, 'dists');
}

/**
 * The decoder proper, as a synchronous generator. It yields an output chunk, or null when it needs the next input
 * chunk, which the caller passes back through next(); undefined there means the input has ended.
 */
function* decoder(consumed: Consumed, deadline: number | undefined): Generator<Uint8Array | null, void, Uint8Array | undefined> {
  let buf: Uint8Array = new Uint8Array(0);
  let pos = 0;
  let taken = 0;
  let hold = 0;
  let bits = 0;

  const win = new Uint8Array(WINDOW);
  let wpos = 0;
  let total = 0;

  const lens = new Uint8Array(286 + 32);
  const lenCode = new Huffman();
  const distCode = new Huffman();
  const clCode = new Huffman();

  /** Takes bytes from the current chunk until `n` bits are held or the chunk runs out. n is at most 16. */
  const fill = (n: number): boolean => {
    while (bits < n && pos < buf.length) {
      hold |= buf[pos++] << bits;
      bits += 8;
      taken++;
    }
    return bits >= n;
  };
  const drop = (n: number) => {
    hold >>>= n;
    bits -= n;
  };
  const used = () => {
    consumed.bytes = taken - (bits >>> 3);
  };
  /** Decodes one symbol from the bits held, or returns NEED or INVALID. Consumes nothing unless it succeeds. */
  const decode = (h: Huffman): number => {
    fill(MAXBITS);
    if (bits >= FAST) {
      const e = h.fast[hold & ((1 << FAST) - 1)];
      if (e !== 0) {
        drop(e & 15);
        return e >>> 4;
      }
    }
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len <= h.maxLen; len++) {
      if (bits < len) return NEED;
      code |= (hold >>> (len - 1)) & 1;
      const count = h.count[len];
      if (code - count < first) {
        drop(len);
        return h.symbol[index + code - first];
      }
      index += count;
      first = (first + count) << 1;
      code <<= 1;
    }
    return INVALID;
  };

  // Pulls the next chunk from the caller. Used as `yield* more()`, which happens once per input chunk.
  function* more(): Generator<null, void, Uint8Array | undefined> {
    used();
    const next = yield null;
    if (next === undefined) throw new DataError('Deflate64 stream ends before its final block', true);
    buf = next;
    pos = 0;
  }

  let last = false;
  while (!last) {
    checkTime(deadline);
    while (!fill(3)) yield* more();
    last = (hold & 1) === 1;
    const type = (hold >>> 1) & 3;
    drop(3);

    if (type === 0) {
      drop(bits & 7);
      while (!fill(16)) yield* more();
      const len = hold & 0xffff;
      drop(16);
      while (!fill(16)) yield* more();
      const nlen = hold & 0xffff;
      drop(16);
      if (len !== (~nlen & 0xffff)) throw new DataError('Deflate64 stored block lengths do not match');
      let left = len;
      // Whole bytes still held come first; bits is a multiple of 8 here.
      while (left > 0 && bits > 0) {
        win[wpos++] = hold & 0xff;
        drop(8);
        left--;
        total++;
        if (wpos === WINDOW) {
          used();
          yield win.slice(0, WINDOW);
          checkTime(deadline);
          wpos = 0;
        }
      }
      while (left > 0) {
        if (pos === buf.length) yield* more();
        const n = Math.min(left, buf.length - pos, WINDOW - wpos);
        win.set(buf.subarray(pos, pos + n), wpos);
        pos += n;
        taken += n;
        wpos += n;
        total += n;
        left -= n;
        if (wpos === WINDOW) {
          used();
          yield win.slice(0, WINDOW);
          checkTime(deadline);
          wpos = 0;
        }
      }
      continue;
    }
    if (type === 3) throw new DataError('Deflate64 block type 3 is invalid');

    let lc = fixedLen;
    let dc = fixedDist;
    if (type === 2) {
      while (!fill(14)) yield* more();
      const nlen = (hold & 31) + 257;
      const ndist = ((hold >>> 5) & 31) + 1;
      const ncode = ((hold >>> 10) & 15) + 4;
      drop(14);
      if (nlen > 286) throw new DataError('Deflate64 block has too many literal/length codes');
      lens.fill(0, 0, 19);
      for (let i = 0; i < ncode; i++) {
        while (!fill(3)) yield* more();
        lens[CL_ORDER[i]] = hold & 7;
        drop(3);
      }
      const clErr = build(clCode, lens, 0, 19, 'codes');
      if (clErr !== undefined) throw new DataError(`Deflate64 code-length code is invalid: ${clErr}`);
      const want = nlen + ndist;
      let have = 0;
      // lens is reused: the code-length code is already built from its first 19 entries.
      while (have < want) {
        let sym = decode(clCode);
        while (sym === NEED) {
          yield* more();
          sym = decode(clCode);
        }
        if (sym === INVALID) throw new DataError('Deflate64 code-length code has no meaning');
        if (sym < 16) {
          lens[have++] = sym;
          continue;
        }
        let rep: number;
        let value = 0;
        if (sym === 16) {
          if (have === 0) throw new DataError('Deflate64 repeat code with no previous length');
          value = lens[have - 1];
          while (!fill(2)) yield* more();
          rep = 3 + (hold & 3);
          drop(2);
        } else if (sym === 17) {
          while (!fill(3)) yield* more();
          rep = 3 + (hold & 7);
          drop(3);
        } else {
          while (!fill(7)) yield* more();
          rep = 11 + (hold & 127);
          drop(7);
        }
        if (have + rep > want) throw new DataError('Deflate64 code lengths run past HLIT + HDIST');
        lens.fill(value, have, have + rep);
        have += rep;
      }
      if (lens[256] === 0) throw new DataError('Deflate64 block has no end-of-block code');
      const lErr = build(lenCode, lens, 0, nlen, 'lens');
      if (lErr !== undefined) throw new DataError(`Deflate64 literal/length code is invalid: ${lErr}`);
      const dErr = build(distCode, lens, nlen, ndist, 'dists');
      if (dErr !== undefined) throw new DataError(`Deflate64 distance code is invalid: ${dErr}`);
      lc = lenCode;
      dc = distCode;
    }

    for (;;) {
      let sym = decode(lc);
      while (sym === NEED) {
        yield* more();
        sym = decode(lc);
      }
      if (sym === INVALID) throw new DataError('Deflate64 literal/length code has no meaning');
      if (sym < 256) {
        win[wpos++] = sym;
        total++;
        if (wpos === WINDOW) {
          used();
          yield win.slice(0, WINDOW);
          checkTime(deadline);
          wpos = 0;
        }
        continue;
      }
      if (sym === 256) break;
      sym -= 257;
      if (sym >= 29) throw new DataError('Deflate64 literal/length code 286 or 287 is invalid');
      let length = LBASE[sym];
      const lx = LEXT[sym];
      if (lx > 0) {
        while (!fill(lx)) yield* more();
        length += hold & ((1 << lx) - 1);
        drop(lx);
      }
      let dsym = decode(dc);
      while (dsym === NEED) {
        yield* more();
        dsym = decode(dc);
      }
      if (dsym === INVALID) throw new DataError('Deflate64 distance code has no meaning');
      let dist = DBASE[dsym];
      const dx = DEXT[dsym];
      if (dx > 0) {
        while (!fill(dx)) yield* more();
        dist += hold & ((1 << dx) - 1);
        drop(dx);
      }
      if (dist > total) throw new DataError('Deflate64 distance reaches before the start of the output');
      total += length;
      // dist <= WINDOW, so the source byte is always still in the window. Byte by byte, so an overlapping match repeats.
      let from = (wpos - dist) & (WINDOW - 1);
      while (length > 0) {
        win[wpos++] = win[from];
        from = (from + 1) & (WINDOW - 1);
        length--;
        if (wpos === WINDOW) {
          used();
          yield win.slice(0, WINDOW);
          checkTime(deadline);
          wpos = 0;
        }
      }
    }
  }
  used();
  if (wpos > 0) yield win.slice(0, wpos);
}

/**
 * Decodes a raw Deflate64 stream. Stops after the final block; consumed.bytes then counts the input bytes the stream
 * used, so bytes after it are the caller's. Output comes in chunks of at most 64 KiB.
 */
export async function* inflate64(chunks: AsyncIterable<Uint8Array>, consumed?: Consumed, deadline?: number): AsyncGenerator<Uint8Array> {
  const count = consumed ?? { bytes: 0 };
  count.bytes = 0;
  const it = chunks[Symbol.asyncIterator]();
  const core = decoder(count, deadline);
  let finished = false;
  try {
    let r = core.next(undefined);
    while (r.done !== true) {
      if (r.value === null) {
        let next = await it.next();
        while (next.done !== true && next.value.length === 0) next = await it.next();
        r = core.next(next.done === true ? undefined : next.value);
      } else {
        yield r.value;
        r = core.next(undefined);
      }
    }
    finished = true;
  } finally {
    core.return(undefined);
    if (!finished) await it.return?.();
  }
}
