// A bzip2 decoder and encoder. Node has no bzip2, and this package takes no runtime dependency, so both are ours.
// They follow the format as bzip2 1.0.8 reads and writes it: blocks of run-length coded bytes put through the
// Burrows-Wheeler transform, move-to-front and Huffman coding.
import type { Consumed } from './codecs';
import { DataError } from './errors';

/** bzip2's CRC-32: ZIP's polynomial, most significant bit first. */
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i << 24;
  for (let k = 0; k < 8; k++) c = c & 0x80000000 ? (c << 1) ^ 0x04c11db7 : c << 1;
  CRC_TABLE[i] = c >>> 0;
}

const BLOCK_MAGIC_HI = 0x314159;
const BLOCK_MAGIC_LO = 0x265359;
const END_MAGIC_HI = 0x177245;
const END_MAGIC_LO = 0x385090;
const MAX_GROUPS = 6;
const MAX_ALPHA = 258;
const MAX_CODE_LEN = 20;
const GROUP_SIZE = 50;
/** bzip2 1.0.8 reads at most this many selectors and skips the rest. */
const MAX_SELECTORS = 18002;
/**
 * The table bzip2 0.9.0 used to randomise blocks of repetitive data, which later versions still read. Every byte of
 * such a block, before the run-length decoding, has its low bit flipped where the table's countdown reaches 1.
 */
const RAND_NUMS = [
  619, 720, 127, 481, 931, 816, 813, 233, 566, 247, 985, 724, 205, 454, 863, 491, 741, 242, 949, 214, 733, 859, 335, 708, 621, 574, 73, 654, 730, 472, 419, 436, 278, 496, 867, 210, 399, 680, 480, 51,
  878, 465, 811, 169, 869, 675, 611, 697, 867, 561, 862, 687, 507, 283, 482, 129, 807, 591, 733, 623, 150, 238, 59, 379, 684, 877, 625, 169, 643, 105, 170, 607, 520, 932, 727, 476, 693, 425, 174, 647,
  73, 122, 335, 530, 442, 853, 695, 249, 445, 515, 909, 545, 703, 919, 874, 474, 882, 500, 594, 612, 641, 801, 220, 162, 819, 984, 589, 513, 495, 799, 161, 604, 958, 533, 221, 400, 386, 867, 600, 782,
  382, 596, 414, 171, 516, 375, 682, 485, 911, 276, 98, 553, 163, 354, 666, 933, 424, 341, 533, 870, 227, 730, 475, 186, 263, 647, 537, 686, 600, 224, 469, 68, 770, 919, 190, 373, 294, 822, 808, 206,
  184, 943, 795, 384, 383, 461, 404, 758, 839, 887, 715, 67, 618, 276, 204, 918, 873, 777, 604, 560, 951, 160, 578, 722, 79, 804, 96, 409, 713, 940, 652, 934, 970, 447, 318, 353, 859, 672, 112, 785,
  645, 863, 803, 350, 139, 93, 354, 99, 820, 908, 609, 772, 154, 274, 580, 184, 79, 626, 630, 742, 653, 282, 762, 623, 680, 81, 927, 626, 789, 125, 411, 521, 938, 300, 821, 78, 343, 175, 128, 250,
  170, 774, 972, 275, 999, 639, 495, 78, 352, 126, 857, 956, 358, 619, 580, 124, 737, 594, 701, 612, 669, 112, 134, 694, 363, 992, 809, 743, 168, 974, 944, 375, 748, 52, 600, 747, 642, 182, 862, 81,
  344, 805, 988, 739, 511, 655, 814, 334, 249, 515, 897, 955, 664, 981, 649, 113, 974, 459, 893, 228, 433, 837, 553, 268, 926, 240, 102, 654, 459, 51, 686, 754, 806, 760, 493, 403, 415, 394, 687, 700,
  946, 670, 656, 610, 738, 392, 760, 799, 887, 653, 978, 321, 576, 617, 626, 502, 894, 679, 243, 440, 680, 879, 194, 572, 640, 724, 926, 56, 204, 700, 707, 151, 457, 449, 797, 195, 791, 558, 945, 679,
  297, 59, 87, 824, 713, 663, 412, 693, 342, 606, 134, 108, 571, 364, 631, 212, 174, 643, 304, 329, 343, 97, 430, 751, 497, 314, 983, 374, 822, 928, 140, 206, 73, 263, 980, 736, 876, 478, 430, 305,
  170, 514, 364, 692, 829, 82, 855, 953, 676, 246, 369, 970, 294, 750, 807, 827, 150, 790, 288, 923, 804, 378, 215, 828, 592, 281, 565, 555, 710, 82, 896, 831, 547, 261, 524, 462, 293, 465, 502, 56,
  661, 821, 976, 991, 658, 869, 905, 758, 745, 193, 768, 550, 608, 933, 378, 286, 215, 979, 792, 961, 61, 688, 793, 644, 986, 403, 106, 366, 905, 644, 372, 567, 466, 434, 645, 210, 389, 550, 919, 135,
  780, 773, 635, 389, 707, 100, 626, 958, 165, 504, 920, 176, 193, 713, 857, 265, 203, 50, 668, 108, 645, 990, 626, 197, 510, 357, 358, 850, 858, 364, 936, 638,
];
/** The largest compressed block: 900,001 symbols of 20 bits, with room for the tables. */
const MAX_BLOCK_BYTES = 3 * 1024 * 1024;
const OUT_CHUNK = 65536;

/** Where each stream of a bzip2 file sits, and what follows the last. */
export interface Bzip2Info {
  streams: Array<{ start: number; end: number; level: number }>;
  /** Bytes after the last stream. */
  trailing: number;
  /** True when every trailing byte is zero. */
  trailingZeros: boolean;
}

/** Reads bits, most significant first, from chunks that arrive as the decoder asks for them. */
class BitInput {
  private buf: Uint8Array = new Uint8Array(0);
  private pos = 0;
  private acc = 0;
  private n = 0;
  /** Offset in the whole input of buf[0]. */
  private base = 0;
  private done = false;
  constructor(private readonly it: AsyncIterator<Uint8Array>) {}

  /** Makes sure `min` bytes are buffered, unless the input ends first. */
  async fill(min: number): Promise<void> {
    while (!this.done && this.buf.length - this.pos < min) {
      const r = await this.it.next();
      if (r.done) {
        this.done = true;
        break;
      }
      // Bytes already taken into the bit buffer stay, so peek() and offset still find them.
      const keep = this.pos - Math.ceil(this.n / 8);
      const rest = this.buf.subarray(keep);
      const next = new Uint8Array(rest.length + r.value.length);
      next.set(rest, 0);
      next.set(r.value, rest.length);
      this.base += keep;
      this.buf = next;
      this.pos -= keep;
    }
  }

  bits(k: number): number {
    while (this.n < k) {
      if (this.pos >= this.buf.length) throw new DataError('The bzip2 data ends early', true);
      this.acc = (this.acc << 8) | this.buf[this.pos++];
      this.n += 8;
    }
    this.n -= k;
    return (this.acc >>> this.n) & ((1 << k) - 1);
  }

  bit(): number {
    return this.bits(1);
  }

  /** Drops the rest of the current byte. */
  align(): void {
    this.n -= this.n % 8;
  }

  /** Offset in the whole input of the next byte not yet taken into the bit buffer, after align(). */
  get offset(): number {
    return this.base + this.pos - this.n / 8;
  }

  /** The next `count` buffered bytes after align(), without taking them. */
  peek(count: number): Uint8Array {
    const at = this.pos - this.n / 8;
    return this.buf.subarray(at, at + count);
  }

  /** Counts the rest of the input, and whether it is all zero, taking it. */
  async drain(): Promise<{ bytes: number; zeros: boolean }> {
    let bytes = 0;
    let zeros = true;
    const tally = (b: Uint8Array) => {
      bytes += b.length;
      if (zeros && b.some(x => x !== 0)) zeros = false;
    };
    tally(this.peek(this.buf.length));
    this.pos = this.buf.length;
    this.n = 0;
    for (;;) {
      const r = await this.it.next();
      if (r.done) break;
      tally(r.value);
    }
    return { bytes, zeros };
  }
}

/** Decoding tables for one Huffman table, as bzip2 builds them. */
interface Table {
  limit: Int32Array;
  base: Int32Array;
  perm: Int32Array;
  minLen: number;
}

function decodeTable(lengths: Uint8Array, alphaSize: number): Table {
  let minLen = 32;
  let maxLen = 0;
  for (let i = 0; i < alphaSize; i++) {
    minLen = Math.min(minLen, lengths[i]);
    maxLen = Math.max(maxLen, lengths[i]);
  }
  const perm = new Int32Array(MAX_ALPHA);
  const base = new Int32Array(MAX_CODE_LEN + 3);
  const limit = new Int32Array(MAX_CODE_LEN + 3);
  let pp = 0;
  for (let i = minLen; i <= maxLen; i++) for (let j = 0; j < alphaSize; j++) if (lengths[j] === i) perm[pp++] = j;
  for (let i = 0; i < alphaSize; i++) base[lengths[i] + 1]++;
  for (let i = 1; i < base.length; i++) base[i] += base[i - 1];
  let vec = 0;
  for (let i = minLen; i <= maxLen; i++) {
    vec += base[i + 1] - base[i];
    limit[i] = vec - 1;
    vec <<= 1;
  }
  for (let i = minLen + 1; i <= maxLen; i++) base[i] = ((limit[i - 1] + 1) << 1) - base[i];
  return { limit, base, perm, minLen };
}

/** One block's bytes before the run-length decoding, with what the inverse transform needs. */
interface Block {
  crc: number;
  randomised: boolean;
  tt: Uint32Array;
  length: number;
  origPtr: number;
}

/** Reads one block after its magic number. */
function readBlock(input: BitInput, level: number, tt: Uint32Array): Block {
  const crc = ((input.bits(16) << 16) | input.bits(16)) >>> 0;
  const randomised = input.bit() === 1;
  const origPtr = input.bits(24);
  const used = input.bits(16);
  const seqToUnseq = new Uint8Array(256);
  let nInUse = 0;
  for (let i = 0; i < 16; i++) {
    if (!(used & (0x8000 >> i))) continue;
    const bits = input.bits(16);
    for (let j = 0; j < 16; j++) if (bits & (0x8000 >> j)) seqToUnseq[nInUse++] = i * 16 + j;
  }
  if (nInUse === 0) throw new DataError('A bzip2 block uses no byte values');
  const alphaSize = nInUse + 2;
  const nGroups = input.bits(3);
  if (nGroups < 2 || nGroups > MAX_GROUPS) throw new DataError('A bzip2 block has a bad number of Huffman tables');
  const nSelectors = input.bits(15);
  if (nSelectors < 1) throw new DataError('A bzip2 block has no selectors');
  const selectors = new Uint8Array(Math.min(nSelectors, MAX_SELECTORS));
  const mtfGroups = [0, 1, 2, 3, 4, 5];
  for (let i = 0; i < nSelectors; i++) {
    let j = 0;
    while (input.bit()) {
      j++;
      if (j >= nGroups) throw new DataError('A bzip2 selector names a table that is not there');
    }
    if (i >= MAX_SELECTORS) continue;
    const v = mtfGroups[j];
    for (let k = j; k > 0; k--) mtfGroups[k] = mtfGroups[k - 1];
    mtfGroups[0] = v;
    selectors[i] = v;
  }
  const tables: Table[] = [];
  const lengths = new Uint8Array(MAX_ALPHA);
  for (let t = 0; t < nGroups; t++) {
    let curr = input.bits(5);
    for (let i = 0; i < alphaSize; i++) {
      for (;;) {
        if (curr < 1 || curr > MAX_CODE_LEN) throw new DataError('A bzip2 Huffman code length is out of range');
        if (!input.bit()) break;
        curr += input.bit() ? -1 : 1;
      }
      lengths[i] = curr;
    }
    tables.push(decodeTable(lengths, alphaSize));
  }

  const eob = nInUse + 1;
  const max = 100000 * level;
  const counts = new Int32Array(256);
  const mtf = new Uint8Array(256);
  for (let i = 0; i < 256; i++) mtf[i] = i;
  let length = 0;
  let group = -1;
  let left = 0;
  let table = tables[0];
  const next = (): number => {
    if (left === 0) {
      group++;
      if (group >= selectors.length) throw new DataError('A bzip2 block runs past its selectors');
      table = tables[selectors[group]];
      left = GROUP_SIZE;
    }
    left--;
    let len = table.minLen;
    let code = input.bits(len);
    while (code > table.limit[len]) {
      len++;
      if (len > MAX_CODE_LEN) throw new DataError('A bzip2 Huffman code is not in its table');
      code = (code << 1) | input.bit();
    }
    const idx = code - table.base[len];
    if (idx < 0 || idx >= MAX_ALPHA) throw new DataError('A bzip2 Huffman code is not in its table');
    return table.perm[idx];
  };
  let sym = next();
  for (;;) {
    if (sym === eob) break;
    if (sym <= 1) {
      let run = -1;
      let n = 1;
      do {
        if (n >= 2 * 1024 * 1024) throw new DataError('A bzip2 run is too long');
        run += (sym + 1) * n;
        n *= 2;
        sym = next();
      } while (sym <= 1);
      run++;
      const uc = seqToUnseq[mtf[0]];
      if (length + run > max) throw new DataError('A bzip2 block is longer than its level allows');
      counts[uc] += run;
      tt.fill(uc, length, length + run);
      length += run;
      continue;
    }
    if (length >= max) throw new DataError('A bzip2 block is longer than its level allows');
    const nn = sym - 1;
    if (nn >= nInUse) throw new DataError('A bzip2 symbol names a byte value the block does not use');
    const v = mtf[nn];
    mtf.copyWithin(1, 0, nn);
    mtf[0] = v;
    const uc = seqToUnseq[v];
    counts[uc]++;
    tt[length++] = uc;
    sym = next();
  }
  if (origPtr >= length) throw new DataError('A bzip2 block starts outside itself');
  // The inverse transform links each position to the one that follows it, in the high bits of tt.
  const cftab = new Int32Array(257);
  for (let i = 0; i < 256; i++) cftab[i + 1] = cftab[i] + counts[i];
  for (let i = 0; i < length; i++) {
    const uc = tt[i] & 0xff;
    tt[cftab[uc]] |= i << 8;
    cftab[uc]++;
  }
  return { crc, randomised, tt, length, origPtr };
}

/** Undoes the transform and the first run-length coding of a block, in chunks, checking its CRC at the end. */
function* blockBytes(b: Block): Generator<Uint8Array> {
  const out = new Uint8Array(OUT_CHUNK);
  let o = 0;
  let crc = 0xffffffff;
  let pos = b.tt[b.origPtr] >>> 8;
  let last = -1;
  let run = 0;
  let toGo = 0;
  let tablePos = 0;
  for (let left = b.length; left > 0; left--) {
    pos = b.tt[pos];
    let ch = pos & 0xff;
    pos >>>= 8;
    if (b.randomised) {
      if (toGo === 0) {
        toGo = RAND_NUMS[tablePos];
        tablePos = (tablePos + 1) % 512;
      }
      toGo--;
      if (toGo === 1) ch ^= 1;
    }
    if (run === 4) {
      for (let n = 0; n < ch; n++) {
        out[o++] = last;
        crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ last) & 0xff]) >>> 0;
        if (o === OUT_CHUNK) {
          yield out.slice();
          o = 0;
        }
      }
      run = 0;
      continue;
    }
    if (ch === last) run++;
    else {
      last = ch;
      run = 1;
    }
    out[o++] = ch;
    crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ ch) & 0xff]) >>> 0;
    if (o === OUT_CHUNK) {
      yield out.slice();
      o = 0;
    }
  }
  if (o) yield out.slice(0, o);
  if (~crc >>> 0 !== b.crc) throw new DataError('A bzip2 block does not match its CRC');
}

const isStreamHeader = (b: Uint8Array) => b.length >= 4 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68 && b[3] >= 0x31 && b[3] <= 0x39;

/**
 * Decodes bzip2 data. With `multi`, streams that follow each other decode as one, the way bzip2 reads them, and
 * `info` records where each sits and what follows the last. Without it the data must be one stream and nothing
 * after it, as in a ZIP entry. Corrupt or cut-short data throws DataError.
 */
export async function* bunzip2(chunks: AsyncIterable<Uint8Array>, info: Bzip2Info, multi: boolean, consumed?: Consumed): AsyncGenerator<Uint8Array> {
  const input = new BitInput(chunks[Symbol.asyncIterator]());
  let tt: Uint32Array | undefined;
  for (;;) {
    await input.fill(4);
    const start = input.offset;
    if (!isStreamHeader(input.peek(4))) {
      if (info.streams.length === 0) throw new DataError('No bzip2 stream header');
      break;
    }
    input.bits(24);
    const level = input.bits(8) - 0x30;
    if (!tt || tt.length < level * 100000) tt = new Uint32Array(level * 100000);
    let combined = 0;
    for (;;) {
      await input.fill(MAX_BLOCK_BYTES);
      const hi = input.bits(24);
      const lo = input.bits(24);
      if (hi === BLOCK_MAGIC_HI && lo === BLOCK_MAGIC_LO) {
        const block = readBlock(input, level, tt);
        if (consumed) consumed.bytes = Math.floor(input.offset);
        for (const c of blockBytes(block)) yield c;
        combined = (((combined << 1) | (combined >>> 31)) ^ block.crc) >>> 0;
        continue;
      }
      if (hi !== END_MAGIC_HI || lo !== END_MAGIC_LO) throw new DataError('A bzip2 block starts with the wrong magic number');
      const stored = ((input.bits(16) << 16) | input.bits(16)) >>> 0;
      if (stored !== combined) throw new DataError('A bzip2 stream does not match its CRC');
      input.align();
      break;
    }
    info.streams.push({ start, end: input.offset, level });
    if (consumed) consumed.bytes = input.offset;
    if (!multi) break;
  }
  const rest = await input.drain();
  info.trailing = rest.bytes;
  info.trailingZeros = rest.zeros;
  if (!multi && rest.bytes) throw new DataError('Data follows the bzip2 stream');
}

// ---------------------------------------------------------------------------------------------------------------
// The encoder.

/** Writes bits, most significant first. */
class BitOutput {
  private buf = new Uint8Array(1 << 16);
  private len = 0;
  private acc = 0;
  private n = 0;
  put(k: number, v: number): void {
    // k is at most 24, so the accumulator never holds more than 31 bits.
    this.acc = (this.acc << k) | (v & ((1 << k) - 1));
    this.n += k;
    while (this.n >= 8) {
      this.n -= 8;
      this.byte((this.acc >>> this.n) & 0xff);
    }
  }
  put32(v: number): void {
    this.put(16, v >>> 16);
    this.put(16, v & 0xffff);
  }
  private byte(b: number): void {
    if (this.len === this.buf.length) {
      const bigger = new Uint8Array(this.buf.length * 2);
      bigger.set(this.buf);
      this.buf = bigger;
    }
    this.buf[this.len++] = b;
  }
  /** The whole bytes written so far, which leaves the bits of a part byte for later. */
  take(): Uint8Array {
    const out = this.buf.slice(0, this.len);
    this.len = 0;
    return out;
  }
  /** Pads the last byte with zero bits. */
  flush(): void {
    if (this.n > 0) this.put(8 - this.n, 0);
  }
}

/**
 * Sorts the rotations of `block` by prefix doubling, and returns the last column and where the block itself landed.
 * Rotations that are equal keep any order, which the decoder reads back the same.
 */
function bwt(block: Uint8Array): { last: Uint8Array; origPtr: number } {
  const n = block.length;
  const sa = new Int32Array(n);
  let rank = new Int32Array(n);
  let next = new Int32Array(n);
  const tmp = new Int32Array(n);
  const cnt = new Int32Array(Math.max(256, n) + 1);
  for (let i = 0; i < n; i++) cnt[block[i] + 1]++;
  for (let i = 1; i <= 256; i++) cnt[i] += cnt[i - 1];
  for (let i = 0; i < n; i++) sa[cnt[block[i]]++] = i;
  for (let i = 0; i < n; i++) rank[i] = block[i];
  let classes = 256;
  for (let k = 1; k < n; k *= 2) {
    // sa is in order of the first k bytes, so these start positions are in order of the k bytes after them.
    for (let j = 0; j < n; j++) tmp[j] = (sa[j] - k + n) % n;
    cnt.fill(0, 0, classes + 1);
    for (let j = 0; j < n; j++) cnt[rank[tmp[j]] + 1]++;
    for (let j = 1; j <= classes; j++) cnt[j] += cnt[j - 1];
    for (let j = 0; j < n; j++) sa[cnt[rank[tmp[j]]]++] = tmp[j];
    let c = 0;
    next[sa[0]] = 0;
    for (let j = 1; j < n; j++) {
      const cur = sa[j];
      const prev = sa[j - 1];
      if (rank[cur] !== rank[prev] || rank[(cur + k) % n] !== rank[(prev + k) % n]) c++;
      next[cur] = c;
    }
    [rank, next] = [next, rank];
    classes = c + 1;
    if (classes === n) break;
  }
  const last = new Uint8Array(n);
  let origPtr = 0;
  for (let j = 0; j < n; j++) {
    if (sa[j] === 0) origPtr = j;
    last[j] = block[(sa[j] + n - 1) % n];
  }
  return { last, origPtr };
}

/** Huffman code lengths of at most `maxLen` bits for every symbol, as bzip2 makes them: zero counts count as one. */
function codeLengths(freq: Int32Array, alphaSize: number, maxLen: number): Uint8Array {
  const weight = Array.from({ length: alphaSize }, (_, i) => Math.max(1, freq[i]));
  for (;;) {
    // Nodes 0..alphaSize-1 are leaves. Each merge makes a new node from the two lightest.
    const parent = new Int32Array(alphaSize * 2).fill(-1);
    const w = [...weight];
    const live = Array.from({ length: alphaSize }, (_, i) => i);
    while (live.length > 1) {
      live.sort((x, y) => w[x] - w[y] || x - y);
      const [a, b] = live.splice(0, 2);
      const node = w.length;
      w.push(w[a] + w[b]);
      parent[a] = node;
      parent[b] = node;
      live.push(node);
    }
    const lengths = new Uint8Array(alphaSize);
    let longest = 0;
    for (let i = 0; i < alphaSize; i++) {
      let d = 0;
      for (let p = parent[i]; p >= 0; p = parent[p]) d++;
      lengths[i] = Math.max(1, d);
      longest = Math.max(longest, lengths[i]);
    }
    if (longest <= maxLen) return lengths;
    for (let i = 0; i < alphaSize; i++) weight[i] = 1 + Math.floor(weight[i] / 2);
  }
}

/** Writes one block: the transform, move-to-front with zero runs, and one Huffman table used twice. */
function writeBlock(out: BitOutput, block: Uint8Array, crc: number): void {
  const { last, origPtr } = bwt(block);
  const inUse = new Uint8Array(256);
  for (const b of last) inUse[b] = 1;
  const unseqToSeq = new Uint8Array(256);
  let nInUse = 0;
  for (let i = 0; i < 256; i++) if (inUse[i]) unseqToSeq[i] = nInUse++;
  const alphaSize = nInUse + 2;
  const eob = nInUse + 1;
  const mtfv = new Uint16Array(block.length + 1);
  const freq = new Int32Array(alphaSize);
  let wr = 0;
  const emit = (s: number) => {
    mtfv[wr++] = s;
    freq[s]++;
  };
  const flushZeros = (z: number) => {
    let zPend = z - 1;
    for (;;) {
      emit(zPend & 1 ? 1 : 0);
      if (zPend < 2) break;
      zPend = (zPend - 2) >> 1;
    }
  };
  const yy = new Uint8Array(nInUse);
  for (let i = 0; i < nInUse; i++) yy[i] = i;
  let zeros = 0;
  for (const b of last) {
    const s = unseqToSeq[b];
    if (yy[0] === s) {
      zeros++;
      continue;
    }
    if (zeros) flushZeros(zeros);
    zeros = 0;
    let j = 1;
    while (yy[j] !== s) j++;
    yy.copyWithin(1, 0, j);
    yy[0] = s;
    emit(j + 1);
  }
  if (zeros) flushZeros(zeros);
  emit(eob);
  const lengths = codeLengths(freq, alphaSize, 17);
  const codes = new Int32Array(alphaSize);
  let vec = 0;
  for (let n = 1; n <= 17; n++) {
    for (let i = 0; i < alphaSize; i++) if (lengths[i] === n) codes[i] = vec++;
    vec <<= 1;
  }
  out.put(24, BLOCK_MAGIC_HI);
  out.put(24, BLOCK_MAGIC_LO);
  out.put32(crc);
  out.put(1, 0);
  out.put(24, origPtr);
  let used16 = 0;
  for (let i = 0; i < 16; i++) if (inUse.subarray(i * 16, i * 16 + 16).some(x => x === 1)) used16 |= 0x8000 >> i;
  out.put(16, used16);
  for (let i = 0; i < 16; i++) {
    if (!(used16 & (0x8000 >> i))) continue;
    let bits = 0;
    for (let j = 0; j < 16; j++) if (inUse[i * 16 + j]) bits |= 0x8000 >> j;
    out.put(16, bits);
  }
  const nSelectors = Math.ceil(wr / GROUP_SIZE);
  out.put(3, 2);
  out.put(15, nSelectors);
  // Every selector picks the first table, which move-to-front codes as a single zero bit.
  for (let i = 0; i < nSelectors; i++) out.put(1, 0);
  for (let t = 0; t < 2; t++) {
    let curr = lengths[0];
    out.put(5, curr);
    for (let i = 0; i < alphaSize; i++) {
      while (curr < lengths[i]) {
        out.put(2, 2);
        curr++;
      }
      while (curr > lengths[i]) {
        out.put(2, 3);
        curr--;
      }
      out.put(1, 0);
    }
  }
  for (let i = 0; i < wr; i++) out.put(lengths[mtfv[i]], codes[mtfv[i]]);
}

/** Compresses `chunks` as one bzip2 stream with blocks of `level` hundred thousand bytes. */
export async function* bzip2(chunks: AsyncIterable<Uint8Array>, level = 9): AsyncGenerator<Uint8Array> {
  const out = new BitOutput();
  out.put(24, 0x425a68);
  out.put(8, 0x30 + level);
  // bzip2 leaves 19 bytes of room, as its own encoder does.
  const max = level * 100000 - 19;
  const block = new Uint8Array(max);
  let len = 0;
  let crc = 0xffffffff;
  let combined = 0;
  let runChar = -1;
  let runLen = 0;
  const endBlock = () => {
    if (len === 0) return;
    const blockCrc = ~crc >>> 0;
    writeBlock(out, block.subarray(0, len), blockCrc);
    combined = (((combined << 1) | (combined >>> 31)) ^ blockCrc) >>> 0;
    len = 0;
    crc = 0xffffffff;
  };
  const flushRun = () => {
    if (runLen === 0) return;
    if (len + 5 > max) endBlock();
    for (let i = 0; i < runLen; i++) crc = ((crc << 8) ^ CRC_TABLE[((crc >>> 24) ^ runChar) & 0xff]) >>> 0;
    for (let i = 0; i < Math.min(runLen, 4); i++) block[len++] = runChar;
    if (runLen >= 4) block[len++] = runLen - 4;
    runLen = 0;
  };
  for await (const c of chunks) {
    for (const b of c) {
      if (b === runChar && runLen < 255) {
        runLen++;
        continue;
      }
      flushRun();
      runChar = b;
      runLen = 1;
    }
    const done = out.take();
    if (done.length) yield done;
  }
  flushRun();
  endBlock();
  out.put(24, END_MAGIC_HI);
  out.put(24, END_MAGIC_LO);
  out.put32(combined);
  out.flush();
  yield out.take();
}
