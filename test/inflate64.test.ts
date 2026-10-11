import { execFileSync, spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { expect } from 'chai';
import type { Consumed } from '../src/codecs';
import { DataError, TimeLimitError } from '../src/errors';
import { inflate64 } from '../src/inflate64';

const FIXTURES = path.join(__dirname, '..', '..', 'test', 'fixtures', 'deflate64');
const manifest: Record<string, { size: number; sha256: string }> = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'manifest.json'), 'utf8'));
const fixture = (name: string) => new Uint8Array(fs.readFileSync(path.join(FIXTURES, `${name}.d64`)));
const sha256 = (b: Uint8Array) => crypto.createHash('sha256').update(b).digest('hex');
const has7z = spawnSync('7z', ['i'], { stdio: 'ignore' }).status === 0;

const once = (b: Uint8Array) =>
  (async function* () {
    yield b;
  })();
const bytewise = (b: Uint8Array) =>
  (async function* () {
    for (let i = 0; i < b.length; i++) yield b.subarray(i, i + 1);
  })();

async function decode(source: AsyncIterable<Uint8Array>, consumed?: Consumed, deadline?: number): Promise<Uint8Array> {
  const parts: Uint8Array[] = [];
  for await (const c of inflate64(source, consumed, deadline)) {
    expect(c.length).to.be.at.most(65536);
    parts.push(c);
  }
  return Buffer.concat(parts);
}

async function failure(stream: Uint8Array): Promise<unknown> {
  try {
    await decode(once(stream));
  } catch (e) {
    return e;
  }
  throw new Error('decoded without an error');
}

async function expectData(stream: Uint8Array, pattern: RegExp, truncated = false) {
  const e = await failure(stream);
  expect(e).to.be.instanceOf(DataError);
  expect((e as DataError).message).to.match(pattern);
  expect((e as DataError).truncated).to.equal(truncated);
}

// Deflate64 tables, typed from zlib contrib/infback9/inftree9.c independently of src/inflate64.ts.
const LBASE = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 3];
const LEXT = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 16];
const DBASE = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577, 32769, 49153];
const DEXT = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14];
const CL_ORDER = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];

/** Canonical codes for a set of lengths, as RFC 1951 3.2.2 assigns them. */
function canonical(lens: number[]): number[] {
  const count = new Array<number>(17).fill(0);
  for (const l of lens) if (l > 0) count[l]++;
  const next = new Array<number>(17).fill(0);
  let code = 0;
  for (let len = 1; len <= 16; len++) {
    code = (code + count[len - 1]) << 1;
    next[len] = code;
  }
  next[1] = 0;
  code = 0;
  for (let len = 1; len <= 16; len++) {
    next[len] = code;
    code = (code + count[len]) << 1;
  }
  return lens.map(l => (l > 0 ? next[l]++ : 0));
}

interface Code {
  litLens: number[];
  litCodes: number[];
  distLens: number[];
  distCodes: number[];
}

function makeCode(litLens: number[], distLens: number[]): Code {
  return { litLens, litCodes: canonical(litLens), distLens, distCodes: canonical(distLens) };
}

const FIXED_LIT = [...new Array<number>(144).fill(8), ...new Array<number>(112).fill(9), ...new Array<number>(24).fill(7), ...new Array<number>(8).fill(8)];
const FIXED = makeCode(FIXED_LIT, new Array<number>(32).fill(5));
/** A complete literal/length code over all 286 symbols: 256 of 9 bits, 28 of 6, 2 of 5. */
const STD_LIT = [...new Array<number>(256).fill(9), ...new Array<number>(28).fill(6), 5, 5];
/** A complete code-length code: symbols 0..12 of 4 bits, 13..18 of 5. */
const STD_CL = [...new Array<number>(13).fill(4), ...new Array<number>(6).fill(5)];

/** Writes bits LSB first, as Deflate packs them. */
class Bits {
  private readonly out: number[] = [];
  private acc = 0;
  private n = 0;

  put(value: number, count: number): this {
    for (let i = 0; i < count; i++) {
      this.acc |= ((value >>> i) & 1) << this.n;
      if (++this.n === 8) {
        this.out.push(this.acc);
        this.acc = 0;
        this.n = 0;
      }
    }
    return this;
  }

  /** A Huffman code, which goes most significant bit first. */
  huff(code: number, len: number): this {
    for (let i = len - 1; i >= 0; i--) this.put((code >>> i) & 1, 1);
    return this;
  }

  align(): this {
    if (this.n > 0) this.put(0, 8 - this.n);
    return this;
  }

  bytes(): Uint8Array {
    const o = this.out.slice();
    if (this.n > 0) o.push(this.acc);
    return Uint8Array.from(o);
  }

  lit(c: Code, sym: number): this {
    return this.huff(c.litCodes[sym], c.litLens[sym]);
  }

  /** A length symbol with an explicit extra value, then a distance symbol with an explicit extra value. */
  raw(c: Code, lsym: number, lextra: number, dsym: number, dextra: number): this {
    this.lit(c, lsym).put(lextra, LEXT[lsym - 257]);
    return this.huff(c.distCodes[dsym], c.distLens[dsym]).put(dextra, DEXT[dsym]);
  }

  /** A match, with codes 257..284 for lengths up to 258 and code 285 above that. */
  match(c: Code, length: number, dist: number): this {
    let l = 28;
    if (length <= 258) {
      l = 27;
      while (LBASE[l] > length) l--;
    }
    let d = 31;
    while (DBASE[d] > dist) d--;
    return this.raw(c, 257 + l, length - LBASE[l], d, dist - DBASE[d]);
  }

  fixed(last: boolean): this {
    return this.put(last ? 1 : 0, 1).put(1, 2);
  }

  stored(last: boolean, data: Uint8Array, nlen = ~data.length & 0xffff): this {
    this.put(last ? 1 : 0, 1)
      .put(0, 2)
      .align()
      .put(data.length, 16)
      .put(nlen, 16);
    for (const b of data) this.put(b, 8);
    return this;
  }

  /**
   * A dynamic block header. The lengths go out as plain code-length symbols unless `clSyms` gives the symbols
   * ([symbol, extra value]) to write instead.
   */
  dynamic(last: boolean, litLens: number[], distLens: number[], opts: { nlen?: number; clLens?: number[]; clSyms?: Array<[number, number]> } = {}): Code {
    const nlen = opts.nlen ?? litLens.length;
    const clLens = opts.clLens ?? STD_CL;
    const clCodes = canonical(clLens);
    this.put(last ? 1 : 0, 1)
      .put(2, 2)
      .put(nlen - 257, 5)
      .put(distLens.length - 1, 5)
      .put(15, 4);
    for (const s of CL_ORDER) this.put(clLens[s], 3);
    const syms: Array<[number, number]> = opts.clSyms ?? [...litLens, ...distLens].map(l => [l, 0]);
    for (const [s, extra] of syms) {
      this.huff(clCodes[s], clLens[s]);
      if (s === 16) this.put(extra, 2);
      if (s === 17) this.put(extra, 3);
      if (s === 18) this.put(extra, 7);
    }
    return makeCode(litLens, distLens);
  }
}

/**
 * An independent bit-at-a-time decoder after zlib's contrib/puff, kept slow and simple. It checks the 7z-made
 * fixtures a second way and counts which length and distance codes they use.
 */
function reference(data: Uint8Array): { out: Uint8Array; len285: number; dist30: number; dist31: number; maxDist: number; maxLen: number } {
  let pos = 0;
  let bit = 0;
  const get = (n: number) => {
    let v = 0;
    for (let i = 0; i < n; i++) {
      if (pos >= data.length) throw new Error('reference: out of input');
      v |= ((data[pos] >>> bit) & 1) << i;
      if (++bit === 8) {
        bit = 0;
        pos++;
      }
    }
    return v;
  };
  const table = (lens: number[]) => {
    const count = new Array<number>(16).fill(0);
    for (const l of lens) count[l]++;
    count[0] = 0;
    const symbols: number[] = [];
    for (let len = 1; len < 16; len++) for (let s = 0; s < lens.length; s++) if (lens[s] === len) symbols.push(s);
    return { count, symbols };
  };
  const sym = (h: { count: number[]; symbols: number[] }) => {
    let code = 0;
    let first = 0;
    let index = 0;
    for (let len = 1; len < 16; len++) {
      code |= get(1);
      const c = h.count[len];
      if (code - c < first) return h.symbols[index + code - first];
      index += c;
      first = (first + c) << 1;
      code <<= 1;
    }
    throw new Error('reference: bad code');
  };
  const out: number[] = [];
  const stats = { len285: 0, dist30: 0, dist31: 0, maxDist: 0, maxLen: 0 };
  let last = 0;
  while (last === 0) {
    last = get(1);
    const type = get(2);
    if (type === 0) {
      if (bit > 0) {
        bit = 0;
        pos++;
      }
      const len = get(16);
      get(16);
      for (let i = 0; i < len; i++) out.push(get(8));
      continue;
    }
    let lit = table(FIXED_LIT);
    let dist = table(new Array<number>(32).fill(5));
    if (type === 2) {
      const nlen = get(5) + 257;
      const ndist = get(5) + 1;
      const ncode = get(4) + 4;
      const cl = new Array<number>(19).fill(0);
      for (let i = 0; i < ncode; i++) cl[CL_ORDER[i]] = get(3);
      const clt = table(cl);
      const lens: number[] = [];
      while (lens.length < nlen + ndist) {
        const s = sym(clt);
        if (s < 16) lens.push(s);
        else if (s === 16) for (let i = 3 + get(2), v = lens[lens.length - 1]; i > 0; i--) lens.push(v);
        else for (let i = s === 17 ? 3 + get(3) : 11 + get(7); i > 0; i--) lens.push(0);
      }
      lit = table(lens.slice(0, nlen));
      dist = table(lens.slice(nlen));
    }
    for (;;) {
      const s = sym(lit);
      if (s < 256) out.push(s);
      else if (s === 256) break;
      else {
        const length = LBASE[s - 257] + get(LEXT[s - 257]);
        if (s === 285) stats.len285++;
        stats.maxLen = Math.max(stats.maxLen, length);
        const d = sym(dist);
        if (d === 30) stats.dist30++;
        if (d === 31) stats.dist31++;
        const distance = DBASE[d] + get(DEXT[d]);
        stats.maxDist = Math.max(stats.maxDist, distance);
        for (let i = 0; i < length; i++) out.push(out[out.length - distance]);
      }
    }
  }
  return { out: Uint8Array.from(out), ...stats };
}

const CRC = new Int32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c;
});
const crc32 = (b: Uint8Array) => {
  let c = -1;
  for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8);
  return (c ^ -1) >>> 0;
};

/** One entry, method 9, in a minimal ZIP: local header, data, central directory, end record. */
function zip9(stream: Uint8Array, output: Uint8Array): Buffer {
  const name = Buffer.from('a.bin');
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(21, 4);
  local.writeUInt16LE(9, 8);
  local.writeUInt32LE(crc32(output), 14);
  local.writeUInt32LE(stream.length, 18);
  local.writeUInt32LE(output.length, 22);
  local.writeUInt16LE(name.length, 26);
  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(21, 4);
  central.writeUInt16LE(21, 6);
  central.writeUInt16LE(9, 10);
  central.writeUInt32LE(crc32(output), 16);
  central.writeUInt32LE(stream.length, 20);
  central.writeUInt32LE(output.length, 24);
  central.writeUInt16LE(name.length, 28);
  const cdOffset = 30 + name.length + stream.length;
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(1, 8);
  end.writeUInt16LE(1, 10);
  end.writeUInt32LE(46 + name.length, 12);
  end.writeUInt32LE(cdOffset, 16);
  return Buffer.concat([local, name, stream, central, name, end]);
}

/** Deterministic bytes: xorshift32. */
function pseudo(seed: number, n: number): Uint8Array {
  let s = seed;
  const b = new Uint8Array(n);
  for (let i = 0; i < n; i++) {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    b[i] = s & 0xff;
  }
  return b;
}

const ascii = (s: string) => Uint8Array.from(Buffer.from(s));
const repeat = (b: Uint8Array, n: number) => Buffer.concat(new Array<Uint8Array>(n).fill(b));

interface Crafted {
  name: string;
  stream: Uint8Array;
  output: Uint8Array;
}

/** Valid hand-made streams, each with the output it must decode to. */
function crafted(): Crafted[] {
  const list: Crafted[] = [];

  {
    const w = new Bits().fixed(true);
    for (const b of ascii('hello, ')) w.lit(FIXED, b);
    w.match(FIXED, 5, 7).lit(FIXED, 256);
    list.push({ name: 'fixed block with a match', stream: w.bytes(), output: ascii('hello, hello') });
  }
  {
    const w = new Bits().fixed(true);
    w.lit(FIXED, 0x61).match(FIXED, 100, 1);
    for (const b of ascii('xyz')) w.lit(FIXED, b);
    w.match(FIXED, 10, 3).lit(FIXED, 256);
    list.push({ name: 'matches that overlap themselves', stream: w.bytes(), output: Buffer.concat([repeat(ascii('a'), 101), ascii('xyzxyzxyzxyzx')]) });
  }
  {
    const w = new Bits().stored(false, new Uint8Array(0)).stored(false, ascii('stored ')).fixed(false);
    w.lit(FIXED, 0x41).lit(FIXED, 256);
    w.stored(true, pseudo(5, 65535));
    list.push({ name: 'stored blocks, empty and full, between fixed blocks', stream: w.bytes(), output: Buffer.concat([ascii('stored A'), pseudo(5, 65535)]) });
  }
  {
    // Length code 285 with extra values 0, 255 and 65535, in fixed and dynamic blocks.
    const w = new Bits().fixed(false);
    w.lit(FIXED, 0x7a).raw(FIXED, 285, 0, 0, 0).raw(FIXED, 285, 255, 0, 0).raw(FIXED, 285, 65535, 0, 0).lit(FIXED, 256);
    const c = w.dynamic(true, STD_LIT, new Array<number>(32).fill(5));
    w.raw(c, 285, 0, 0, 0).raw(c, 285, 255, 0, 0).raw(c, 285, 65535, 0, 0).lit(c, 256);
    list.push({ name: 'length code 285 with extra 0, 255, 65535', stream: w.bytes(), output: repeat(ascii('z'), 1 + 2 * (3 + 258 + 65538)) });
  }
  {
    // 65,536 bytes of known data, then copies from 32,769 back (code 30, extra 0) and 65,536 back (code 31, extra 16383).
    const base = pseudo(7, 65536);
    const w = new Bits().stored(false, base.subarray(0, 65535)).stored(false, base.subarray(65535));
    const c = w.dynamic(false, STD_LIT, new Array<number>(32).fill(5));
    w.raw(c, 284, 31, 30, 0).raw(c, 284, 31, 31, 16383).lit(c, 256);
    w.fixed(true).match(FIXED, 300, 32769).match(FIXED, 4, 65536).lit(FIXED, 256);
    const out = [...base];
    const copy = (len: number, dist: number) => {
      for (let i = 0; i < len; i++) out.push(out[out.length - dist]);
    };
    copy(258, 32769);
    copy(258, 65536);
    copy(300, 32769);
    copy(4, 65536);
    list.push({ name: 'distances 32,769 and 65,536', stream: w.bytes(), output: Uint8Array.from(out) });
  }
  {
    // zlib inftrees.c allows one incomplete code: a single code of length 1. Here it is the distance code.
    const w = new Bits();
    const c = w.dynamic(true, STD_LIT, [1]);
    w.lit(c, 0x62).match(c, 9, 1).lit(c, 256);
    list.push({ name: 'a distance code of one 1-bit code', stream: w.bytes(), output: repeat(ascii('b'), 10) });
  }
  {
    // A distance code with no lengths at all is allowed while no distance is decoded.
    const w = new Bits();
    const c = w.dynamic(true, STD_LIT, [0]);
    for (const b of ascii('no matches')) w.lit(c, b);
    w.lit(c, 256);
    list.push({ name: 'an empty distance code', stream: w.bytes(), output: ascii('no matches') });
  }
  {
    // Repeat codes 16, 17 and 18 in a dynamic header. Distance code: symbols 0 and 31 of one bit each, 30 zeros between.
    const syms: Array<[number, number]> = [[9, 0]];
    for (let have = 1; have < 256; ) {
      const n = Math.min(6, 256 - have);
      syms.push(n >= 3 ? [16, n - 3] : [9, 0]);
      have += n >= 3 ? n : 1;
    }
    syms.push([6, 0], [16, 3], [16, 3], [16, 3], [16, 3], [16, 0], [5, 0], [5, 0]);
    syms.push([1, 0], [18, 9], [17, 7], [1, 0]);
    const dist = [1, ...new Array<number>(30).fill(0), 1];
    const w = new Bits();
    const c = w.dynamic(true, STD_LIT, dist, { clSyms: syms });
    w.lit(c, 0x63).match(c, 4, 1).lit(c, 256);
    list.push({ name: 'a dynamic header written with repeat codes 16, 17 and 18', stream: w.bytes(), output: repeat(ascii('c'), 5) });
  }
  return list;
}

describe('inflate64', () => {
  describe('7z-made streams', () => {
    for (const name of Object.keys(manifest).sort()) {
      it(`decodes ${name} to the input 7z compressed, using every byte`, async () => {
        const input = fixture(name);
        const consumed = { bytes: -1 };
        const out = await decode(once(input), consumed);
        expect(out.length).to.equal(manifest[name].size);
        expect(sha256(out)).to.equal(manifest[name].sha256);
        expect(consumed.bytes).to.equal(input.length);
      });
    }

    // 7z's Deflate64 encoder never writes length code 285 (its longest match here is 257, as code 284), so the
    // hand-made streams cover 285, and 7z t checks those.
    it('agree with an independent bit-at-a-time decoder, and cover distance codes 30 and 31', () => {
      const totals = { len285: 0, dist30: 0, dist31: 0 };
      const covered: string[] = [];
      for (const name of Object.keys(manifest).sort()) {
        const r = reference(fixture(name));
        expect(sha256(r.out), name).to.equal(manifest[name].sha256);
        totals.len285 += r.len285;
        totals.dist30 += r.dist30;
        totals.dist31 += r.dist31;
        covered.push(`${name}: 285 x${r.len285}, d30 x${r.dist30}, d31 x${r.dist31}, max distance ${r.maxDist}, max length ${r.maxLen}`);
      }
      if (process.env.D64_COVERAGE) console.log(covered.join('\n'));
      expect(totals.dist30, covered.join('\n')).to.be.above(0);
      expect(totals.dist31, covered.join('\n')).to.be.above(0);
    });
  });

  describe('hand-made streams', () => {
    for (const c of crafted()) {
      it(`decodes ${c.name}`, async () => {
        const consumed = { bytes: -1 };
        const out = await decode(once(c.stream), consumed);
        expect(out.length).to.equal(c.output.length);
        expect(Buffer.from(out).equals(Buffer.from(c.output))).to.equal(true);
        expect(consumed.bytes).to.equal(c.stream.length);
      });

      it(`agrees with 7z on ${c.name}`, function () {
        if (!has7z) this.skip();
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'inflate64-'));
        try {
          const file = path.join(dir, 'crafted.zip');
          fs.writeFileSync(file, zip9(c.stream, c.output));
          const test = spawnSync('7z', ['t', file], { encoding: 'utf8' });
          expect(test.status, test.stdout + test.stderr).to.equal(0);
          expect(test.stdout).to.contain('Everything is Ok');
          const out = execFileSync('7z', ['x', '-so', file], { maxBuffer: 1 << 26, stdio: ['ignore', 'pipe', 'ignore'] });
          expect(sha256(out)).to.equal(sha256(c.output));
        } finally {
          fs.rmSync(dir, { recursive: true, force: true });
        }
      });
    }
  });

  describe('stream end and chunking', () => {
    it('gives the same output and count fed one byte at a time and as one chunk', async () => {
      for (const s of [fixture('far-mx9'), fixture('text-mx1'), ...crafted().map(c => c.stream)]) {
        const a = { bytes: 0 };
        const b = { bytes: 0 };
        const whole = await decode(once(s), a);
        const bytes = await decode(bytewise(s), b);
        expect(sha256(bytes)).to.equal(sha256(whole));
        expect(a.bytes).to.equal(s.length);
        expect(b.bytes).to.equal(s.length);
      }
    });

    it('counts only the bytes the stream used when more follow, in one chunk or byte by byte', async () => {
      for (const s of [fixture('runs-mx9'), fixture('empty-mx9'), ...crafted().map(c => c.stream)]) {
        const tail = ascii('TRAILING');
        const joined = Buffer.concat([s, tail]);
        const a = { bytes: 0 };
        const b = { bytes: 0 };
        await decode(once(joined), a);
        await decode(bytewise(joined), b);
        expect(a.bytes).to.equal(s.length);
        expect(b.bytes).to.equal(s.length);
      }
    });

    it('does not pull another chunk once the final block is done', async () => {
      const s = fixture('text-mx9');
      const source = (async function* () {
        yield s;
        throw new Error('read past the stream');
      })();
      const consumed = { bytes: 0 };
      const out = await decode(source, consumed);
      expect(sha256(out)).to.equal(manifest['text-mx9'].sha256);
      expect(consumed.bytes).to.equal(s.length);
    });

    it('keeps the count current while it decodes', async () => {
      const s = fixture('big-mx9');
      const consumed = { bytes: 0 };
      const seen: number[] = [];
      for await (const _ of inflate64(bytewise(s), consumed)) seen.push(consumed.bytes);
      expect(seen.length).to.be.above(10);
      expect(seen[0]).to.be.above(0).and.below(s.length);
      for (let i = 1; i < seen.length; i++) expect(seen[i]).to.be.at.least(seen[i - 1]);
      expect(consumed.bytes).to.equal(s.length);
    });

    it('reports every cut-short stream as truncated', async () => {
      for (const s of [fixture('empty-mx1'), fixture('runs-mx9'), ...crafted().map(c => c.stream)]) {
        const step = Math.max(1, Math.floor(s.length / 300));
        for (let n = 0; n < s.length; n += step) await expectData(s.subarray(0, n), /ends before its final block/, true);
        await expectData(s.subarray(0, s.length - 1), /ends before its final block/, true);
      }
    });
  });

  describe('corrupt data', () => {
    const dist32 = new Array<number>(32).fill(5);
    const header = (lit: number[], dist: number[], opts?: { nlen?: number; clLens?: number[]; clSyms?: Array<[number, number]> }) => {
      const w = new Bits();
      w.dynamic(true, lit, dist, opts);
      return w.put(0, 32).bytes();
    };

    it('rejects an over-subscribed literal/length code', async () => {
      const lit = STD_LIT.slice();
      lit[0] = 1;
      await expectData(header(lit, dist32), /literal\/length code is invalid: over-subscribed/);
    });

    it('rejects an incomplete literal/length code', async () => {
      const lit = STD_LIT.slice();
      lit[0] = 0;
      await expectData(header(lit, dist32), /literal\/length code is invalid: incomplete/);
    });

    it('rejects an over-subscribed distance code', async () => {
      await expectData(header(STD_LIT, new Array<number>(32).fill(4)), /distance code is invalid: over-subscribed/);
    });

    it('rejects an incomplete distance code longer than one bit', async () => {
      await expectData(header(STD_LIT, [5, 0, 0, 0, 0, 0, 5]), /distance code is invalid: incomplete/);
      await expectData(header(STD_LIT, [2, 2, 2]), /distance code is invalid: incomplete/);
    });

    it('rejects an incomplete code-length code, even one of a single 1-bit code', async () => {
      await expectData(header(STD_LIT, dist32, { clLens: new Array<number>(19).fill(5) }), /code-length code is invalid: incomplete/);
      const one = new Array<number>(19).fill(0);
      one[0] = 1;
      await expectData(header(STD_LIT, dist32, { clLens: one, clSyms: [[0, 0]] }), /code-length code is invalid: incomplete/);
    });

    it('rejects an over-subscribed code-length code and one with no lengths', async () => {
      await expectData(header(STD_LIT, dist32, { clLens: new Array<number>(19).fill(3) }), /code-length code is invalid: over-subscribed/);
      await expectData(header(STD_LIT, dist32, { clLens: new Array<number>(19).fill(0), clSyms: [] }), /code-length code is invalid: no codes/);
    });

    it('rejects the unused half of a single 1-bit distance code', async () => {
      const w = new Bits();
      const c = w.dynamic(true, STD_LIT, [1]);
      w.lit(c, 0x62).lit(c, 257).put(1, 1).put(0, 32);
      await expectData(w.bytes(), /distance code has no meaning/);
    });

    it('rejects a match when the distance code is empty', async () => {
      const w = new Bits();
      const c = w.dynamic(true, STD_LIT, [0]);
      w.lit(c, 0x62).lit(c, 257).put(0, 32);
      await expectData(w.bytes(), /distance code has no meaning/);
    });

    it('rejects literal/length codes 286 and 287', async () => {
      for (const sym of [286, 287]) await expectData(new Bits().fixed(true).lit(FIXED, sym).put(0, 32).bytes(), /286 or 287/);
    });

    it('rejects a distance past the start of the output', async () => {
      await expectData(new Bits().fixed(true).lit(FIXED, 1).match(FIXED, 3, 2).lit(FIXED, 256).bytes(), /before the start of the output/);
      const w = new Bits().stored(false, pseudo(3, 65535));
      await expectData(w.fixed(true).match(FIXED, 3, 65536).lit(FIXED, 256).bytes(), /before the start of the output/);
    });

    it('rejects a stored block whose LEN and NLEN disagree', async () => {
      await expectData(new Bits().stored(true, ascii('abc'), 0).bytes(), /stored block lengths/);
    });

    it('rejects block type 3', async () => {
      await expectData(new Bits().put(1, 1).put(3, 2).put(0, 16).bytes(), /block type 3/);
    });

    it('rejects a repeat code with no previous length', async () => {
      await expectData(header(STD_LIT, dist32, { clSyms: [[16, 0]] }), /repeat code with no previous length/);
    });

    it('rejects code lengths that run past HLIT + HDIST', async () => {
      const syms: Array<[number, number]> = STD_LIT.map(l => [l, 0]);
      for (let i = 0; i < 31; i++) syms.push([5, 0]);
      syms.push([16, 0]);
      await expectData(header(STD_LIT, dist32, { clSyms: syms }), /run past HLIT \+ HDIST/);
      await expectData(header(STD_LIT, dist32, { clSyms: [...STD_LIT.map((l): [number, number] => [l, 0]), [18, 127]] }), /run past HLIT \+ HDIST/);
    });

    it('rejects more than 286 literal/length codes', async () => {
      await expectData(header([...STD_LIT, 0], dist32, { nlen: 287 }), /too many literal\/length codes/);
    });

    it('rejects a literal/length code with no end-of-block', async () => {
      const lit = STD_LIT.slice();
      lit[256] = 0;
      await expectData(header(lit, dist32), /no end-of-block/);
    });
  });

  describe('limits', () => {
    /** About 3.7 KB that decodes to 64 MiB: a literal, then 1,024 matches of 65,538 bytes at distance 1. */
    const bomb = () => {
      const w = new Bits().fixed(true).lit(FIXED, 0x42);
      for (let i = 0; i < 1024; i++) w.raw(FIXED, 285, 65535, 0, 0);
      return w.lit(FIXED, 256).bytes();
    };

    it('yields a bomb in chunks of at most 64 KiB and stops when the caller does', async () => {
      const s = bomb();
      expect(s.length).to.be.below(4000);
      let closed = false;
      const source = (async function* () {
        try {
          yield s;
        } finally {
          closed = true;
        }
      })();
      let chunks = 0;
      let bytes = 0;
      for await (const c of inflate64(source)) {
        expect(c.length).to.be.at.most(65536);
        chunks++;
        bytes += c.length;
        if (chunks === 3) break;
      }
      expect(chunks).to.equal(3);
      expect(bytes).to.equal(3 * 65536);
      expect(closed).to.equal(true);
    });

    it('decodes the whole bomb to 64 MiB', async () => {
      let bytes = 0;
      for await (const c of inflate64(once(bomb()))) {
        expect(c.length).to.be.at.most(65536);
        bytes += c.length;
      }
      expect(bytes).to.equal(1 + 1024 * 65538);
    });

    it('throws the time limit error for a deadline already past', async () => {
      const e = await (async () => {
        try {
          await decode(once(fixture('text-mx9')), undefined, Date.now() - 1);
        } catch (err) {
          return err;
        }
        return undefined;
      })();
      expect(e).to.be.instanceOf(TimeLimitError);
      expect((e as TimeLimitError).code).to.equal('DEFUSE_LIMIT');
    });

    it('checks the clock once per block, so many empty blocks cannot outrun the deadline', async () => {
      const w = new Bits();
      for (let i = 0; i < 5000; i++) w.fixed(false).lit(FIXED, 256);
      const s = w.fixed(true).lit(FIXED, 256).bytes();
      const real = Date.now;
      let calls = 0;
      Date.now = () => {
        calls++;
        return 0;
      };
      try {
        await decode(once(s), undefined, 1);
      } finally {
        Date.now = real;
      }
      expect(calls).to.be.at.least(5001);
    });

    it('checks the clock for every 64 KiB of output inside one block', async () => {
      const real = Date.now;
      let calls = 0;
      Date.now = () => {
        calls++;
        return 0;
      };
      try {
        await decode(once(new Bits().fixed(true).lit(FIXED, 0).raw(FIXED, 285, 65535, 0, 0).raw(FIXED, 285, 65535, 0, 0).raw(FIXED, 285, 65535, 0, 0).lit(FIXED, 256).bytes()), undefined, 1);
      } finally {
        Date.now = real;
      }
      expect(calls).to.be.at.least(4);
    });
  });
});
