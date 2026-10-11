import * as crypto from 'node:crypto';
import { expect } from 'chai';
import { deriveKey, parseAesProps } from '../src/aes7z';
import { Crc64, makeCheck } from '../src/checks';
import { Lzma2Feeder } from '../src/coders';
import { crc32, tableCrc32 } from '../src/crc32';
import { RawLzmaEncoder } from '../src/encoder';
import { DeltaStream, SimpleFilterStream } from '../src/filters';
import { detectLzmaFormat, looksLikeLzma } from '../src/lzma-sniff';
import { Lzma1Stream } from '../src/lzma1-stream';
import { HeaderReader } from '../src/sevenzip';

describe('checks', () => {
  it('computes CRC-32 with the table and with zlib alike', () => {
    const b = crypto.randomBytes(5000);
    expect(tableCrc32(b)).to.equal(crc32(b));
    expect(tableCrc32(Buffer.from('123456789'))).to.equal(0xcbf43926);
  });

  it('computes the CRC-64 of xz', () => {
    const c = new Crc64();
    c.update(Buffer.from('123456789'));
    expect(Buffer.from(c.digest()).readBigUInt64LE()).to.equal(0x995dc9bbdf1939fan);
  });

  it('makes no check for an unknown ID', () => {
    expect(makeCheck(2)).to.equal(undefined);
    expect(makeCheck(0)?.digest().length).to.equal(0);
    expect(makeCheck(10)?.digest().length).to.equal(32);
  });
});

describe('sniffing', () => {
  it('detects xz, 7z and lzma by content', () => {
    expect(detectLzmaFormat(Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0, 0]))?.format).to.equal('xz');
    expect(detectLzmaFormat(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4]))?.format).to.equal('7z');
    expect(looksLikeLzma(Buffer.from('5d00000100ffffffffffffffff0000', 'hex'))).to.equal(true);
    expect(looksLikeLzma(Buffer.from('5d00000500ffffffffffffffff0000', 'hex'))).to.equal(false);
    expect(looksLikeLzma(Buffer.from('plain text and more text'))).to.equal(false);
  });
});

describe('7z numbers', () => {
  it('reads each length of number', () => {
    const r = new HeaderReader(Buffer.from([0x7f, 0x80, 0x80, 0xc0, 0x00, 0x40, 0xff, 1, 2, 3, 4, 5, 6, 0, 0]));
    expect(r.number()).to.equal(0x7f);
    expect(r.number()).to.equal(0x80);
    expect(r.number()).to.equal(0x4000);
    expect(r.number()).to.equal(0x060504030201 + 0);
  });

  it('refuses a count larger than the bytes left', () => {
    const r = new HeaderReader(Buffer.from([0x90, 0x00]));
    expect(() => r.count(1)).to.throw(/larger than the header/);
  });
});

describe('streaming decoders', () => {
  const lzma1 = (data: Buffer) => {
    const e = new RawLzmaEncoder(data.length);
    return Buffer.concat([e.write(data), e.finish()]);
  };

  it('decodes LZMA1 fed a byte at a time as it decodes it whole', () => {
    const data = Buffer.from('abcabcabc '.repeat(500));
    const packed = lzma1(data);
    const run = (step: number) => {
      const out: Buffer[] = [];
      const s = new Lzma1Stream({ lc: 3, lp: 0, pb: 2, dictSize: 1 << 16 }, data.length, c => out.push(Buffer.from(c)), true);
      for (let i = 0; i < packed.length; i += step) s.write(packed.subarray(i, i + step));
      s.end();
      return Buffer.concat(out);
    };
    expect(run(1).equals(data)).to.equal(true);
    expect(run(packed.length).equals(data)).to.equal(true);
  });

  it('feeds LZMA2 a chunk at a time and knows where it ends', () => {
    const f = new Lzma2Feeder(1 << 16);
    const used = f.push(Buffer.from([0x01, 0x00, 0x02, 0x61, 0x62, 0x63, 0x00, 0x99, 0x99]));
    expect(used).to.equal(7);
    expect(f.ended).to.equal(true);
    expect(Buffer.concat(f.take()).toString()).to.equal('abc');
  });

  it('runs branch filters on pieces as on the whole', () => {
    const data = crypto.randomBytes(10000);
    for (let i = 0; i < data.length - 8; i += 37) data[i] = 0xe8;
    for (const kind of ['x86', 'powerpc', 'ia64', 'arm', 'armthumb', 'sparc', 'arm64', 'riscv'] as const) {
      const whole = new SimpleFilterStream(kind, 0);
      const a = Buffer.concat([whole.push(Buffer.from(data)), whole.end()]);
      const piecewise = new SimpleFilterStream(kind, 0);
      const parts: Uint8Array[] = [];
      for (let i = 0; i < data.length; i += 7) parts.push(Buffer.from(piecewise.push(Buffer.from(data.subarray(i, i + 7)))));
      parts.push(piecewise.end());
      expect(Buffer.concat(parts).equals(a), kind).to.equal(true);
    }
    const d = new DeltaStream(2);
    expect(Buffer.from(d.push(Buffer.from([1, 2, 1, 1, 1, 1]))).toString('hex')).to.equal('010202030304');
  });
});

describe('7zAES', () => {
  it('reads properties and refuses more than 2^24 rounds', () => {
    const p = parseAesProps(Buffer.concat([Buffer.from([0xc0 | 19, 0xff]), Buffer.alloc(32, 1)]));
    expect(p.numCyclesPower).to.equal(19);
    expect(p.salt.length).to.equal(16);
    expect(() => parseAesProps(Buffer.from([0x1e]))).to.throw(/2\^30/);
    expect(() => parseAesProps(Buffer.from([0xc0 | 19, 0x00, 1, 2, 3]))).to.throw(/do not match/);
  });

  it('derives the key 7-Zip derives, in batches', () => {
    const props = { numCyclesPower: 4, salt: Buffer.from('salt'), iv: new Uint8Array(16) };
    const pw = Buffer.from('pw', 'utf16le');
    const h = crypto.createHash('sha256');
    for (let r = 0; r < 16; r++) {
      const c = Buffer.alloc(8);
      c.writeUInt32LE(r);
      h.update(Buffer.concat([props.salt, pw, c]));
    }
    expect(deriveKey('pw', props, undefined).equals(h.digest())).to.equal(true);
    expect(
      deriveKey('pw', { ...props, numCyclesPower: 0x3f }, undefined)
        .subarray(0, 8)
        .equals(Buffer.concat([props.salt, pw])),
    ).to.equal(true);
  });
});
