import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { bufferSource, inspectArchive } from '../src';
import { type Bzip2Info, bunzip2 } from '../src/bzip2';
import { cabChecksum } from '../src/cab';
import { collect } from '../src/codecs';
import { crc32, tableCrc32 } from '../src/crc32';
import { DataError, UnsupportedError } from '../src/errors';
import { looksLikeBrotli } from '../src/single';
import { extensionOf } from '../src/sniff';
import { numeric, parsePax } from '../src/tar';
import { AesCtr, aesKeys, pbkdf2Sha1, ZipCryptoKeys, zipCryptoOpens } from '../src/zipcrypt';
import { zstdLayout } from '../src/zstd';
import { build, failure, keepAll, kinds } from './helpers/util';

const once = (b: Uint8Array) =>
  (async function* () {
    yield b;
  })();

describe('CRC-32', () => {
  // Copied from office-defuse test/crc32.test.ts.
  it('uses zlib.crc32 when Node has it', () => {
    const native = (zlib as { crc32?: unknown }).crc32;
    expect(crc32).to.equal(native ?? tableCrc32);
  });

  it('gives the check value of the ZIP CRC-32 from the table', () => {
    expect(tableCrc32(Buffer.from('123456789'))).to.equal(0xcbf43926);
    expect(crc32(Buffer.from('123456789'))).to.equal(0xcbf43926);
    expect(tableCrc32(new Uint8Array(0))).to.equal(0);
  });

  it('gives the same value from the table and from crc32, whole and continued across pieces', () => {
    for (const size of [1, 7, 1000, 65537]) {
      const data = crypto.randomBytes(size);
      const cut = Math.floor(size / 3);
      expect(tableCrc32(data), `size ${size}`).to.equal(crc32(data));
      expect(tableCrc32(data.subarray(cut), tableCrc32(data.subarray(0, cut))), `size ${size}`).to.equal(crc32(data));
    }
  });
});

describe('ZIP encryption', () => {
  it('derives keys with PBKDF2 over HMAC-SHA1 as RFC 6070 gives them', () => {
    expect(pbkdf2Sha1(Buffer.from('password'), Buffer.from('salt'), 2, 20).toString('hex')).to.equal('ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957');
    expect(pbkdf2Sha1(Buffer.from('passwordPASSWORDpassword'), Buffer.from('saltSALTsaltSALTsaltSALTsaltSALTsalt'), 4096, 25).toString('hex')).to.equal(
      '3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038',
    );
  });

  it('runs AES in counter mode with a little-endian counter that starts at 1', () => {
    const key = Buffer.alloc(16, 1);
    const ecb = crypto.createCipheriv('aes-128-ecb', key, null);
    ecb.setAutoPadding(false);
    const counter = Buffer.alloc(32);
    counter[0] = 1;
    counter[16] = 2;
    const pad = ecb.update(counter);
    const data = Buffer.alloc(32, 0x5a);
    const ctr = new AesCtr(key);
    // Pieces of any length give the same key stream.
    const out = Buffer.concat([ctr.apply(data.subarray(0, 5)), ctr.apply(data.subarray(5))]);
    expect(out.equals(Buffer.from(data.map((b, i) => b ^ pad[i])))).to.equal(true);
    expect(aesKeys(Buffer.from('pw'), Buffer.alloc(16), 256).key.length).to.equal(32);
  });

  it("encrypts and decrypts PKWARE's traditional cipher, and checks the header's last byte", () => {
    const data = Buffer.concat([Buffer.alloc(11, 1), Buffer.from([0xab]), Buffer.from('secret data')]);
    const enc = new ZipCryptoKeys(Buffer.from('pw')).encrypt(data);
    expect(Buffer.from(new ZipCryptoKeys(Buffer.from('pw')).decrypt(enc)).equals(data)).to.equal(true);
    expect(zipCryptoOpens(enc.subarray(0, 12), Buffer.from('pw'), 0xab)).to.equal(true);
    expect(zipCryptoOpens(enc.subarray(0, 12), Buffer.from('px'), 0xab)).to.equal(false);
  });
});

describe('bzip2', () => {
  const decode = (b: Uint8Array, multi = true) => collect(bunzip2(once(b), { streams: [], trailing: 0, trailingZeros: true } as Bzip2Info, multi));

  it('decodes an empty stream and refuses degenerate and cut-short data as DataError', async () => {
    expect((await decode(Buffer.from('425a683917724538509000000000', 'hex'))).length).to.equal(0);
    for (const bad of [Buffer.alloc(0), Buffer.from('BZh9'), Buffer.from('BZh91AY&SY'), build.BZ.text.subarray(0, 30), Buffer.concat([Buffer.from('BZh9'), Buffer.alloc(100, 0xff)])]) {
      expect(await failure(decode(bad)), bad.toString('hex').slice(0, 20)).to.be.instanceOf(DataError);
    }
  });

  it('refuses data after the stream inside a ZIP entry, and reads several streams in a file', async () => {
    expect(await failure(decode(Buffer.concat([build.BZ.one, build.BZ.two]), false))).to.be.instanceOf(DataError);
    expect((await decode(Buffer.concat([build.BZ.one, build.BZ.two]))).toString()).to.equal('first stream\nsecond stream\n');
  });
});

describe('zstd frames', () => {
  const layout = (b: Buffer, single = false) =>
    zstdLayout(
      async (o, n) => b.subarray(o, o + n),
      0,
      b.length,
      single,
      () => undefined,
    );

  it('walks frames without decoding them, and counts what follows', async () => {
    const l = await layout(Buffer.concat([build.ZS.one, build.ZS.two, Buffer.from('tail')]));
    expect(l.frames.map(f => f.end - f.start)).to.deep.equal([build.ZS.one.length, build.ZS.two.length]);
    expect([l.trailing, l.trailingZeros]).to.deep.equal([4, false]);
  });

  it('refuses a frame cut short, a reserved block and a frame that needs a dictionary', async () => {
    expect(await failure(layout(build.ZS.text.subarray(0, build.ZS.text.length - 3)))).to.be.instanceOf(DataError);
    const dict = Buffer.from(build.ZS.text);
    dict[4] |= 1;
    expect(await failure(layout(Buffer.concat([dict.subarray(0, 5), Buffer.from([7]), dict.subarray(5)])))).to.be.instanceOf(UnsupportedError);
    expect(await failure(layout(Buffer.from('not zstd'), true))).to.be.instanceOf(DataError);
  });
});

describe('Brotli detection', () => {
  it('takes content that decodes as Brotli and ends with its stream, and nothing else', async () => {
    const yes = zlib.brotliCompressSync(Buffer.from('hello hello hello'));
    expect(await looksLikeBrotli(bufferSource(yes))).to.equal(true);
    for (const no of [Buffer.from('plain text\n'), Buffer.concat([yes, Buffer.from('x')]), Buffer.alloc(0), Buffer.from(';garbage')]) {
      expect(await looksLikeBrotli(bufferSource(no)), JSON.stringify(no.toString())).to.equal(false);
    }
    const big = zlib.brotliCompressSync(crypto.randomBytes(200_000));
    expect(await looksLikeBrotli(bufferSource(big))).to.equal(true);
    // Incompressible data goes into uncompressed meta-blocks, whose bytes decode as anything until the next header.
    expect(await looksLikeBrotli(bufferSource(Buffer.concat([big.subarray(0, 150_000), crypto.randomBytes(50_000)])))).to.equal(false);
  });
});

describe('tar fields', () => {
  it('reads octal and base-256 numbers, negative ones included, and refuses values past a safe integer', () => {
    const field = (b: number[]) => numeric(Uint8Array.from(b), 0, b.length);
    expect(field([0x30, 0x37, 0x37, 0x37, 0x20, 0])).to.equal(0o777);
    expect(field([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x00])).to.equal(512);
    expect(field([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00])).to.equal(-512);
    expect(field([0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])).to.equal(undefined);
    expect(field([0x31, 0x78])).to.equal(undefined);
  });

  it('parses pax records, keeps an all-digit value as text, and stops at a malformed record', () => {
    const ok = parsePax(Buffer.concat([build.paxRecord('path', '12345'), build.paxRecord('linkpath', Buffer.from('a\0b'))]));
    expect(ok.records.map(r => [r.key, r.value.toString('latin1')])).to.deep.equal([
      ['path', '12345'],
      ['linkpath', 'a\0b'],
    ]);
    for (const bad of ['5 a=b', 'x path=y\n', '99 path=y\n', '9 nokey\n']) expect(parsePax(Buffer.from(bad)).malformed, bad).to.be.a('string');
  });

  it('refuses a negative size and cuts a pax name at a NUL, as GNU tar does', async () => {
    const negative = build.tar(build.tarEntry({ name: 'a', size: Buffer.from([0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0x00]) }));
    expect(kinds(await inspectArchive(negative, { filePlugins: [keepAll] }))).to.deep.equal(['CORRUPTED/UNPARSEABLE']);
    const nul = build.tar(build.pax([['path', Buffer.from('visible.txt\0hidden.txt')]]), build.tarEntry({ name: 'x' }, 'x'));
    const r = await inspectArchive(nul, { filePlugins: [keepAll] });
    expect(r.findings.map(f => [f.detail, f.location])).to.deep.equal([
      ['MALFORMED_HEADER', 'entry "visible.txt"'],
      ['PLUGIN_PASSED', 'entry "visible.txt"'],
    ]);
  });
});

describe('cabinet checksum', () => {
  it('XORs little-endian words and takes an odd tail high byte first', () => {
    expect(cabChecksum(Buffer.from([1, 0, 0, 0, 2, 0, 0, 0]))).to.equal(3);
    expect(cabChecksum(Buffer.from([1, 2, 3]))).to.equal(0x010203);
    expect(cabChecksum(Buffer.from([1, 2]))).to.equal(0x0102);
    expect(cabChecksum(Buffer.from([1]), 0x100)).to.equal(0x101);
  });
});

describe('extensions', () => {
  it('takes the extension after dots and spaces Windows drops, in linear time on long runs', () => {
    expect(extensionOf('page.html. ')).to.equal('html');
    const started = Date.now();
    expect(extensionOf(`a${'.'.repeat(200_000)} `)).to.equal(undefined);
    expect(extensionOf(`${'.'.repeat(200_000)}x`)).to.equal('x');
    expect(Date.now() - started).to.be.lessThan(500);
  });
});
