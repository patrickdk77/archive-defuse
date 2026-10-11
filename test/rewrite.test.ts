import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { type ArchiveCategory, type ArchiveDetail, type ContainedFilePlugin, disarmArchive, inspectArchive } from '../src';
import { bunzip2, bzip2 } from '../src/bzip2';
import { collect } from '../src/codecs';
import { build, fixture, hasZstd, keepAll, kinds, must, pythonList, sha16 } from './helpers/util';

const { zip, tar, tarEntry, gzipMember, text, BZ } = build;
const keep = { filePlugins: [keepAll] };
const info = (category: string, detail: string) => ({ category: category as ArchiveCategory, detail: detail as ArchiveDetail, action: 'info' as const });

/** A plugin that rewrites text entries in upper case and keeps everything else. */
const upper: ContainedFilePlugin = {
  kind: 'file',
  name: 'upper',
  accepts: () => true,
  async process(file, sink) {
    if (!file.name?.endsWith('.txt')) return 'passed';
    const size = await file.source.size();
    await sink.write(
      Buffer.from(
        Buffer.from(await file.source.read(0, size))
          .toString('latin1')
          .toUpperCase(),
        'latin1',
      ),
    );
    return 'scrubbed';
  },
};

/** Every local header's compressed bytes in a ZIP, by entry name. */
function compressedBytes(z: Uint8Array): Map<string, string> {
  const b = Buffer.from(z);
  const out = new Map<string, string>();
  for (let p = b.indexOf(Buffer.from([0x50, 0x4b, 3, 4])); p >= 0; p = b.indexOf(Buffer.from([0x50, 0x4b, 3, 4]), p + 30)) {
    const csize = b.readUInt32LE(p + 18);
    const nameLength = b.readUInt16LE(p + 26);
    const extraLength = b.readUInt16LE(p + 28);
    const name = b.toString('utf8', p + 30, p + 30 + nameLength);
    out.set(name, sha16(b.subarray(p + 30 + nameLength + extraLength, p + 30 + nameLength + extraLength + csize)));
  }
  return out;
}

describe('the rewrite', () => {
  it('writes a ZIP that Python reads, keeps compressed bytes nothing changed, and compresses again what a plugin rewrote', async () => {
    const source = zip([text('a.txt'), { name: 'b.bin', data: Buffer.alloc(5000, 7) }, { name: 'stored.bin', data: 'stored bytes', method: 0 }]);
    const r = await disarmArchive(source, { filePlugins: [upper] });
    expect(r.status).to.equal('defused');
    const out = must(r.bytes, 'output');
    const listed = pythonList('zip', out);
    expect(listed.map(e => e[0])).to.deep.equal(['a.txt', 'b.bin', 'stored.bin']);
    const before = compressedBytes(source);
    const after = compressedBytes(out);
    expect(after.get('b.bin')).to.equal(before.get('b.bin'));
    expect(after.get('stored.bin')).to.equal(before.get('stored.bin'));
    expect(after.get('a.txt')).to.not.equal(before.get('a.txt'));
    expect(listed[0][2]).to.equal(sha16(Buffer.from('A.TXT HOLDS PLAIN TEXT.\n')));
  });

  it('removes entries and their directory records, and fixes names in both headers', async () => {
    const r = await disarmArchive(zip([text('../up.txt'), { name: 'dev', data: '', method: 0, mode: 0o020644 }, text('kept.txt')]), keep);
    const out = Buffer.from(must(r.bytes, 'output'));
    expect(pythonList('zip', out).map(e => e[0])).to.deep.equal(['up.txt', 'kept.txt']);
    expect(out.includes(Buffer.from('../up.txt'))).to.equal(false);
    expect(out.includes(Buffer.from('dev'))).to.equal(false);
  });

  it('writes decrypted entries without encryption, copying their compressed bytes', async () => {
    const r = await disarmArchive(fixture('zip-aes.zip'), { ...keep, password: 'battery staple' });
    const listed = pythonList('zip', must(r.bytes, 'output'));
    expect(listed.map(e => e[2])).to.deep.equal([sha16(Buffer.from('This entry is encrypted with ZipCrypto.\n'.repeat(4))), sha16(Buffer.from('This entry is encrypted with ZipCrypto.\n'.repeat(4)))]);
    const z = await disarmArchive(fixture('zip-zipcrypto.zip'), { ...keep, password: 'correct horse' });
    expect(pythonList('zip', must(z.bytes, 'output'))[0][2]).to.equal(listed[0][2]);
  });

  it('stores an entry when deflate would pass the ratio limit, so the output reads under the same limit', async () => {
    const zeros = Buffer.alloc(3 * 1024 * 1024);
    const r = await disarmArchive(zip([{ name: 'zeros.bin', data: zeros, method: 0 }]), {
      filePlugins: [{ ...upper, process: async (_f, sink) => sink.write(zeros).then(() => 'scrubbed' as const) }],
    });
    const out = must(r.bytes, 'output');
    expect(Buffer.from(out).readUInt16LE(8)).to.equal(0);
    expect((await inspectArchive(out, keep)).status).to.equal('clean');
  });

  it('keeps bytes before and after the archive when their findings are info', async () => {
    const source = zip([text('a.txt')], { prefix: Buffer.from('#!/bin/sh\n'), trailing: Buffer.from('tail') });
    const r = await disarmArchive(source, { ...keep, actionOverrides: [info('STRUCTURE', 'LEADING_BYTES'), info('STRUCTURE', 'TRAILING_BYTES')] });
    const out = Buffer.from(must(r.bytes, 'output'));
    expect(out.subarray(0, 10).toString()).to.equal('#!/bin/sh\n');
    expect(out.subarray(-4).toString()).to.equal('tail');
    expect(pythonList('zip', out).map(e => e[0])).to.deep.equal(['a.txt']);
  });

  it('strips times, owners, comments and attributes with stripMetadata', async () => {
    const r = await disarmArchive(fixture('zip-comments.zip'), { ...keep, stripMetadata: true });
    const out = Buffer.from(must(r.bytes, 'output'));
    expect(out.includes(Buffer.from('comment'))).to.equal(false);
    const t = await disarmArchive(fixture('tar-pax.tar'), { ...keep, stripMetadata: true });
    const tarOut = Buffer.from(must(t.bytes, 'output')).toString('latin1');
    expect(tarOut).to.not.include('user.note');
    expect(tarOut).to.not.include('global comment');
  });

  it('writes a tar that Python reads, with pax records for long and non-ASCII names, and sparse files written out', async () => {
    for (const name of ['tar-pax.tar', 'tar-gnu-long-name.tar', 'tar-sparse-gnu.tar', 'tar-sparse-pax.tar', 'tar-clean.tar']) {
      const r = await disarmArchive(fixture(name), keep);
      const before = await inspectArchive(fixture(name), keep);
      expect(before.status, name).to.equal('clean');
      const listed = pythonList('tar', must(r.bytes, 'output'));
      expect(listed.length, name).to.be.greaterThan(0);
      if (name.startsWith('tar-sparse')) {
        const content = Buffer.alloc(65536);
        content.fill(0x61, 0, 512);
        content.fill(0x62, 32768, 33280);
        expect(listed[0][2], name).to.equal(sha16(content));
      }
    }
  });

  it('writes one gzip member with the fixed name, copying the deflate stream of a single member', async () => {
    const r = await disarmArchive(fixture('gzip-name-traversal.gz'), keep);
    const out = Buffer.from(must(r.bytes, 'output'));
    expect(out.subarray(10, 17).toString('latin1')).to.equal('.bashrc');
    expect(pythonList('gzip', out)[0][2]).to.equal(sha16(Buffer.from('text\n')));
    const members = await disarmArchive(fixture('gzip-members.gz'), keep);
    expect(pythonList('gzip', must(members.bytes, 'output'))[0][2]).to.equal(sha16(Buffer.from('first member\nsecond member\n')));
    const plain = gzipMember(Buffer.from('copied\n'));
    const copied = await disarmArchive(plain, keep);
    expect(Buffer.from(must(copied.bytes, 'output')).subarray(10).equals(plain.subarray(10))).to.equal(true);
  });

  it('writes bzip2 streams that Python reads, merging several streams into one', async () => {
    const r = await disarmArchive(fixture('bzip2-streams.bz2'), keep);
    const out = must(r.bytes, 'output');
    expect(pythonList('bzip2', out)[0][2]).to.equal(sha16(Buffer.from('first stream\nsecond stream\n')));
    const copied = await disarmArchive(BZ.text, keep);
    expect(Buffer.from(must(copied.bytes, 'output')).equals(BZ.text)).to.equal(true);
  });

  it('encodes bzip2 that Python decodes, over runs, all byte values and several blocks', async () => {
    const random = Buffer.alloc(1_000_000);
    let x = 7;
    for (let i = 0; i < random.length; i++) {
      x = (x * 1103515245 + 12345) >>> 0;
      random[i] = x >>> 24;
    }
    for (const data of [Buffer.alloc(0), Buffer.from('a'), Buffer.alloc(300_000, 0x61), Buffer.concat([Buffer.alloc(255, 1), Buffer.alloc(256, 2), Buffer.alloc(4, 3)]), random]) {
      for (const level of [1, 9]) {
        const encoded = await collect(
          bzip2(
            (async function* () {
              yield data;
            })(),
            level,
          ),
        );
        const viaPython = pythonList('bzip2', encoded)[0][2];
        expect(viaPython, `${data.length} at level ${level}`).to.equal(sha16(data));
        const streams = { streams: [], trailing: 0, trailingZeros: true };
        expect(
          (
            await collect(
              bunzip2(
                (async function* () {
                  yield encoded;
                })(),
                streams,
                true,
              ),
            )
          ).equals(data),
        ).to.equal(true);
      }
    }
  });

  it('writes zstd and Brotli outputs that Node decodes', async function () {
    if (!hasZstd) this.skip();
    for (const [name, decode] of [
      ['zstd-frames.zst', (b: Buffer) => (zlib as unknown as { zstdDecompressSync(b: Buffer): Buffer }).zstdDecompressSync(b)],
      ['brotli-clean.br', (b: Buffer) => zlib.brotliDecompressSync(b)],
    ] as const) {
      const r = await disarmArchive(fixture(name), { filePlugins: [upper] });
      const out = Buffer.from(must(r.bytes, 'output'));
      expect(decode(out).length, name).to.be.greaterThan(0);
    }
  });

  it('writes a cabinet again, copying folders nothing changed and building one a plugin changed', async () => {
    const source = fixture('cab-clean.cab');
    const kept = await disarmArchive(source, keep);
    const out = Buffer.from(must(kept.bytes, 'output'));
    expect(out.length).to.equal(source.length);
    const changed = await disarmArchive(source, { filePlugins: [upper] });
    const again = await inspectArchive(must(changed.bytes, 'output'), keep);
    expect(again.entries).to.equal(3);
    expect(kinds(again)).to.deep.equal(['ENTRY/PLUGIN_PASSED', 'ENTRY/PLUGIN_PASSED', 'ENTRY/PLUGIN_PASSED']);
  });

  it('writes the hard links of a tar after the file they name, renamed with it', async () => {
    const r = await disarmArchive(tar(tarEntry({ name: 'a\u0001.txt' }, 'x'), tarEntry({ name: 'b.txt', type: '1', link: 'a\u0001.txt' })), keep);
    expect(pythonList('tar', must(r.bytes, 'output')).map(e => [e[0], e[1], e[1] === 'link' ? e[2] : ''])).to.deep.equal([
      ['a_.txt', 'file', ''],
      ['b.txt', 'link', 'a_.txt'],
    ]);
  });
});
