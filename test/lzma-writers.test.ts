import * as crypto from 'node:crypto';
import { expect } from 'chai';
import { bufferSink, bufferSource, disarmArchive, inspectArchive } from '../src';
import { TempDir } from '../src/io';
import { type Content, writeAlone, writeSevenZip, writeXz } from '../src/lzma-writers';
import type { ContainedFile } from '../src/types';
import { contentOf, keepAll, list7z } from './helpers/lzma';

const textOf = (n: number) => Buffer.from('the quick brown fox jumps over the lazy dog\n'.repeat(Math.ceil(n / 44)).slice(0, n));
const noTime = () => undefined;

async function written(fn: (sink: ReturnType<typeof bufferSink>) => Promise<void>): Promise<Buffer> {
  const sink = bufferSink();
  await fn(sink);
  return Buffer.from(sink.result());
}

async function decoded(bytes: Uint8Array): Promise<Buffer> {
  const seen: ContainedFile[] = [];
  const r = await inspectArchive(bytes, { filePlugins: [keepAll(seen)] });
  expect(r.status).to.equal('clean');
  return seen.length ? Buffer.from(await seen[0].source.read(0, seen[0].size)) : Buffer.alloc(0);
}

describe('xz, lzma and 7z writers', () => {
  for (const n of [0, 1, 1023, 32768, 65536, 65537, 200_000]) {
    for (const kind of ['text', 'random']) {
      const data = kind === 'text' ? textOf(n) : crypto.randomBytes(n);
      it(`writes ${n} bytes of ${kind} as xz and lzma that decode to the same bytes, the same way each time`, async () => {
        const content = () => (data.length ? bufferSource(data) : undefined);
        const xz = await written(s => writeXz(content(), 4, s, noTime));
        expect((await decoded(xz)).equals(data)).to.equal(true);
        const xz2 = await written(s => writeXz(content(), 4, s, noTime));
        expect(xz2.equals(xz)).to.equal(true);
        const lz = await written(s => writeAlone(content(), s, noTime));
        expect((await decoded(lz)).equals(data)).to.equal(true);
      });
    }
  }

  it('writes every xz check type', async () => {
    const data = textOf(5000);
    for (const check of [0, 1, 4, 10]) {
      const xz = await written(s => writeXz(bufferSource(data), check, s, noTime));
      expect(xz[7]).to.equal(check);
      expect((await decoded(xz)).equals(data)).to.equal(true);
    }
  });

  it('keeps stored content out of the first 1024 bytes of an xz file', async () => {
    const data = Buffer.concat([Buffer.from('%PDF-1.7\n'), crypto.randomBytes(100_000)]);
    const xz = await written(s => writeXz(bufferSource(data), 4, s, noTime));
    expect(xz.subarray(0, 1024).includes(Buffer.from('%PDF-'))).to.equal(false);
  });

  it('writes a 7z archive with directories, empty files, attributes and times', async () => {
    const a = textOf(70_000);
    const t = Buffer.alloc(8, 1);
    const temp = new TempDir();
    const out = await written(s =>
      writeSevenZip(
        [
          { name: 'd', dir: true, attrib: 0x10 },
          { name: 'd/a.txt', dir: false, attrib: 0x20, mtime: t, content: contentOf(a) },
          { name: 'd/empty', dir: false, content: contentOf(Buffer.alloc(0)) },
        ],
        s,
        temp,
        1 << 20,
        noTime,
      ),
    );
    await temp.cleanup();
    const listed = await list7z(out);
    expect(listed.map(l => [l.name, l.kind, l.size])).to.deep.equal([
      ['d', 'dir', 0],
      ['d/a.txt', 'file', a.length],
      ['d/empty', 'file', 0],
    ]);
    const r = await disarmArchive(out, { filePlugins: [keepAll()] });
    expect(Buffer.compare(r.bytes as Uint8Array, out)).to.equal(0);
  });

  it('refuses content that holds other than its size', async () => {
    const temp = new TempDir();
    const short: Content = { size: 10, chunks: contentOf(Buffer.alloc(5)).chunks };
    let failed: unknown;
    try {
      await writeSevenZip([{ name: 'a', dir: false, content: short }], bufferSink(), temp, 1 << 20, noTime);
    } catch (e) {
      failed = e;
    }
    await temp.cleanup();
    expect(String(failed)).to.match(/fewer bytes than its size/);
  });

  it('writes an empty 7z archive as the 32-byte signature header', async () => {
    const out = await written(s => writeSevenZip([], s, new TempDir(), 1 << 20, noTime));
    expect(out.length).to.equal(32);
    expect((await inspectArchive(out)).status).to.equal('clean');
  });
});
