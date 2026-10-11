import * as crypto from 'node:crypto';
import { expect } from 'chai';
import { bufferSink, bufferSource, disarmArchive, disarmArchiveSource, inspectArchive, inspectArchiveSource } from '../src';
import { TempDir } from '../src/io';
import { writeSevenZip, writeXz } from '../src/lzma-writers';
import { contentOf, fixture, keepAll } from './helpers/lzma';
import { kinds } from './helpers/util';

const noTime = () => undefined;

async function xzOf(data: Uint8Array): Promise<Buffer> {
  const sink = bufferSink();
  await writeXz(bufferSource(data), 4, sink, noTime);
  return Buffer.from(sink.result());
}

async function sevenOf(files: Array<[string, Uint8Array]>): Promise<Buffer> {
  const sink = bufferSink();
  const temp = new TempDir();
  await writeSevenZip(
    files.map(([name, data]) => ({ name, dir: false, content: contentOf(data) })),
    sink,
    temp,
    1 << 20,
    noTime,
  );
  await temp.cleanup();
  return Buffer.from(sink.result());
}

describe('limits on xz, lzma and 7z files', () => {
  it('rejects a file over the file size limit unread', async () => {
    const r = await inspectArchive(fixture('xz-crc64.xz'), { limits: { fileSize: 10 } });
    expect(kinds(r)).to.deep.equal(['LIMIT/FILE_SIZE']);
    expect(r.risk).to.equal('UNKNOWN');
  });

  it('stops a stream that decodes past the decompressed size limit', async () => {
    const xz = await xzOf(crypto.randomBytes(300_000));
    const r = await inspectArchive(xz, { filePlugins: [keepAll()], limits: { decompressedBytes: 100_000 } });
    expect(kinds(r)).to.deep.equal(['LIMIT/DECOMPRESSED_SIZE']);
  });

  it('counts every entry of a run toward the total decompressed size limit', async () => {
    const a = crypto.randomBytes(60_000);
    const seven = await sevenOf([
      ['a', a],
      ['b', a],
    ]);
    const r = await inspectArchive(seven, { filePlugins: [keepAll()], limits: { totalDecompressedBytes: 100_000 } });
    expect(kinds(r)).to.include('LIMIT/TOTAL_DECOMPRESSED_SIZE');
  });

  it('stops a bomb at the ratio limit within the first megabytes', async () => {
    const t = Date.now();
    const r = await inspectArchive(fixture('xz-bomb.xz'), { filePlugins: [keepAll()] });
    expect(kinds(r)).to.deep.equal(['LIMIT/RATIO']);
    expect(Date.now() - t).to.be.lessThan(5000);
    const raised = await inspectArchive(fixture('xz-bomb.xz'), { filePlugins: [keepAll()], limits: { compressionRatio: 1e9, decompressedBytes: 2 * 1024 * 1024 } });
    expect(kinds(raised)).to.deep.equal(['LIMIT/DECOMPRESSED_SIZE']);
  });

  it('rejects at the time limit', async () => {
    const r = await inspectArchive(fixture('xz-bomb.xz'), { filePlugins: [keepAll()], limits: { timeMs: -1, compressionRatio: 1e9 } });
    expect(kinds(r)).to.deep.equal(['LIMIT/TIME']);
    const d = await disarmArchiveSource(bufferSource(fixture('7z-copy.7z')), bufferSink(), { filePlugins: [keepAll()], limits: { timeMs: -1 } });
    expect(d.status).to.equal('rejected');
    expect(kinds(d.before)).to.deep.equal(['LIMIT/TIME']);
  });

  it('rejects at the nesting limit', async () => {
    const r = await inspectArchive(fixture('xz-crc64.xz'), { limits: { nestingDepth: -1 } });
    expect(kinds(r)).to.deep.equal(['LIMIT/NESTING_DEPTH']);
  });

  it('puts decoded files above the memory threshold through temporary files', async () => {
    const r = await inspectArchive(fixture('7z-copy.7z'), { filePlugins: [keepAll()], memoryThreshold: 1024 });
    expect(kinds(r)).to.include('PROCESSING/MEMORY_FALLBACK');
    expect(r.status).to.equal('clean');
    const d = await disarmArchive(fixture('7z-copy.7z'), { filePlugins: [keepAll()], memoryThreshold: 1024 });
    expect(d.status).to.equal('clean');
  });

  it('inspects a file source and closes it', async () => {
    let closed = false;
    const src = bufferSource(fixture('xz-crc64.xz'));
    const r = await inspectArchiveSource(
      {
        ...src,
        close: async () => {
          closed = true;
        },
      },
      { filePlugins: [keepAll()] },
    );
    expect(r.status).to.equal('clean');
    expect(closed).to.equal(true);
  });

  it('stores what LZMA would compress past the ratio limit, so the rewrite passes its own check', async () => {
    const zeros = Buffer.alloc(3 * 1024 * 1024);
    // A 7z archive whose one file is stored, which reads clean, and which LZMA would squeeze far past 1,000 to 1.
    const sink = bufferSink();
    const temp = new TempDir();
    await writeSevenZip([{ name: 'z.bin', dir: false, content: contentOf(zeros) }], sink, temp, 1 << 20, noTime, 1000);
    await temp.cleanup();
    const seven = Buffer.from(sink.result());
    expect(seven.length).to.be.greaterThan(zeros.length);
    const d = await disarmArchive(seven, { filePlugins: [keepAll()] });
    expect([d.status, kinds(d.before)]).to.deep.equal(['clean', ['ENTRY/PLUGIN_PASSED']]);
    expect((d.bytes as Uint8Array).length).to.be.greaterThan(zeros.length);
    // An xz file of stored chunks with a few bytes after it, which the rewrite has to write again. Its LZMA2 chunks
    // reset the dictionary every 64 KiB, so even zeros stay under 1,000 to 1 and need no storing.
    const xzSink = bufferSink();
    await writeXz(bufferSource(zeros), 4, xzSink, noTime, true);
    const xz = Buffer.concat([xzSink.result(), Buffer.from('appended')]);
    const dx = await disarmArchive(xz, { filePlugins: [keepAll()] });
    expect([dx.status, kinds(dx.before)]).to.deep.equal(['defused', ['ENTRY/PLUGIN_PASSED', 'STRUCTURE/TRAILING_BYTES']]);
    expect((await inspectArchive(dx.bytes as Uint8Array, { filePlugins: [keepAll()] })).status).to.equal('clean');
  });

  it('writes nothing when the output does not pass its own inspection', async () => {
    // The plugin says the bytes it kept still hold something to strip, so the output cannot pass its check.
    const sink = bufferSink();
    const leftover = { category: 'IMAGE', detail: 'EXIF', description: 'still there', action: 'strip' as const };
    const r = await disarmArchiveSource(bufferSource(fixture('7z-copy.7z')), sink, {
      filePlugins: [{ kind: 'file', name: 'leaky', accepts: () => true, process: async () => ({ result: 'passed', outputFindings: [leftover] }) }],
    });
    expect(r.status).to.equal('rejected');
    expect(kinds(r.before)).to.include('PROCESSING/VERIFICATION_FAILED');
    expect(sink.size()).to.equal(0);
  });
});
