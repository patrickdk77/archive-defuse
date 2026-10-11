import { expect } from 'chai';
import { type ArchiveOptions, archivePlugin, bufferSource, disarmArchive, inspectArchive } from '../src';
import type { ContainedFile } from '../src/types';
import { fixture, keepAll } from './helpers/lzma';
import { build, kinds } from './helpers/util';

describe('archivePlugin on xz, lzma and 7z files', () => {
  it('accepts xz, lzma and 7z content whatever the name, and nothing else', async () => {
    const p = archivePlugin();
    const file = (bytes: Buffer, name: string): ContainedFile => ({ name, size: bytes.length, location: name, depth: 1, source: bufferSource(bytes) });
    expect(await p.accepts(file(fixture('xz-crc64.xz'), 'x.bin'))).to.equal(true);
    expect(await p.accepts(file(fixture('7z-copy.7z'), 'x.txt'))).to.equal(true);
    expect(await p.accepts(file(fixture('lzma-unknown-size.lzma'), 'x'))).to.equal(true);
    expect(await p.accepts(file(Buffer.from('plain text'), 'x.7z'))).to.equal(false);
  });

  it('reads a ZIP with zero bytes in front as a ZIP, though 14 zero bytes pass the .lzma header test', async () => {
    const zip = build.zip([build.text('a.txt')]);
    const r = await inspectArchive(Buffer.concat([Buffer.alloc(16), zip]), { filePlugins: [keepAll()] });
    expect(r.format).to.equal('zip');
    expect(kinds(r)).to.include.members(['STRUCTURE/LEADING_BYTES', 'ENTRY/PLUGIN_PASSED']);
    expect(kinds(r)).to.not.include('STRUCTURE/POLYGLOT');
  });

  it('reports a bomb in an xz file inside an xz file, with weights on the findings it returns', async () => {
    const nested = fixture('xz-nested-bomb.xz');
    const r = await disarmArchive(nested, { filePlugins: [archivePlugin({ filePlugins: [archivePlugin({ filePlugins: [keepAll()] })] })] });
    // Three levels down sit 16 MiB of zeros, which the ratio limit stops. The level above removes that file, and an xz
    // file whose one file goes leaves nothing to write, so the upload rejects, as a gzip file does.
    expect(r.status).to.equal('rejected');
    const limit = r.before.findings.find(f => f.detail === 'RATIO');
    expect(limit?.action).to.equal('strip');
    expect(limit?.attachment).to.equal('unnamed file > unnamed file');
    expect(typeof limit?.weight).to.equal('number');
  });

  it('without options takes the options of the run that found the file', async () => {
    const options: ArchiveOptions = { filePlugins: [archivePlugin()], limits: { nestingDepth: 1 } };
    const r = await inspectArchive(fixture('xz-nested-bomb.xz'), options);
    expect(r.status).to.equal('rejected');
    expect(kinds(r)).to.include('LIMIT/NESTING_DEPTH');
  });
});
