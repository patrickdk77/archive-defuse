import { expect } from 'chai';
import { archivePlugin, bufferSink, bufferSource, type ContainedFile, type ContainedFilePlugin, disarmArchive, inspectArchive, type PluginContext, passThrough } from '../src';
import { build, failure, fixture, keepAll, kinds, line, must, of, pythonList } from './helpers/util';

const { zip, text, tar, tarEntry, gzipMember } = build;

const fileOf = (bytes: Uint8Array, name?: string, depth = 1): ContainedFile => ({ name, size: bytes.length, location: 'test', depth, source: bufferSource(bytes) });

describe('file plugins', () => {
  it('hand every file entry to the plugins in order, with its name, sniffed type, size, depth and the deadline', async () => {
    const seen: Array<[string | undefined, string | undefined, number, number, number | undefined]> = [];
    const spy: ContainedFilePlugin = {
      kind: 'file',
      name: 'spy',
      accepts: () => true,
      async process(file, _sink, context) {
        seen.push([file.name, file.sniffedType, file.size, context.depth, context.deadline === undefined ? undefined : 1]);
        return 'passed';
      },
    };
    await inspectArchive(zip([text('a.txt'), { name: 'dir/', data: '', method: 0 }, { name: 'b.pdf', data: '%PDF-1.4 x' }]), { filePlugins: [spy], limits: { timeMs: 60_000 } });
    expect(seen).to.deep.equal([
      ['a.txt', undefined, 24, 1, 1],
      ['b.pdf', 'application/pdf', 10, 1, 1],
    ]);
  });

  it('remove an entry no plugin accepts, as pdf-defuse removes an attached file no plugin takes', async () => {
    const r = await disarmArchive(zip([text('a.txt'), text('b.csv')]), { filePlugins: [passThrough(['csv'])] });
    expect(r.before.findings.map(line)).to.deep.equal(['strip ENTRY/NO_PLUGIN', 'info ENTRY/PLUGIN_PASSED']);
    expect(pythonList('zip', must(r.bytes, 'output')).map(e => e[0])).to.deep.equal(['b.csv']);
  });

  it('keep an entry no plugin accepts when NO_PLUGIN is info', async () => {
    const r = await disarmArchive(zip([text('a.txt')]), { actionOverrides: [{ category: 'ENTRY' as never, detail: 'NO_PLUGIN' as never, action: 'info' }] });
    expect(r.status).to.equal('clean');
    expect(pythonList('zip', must(r.bytes, 'output')).map(e => e[0])).to.deep.equal(['a.txt']);
  });

  it('take the bytes a plugin writes, remove what it removes or fails on, and bring its findings in with the entry as attachment', async () => {
    const plugin: ContainedFilePlugin = {
      kind: 'file',
      name: 'judge',
      accepts: () => true,
      async process(file, sink) {
        if (file.name === 'remove.txt') return { result: 'removed', findings: [{ category: 'X', detail: 'Y', description: 'inner', action: 'reject' }] };
        if (file.name === 'fail.txt') throw new Error('broken plugin');
        if (file.name === 'empty-scrub.txt') return 'scrubbed';
        await sink.write(Buffer.from('replaced'));
        return { result: 'scrubbed', findings: [{ category: 'X', detail: 'Z', description: 'inner', action: 'strip', location: 'part 1' }] };
      },
    };
    const r = await disarmArchive(zip([text('remove.txt'), text('fail.txt'), text('empty-scrub.txt'), text('keep.txt')]), { filePlugins: [plugin] });
    expect(r.before.findings.map(line)).to.deep.equal([
      'strip ENTRY/PLUGIN_REMOVED',
      'strip X/Y in remove.txt',
      'strip ENTRY/PLUGIN_FAILED',
      'strip ENTRY/PLUGIN_FAILED',
      'info ENTRY/PLUGIN_SCRUBBED',
      'strip X/Z in keep.txt',
    ]);
    expect(of(r.before, 'X/Z')[0].location).to.equal('entry "keep.txt" > part 1');
    expect(pythonList('zip', must(r.bytes, 'output'))).to.deep.equal([['keep.txt', 'file', pythonList('zip', zip([{ name: 'keep.txt', data: 'replaced' }]))[0][2]]]);
  });

  it('report a type mismatch between the name and the content, without a plugin checking it', async () => {
    const r = await inspectArchive(zip([{ name: 'photo.jpg', data: 'MZ executable' }]), { filePlugins: [passThrough(['jpg'])] });
    expect(r.findings.map(line)).to.deep.equal(['info ENTRY/TYPE_MISMATCH', 'info ENTRY/PLUGIN_PASSED']);
  });

  it('pass a limit or an I/O error a plugin throws up through the archive', async () => {
    const limit: ContainedFilePlugin = { ...keepAll, process: async () => Promise.reject(Object.assign(new Error('deep'), { code: 'DEFUSE_LIMIT', limit: 'nesting' })) };
    const r = await inspectArchive(zip([text('a.txt')]), { filePlugins: [limit] });
    expect(r.findings.map(line).slice(-1)).to.deep.equal(['reject LIMIT/NESTING_DEPTH']);
    const io: ContainedFilePlugin = {
      ...keepAll,
      process: async () => Promise.reject(Object.assign(new Error('disk'), { code: 'DEFUSE_IO', cause: Object.assign(new Error('EIO'), { code: 'EIO' }) })),
    };
    const e = await failure(inspectArchive(zip([text('a.txt')]), { filePlugins: [io] }));
    expect((e as { code?: string }).code).to.equal('EIO');
  });
});

describe('archivePlugin', () => {
  it('accepts archives by content, whatever the name says, Brotli by its name, and declines other content', async () => {
    const plugin = archivePlugin();
    for (const name of ['zip-clean.zip', 'tar-clean.tar', 'gzip-clean.txt.gz', 'bzip2-clean.bz2', 'cab-clean.cab', 'zip-prepended.zip']) {
      expect(await plugin.accepts(fileOf(fixture(name), 'misnamed.txt')), name).to.equal(true);
    }
    // Brotli has no signature, so the name or the declared type has to say it.
    expect(await plugin.accepts(fileOf(fixture('brotli-clean.br'), 'misnamed.txt'))).to.equal(false);
    expect(await plugin.accepts(fileOf(fixture('brotli-clean.br'), 'data.br'))).to.equal(true);
    expect(await plugin.accepts(fileOf(Buffer.from('plain text that is no archive'), 'x.zip'))).to.equal(false);
    expect(await plugin.accepts(fileOf(Buffer.from('%PDF-1.7\n'), 'x.tar'))).to.equal(false);
  });

  it('defuses an archive inside another file, returning its findings with their weights and the rewritten bytes', async () => {
    const sink = bufferSink();
    const inner = zip([text('../up.txt')]);
    const r = await archivePlugin({ filePlugins: [keepAll] }).process(fileOf(inner, 'inner.zip'), sink, { depth: 1 });
    expect(typeof r === 'string' ? r : r.result).to.equal('scrubbed');
    const findings = typeof r === 'string' ? [] : (r.findings ?? []);
    expect(findings.map(f => [f.category, f.detail, f.weight])).to.deep.equal([
      ['NAME', 'TRAVERSAL', 70],
      ['ENTRY', 'PLUGIN_PASSED', 20],
    ]);
    expect(pythonList('zip', sink.result()).map(e => e[0])).to.deep.equal(['up.txt']);
  });

  it("uses the options of the archive-defuse run that found the file when built without its own, so a .tar.gz reaches the tar's entries", async () => {
    const r = await inspectArchive(fixture('gzip-tar.tar.gz'), { filePlugins: [archivePlugin(), keepAll], stripMetadata: true });
    expect(r.findings.map(line)).to.include('info METADATA/STRIPPED in project.tar');
  });

  it('removes a nested archive that rejects, and keeps the container', async () => {
    const inner = zip([{ name: 'x', data: 'x', flags: 0x41 }]);
    const r = await disarmArchive(zip([{ name: 'inner.zip', data: inner, method: 0 }, text('kept.txt')]), { filePlugins: [archivePlugin(), keepAll] });
    expect(r.status).to.equal('defused');
    expect(r.before.findings.map(line)).to.deep.equal(['strip ENTRY/PLUGIN_REMOVED', 'strip ENCRYPTED/UNSUPPORTED in inner.zip', 'info ENTRY/PLUGIN_PASSED']);
  });

  it('stops at the nesting limit, which counts depth across every format, and throws the limit up from a nested run', async () => {
    let bytes: Buffer = Buffer.from('core\n');
    for (let i = 0; i < 12; i++) bytes = gzipMember(bytes, { name: `level-${i}` });
    const r = await inspectArchive(bytes, { filePlugins: [archivePlugin(), keepAll] });
    expect(r.findings.map(line).slice(-1)).to.deep.equal(['reject LIMIT/NESTING_DEPTH']);
    const nested = await failure(archivePlugin({ limits: { nestingDepth: 2 } }).process(fileOf(gzipMember(Buffer.from('x')), 'x.gz', 3), bufferSink(), { depth: 3 } as PluginContext));
    expect((nested as { code?: string; limit?: string }).limit).to.equal('nesting');
  });

  it('shares the deadline of the run that found the file', async () => {
    const e = await failure(archivePlugin().process(fileOf(tar(tarEntry({ name: 'a.txt' }, 'a')), 'a.tar'), bufferSink(), { depth: 1, deadline: Date.now() - 1 }));
    expect((e as { code?: string; limit?: string }).limit).to.equal('time');
  });
});

describe('passThrough', () => {
  it('keeps entries by extension or by MIME type', async () => {
    const r = await inspectArchive(zip([text('a.CSV'), { name: 'b', data: '%PDF-1.4' }, text('c.txt')]), { filePlugins: [passThrough(['.csv', 'application/pdf'])] });
    expect(kinds(r)).to.deep.equal(['ENTRY/PLUGIN_PASSED', 'ENTRY/PLUGIN_PASSED', 'ENTRY/NO_PLUGIN']);
  });
});
