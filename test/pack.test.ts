import * as crypto from 'node:crypto';
import { Readable } from 'node:stream';
import { expect } from 'chai';
import {
  ArchiveReadError,
  type ArchiveWriter,
  bufferSink,
  type CompressFormat,
  compress,
  compressStream,
  createArchive,
  createArchiveBytes,
  createArchiveStream,
  createArchiveWriter,
  decompress,
  inspectArchive,
  openArchive,
  type PackEntry,
  PackError,
  type PackFormat,
  type PackOptions,
} from '../src';
import { deflateRaw } from '../src/codecs';
import { crc32 } from '../src/crc32';
import { ZipOutput } from '../src/zip-writer';
import { fixture as lzmaFixture } from './helpers/lzma';
import { failure, fixture, hasZstd, keepAll, kinds, pythonList } from './helpers/util';

const text = 'hello world\n'.repeat(500);
const random = crypto.randomBytes(200_000);

/** Entries of every kind, with content as text, bytes, a stream and a function that opens a stream when called. */
const entries = (): PackEntry[] => [
  { name: 'mimetype', data: 'application/vnd.oasis.opendocument.spreadsheet', store: true },
  { name: 'docs/' },
  { name: 'docs/a.txt', data: text },
  { name: 'docs/random.bin', data: random },
  { name: 'docs/stream.txt', data: Readable.from([Buffer.from('part one, '), 'part two']) },
  { name: 'docs/lazy.txt', data: async () => Readable.from(['opened ', 'late']) },
  { name: 'link', linkTarget: 'docs/a.txt' },
  { name: 'caf\u00e9 \u4e2d.txt', data: 'non-ASCII name' },
  { name: `${'folder/'.repeat(30)}deep.txt`, data: 'a long name' },
];

const ARCHIVES: PackFormat[] = ['zip', 'tar', 'tar.gz', 'tar.bz2', 'tar.zst', 'tar.xz', '7z'];
const SINGLES: CompressFormat[] = ['gzip', 'bzip2', 'zstd', 'brotli', 'xz', 'lzma'];
const needsZstd = (f: string) => f.includes('zst');

describe('createArchive and openArchive', () => {
  for (const format of ARCHIVES) {
    it(`writes ${format} that reads back entry by entry`, async function () {
      if (needsZstd(format) && !hasZstd) this.skip();
      const bytes = await createArchiveBytes(format, entries());
      let reader = await openArchive(bytes);
      // A compressed tar opens as the compressed file, whose one entry is the tar.
      if (format.startsWith('tar.')) reader = await openArchive(await reader.bytes(reader.entries[0]));
      expect(reader.entries.map(e => [e.name, e.kind])).to.deep.equal([
        ['mimetype', 'file'],
        ['docs/', 'directory'],
        ['docs/a.txt', 'file'],
        ['docs/random.bin', 'file'],
        ['docs/stream.txt', 'file'],
        ['docs/lazy.txt', 'file'],
        ['link', 'symlink'],
        ['caf\u00e9 \u4e2d.txt', 'file'],
        [`${'folder/'.repeat(30)}deep.txt`, 'file'],
      ]);
      expect(reader.find('link')?.linkTarget).to.equal('docs/a.txt');
      expect(await reader.text('docs/a.txt')).to.equal(text);
      expect((await reader.bytes('docs/random.bin')).equals(random)).to.equal(true);
      expect(await reader.text('docs/stream.txt')).to.equal('part one, part two');
      expect(await reader.text('docs/lazy.txt')).to.equal('opened late');
      await reader.close();
    });
  }

  it('writes ZIP and tar that Python reads, and archives that inspect clean', async () => {
    const zip = await createArchiveBytes('zip', entries());
    expect(pythonList('zip', zip).map(([name]) => name)).to.include('docs/stream.txt');
    const tar = await createArchiveBytes('tar', entries());
    expect(pythonList('tar', tar).find(([name]) => name === 'link')).to.deep.equal(['link', 'sym', 'docs/a.txt']);
    for (const bytes of [zip, tar, await createArchiveBytes('7z', entries())]) {
      const r = await inspectArchive(bytes, { filePlugins: [keepAll] });
      expect([r.status, kinds(r).filter(k => k !== 'ENTRY/PLUGIN_PASSED')]).to.deep.equal(['clean', ['LINK/SYMLINK']]);
    }
  });

  it('writes the ZIP entries in order, with a stored entry flagged store and no extra fields, as ODF needs', async () => {
    const zip = Buffer.from(await createArchiveBytes('zip', entries()));
    // The first local header: method 0 at offset 8, no extra field at offset 28, and the name at offset 30.
    expect([zip.readUInt16LE(8), zip.readUInt16LE(28), zip.toString('latin1', 30, 38)]).to.deep.equal([0, 0, 'mimetype']);
    expect(zip.toString('latin1', 38, 38 + 46)).to.equal('application/vnd.oasis.opendocument.spreadsheet');
  });

  it('stores a file deflate would compress past the ratio limit, so the archive reads under the default limits', async () => {
    const zeros = Buffer.alloc(3 * 1024 * 1024);
    for (const format of ['zip', '7z'] as const) {
      const bytes = await createArchiveBytes(format, [{ name: 'zeros.bin', data: zeros }]);
      expect(bytes.length, format).to.be.greaterThan(zeros.length);
      const reader = await openArchive(bytes);
      expect((await reader.bytes('zeros.bin')).equals(zeros), format).to.equal(true);
    }
    const small = await createArchiveBytes('zip', [{ name: 'zeros.bin', data: zeros }], { ratioLimit: Number.POSITIVE_INFINITY });
    expect(small.length).to.be.lessThan(10_000);
  });

  it('refuses names that leave the folder they are extracted to, before writing anything', async () => {
    for (const name of ['', '../up.txt', 'a/../../b', '/etc/passwd', 'C:\\x', 'a\0b']) {
      const sink = bufferSink();
      const e = await failure(
        createArchive(
          'zip',
          [
            { name: 'ok.txt', data: 'x' },
            { name, data: 'x' },
          ],
          sink,
        ),
      );
      expect(e, JSON.stringify(name)).to.be.instanceOf(PackError);
    }
  });

  it('refuses names the inspection would change, so an archive it writes inspects without name findings', async () => {
    const refused: Array<[string, RegExp]> = [
      ['.', /empty or "." part/],
      ['a/./b.txt', /empty or "." part/],
      ['a//b.txt', /empty or "." part/],
      ['...', /".." part/],
      ['.. ', /".." part/],
      ['a/. /b.txt', /Windows cannot create/],
      [' ', /Windows cannot create/],
      ['name.', /Windows cannot create/],
      ['notes/a:b.txt', /Windows cannot create/],
      ['con.txt', /Windows cannot create/],
      ['a\\b.txt', /backslash/],
      ['tab\there.txt', /control character/],
      ['x‮txt.exe', /control character/],
    ];
    for (const format of ['zip', 'tar'] as const) {
      for (const [name, why] of refused) {
        const e = await failure(createArchive(format, [{ name, data: 'x' }], bufferSink()));
        expect(e, `${format} ${JSON.stringify(name)}`).to.be.instanceOf(PackError);
        expect(String(e), JSON.stringify(name)).to.match(why);
      }
    }
  });

  it('refuses names that leave their folder after NFKC normalization or Windows best fit, and keeps the others', async () => {
    const refused: Array<[string, RegExp]> = [
      ['．．/x.txt', /NFKC/],
      ['‥/x.txt', /NFKC/],
      ['..∕x.txt', /best fit/],
      ['∕etc∕passwd', /best fit/],
      ['¥..¥x.txt', /best fit/],
      ['a₩..₩..₩x.txt', /best fit/],
      ['C։∖x.txt', /best fit/],
      ['C：＼x.txt', /NFKC/],
    ];
    for (const [name, how] of refused) {
      const e = await failure(createArchive('zip', [{ name, data: 'x' }], bufferSink()));
      expect(e, JSON.stringify(name)).to.be.instanceOf(PackError);
      expect(String(e), JSON.stringify(name)).to.match(how);
    }
    const kept = ['price¥100.txt', '¿Qué.txt', 'a／b.txt', '．．.txt', '℀.txt', 'café´s.txt'];
    const bytes = await createArchiveBytes(
      'zip',
      kept.map(name => ({ name, data: name })),
    );
    const reader = await openArchive(bytes);
    try {
      expect(reader.entries.map(x => x.name)).to.deep.equal(kept);
    } finally {
      await reader.close();
    }
    const r = await inspectArchive(bytes, { filePlugins: [keepAll] });
    expect(r.status).to.equal('clean');
  });

  it('fails the output when an entry stream fails, instead of ending it', async () => {
    const broken = async function* () {
      yield Buffer.from('first');
      throw new Error('the source broke');
    };
    const stream = createArchiveStream('zip', [{ name: 'a.txt', data: broken() }]);
    const e = await failure(
      (async () => {
        for await (const _ of stream) {
          // Reading until the stream fails.
        }
      })(),
    );
    expect(String(e)).to.match(/the source broke/);
    let aborted: unknown;
    const sink = {
      ...bufferSink(),
      abort: async (err: unknown) => {
        aborted = err;
      },
    };
    await failure(createArchive('tar', [{ name: 'a.txt', data: broken() }], sink));
    expect(String(aborted)).to.match(/the source broke/);
  });
});

describe('streaming ZIP', () => {
  /** Local headers by name, read through the central directory: flags, method and the compressed size they give. */
  function localHeaders(zip: Uint8Array): Map<string, { flags: number; method: number; compressedSize: number }> {
    const b = Buffer.from(zip);
    const end = b.length - 22;
    const out = new Map<string, { flags: number; method: number; compressedSize: number }>();
    for (let i = 0, q = b.readUInt32LE(end + 16); i < b.readUInt16LE(end + 10); i++) {
      const n = b.readUInt16LE(q + 28);
      const at = b.readUInt32LE(q + 42);
      out.set(b.subarray(q + 46, q + 46 + n).toString(), { flags: b.readUInt16LE(at + 6), method: b.readUInt16LE(at + 8), compressedSize: b.readUInt32LE(at + 18) });
      q += 46 + n + b.readUInt16LE(q + 30) + b.readUInt16LE(q + 32);
    }
    return out;
  }
  async function* rows(n: number): AsyncGenerator<string> {
    yield '<?xml version="1.0" encoding="UTF-8"?>\n<sheetData>\n';
    for (let i = 0; i < n; i++) yield `<row r="${i}"><c><v>${(i * 31) % 997}</v></c></row>\n`;
    yield '</sheetData>\n';
  }
  const streamed = (): PackEntry[] => [
    { name: 'mimetype', data: 'application/vnd.oasis.opendocument.spreadsheet', store: true },
    { name: 'content.xml', data: rows(50_000) },
    { name: 'empty.txt', data: Readable.from([]) },
    { name: 'pictures/' },
    { name: 'pictures/random.bin', data: () => Readable.from([random]) },
    { name: 'link', linkTarget: 'content.xml' },
  ];

  it('writes each file as it arrives, with no temporary file, and the archive reads back everywhere', async () => {
    // A temporary file would fail here, as it does for the default mode.
    const options = { streaming: true, tempDir: '/nonexistent-folder/for-temp', memoryThreshold: 0 };
    const zip = await createArchiveBytes('zip', streamed(), options);
    expect(((await failure(createArchiveBytes('zip', streamed(), { tempDir: options.tempDir, memoryThreshold: 0 }))) as { code?: string }).code).to.equal('ENOENT');
    const reader = await openArchive(zip);
    let expected = '';
    for await (const r of rows(50_000)) expected += r;
    expect(await reader.text('content.xml')).to.equal(expected);
    expect((await reader.bytes('pictures/random.bin')).equals(random)).to.equal(true);
    expect((await reader.bytes('empty.txt')).length).to.equal(0);
    expect(reader.find('link')?.linkTarget).to.equal('content.xml');
    await reader.close();
    expect(pythonList('zip', zip).map(([name]) => name)).to.deep.equal(['mimetype', 'content.xml', 'empty.txt', 'pictures/', 'pictures/random.bin', 'link']);
    const r = await inspectArchive(zip, { filePlugins: [keepAll] });
    expect([r.status, kinds(r).filter(k => k !== 'ENTRY/PLUGIN_PASSED')]).to.deep.equal(['clean', ['LINK/SYMLINK']]);
  });

  it('gives a streamed file a data descriptor, and keeps sizes in the header of a stored file, an empty one, a folder and a link', async () => {
    const headers = localHeaders(await createArchiveBytes('zip', streamed(), { streaming: true }));
    expect([...headers].map(([name, h]) => [name, h.flags & 8, h.method, h.compressedSize > 0])).to.deep.equal([
      ['mimetype', 0, 0, true],
      ['content.xml', 8, 8, false],
      ['empty.txt', 0, 0, false],
      ['pictures/', 0, 0, false],
      ['pictures/random.bin', 8, 8, false],
      ['link', 0, 0, true],
    ]);
    // At level 0, deflate's stored blocks still stream.
    const level0 = localHeaders(await createArchiveBytes('zip', [{ name: 'a.txt', data: rows(10) }], { streaming: true, level: 0 }));
    expect(level0.get('a.txt')).to.include({ flags: 8, method: 8 });
  });

  it('writes ZIP only, since tar and 7z need sizes first', async () => {
    for (const format of ['tar', 'tar.gz', '7z'] as const) {
      const e = await failure(createArchiveBytes(format, [{ name: 'a.txt', data: 'x' }], { streaming: true }));
      expect(e, format).to.be.instanceOf(PackError);
    }
  });

  it('stops when the output stream is destroyed, and fails the output when an entry stream fails', async () => {
    let stream: Readable | undefined;
    const { state, source } = endless(20, () => stream as Readable);
    stream = createArchiveStream('zip', [{ name: 'endless.bin', data: source() }], { streaming: true });
    stream.resume();
    await state.closed;
    expect(state.produced).to.be.within(20, 24);
    const broken = async function* () {
      yield Buffer.from('first');
      throw new Error('the source broke');
    };
    let aborted: unknown;
    const sink = {
      ...bufferSink(),
      abort: async (err: unknown) => {
        aborted = err;
      },
    };
    await failure(createArchive('zip', [{ name: 'a.txt', data: broken() }], sink, { streaming: true }));
    expect(String(aborted)).to.match(/the source broke/);
  });
});

/**
 * A source that never ends, which destroys `out` after `after` chunks. `closed` settles when the source is closed,
 * and `produced` counts the chunks it made. Small chunks go on in batches of 64 KiB, four of these, so the work stops
 * within one batch of the destroy.
 */
function endless(after: number, out: () => { destroy(): void }) {
  let done: () => void = () => undefined;
  const state = {
    produced: 0,
    closed: new Promise<void>(resolve => {
      done = resolve;
    }),
  };
  async function* source(): AsyncGenerator<Uint8Array> {
    try {
      for (;;) {
        state.produced++;
        yield crypto.randomBytes(16 * 1024);
        if (state.produced === after) out().destroy();
        await new Promise(r => setImmediate(r));
      }
    } finally {
      done();
    }
  }
  return { state, source };
}

describe('cancelling', () => {
  for (const format of ['zip', 'tar', 'tar.xz', '7z'] as const) {
    it(`stops reading a ${format} entry when the output stream is destroyed`, async () => {
      let stream: Readable | undefined;
      const { state, source } = endless(20, () => stream as Readable);
      let pulled = 0;
      async function* list(): AsyncGenerator<PackEntry> {
        pulled++;
        yield { name: 'endless.bin', data: source() };
        pulled++;
        yield { name: 'never.txt', data: 'x' };
      }
      stream = createArchiveStream(format, list());
      stream.resume();
      await state.closed;
      expect(state.produced).to.be.within(20, 24);
      expect(pulled).to.equal(1);
    });
  }

  for (const format of ['gzip', 'xz'] as const) {
    it(`stops compressing ${format} when the output stream is destroyed`, async () => {
      let stream: Readable | undefined;
      const { state, source } = endless(20, () => stream as Readable);
      stream = compressStream(format, source());
      stream.resume();
      await state.closed;
      expect(state.produced).to.be.within(20, 24);
    });
  }

  it("stops at the signal's abort, aborts the sink and throws the signal's reason", async () => {
    const before = new AbortController();
    before.abort(new Error('stopped before'));
    let pulled = false;
    const e1 = await failure(
      createArchive(
        'zip',
        (async function* () {
          pulled = true;
          yield { name: 'a.txt', data: 'x' };
        })(),
        bufferSink(),
        { signal: before.signal },
      ),
    );
    expect(String(e1)).to.match(/stopped before/);
    expect(pulled).to.equal(false);

    const during = new AbortController();
    const { state, source } = endless(20, () => ({ destroy: () => during.abort(new Error('stopped during')) }));
    let aborted: unknown;
    const sink = {
      ...bufferSink(),
      abort: async (err: unknown) => {
        aborted = err;
      },
    };
    const e2 = await failure(createArchive('7z', [{ name: 'endless.bin', data: source() }], sink, { signal: during.signal }));
    await state.closed;
    expect(String(e2)).to.match(/stopped during/);
    expect(String(aborted)).to.match(/stopped during/);
    expect(state.produced).to.be.within(20, 24);

    const e3 = await failure(compress('lzma', 'x', { signal: before.signal }));
    expect(String(e3)).to.match(/stopped before/);
  });
});

describe('compress and decompress', () => {
  const data = Buffer.concat([Buffer.from(text), random]);
  for (const format of SINGLES) {
    it(`round-trips ${format}`, async function () {
      if (needsZstd(format) && !hasZstd) this.skip();
      const packed = await compress(format, Readable.from([data.subarray(0, 1000), data.subarray(1000)]));
      expect((await decompress(packed)).equals(data)).to.equal(true);
    });
  }

  it('refuses to decompress an archive of entries, which openArchive reads', async () => {
    const e = await failure(decompress(await createArchiveBytes('zip', [{ name: 'a', data: 'x' }])));
    expect([e instanceof ArchiveReadError, (e as ArchiveReadError).detail]).to.deep.equal([true, 'NOT_SINGLE']);
  });
});

describe('openArchive', () => {
  it('reads encrypted entries with the passwords given, trying each in order', async () => {
    const zip = await openArchive(fixture('zip-zipcrypto.zip'), { password: ['wrong', 'correct horse'] });
    const file = zip.entries.find(entry => entry.kind === 'file');
    expect(file?.encrypted).to.equal(true);
    expect((await zip.bytes(file?.name ?? '')).length).to.be.greaterThan(0);
    const seven = await openArchive(lzmaFixture('7z-aes.7z'), { password: 'right password' });
    expect((await seven.text('docs/a.txt')).length).to.be.greaterThan(0);
    const none = await openArchive(fixture('zip-zipcrypto.zip'));
    const e = await failure(none.bytes(file?.name ?? ''));
    expect((e as ArchiveReadError).detail).to.equal('PASSWORD_REQUIRED');
  });

  it('applies the inspection limits to every read', async () => {
    // This bomb declares its sizes, so it fails when it opens.
    const e = await failure(openArchive(fixture('zip-ratio-bomb.zip')));
    expect([e instanceof ArchiveReadError, (e as ArchiveReadError).category, (e as ArchiveReadError).detail]).to.deep.equal([true, 'LIMIT', 'RATIO']);
    // This one declares nothing, so it fails as it decodes.
    const gz = await openArchive(fixture('gzip-ratio-bomb.gz'));
    expect(((await failure(gz.bytes(gz.entries[0]))) as ArchiveReadError).detail).to.equal('RATIO');
    const big = await failure(openArchive(await createArchiveBytes('zip', [{ name: 'a.bin', data: random }]), { limits: { decompressedBytes: 1000 } }));
    expect((big as ArchiveReadError).detail).to.equal('DECOMPRESSED_SIZE');
  });

  it('throws an ArchiveReadError for a file it does not read, and for an entry that is not there', async () => {
    const e = await failure(openArchive(Buffer.from('just some text, not an archive')));
    expect([e instanceof ArchiveReadError, (e as ArchiveReadError).detail]).to.deep.equal([true, 'UNPARSEABLE']);
    const zip = await openArchive(await createArchiveBytes('zip', [{ name: 'a.txt', data: 'x' }, { name: 'dir/' }]));
    expect(((await failure(zip.bytes('missing.txt'))) as ArchiveReadError).detail).to.equal('NOT_FOUND');
    expect(((await failure(zip.bytes('dir/'))) as ArchiveReadError).detail).to.equal('NO_CONTENT');
  });

  it('gives names as the archive stores them, with no rule applied', async () => {
    const zip = await openArchive(fixture('zip-traversal.zip'));
    expect(zip.entries.map(e => e.name)).to.include('../outside.txt');
  });
});

/** All of a stream's bytes. */
async function collect(stream: Readable): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const c of stream) parts.push(c as Buffer);
  return Buffer.concat(parts);
}

const tick = () => new Promise(resolve => setImmediate(resolve));

/** Waits until `add` throws, as it does once the archive has failed, for up to two seconds. */
async function addFails(w: ArchiveWriter): Promise<unknown> {
  for (let i = 0; i < 200; i++) {
    try {
      w.add({ name: `late-${i}.txt`, data: 'late' });
    } catch (e) {
      return e;
    }
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  return undefined;
}

describe('archive writer', () => {
  const mtime = new Date('2024-05-06T07:08:09Z');

  it('writes the archive createArchive writes, with entries added while it runs', async () => {
    for (const format of ARCHIVES) {
      if (needsZstd(format) && !hasZstd) continue;
      for (const streaming of format === 'zip' ? [false, true] : [false]) {
        const options: PackOptions = { mtime, streaming };
        const expected = Buffer.from(await createArchiveBytes(format, entries(), options));
        const w = createArchiveWriter(format, options);
        const read = collect(w.stream);
        for (const e of entries()) {
          w.add(e);
          await tick();
        }
        await w.finish();
        expect((await read).equals(expected), `${format}, streaming ${streaming}`).to.equal(true);
      }
    }
  });

  it('takes entries from synchronous code before the stream is read', async () => {
    const options: PackOptions = { mtime, streaming: true };
    const w = createArchiveWriter('zip', options);
    for (const e of entries()) w.add(e);
    const finished = w.finish();
    const zip = await collect(w.stream);
    await finished;
    expect(zip.equals(Buffer.from(await createArchiveBytes('zip', entries(), options)))).to.equal(true);
  });

  it('throws on add after finish, and writes what came before', async () => {
    const w = createArchiveWriter('tar');
    const read = collect(w.stream);
    w.add({ name: 'a.txt', data: 'a' });
    const finished = w.finish();
    expect(() => w.add({ name: 'b.txt', data: 'b' })).to.throw(PackError, /after the archive was finished/);
    await finished;
    expect(pythonList('tar', await read).map(([name]) => name)).to.deep.equal(['a.txt']);
  });

  it('fails on an entry createArchive refuses: the stream errors, add throws with the cause, and finish rejects', async () => {
    const w = createArchiveWriter('zip', { streaming: true });
    const read = failure(collect(w.stream));
    w.add({ name: 'a.txt', data: 'a' });
    w.add({ name: '../escape.txt', data: 'b' });
    const error = await read;
    expect(error).to.be.instanceOf(PackError);
    let added: unknown;
    try {
      w.add({ name: 'c.txt', data: 'c' });
    } catch (e) {
      added = e;
    }
    expect(added).to.be.instanceOf(PackError);
    expect((added as Error).cause).to.equal(error);
    expect(await failure(w.finish())).to.equal(error);
  });

  it('stops on abort: the stream is destroyed with the reason, and finish rejects with it', async () => {
    const w = createArchiveWriter('zip', { streaming: true });
    const read = failure(collect(w.stream));
    w.add({ name: 'a.txt', data: 'a' });
    await tick();
    const reason = new Error('the caller gave up');
    w.abort(reason);
    expect(await read).to.equal(reason);
    expect(await failure(w.finish())).to.equal(reason);
    expect(() => w.add({ name: 'b.txt', data: 'b' })).to.throw(PackError, /after the archive was aborted/);
  });

  it('stops waiting for entries when the reader goes away or the signal aborts', async () => {
    const left = createArchiveWriter('zip', { streaming: true });
    left.add({ name: 'a.txt', data: 'a' });
    await tick();
    left.stream.destroy();
    expect(await addFails(left)).to.be.instanceOf(PackError);
    expect(String(await failure(left.finish()))).to.match(/closed before all data was written/);

    const controller = new AbortController();
    const signalled = createArchiveWriter('zip', { streaming: true, signal: controller.signal });
    const read = failure(collect(signalled.stream));
    signalled.add({ name: 'a.txt', data: 'a' });
    await tick();
    controller.abort(new Error('the signal fired'));
    expect(await addFails(signalled)).to.be.instanceOf(PackError);
    expect(String(await failure(signalled.finish()))).to.match(/the signal fired/);
    await read;
  });

  it('throws at once for an unknown format, and for streaming with a format other than ZIP', () => {
    expect(() => createArchiveWriter('rar' as PackFormat)).to.throw(PackError);
    expect(() => createArchiveWriter('tar', { streaming: true })).to.throw(PackError);
  });
});

describe('entry size', () => {
  // A temporary file fails here, so these show which entries are written without one.
  const noTemp: PackOptions = { tempDir: '/nonexistent-folder/for-temp', memoryThreshold: 0 };
  const sizedFiles = (): PackEntry[] => [
    { name: 'random.bin', data: random },
    { name: 'text.txt', data: text },
    { name: 'stream.bin', data: Readable.from([random.subarray(0, 1000), random.subarray(1000)]), size: random.length },
    { name: 'lazy.txt', data: () => Readable.from([text]), size: Buffer.byteLength(text) },
    { name: 'empty.txt', data: Readable.from([]), size: 0 },
  ];

  it('lets tar write a file of known size as it arrives, with no temporary file', async () => {
    for (const format of ['tar', 'tar.gz', 'tar.bz2'] as const) {
      let reader = await openArchive(await createArchiveBytes(format, sizedFiles(), noTemp));
      // A compressed tar opens as the compressed file, whose one entry is the tar.
      if (format !== 'tar') reader = await openArchive(await reader.bytes(reader.entries[0]));
      expect((await reader.bytes('random.bin')).equals(random), format).to.equal(true);
      expect((await reader.bytes('stream.bin')).equals(random), format).to.equal(true);
      expect(await reader.text('text.txt'), format).to.equal(text);
      expect(await reader.text('lazy.txt'), format).to.equal(text);
      expect((await reader.bytes('empty.txt')).length, format).to.equal(0);
      await reader.close();
    }
    expect(pythonList('tar', await createArchiveBytes('tar', sizedFiles(), noTemp)).map(([name]) => name)).to.deep.equal(['random.bin', 'text.txt', 'stream.bin', 'lazy.txt', 'empty.txt']);
    // A stream without a size is read first, so it still needs the temporary file.
    const e = await failure(createArchiveBytes('tar', [{ name: 'a.bin', data: Readable.from([random]) }], noTemp));
    expect((e as { code?: string }).code).to.equal('ENOENT');
  });

  it('fails the archive when a stream comes to another size, in every format', async () => {
    for (const format of ARCHIVES) {
      if (needsZstd(format) && !hasZstd) continue;
      for (const streaming of format === 'zip' ? [false, true] : [false]) {
        const label = `${format}, streaming ${streaming}`;
        const short = await failure(createArchiveBytes(format, [{ name: 'a.bin', data: Readable.from([Buffer.alloc(10)]), size: 11 }], { streaming }));
        expect(String(short), label).to.match(/has 10 bytes, not the 11 its size gives/);
        const long = await failure(createArchiveBytes(format, [{ name: 'a.bin', data: Readable.from([Buffer.alloc(5), Buffer.alloc(5)]), size: 9 }], { streaming }));
        expect(String(long), label).to.match(/has more than the 9 bytes its size gives/);
      }
    }
  });

  it('refuses bytes of another size, a size on a folder or a link, and a size that is not a whole number', async () => {
    const refused: Array<[PackEntry, RegExp]> = [
      [{ name: 'a.txt', data: 'abc', size: 4 }, /holds 3 bytes, not the 4/],
      [{ name: 'a.txt', data: () => 'abc', size: 2 }, /holds 3 bytes, not the 2/],
      [{ name: 'a.txt', size: 1 }, /holds 0 bytes, not the 1/],
      [{ name: 'd/', size: 0 }, /only a file takes a size/],
      [{ name: 'l', linkTarget: 'a.txt', size: 5 }, /only a file takes a size/],
      [{ name: 'a.bin', data: Readable.from([]), size: -1 }, /not a whole number of bytes/],
      [{ name: 'a.bin', data: Readable.from([]), size: 1.5 }, /not a whole number of bytes/],
    ];
    for (const [entry, message] of refused) {
      for (const format of ['zip', 'tar'] as const) {
        const e = await failure(createArchiveBytes(format, [entry], {}));
        expect(e, `${entry.name} ${format}`).to.be.instanceOf(PackError);
        expect(String(e)).to.match(message);
      }
    }
  });
});

describe('ZIP64 fields of a streamed entry', () => {
  /** The first entry's local header, and the length of its data descriptor. */
  function firstEntry(zip: Uint8Array) {
    const b = Buffer.from(zip);
    const n = b.readUInt16LE(26);
    const x = b.readUInt16LE(28);
    const end = b.length - 22;
    const central = b.readUInt32LE(end + 16);
    const compressedSize = b.readUInt32LE(central + 20);
    return {
      version: b.readUInt16LE(4),
      flags: b.readUInt16LE(6),
      sizes: [b.readUInt32LE(18), b.readUInt32LE(22)],
      extra: b.subarray(30 + n, 30 + n + x),
      descriptor: central - (30 + n + x + compressedSize),
    };
  }

  it('gives none to a file of known size that does not need them, nor to a stream without a size', async () => {
    const files: PackEntry[] = [
      { name: 'a.txt', data: text },
      { name: 'a.bin', data: Readable.from([random]), size: random.length },
      { name: 'a.bin', data: Readable.from([random]) },
    ];
    for (const file of files) {
      const h = firstEntry(await createArchiveBytes('zip', [file], { streaming: true }));
      expect([h.version, h.flags & 8, h.sizes, h.extra.length, h.descriptor], file.name).to.deep.equal([20, 8, [0, 0], 0, 16]);
    }
  });

  it('writes them as Python does for an entry that may pass 4 GiB, and the archive reads back', async () => {
    const data = Buffer.from(text);
    const sink = bufferSink();
    const out = new ZipOutput(sink);
    const info = {
      name: Buffer.from('big.txt'),
      flags: 0,
      method: 8,
      versionNeeded: 20,
      versionMadeBy: (3 << 8) | 30,
      externalAttr: (0o100644 << 16) >>> 0,
      internalAttr: 0,
      time: 0,
      date: (44 << 9) | (1 << 5) | 1,
      crc: 0,
      compressedSize: 0,
      size: 0,
      extras: new Uint8Array(0),
      comment: new Uint8Array(0),
    };
    const chunks = async function* () {
      yield data;
    };
    await out.streamEntry(info, deflateRaw(chunks(), 6), () => ({ crc: crc32(data, 0), size: data.length }), true);
    await out.end(new Uint8Array(0));
    const zip = sink.result();
    const h = firstEntry(zip);
    expect([h.version, h.flags & 8, h.sizes, h.descriptor]).to.deep.equal([45, 8, [0xffffffff, 0xffffffff], 24]);
    expect(h.extra.equals(Buffer.concat([Buffer.from([1, 0, 16, 0]), Buffer.alloc(16)]))).to.equal(true);
    const reader = await openArchive(zip);
    expect(await reader.text('big.txt')).to.equal(text);
    await reader.close();
    expect(pythonList('zip', zip).map(([name]) => name)).to.deep.equal(['big.txt']);
  });
});
