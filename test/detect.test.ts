import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ArchiveFormat, archivePlugin, type ByteSource, bufferSource, type ContainedFile, detectArchive, detectArchiveSource, type FormatDetection, inspectArchive, openArchive } from '../src';
import { typeFromName } from '../src/sniff';
import { fixture as lzmaFixture } from './helpers/lzma';
import { build, fixture, fixtures, must } from './helpers/util';

const { zip, text } = build;

/** The format each MIME type names, as the readers name it. */
const FORMATS: Record<string, ArchiveFormat> = {
  'application/zip': 'zip',
  'application/x-tar': 'tar',
  'application/gzip': 'gzip',
  'application/x-bzip2': 'bzip2',
  'application/zstd': 'zstd',
  'application/x-brotli': 'brotli',
  'application/vnd.ms-cab-compressed': 'cab',
  'application/x-7z-compressed': '7z',
  'application/x-xz': 'xz',
  'application/x-lzma': 'lzma',
};

const LZMA = "no signature: the 13-byte header and the first data byte pass liblzma's test for an .lzma file";
const BROTLI = 'no signature: the file decodes as one Brotli stream that ends where the file does, or past 32 MiB without an error';
const EMPTY_TAR = 'no tar header: the file is zeros, at least 1024 bytes and a multiple of 512, as an empty tar is';

/** A RAR 5 signature and a header's worth of bytes after it. */
const rar = () => Buffer.concat([Buffer.from('Rar!\x1a\x07\x01\x00', 'latin1'), Buffer.alloc(64, 0x11)]);
/** The start of a JPEG file, as a picture in front of a ZIP archive has. */
const jpeg = () => Buffer.concat([Buffer.from([0xff, 0xd8, 0xff, 0xe0, 0x00, 0x10]), Buffer.from('JFIF\0', 'latin1'), Buffer.alloc(200, 0x42), Buffer.from([0xff, 0xd9])]);

/** How many leading bytes the inspection reports, which is where the reader found the archive. */
async function leading(bytes: Uint8Array): Promise<number> {
  const r = await inspectArchive(bytes);
  return Number(r.findings.find(f => f.detail === 'LEADING_BYTES')?.data?.bytes ?? 0);
}

const fileOf = (bytes: Uint8Array, name?: string, declaredType?: string): ContainedFile => ({ name, declaredType, size: bytes.length, location: 'test', depth: 1, source: bufferSource(bytes) });

/** Every fixture file, the xz, lzma, 7z and Deflate64 folders included. */
function fixtureFiles(dir = fixtures): string[] {
  return fs
    .readdirSync(dir)
    .flatMap(f => (fs.statSync(path.join(dir, f)).isDirectory() ? fixtureFiles(path.join(dir, f)) : [path.join(dir, f)]))
    .filter(f => !/\.json$|[/\\](LICENSE|README)$/.test(f))
    .sort();
}

describe('detectArchive', () => {
  it('claims each format it reads at offset 0, with the MIME type and extension sniff.ts gives it', async () => {
    const cases: Array<[Buffer, FormatDetection]> = [
      [fixture('zip-clean.zip'), { mimeType: 'application/zip', extension: 'zip', offset: 0 }],
      [fixture('zip-empty.zip'), { mimeType: 'application/zip', extension: 'zip', offset: 0 }],
      [fixture('tar-clean.tar'), { mimeType: 'application/x-tar', extension: 'tar', offset: 0 }],
      [fixture('tar-v7.tar'), { mimeType: 'application/x-tar', extension: 'tar', offset: 0 }],
      [Buffer.alloc(10240), { mimeType: 'application/x-tar', extension: 'tar', offset: 0, heuristic: EMPTY_TAR }],
      [fixture('gzip-clean.txt.gz'), { mimeType: 'application/gzip', extension: 'gz', offset: 0 }],
      [fixture('bzip2-clean.bz2'), { mimeType: 'application/x-bzip2', extension: 'bz2', offset: 0 }],
      // Only the frame's magic number is read, so a Node without zstd detects it too.
      [fixture('zstd-clean.zst'), { mimeType: 'application/zstd', extension: 'zst', offset: 0 }],
      [fixture('zstd-skippable.zst'), { mimeType: 'application/zstd', extension: 'zst', offset: 0 }],
      [fixture('brotli-clean.br'), { mimeType: 'application/x-brotli', extension: 'br', offset: 0, heuristic: BROTLI }],
      [fixture('cab-clean.cab'), { mimeType: 'application/vnd.ms-cab-compressed', extension: 'cab', offset: 0 }],
      [lzmaFixture('7z-copy.7z'), { mimeType: 'application/x-7z-compressed', extension: '7z', offset: 0 }],
      [lzmaFixture('xz-crc64.xz'), { mimeType: 'application/x-xz', extension: 'xz', offset: 0 }],
      [lzmaFixture('lzma-unknown-size.lzma'), { mimeType: 'application/x-lzma', extension: 'lzma', offset: 0, heuristic: LZMA }],
      [fs.readFileSync(path.join(fixtures, 'lzma', 'xz-utils', 'good-known_size-with_eopm.lzma')), { mimeType: 'application/x-lzma', extension: 'lzma', offset: 0, heuristic: LZMA }],
    ];
    for (const [bytes, expected] of cases) {
      // Brotli has no signature and counts only by its name or declared type. The name changes nothing for the rest.
      expect(await detectArchive(bytes, { name: `file.${expected.extension}` }), expected.mimeType).to.deep.equal(expected);
      expect(typeFromName(`x.${expected.extension}`)).to.equal(expected.mimeType);
    }
    const br = fixture('brotli-clean.br');
    expect(await detectArchive(br)).to.equal(undefined);
    expect(await detectArchive(br, { name: 'notes.txt' })).to.equal(undefined);
    expect((await detectArchive(br, { declaredType: 'application/x-brotli' }))?.extension).to.equal('br');
    // One byte that decodes as an empty Brotli stream is text unless it says it is Brotli.
    expect(await detectArchive(Buffer.from('7'))).to.equal(undefined);
    // Zeros are an empty tar only in whole 512-byte blocks, two at least. Fewer pass the .lzma header test from 14 bytes.
    for (const size of [14, 512, 1000]) {
      expect(await detectArchive(Buffer.alloc(size)), `${size} zeros`).to.deep.equal({ mimeType: 'application/x-lzma', extension: 'lzma', offset: 0, heuristic: LZMA });
    }
    expect(await detectArchive(Buffer.alloc(13))).to.equal(undefined);
  });

  it('decides by the content alone, whatever the name or the declared type says, except for Brotli', async () => {
    const gz = fixture('gzip-clean.txt.gz');
    const found = await detectArchive(gz);
    expect(await detectArchive(gz, { name: 'notes.txt', declaredType: 'text/plain' })).to.deep.equal(found);
    expect(await detectArchive(Buffer.from('plain text that is no archive'), { name: 'a.zip', declaredType: 'application/zip' })).to.equal(undefined);
  });

  it('finds a ZIP archive from its end record at the offset where the ZIP reader finds it', async () => {
    const behindJpeg = zip([text('a.txt'), text('b.txt')], { prefix: jpeg() });
    expect(await detectArchive(behindJpeg)).to.deep.equal({ mimeType: 'application/zip', extension: 'zip', offset: jpeg().length });
    // Zero bytes in front pass the .lzma header test, and the end record comes first. The reader corrects the offsets.
    const behindZeros = Buffer.concat([Buffer.alloc(16), zip([text('a.txt')])]);
    expect(await detectArchive(behindZeros)).to.deep.equal({ mimeType: 'application/zip', extension: 'zip', offset: 16 });
    // An executable stub, a script and a PDF in front, each where the inspection reports the leading bytes end.
    for (const [name, offset] of [
      ['zip-prepended.zip', 128],
      ['zip-offset-shift.zip', 17],
      ['zip-pdf-polyglot.zip', 30],
    ] as const) {
      const bytes = fixture(name);
      expect((await detectArchive(bytes))?.offset, name).to.equal(offset);
      expect(await leading(bytes), name).to.equal(offset);
    }
    for (const bytes of [behindJpeg, behindZeros]) expect((await detectArchive(bytes))?.offset).to.equal(await leading(bytes));
    // A file that starts with a ZIP signature is a ZIP from byte 0, though the reader finds hidden data there.
    expect(await detectArchive(fixture('zip-hidden-data.zip'))).to.deep.equal({ mimeType: 'application/zip', extension: 'zip', offset: 0 });
  });

  it('finds a 7z archive after a self-extracting program at its signature header', async () => {
    for (const [name, offset] of [
      ['7z-sfx-prefix.7z', 302],
      ['7z-leading-text.7z', 17],
    ] as const) {
      const bytes = lzmaFixture(name);
      expect(await detectArchive(bytes), name).to.deep.equal({ mimeType: 'application/x-7z-compressed', extension: '7z', offset });
      expect(await leading(bytes), name).to.equal(offset);
    }
  });

  it('does not claim RAR, which it detects only to reject, or content in no format it reads', async () => {
    expect(await detectArchive(rar())).to.equal(undefined);
    expect(await detectArchive(Buffer.from('Rar!\x1a\x07\x00\xcf\x90\x73\x00\x00\x0d\x00\x00\x00\x00\x00\x00\x00', 'latin1'))).to.equal(undefined);
    const r = await inspectArchive(rar());
    expect(r.findings.map(f => [f.detail, f.data?.reason])).to.deep.equal([['UNPARSEABLE', 'a RAR file, which this package does not read']]);
    // RAR is decided before a ZIP end record is looked for, so a ZIP after it changes nothing.
    expect(await detectArchive(Buffer.concat([rar(), zip([text('a.txt')])]))).to.equal(undefined);
    expect(await detectArchive(Buffer.from('plain text that is no archive'))).to.equal(undefined);
    expect(await detectArchive(Buffer.from('%PDF-1.7\n'))).to.equal(undefined);
    expect(await detectArchive(Buffer.alloc(0))).to.equal(undefined);
    expect(await detectArchive(lzmaFixture('7z-not-7z.7z'))).to.equal(undefined);
    // Raw Deflate64 data is what a ZIP entry holds, not a file this package reads.
    for (const f of fs.readdirSync(path.join(fixtures, 'deflate64')).filter(n => n.endsWith('.d64'))) {
      expect(await detectArchive(fs.readFileSync(path.join(fixtures, 'deflate64', f))), f).to.equal(undefined);
    }
  });

  it('claims a damaged archive the selection picks, which the inspection then rejects with its own finding', async () => {
    for (const [bytes, mimeType, finding] of [
      [fixture('zip-truncated.zip'), 'application/zip', 'CORRUPTED/UNPARSEABLE'],
      [fixture('zip-multi-disk.zip'), 'application/zip', 'STRUCTURE/MULTI_VOLUME'],
      [fixture('tar-damaged-header.tar'), 'application/x-tar', 'CORRUPTED/UNPARSEABLE'],
      [fixture('cab-continued.cab'), 'application/vnd.ms-cab-compressed', 'STRUCTURE/MULTI_VOLUME'],
      [lzmaFixture('7z-truncated.7z'), 'application/x-7z-compressed', 'CORRUPTED/TRUNCATED'],
    ] as const) {
      expect((await detectArchive(bytes))?.mimeType).to.equal(mimeType);
      const r = await inspectArchive(bytes);
      expect([r.status, r.format, r.findings.map(f => `${f.category}/${f.detail}`)]).to.deep.equal(['rejected', undefined, [finding]]);
    }
    // A ZIP found from its end record whose directory is gone: the reader cannot say where it starts, so 0.
    const z = Buffer.from(zip([text('a.txt')], { prefix: jpeg() }));
    z.write('XXXX', z.indexOf(Buffer.from([0x50, 0x4b, 0x01, 0x02])), 'latin1');
    expect(await detectArchive(z)).to.deep.equal({ mimeType: 'application/zip', extension: 'zip', offset: 0 });
    expect((await inspectArchive(z)).findings.map(f => f.detail)).to.deep.equal(['UNPARSEABLE']);
  });

  it('leaves the source open', async () => {
    for (const bytes of [fixture('zip-prepended.zip'), fixture('brotli-clean.br'), lzmaFixture('7z-sfx-prefix.7z'), Buffer.from('plain text')]) {
      let closed = 0;
      const inner = bufferSource(bytes);
      const source: ByteSource = { size: () => inner.size(), read: (o, n) => inner.read(o, n), close: async () => void closed++ };
      await detectArchiveSource(source);
      expect(closed).to.equal(0);
    }
  });

  it('passes read errors on, also from the Brotli test, which catches every error', async () => {
    const eio = () => Object.assign(new Error('read failed'), { code: 'EIO' });
    const bytes = Buffer.from('plain text that is no archive');
    /** Fails each read after the first `ok`. The fourth read of a short file is the Brotli test's. */
    const failingAfter = (ok: number): ByteSource => {
      let reads = 0;
      return { size: async () => bytes.length, read: async (o, n) => (++reads > ok ? Promise.reject(eio()) : bytes.subarray(o, o + n)) };
    };
    for (const ok of [0, 3]) {
      const e = await detectArchiveSource(failingAfter(ok)).then(
        () => undefined,
        (err: unknown) => err,
      );
      expect((e as { code?: string })?.code, `after ${ok} reads`).to.equal('EIO');
    }
    // With all four reads answered, the same file is no archive.
    expect(await detectArchiveSource(failingAfter(4))).to.equal(undefined);
  });

  it('stops at the deadline with the DEFUSE_LIMIT code, also in the Brotli test', async () => {
    const code = (p: Promise<unknown>) =>
      p.then(
        () => undefined,
        (err: unknown) => (err as { code?: string }).code,
      );
    expect(await code(detectArchive(fixture('zip-clean.zip'), { deadline: Date.now() - 1 }))).to.equal('DEFUSE_LIMIT');
    // The third read waits until the deadline has passed, so the Brotli test, which comes next, stops at it.
    const bytes = Buffer.from('plain text that is no archive');
    const deadline = Date.now() + 300;
    let reads = 0;
    const slow: ByteSource = {
      size: async () => bytes.length,
      async read(o, n) {
        if (++reads === 3) while (Date.now() <= deadline) await new Promise(r => setTimeout(r, 10));
        return bytes.subarray(o, o + n);
      },
    };
    expect(await code(detectArchiveSource(slow, { deadline }))).to.equal('DEFUSE_LIMIT');
    expect(reads).to.equal(3);
  });

  it('lets archivePlugin take exactly what it claims, under each name and declared type', async () => {
    const plugin = archivePlugin();
    const inputs = [
      fixture('zip-prepended.zip'),
      fixture('brotli-clean.br'),
      fixture('tar-damaged-header.tar'),
      lzmaFixture('7z-sfx-prefix.7z'),
      lzmaFixture('lzma-unknown-size.lzma'),
      Buffer.alloc(10240),
      rar(),
      Buffer.from('plain text that is no archive'),
      Buffer.from('%PDF-1.7\n'),
    ];
    for (const bytes of inputs) {
      for (const [name, type] of [
        [undefined, undefined],
        ['misnamed.txt', 'text/plain'],
        ['archive.zip', 'application/zip'],
        ['data.br', 'application/x-brotli'],
      ]) {
        const claimed = (await detectArchive(bytes, { name, declaredType: type })) !== undefined;
        expect(await plugin.accepts(fileOf(bytes, name, type)), `${bytes.subarray(0, 8).toString('hex')} as ${name}`).to.equal(claimed);
      }
    }
  });

  it('agrees with the format openArchive reads, for every fixture', async () => {
    // What the selection picks nothing for: the reader then names no format.
    const notOurs = /^(not an archive this package reads|a RAR file, which this package does not read)$/;
    const files = fixtureFiles();
    const manifest = JSON.parse(fs.readFileSync(path.join(fixtures, 'manifest.json'), 'utf8')) as { cases: Array<{ file: string }> };
    expect(manifest.cases.map(c => path.join(fixtures, c.file)).filter(f => !files.includes(f))).to.deep.equal([]);
    for (const file of files) {
      const bytes = fs.readFileSync(file);
      const name = path.relative(fixtures, file);
      // Each fixture's own name, which is how a Brotli file says it is one.
      const found = await detectArchive(bytes, { name: path.basename(file) });
      const read = await openArchive(bytes).then(
        async r => {
          await r.close();
          return r.format;
        },
        (e: unknown) => e as Error,
      );
      if (typeof read === 'string') expect(FORMATS[must(found, name).mimeType], name).to.equal(read);
      else if (notOurs.test(read.message)) expect(found, name).to.equal(undefined);
      // A file the selection picks and the reader then refuses, which the inspection rejects with its own finding.
      else expect(found, `${name}: ${read.message}`).to.not.equal(undefined);
    }
  });
});
