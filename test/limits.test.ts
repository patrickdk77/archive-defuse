import { expect } from 'chai';
import { archivePlugin, disarmArchive, inspectArchive, inspectArchiveSource } from '../src';
import { build, keepAll, line } from './helpers/util';

const { zip, tar, tarEntry, gzipMember, pax } = build;
const keep = { filePlugins: [keepAll] };
const last = (r: { findings: Array<{ action: string; category: string; detail: string }> }) => r.findings.map(f => `${f.action} ${f.category}/${f.detail}`).slice(-1)[0];

describe('limits', () => {
  it('reject a file over fileSize unread, with the size', async () => {
    let reads = 0;
    const bytes = zip([{ name: 'a.txt', data: 'a' }]);
    const source = {
      size: async () => bytes.length,
      read: async (o: number, n: number) => {
        reads++;
        return bytes.subarray(o, o + n);
      },
    };
    const r = await inspectArchiveSource(source, { limits: { fileSize: 10 } });
    expect([r.status, r.score, r.risk, last(r)]).to.deep.equal(['rejected', null, 'UNKNOWN', 'reject LIMIT/FILE_SIZE']);
    expect(reads).to.equal(0);
  });

  it('reject an archive with more entries than the limit, in every format', async () => {
    const files = Array.from({ length: 5 }, (_, i) => ({ name: `f${i}.txt`, data: 'x' }));
    expect(last(await inspectArchive(zip(files), { ...keep, limits: { entries: 4 } }))).to.equal('reject LIMIT/ENTRY_COUNT');
    expect(last(await inspectArchive(tar(...files.map(f => tarEntry({ name: f.name }, f.data))), { ...keep, limits: { entries: 4 } }))).to.equal('reject LIMIT/ENTRY_COUNT');
  });

  it('stop an entry at the decompressed limit whatever its headers declare, and the total across entries', async () => {
    const data = Buffer.alloc(200_000, 0x61);
    const declaredZero = zip([{ name: 'a.bin', data, central: { usize: 0 }, local: { usize: 0 } }]);
    const r = await inspectArchive(declaredZero, { ...keep, limits: { decompressedBytes: 100_000 } });
    // The entry decodes past the size it declares before it reaches the limit, so it goes as damaged.
    expect(r.findings.map(line)).to.deep.equal(['strip CORRUPTED/ENTRY_DATA']);
    const honest = zip([{ name: 'a.bin', data }]);
    expect(last(await inspectArchive(honest, { ...keep, limits: { decompressedBytes: 100_000 } }))).to.equal('reject LIMIT/DECOMPRESSED_SIZE');
    const gz = gzipMember(data);
    expect(last(await inspectArchive(gz, { ...keep, limits: { decompressedBytes: 100_000 } }))).to.equal('reject LIMIT/DECOMPRESSED_SIZE');
    const two = zip([
      { name: 'a.bin', data },
      { name: 'b.bin', data },
    ]);
    expect(last(await inspectArchive(two, { ...keep, limits: { totalDecompressedBytes: 300_000 } }))).to.equal('reject LIMIT/TOTAL_DECOMPRESSED_SIZE');
  });

  it('stop a high-ratio stream early, on inspect, disarm and inside another archive', async () => {
    const zeros = Buffer.alloc(64 * 1024 * 1024);
    const bomb = gzipMember(zeros);
    const started = Date.now();
    expect(last(await inspectArchive(bomb, keep))).to.equal('reject LIMIT/RATIO');
    expect((await disarmArchive(bomb, keep)).status).to.equal('rejected');
    const outer = zip([{ name: 'inner.gz', data: bomb, method: 0 }]);
    const r = await inspectArchive(outer, { filePlugins: [archivePlugin(), keepAll] });
    expect(r.findings.map(line)).to.deep.equal(['strip ENTRY/PLUGIN_REMOVED', 'strip LIMIT/RATIO in inner.gz']);
    expect(Date.now() - started).to.be.lessThan(10_000);
  });

  it('refuse overlapping entries that would decode one stream many times, by the declared total', async () => {
    const data = Buffer.alloc(1024 * 1024, 0x61);
    const one = zip([{ name: 'a.bin', data }]);
    const cd = one.indexOf(Buffer.from([0x50, 0x4b, 1, 2]));
    const record = one.subarray(cd, one.length - 22);
    const copies = Array.from({ length: 40 }, (_, i) => {
      const c = Buffer.from(record);
      c[46] = 0x61 + (i % 26);
      c[47] = 0x30 + Math.floor(i / 26);
      return c;
    });
    const dir = Buffer.concat(copies);
    const end = Buffer.concat([build.u32(0x06054b50), build.u16(0), build.u16(0), build.u16(40), build.u16(40), build.u32(dir.length), build.u32(cd), build.u16(0)]);
    const bomb = Buffer.concat([one.subarray(0, cd), dir, end]);
    const r = await inspectArchive(bomb, { ...keep, limits: { totalDecompressedBytes: 16 * 1024 * 1024 } });
    expect(last(r)).to.equal('reject LIMIT/TOTAL_DECOMPRESSED_SIZE');
  });

  it('stop at the deadline', async () => {
    const bytes = zip([{ name: 'a.txt', data: 'a' }]);
    const slow = { size: async () => bytes.length, read: (o: number, n: number) => new Promise<Uint8Array>(resolve => setTimeout(() => resolve(bytes.subarray(o, o + n)), 5)) };
    const r = await inspectArchiveSource(slow, { ...keep, limits: { timeMs: 1 } });
    expect([r.status, last(r)]).to.deep.equal(['rejected', 'reject LIMIT/TIME']);
  });

  it('cap the regions of a sparse map and the size of a pax header', async () => {
    const big = tar(
      pax([
        ['GNU.sparse.major', '1'],
        ['GNU.sparse.minor', '0'],
        ['GNU.sparse.realsize', '100'],
      ]),
      tarEntry({ name: 's' }, Buffer.concat([Buffer.from('99999999\n'), Buffer.alloc(503)])),
    );
    expect(last(await inspectArchive(big, keep))).to.equal('reject CORRUPTED/UNPARSEABLE');
    const header = tar(Buffer.concat([build.tarHeader({ name: 'PaxHeaders/x', type: 'x', size: 9 * 1024 * 1024 }), Buffer.alloc(512)]));
    expect(last(await inspectArchive(header, keep))).to.match(/reject CORRUPTED\/(UNPARSEABLE|TRUNCATED)/);
  });

  it('cap nesting at 10 by default, so an archive that holds itself ends', async () => {
    let bytes: Buffer = Buffer.from('x');
    for (let i = 0; i < 12; i++) bytes = gzipMember(bytes);
    expect(last(await inspectArchive(bytes, { filePlugins: [archivePlugin(), keepAll] }))).to.equal('reject LIMIT/NESTING_DEPTH');
    expect(last(await inspectArchive(bytes, { filePlugins: [archivePlugin(), keepAll], limits: { nestingDepth: 20 } }))).to.equal('info ENTRY/PLUGIN_PASSED');
  });
});
