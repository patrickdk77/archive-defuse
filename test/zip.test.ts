// Copied from office-defuse test/zip.test.ts. Changed: archive-defuse reads what office-defuse refuses whenever the
// rewrite can settle it, so most cases expect a note and a readable archive instead of a refusal, and the archives are
// built with the shared builders.
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { inspectArchive } from '../src';
import { DataError, StopError } from '../src/errors';
import { bufferSource, Reader } from '../src/io';
import { ZipArchive, type ZipEntry } from '../src/zip';
import { build, failure, keepAll, kinds, must, type ZipEntrySpec } from './helpers/util';

const { zip, extra, u16, u32, u64, crc32 } = build;
const LIMITS = { entries: 10_000, decompressedBytes: 512 * 1024 * 1024, totalDecompressedBytes: 2 * 1024 * 1024 * 1024, compressionRatio: 1000 };
const DOC = 'a document part\n'.repeat(4);
const DOC_DEFLATED = zlib.deflateRawSync(Buffer.from(DOC));

/** Three entries, the last of which a case changes. */
const three = (changes: Partial<ZipEntrySpec> = {}): ZipEntrySpec[] => [
  { name: 'a.txt', data: 'first\n' },
  { name: 'b/c.txt', data: 'second\n' },
  { name: 'b/d.txt', data: DOC, ...changes },
];

const open = (bytes: Uint8Array) => ZipArchive.open(bufferSource(bytes), LIMITS);
const meter = { add: () => undefined, time: () => undefined };

async function contents(z: ZipArchive, e: ZipEntry): Promise<Buffer> {
  const chunks: Uint8Array[] = [];
  for await (const c of z.read(e, meter)) chunks.push(c);
  return Buffer.concat(chunks);
}

/** What a reader refusal stops the run with, as category/detail, or 'no error'. */
async function stopOf(p: Promise<unknown>): Promise<string> {
  const e = await failure(p);
  return e instanceof StopError ? `${e.category}/${e.detail}` : e === undefined ? 'no error' : String(e);
}

/** The archive with a 16-bit field at `at` in the header that starts with `signature` and names `name` set to `value`. */
function patch16(z: Buffer, signature: number, name: string, at: number, value: number): Buffer {
  const nameAt = signature === 0x04034b50 ? 30 : 46;
  for (let p = z.indexOf(u32(signature)); p >= 0; p = z.indexOf(u32(signature), p + 1)) {
    if (z.subarray(p + nameAt, p + nameAt + name.length).toString('latin1') !== name) continue;
    const out = Buffer.from(z);
    out.writeUInt16LE(value, p + at);
    return out;
  }
  throw new Error(`no header for ${name}`);
}

/** The archive with its end record's directory size and offset moved by `size` and `offset` bytes. */
function shiftDirectory(z: Buffer, size: number, offset: number): Buffer {
  const out = Buffer.from(z);
  const end = out.lastIndexOf(u32(0x06054b50));
  out.writeUInt32LE(out.readUInt32LE(end + 12) + size, end + 12);
  out.writeUInt32LE(out.readUInt32LE(end + 16) + offset, end + 16);
  return out;
}

/** An archive whose end record follows a ZIP64 end record and locator, with changes to each. */
function zip64End(
  o: {
    end64?: Partial<{ size: number; count: number; cdSize: number; cdOffset: number; signature: number }>;
    locator?: Partial<{ disk: number; at: number; disks: number }>;
    end?: Record<string, number>;
  } = {},
): Buffer {
  const base = zip(three(), { end: o.end });
  const endAt = base.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const cdSize = base.readUInt32LE(endAt + 12);
  const cdOffset = base.readUInt32LE(endAt + 16);
  const e = { size: 44, count: 3, cdSize, cdOffset, signature: 0x06064b50, ...o.end64 };
  const end64 = Buffer.concat([u32(e.signature), u64(e.size), u16(45), u16(45), u32(0), u32(0), u64(e.count), u64(e.count), u64(e.cdSize), u64(e.cdOffset)]);
  const l = { disk: 0, at: endAt, disks: 1, ...o.locator };
  const locator = Buffer.concat([u32(0x07064b50), u32(l.disk), u64(l.at), u32(l.disks)]);
  return Buffer.concat([base.subarray(0, endAt), end64, locator, base.subarray(endAt)]);
}

/** A signed data descriptor with 32-bit sizes, or 64-bit ones with `wide`. */
const descriptorOf = (data: string, payload: Buffer, wide = false) =>
  Buffer.concat([u32(0x08074b50), u32(crc32(Buffer.from(data))), ...(wide ? [u64(payload.length), u64(Buffer.byteLength(data))] : [u32(payload.length), u32(Buffer.byteLength(data))])]);

const ones = 2n ** 64n - 1n;
const zip64Sizes = (usize: number, csize: number) => extra(1, Buffer.concat([u64(usize), u64(csize)]));

describe('ZIP reader', () => {
  const refused: Array<[string, () => Buffer, string]> = [
    ['a file shorter than an end record', () => Buffer.alloc(10), 'CORRUPTED/UNPARSEABLE'],
    ['a disk number other than 0', () => zip(three(), { end: { disk: 1 } }), 'STRUCTURE/MULTI_VOLUME'],
    ['a directory size larger than the file', () => zip(three(), { end: { cdSize: 100_000 } }), 'CORRUPTED/UNPARSEABLE'],
    ['a central header without its signature', () => shiftDirectory(zip(three()), 4, -4), 'CORRUPTED/UNPARSEABLE'],
    ['a central header whose extra field runs past the directory', () => patch16(zip(three()), 0x02014b50, 'b/d.txt', 30, 1000), 'CORRUPTED/UNPARSEABLE'],
    ['strong encryption', () => zip(three({ flags: 0x0041 })), 'ENCRYPTED/UNSUPPORTED'],
    ['an encrypted central directory', () => zip(three({ flags: 0x2000 })), 'ENCRYPTED/UNSUPPORTED'],
    ['a ZIP64 field whose disk number is not 0', () => zip(three({ central: { disk: 0xffff }, centralExtra: extra(1, u32(1)) })), 'STRUCTURE/MULTI_VOLUME'],
    ['a declared size past the limit', () => zip(three({ central: { usize: 0xffffffff, csize: 0xffffffff }, centralExtra: zip64Sizes(2 ** 40, 2 ** 40) })), 'LIMIT/DECOMPRESSED_SIZE'],
    ['an end record at its maximum with no ZIP64 record', () => zip(three(), { end: { cdOffset: 0xffffffff } }), 'CORRUPTED/UNPARSEABLE'],
    ['a ZIP64 locator on another disk', () => zip64End({ locator: { disks: 2 } }), 'STRUCTURE/MULTI_VOLUME'],
  ];
  for (const [what, make, expected] of refused) {
    it(`refuses ${what} with ${expected} and no score`, async () => {
      const r = await inspectArchive(make(), { filePlugins: [keepAll] });
      expect([r.status, r.score, r.risk]).to.deep.equal(['rejected', null, 'UNKNOWN']);
      expect(kinds(r).slice(-1)[0]).to.equal(expected);
    });
  }

  // Each of these office-defuse refuses. Here the reader notes it and the rewrite settles it.
  const noted: Array<[string, () => Buffer, string]> = [
    ['an end record whose comment runs past the end of the file', () => Buffer.concat([zip(three(), { comment: Buffer.from('x') }).subarray(0, -1)]), 'STRUCTURE/MALFORMED_HEADER'],
    ['entry counts that differ between this disk and the archive', () => patch16(zip(three()), 0x06054b50, '', 8, 2), 'STRUCTURE/HEADER_MISMATCH'],
    ['a directory offset past the end of the file', () => zip(three(), { end: { cdOffset: 100_000 } }), 'STRUCTURE/OFFSET_SHIFT'],
    ['a directory that ends before the end record', () => zip(three(), { end: { cdSize: 46 } }), 'STRUCTURE/HEADER_MISMATCH'],
    ['a directory that holds more than the end record counts', () => zip(three(), { end: { count: 2 } }), 'STRUCTURE/HEADER_MISMATCH'],
    ['an entry name over 1,024 bytes', () => zip([...three(), { name: `b/${'a'.repeat(1100)}.txt`, data: 'x' }]), 'NAME/TOO_LONG'],
    ['an empty entry name', () => zip([...three(), { name: '', data: 'x' }]), 'NAME/EMPTY'],
    ['an entry name with a control character', () => zip([...three(), { name: 'b/a\u0001.txt', data: 'x' }]), 'NAME/CONTROL_CHARACTER'],
    ['an empty path segment', () => zip([...three(), { name: 'b//e.txt', data: 'x' }]), 'NAME/EMPTY_SEGMENT'],
    ['a name flagged UTF-8 that is not valid UTF-8', () => zip([...three(), { name: Buffer.from([0x61, 0xff]), data: 'x', flags: 0x0800 }]), 'NAME/ENCODING'],
    ['an Info-ZIP Unicode path field that is not UTF-8', () => zip(three({ centralExtra: extra(0x7075, Buffer.from([1, 0, 0, 0, 0, 0xff])) })), 'NAME/UNICODE_PATH'],
    ['an extra field block that ends inside a record header', () => zip(three({ centralExtra: Buffer.from([1, 2]) })), 'STRUCTURE/EXTRA_FIELD'],
    [
      'two entries whose names match in Unicode normalization',
      () => zip([...three(), { name: 'b/caf\u00e9.txt', data: 'x', flags: 0x800 }, { name: 'b/cafe\u0301.txt', data: 'y', flags: 0x800 }]),
      'NAME/NORMALIZATION_COLLISION',
    ],
    ['a file and a folder of the same name', () => zip([...three(), { name: 'b/media', data: 'x' }, { name: 'b/media/', data: '', method: 0 }]), 'NAME/FILE_DIRECTORY_CLASH'],
    ['a local header with other flags', () => zip(three({ local: { flags: 0x0800 } })), 'STRUCTURE/HEADER_MISMATCH'],
    ['a local ZIP64 field shorter than its sizes', () => zip(three({ localExtra: extra(1, Buffer.alloc(8)) })), 'STRUCTURE/HEADER_MISMATCH'],
    ['a local ZIP64 field that disagrees with the local size', () => zip(three({ localExtra: zip64Sizes(1, DOC_DEFLATED.length) })), 'STRUCTURE/HEADER_MISMATCH'],
    ['a local size at its maximum with no ZIP64 field', () => zip(three({ local: { usize: 0xffffffff } })), 'STRUCTURE/HEADER_MISMATCH'],
    [
      'a local CRC that disagrees with a data descriptor entry',
      () => zip(three({ flags: 8, local: { crc: 1, csize: 0, usize: 0 }, after: descriptorOf(DOC, DOC_DEFLATED) })),
      'STRUCTURE/HEADER_MISMATCH',
    ],
    [
      'a local size that disagrees with a data descriptor entry',
      () => zip(three({ flags: 8, local: { crc: 0, csize: 0, usize: 1 }, after: descriptorOf(DOC, DOC_DEFLATED) })),
      'STRUCTURE/HEADER_MISMATCH',
    ],
    [
      'a data descriptor with other sizes in either width',
      () => zip(three({ flags: 8, local: { crc: 0, csize: 0, usize: 0 }, after: descriptorOf(DOC, DOC_DEFLATED).fill(0, 8) })),
      'STRUCTURE/HEADER_MISMATCH',
    ],
    ['a ZIP64 locator that points past itself', () => zip64End({ locator: { at: 1_000_000 } }), 'STRUCTURE/HEADER_MISMATCH'],
    ['a ZIP64 locator that points at something else', () => zip64End({ end64: { signature: 0x12345678 } }), 'STRUCTURE/HEADER_MISMATCH'],
    ['a ZIP64 end record that does not end at its locator', () => zip64End({ end64: { size: 48 } }), 'STRUCTURE/HEADER_MISMATCH'],
    ['a ZIP64 end record whose directory size disagrees', () => zip64End({ end64: { cdSize: 1 } }), 'STRUCTURE/HEADER_MISMATCH'],
  ];
  for (const [what, make, expected] of noted) {
    it(`reads ${what} and reports ${expected}`, async () => {
      const r = await inspectArchive(make(), { filePlugins: [keepAll] });
      expect(kinds(r)).to.include(expected);
      expect(r.status).to.equal(expected === 'NAME/TOO_LONG' ? 'clean' : 'strippable');
    });
  }

  // An entry whose data cannot be read is removed, and the rest of the archive stays.
  const broken: Array<[string, () => Buffer]> = [
    ['a ZIP64 offset field beyond a safe integer', () => zip(three({ central: { offset: 0xffffffff }, centralExtra: extra(1, u64(2n ** 60n)) }))],
    ['a local header past the end of the file', () => zip(three({ central: { offset: 99999 } }))],
    ['a local header without its signature', () => patch16(zip(three()), 0x04034b50, 'b/d.txt', 0, 0)],
    ['a local extra field that runs past the file', () => patch16(zip(three()), 0x04034b50, 'b/d.txt', 28, 0xffff)],
    ['a central size at its maximum with no ZIP64 field', () => zip(three({ central: { usize: 0xffffffff } }))],
    ['a stored entry with two sizes', () => zip(three({ method: 0, central: { usize: 5 } }))],
    ['a deflate stream that is corrupt', () => zip(three({ payload: Buffer.from([0xff, 0xff, 0xff, 0xff]) }))],
    ['a deflate stream cut short', () => zip(three({ payload: DOC_DEFLATED.subarray(0, 20) }))],
    ['deflate data followed by leftover bytes', () => zip(three({ payload: Buffer.concat([DOC_DEFLATED, Buffer.alloc(100, 7)]) }))],
  ];
  for (const [what, make] of broken) {
    it(`removes the entry with ${what} as CORRUPTED/ENTRY_DATA`, async () => {
      const r = await inspectArchive(make(), { filePlugins: [keepAll] });
      expect(kinds(r)).to.include('CORRUPTED/ENTRY_DATA');
      expect(r.status).to.equal('strippable');
    });
  }

  it('reads data descriptors of either width when their values agree', async () => {
    const narrow = three({ flags: 8, local: { crc: 0, csize: 0, usize: 0 }, localExtra: zip64Sizes(DOC.length, DOC_DEFLATED.length), after: descriptorOf(DOC, DOC_DEFLATED) });
    const wide = three({ flags: 8, local: { crc: 0, csize: 0, usize: 0 }, after: descriptorOf(DOC, DOC_DEFLATED, true) });
    for (const entries of [narrow, wide]) {
      const z = await open(zip(entries));
      expect(z.notes).to.deep.equal([]);
      expect((await contents(z, z.entries[2])).toString()).to.equal(DOC);
    }
  });

  it('reads a data descriptor after an empty deflated entry, whose wide reading overflows a number', async () => {
    const empty = zlib.deflateRawSync(Buffer.alloc(0));
    const entries = three({ flags: 0x0800 });
    entries.splice(2, 0, { name: 'b/empty.txt', data: '', flags: 0x0808, local: { crc: 0, csize: 0, usize: 0 }, payload: empty, after: descriptorOf('', empty) });
    const z = await open(zip(entries));
    expect(z.notes).to.deep.equal([]);
    expect((await contents(z, z.entries[2])).length).to.equal(0);
  });

  it('reads streamed ZIP64 entries whose local sizes are ones, with the sizes in 24-byte data descriptors', async () => {
    const entries = three({
      flags: 8,
      local: { crc: 0, csize: 0xffffffff, usize: 0xffffffff },
      localExtra: extra(1, Buffer.concat([u64(ones), u64(ones)])),
      central: { csize: 0xffffffff, usize: 0xffffffff },
      centralExtra: zip64Sizes(DOC.length, DOC_DEFLATED.length),
      after: descriptorOf(DOC, DOC_DEFLATED, true),
    });
    const z = await open(zip(entries));
    expect(z.notes).to.deep.equal([]);
    expect((await contents(z, z.entries[2])).toString()).to.equal(DOC);
  });

  it('accepts a ZIP64 end record that agrees with the end record, and one the end record defers to', async () => {
    expect(await stopOf(open(zip64End()))).to.equal('no error');
    expect((await open(zip64End({ end: { count: 0xffff } }))).notes.map(n => n.detail)).to.deep.equal([]);
  });

  it('takes the name from an Info-ZIP Unicode path field whose CRC matches the header name', async () => {
    const field = extra(0x7075, Buffer.concat([Buffer.from([1]), u32(crc32(Buffer.from([0x63, 0x61, 0x66, 0x82]))), Buffer.from('caf\u00e9')]));
    const z = await open(zip([{ name: Buffer.from([0x63, 0x61, 0x66, 0x82]), data: 'x', centralExtra: field, localExtra: field }]));
    expect(z.entries[0].name).to.equal('caf\u00e9');
    expect(z.entries[0].notes.map(n => n.detail)).to.deep.equal(['ENCODING']);
  });

  it('reports bytes before, between and after the entries, and reads on', async () => {
    const leading = await open(zip(three(), { prefix: Buffer.alloc(64, 1) }));
    expect(leading.notes).to.deep.equal([{ category: 'STRUCTURE', detail: 'LEADING_BYTES', data: { bytes: 64 } }]);
    const trailing = await open(zip(three(), { trailing: Buffer.alloc(40, 1) }));
    expect(trailing.notes).to.deep.equal([{ category: 'STRUCTURE', detail: 'TRAILING_BYTES', data: { bytes: 40 } }]);
    const hidden = await open(
      zip([
        { name: 'a.txt', data: 'x' },
        { name: 'b.txt', data: 'y', before: Buffer.alloc(46, 2) },
      ]),
    );
    expect(hidden.notes).to.deep.equal([{ category: 'STRUCTURE', detail: 'HIDDEN_DATA', data: { bytes: 46, localHeaders: 0 } }]);
    const empty = await open(zip([], { prefix: Buffer.from('stub') }));
    expect(empty.notes).to.deep.equal([{ category: 'STRUCTURE', detail: 'LEADING_BYTES', data: { bytes: 4 } }]);
  });

  it('refuses entry counts and declared sizes past the limits before reading any entry data', async () => {
    const bytes = zip(three());
    let reads = 0;
    const counting = {
      size: async () => bytes.length,
      read: async (o: number, n: number) => {
        reads++;
        return bytes.subarray(o, o + n);
      },
    };
    const stop = (limits: Partial<typeof LIMITS>) => stopOf(ZipArchive.open(counting, { ...LIMITS, ...limits }));
    expect(await stop({ entries: 2 })).to.equal('LIMIT/ENTRY_COUNT');
    expect(await stop({ decompressedBytes: 10 })).to.equal('LIMIT/DECOMPRESSED_SIZE');
    expect(await stop({ totalDecompressedBytes: 20 })).to.equal('LIMIT/TOTAL_DECOMPRESSED_SIZE');
    expect(await stop({ entries: 3, decompressedBytes: 1000, totalDecompressedBytes: 2000 })).to.equal('no error');
    // Each open reads the one block that holds the whole small archive, and no entry data.
    expect(reads).to.equal(4);
  });

  it('stops inflating once an entry passes its declared size', async () => {
    const big = Buffer.alloc(4 * 1024 * 1024);
    const z = await open(zip([{ name: 'a.bin', data: big, local: { usize: 1000 }, central: { usize: 1000 } }]));
    let seen = 0;
    const e = await failure(
      (async () => {
        for await (const c of z.read(z.entries[0], meter)) seen += c.length;
      })(),
    );
    expect(e).to.be.instanceOf(DataError);
    expect(seen).to.be.lessThan(big.length);
  });

  it('stops a read that passes the time limit', async () => {
    const z = await open(zip([{ name: 'a.bin', data: Buffer.alloc(1024) }]));
    const late = {
      add: () => undefined,
      time: () => {
        throw Object.assign(new Error('Time limit exceeded'), { code: 'DEFUSE_LIMIT', limit: 'time' });
      },
    };
    const e = await failure(
      (async () => {
        for await (const _ of z.read(must(z.entries[0], 'entry'), late));
      })(),
    );
    expect((e as { code?: string }).code).to.equal('DEFUSE_LIMIT');
  });
});

describe('block reader', () => {
  it('reads ranges across blocks and keeps only the newest blocks', async () => {
    const bytes = Buffer.from(Array.from({ length: 4096 }, (_, i) => i & 0xff));
    const reads: number[] = [];
    const source = {
      size: async () => bytes.length,
      read: async (o: number, n: number) => {
        reads.push(o);
        return bytes.subarray(o, o + n);
      },
    };
    const r = new Reader(source, bytes.length, 256, 2);
    expect(Buffer.from(await r.read(250, 20)).equals(bytes.subarray(250, 270))).to.equal(true);
    expect(Buffer.from(await r.read(4090, 100)).equals(bytes.subarray(4090))).to.equal(true);
    expect((await r.read(5000, 10)).length).to.equal(0);
    // Blocks 0 and 1 were read first, then block 15 pushed block 0 out.
    await r.read(0, 1);
    expect(reads).to.deep.equal([0, 256, 3840, 0]);
  });
});
