import { expect } from 'chai';
import { disarmArchive, inspectArchive } from '../src';
import { crc32 } from '../src/crc32';
import { fixture, manifest, optionsFor } from './helpers/lzma';
import { kinds } from './helpers/util';

const cases = manifest();

/**
 * Published advisories against other archive readers, each with the crafted fixture that holds its pattern and the
 * finding this package makes of it. The IDs were checked against GitHub's advisory database, OSV and NVD.
 */
const ADVISORIES: Array<[string, string, string]> = [
  ['Commons Compress CVE-2021-35515: a 7z coder graph that loops', '7z-coder-loop.7z', 'CORRUPTED/UNPARSEABLE'],
  ['Commons Compress CVE-2021-35516: a pack stream count that asks for a huge allocation', '7z-huge-pack-count.7z', 'CORRUPTED/UNPARSEABLE'],
  ['Commons Compress CVE-2021-35516: a huge folder count', '7z-huge-folder-count.7z', 'CORRUPTED/UNPARSEABLE'],
  ['Commons Compress CVE-2021-35516: a huge file count', '7z-huge-file-count.7z', 'LIMIT/ENTRY_COUNT'],
  ['Commons Compress CVE-2021-35516: a huge coder count', '7z-huge-coder-count.7z', 'CORRUPTED/UNPARSEABLE'],
  ['Commons Compress CVE-2021-35516: a huge coder property size', '7z-huge-property-size.7z', 'CORRUPTED/UNPARSEABLE'],
  ['adm-zip CVE-2026-39244: declared sizes past what memory holds', '7z-declared-huge.7z', 'LIMIT/TOTAL_DECOMPRESSED_SIZE'],
  ['adm-zip CVE-2026-39244: one entry declaring a size past the limit', '7z-entry-huge.7z', 'LIMIT/DECOMPRESSED_SIZE'],
  ['libarchive CVE-2016-4300: a huge substream count', '7z-huge-substreams.7z', 'LIMIT/ENTRY_COUNT'],
  ['libarchive CVE-2016-8689: a file property given twice', '7z-two-empty-stream.7z', 'CORRUPTED/UNPARSEABLE'],
  ['7-Zip CVE-2025-11001 and CVE-2025-11002: a symlink that leaves the tree', '7z-symlink-escape.7z', 'LINK/OUTSIDE'],
  ['7-Zip CVE-2025-55188: symlinks chained out of the tree', '7z-symlink-chain.7z', 'LINK/OUTSIDE'],
  ['tar-fs CVE-2025-48387: symlinks that loop', '7z-symlink-loop.7z', 'LINK/OUTSIDE'],
  ['node-tar CVE-2021-32803: a file written through a link', '7z-through-link.7z', 'LINK/THROUGH_LINK'],
  ['adm-zip CVE-2018-1002204: .. segments', '7z-traversal.7z', 'NAME/TRAVERSAL'],
  ['pnpm CVE-2026-23889: traversal with backslashes', '7z-traversal-backslash.7z', 'NAME/BACKSLASH'],
  ['node-tar CVE-2021-32804: absolute paths', '7z-absolute.7z', 'NAME/ABSOLUTE'],
  ['node-tar CVE-2021-37713: drive letters', '7z-drive-letter.7z', 'NAME/DRIVE_LETTER'],
  ['node-tar CVE-2026-59875: a name with a NUL in it', '7z-embedded-nul.7z', 'CORRUPTED/UNPARSEABLE'],
  ['node-tar CVE-2021-37701: names that differ only in case', '7z-case-collision.7z', 'NAME/CASE_COLLISION'],
  ['node-tar CVE-2021-37712: names that differ only in Unicode normalization', '7z-nfkd-collision.7z', 'NAME/NORMALIZATION_COLLISION'],
  ['adm-zip GHSA-p634-w6r4-rjp2: two entries with one name', '7z-duplicate.7z', 'NAME/DUPLICATE'],
  ['adm-zip CVE-2026-102282: setuid, setgid and sticky bits', '7z-permissions.7z', 'PERMISSIONS/SETUID'],
  ['an encoded header that unpacks past the limit', '7z-encoded-header-huge.7z', 'LIMIT/TOTAL_DECOMPRESSED_SIZE'],
  ['a 7z dictionary past the limit', '7z-big-dictionary.7z', 'LIMIT/DICTIONARY_SIZE'],
  ['an xz dictionary past the limit', 'xz-big-dictionary.xz', 'LIMIT/DICTIONARY_SIZE'],
  ['an lzma dictionary past the limit', 'lzma-big-dictionary.lzma', 'LIMIT/DICTIONARY_SIZE'],
  ['node-tar CVE-2026-59873: an xz bomb', 'xz-bomb.xz', 'LIMIT/RATIO'],
  ['node-tar CVE-2026-59873: an lzma bomb', 'lzma-bomb.lzma', 'LIMIT/RATIO'],
  ['Info-ZIP CVE-2015-7697: an LZMA2 stream with no end', 'xz-lzma2-no-end.xz', 'CORRUPTED/TRUNCATED'],
  ['a truncated 7z LZMA stream', '7z-lzma-truncated.7z', 'CORRUPTED/ENTRY_DATA'],
  ['an xz index whose record count disagrees with the blocks', 'xz-index-count.xz', 'STRUCTURE/INDEX_MISMATCH'],
  ['an xz index whose sizes disagree with the blocks', 'xz-index-size.xz', 'STRUCTURE/INDEX_MISMATCH'],
  ['an xz index that declares a huge record count', 'xz-index-huge.xz', 'STRUCTURE/INDEX_MISMATCH'],
];

/** Sets the next-header CRC and the start-header CRC of a 7z file to match its bytes. */
function fixCrcs(b: Buffer): Buffer {
  const at = 32 + Number(b.readBigUInt64LE(12));
  const size = Number(b.readBigUInt64LE(20));
  if (at + size <= b.length) b.writeUInt32LE(crc32(b.subarray(at, at + size)), 28);
  b.writeUInt32LE(crc32(b.subarray(12, 32)), 8);
  return b;
}

describe('advisories against other archive readers, in xz, lzma and 7z files', () => {
  for (const [what, name, expected] of ADVISORIES) {
    it(`${what}: ${expected}`, async () => {
      const e = cases[name];
      const started = Date.now();
      const r = await inspectArchive(fixture(name), optionsFor(e));
      expect(kinds(r)).to.include(expected);
      expect(Date.now() - started, 'inspection time').to.be.lessThan(5000);
      if (r.status === 'rejected') return;
      // What a rule strips is gone from the copy.
      const d = await disarmArchive(fixture(name), optionsFor(e));
      const after = await inspectArchive(d.bytes as Uint8Array, optionsFor(e));
      expect(kinds(after)).to.not.include(expected);
    });
  }

  it('keeps names like __proto__ as entries and never touches Object.prototype (jszip CVE-2021-23413)', async () => {
    const before = Object.getOwnPropertyNames(Object.prototype).sort();
    const r = await inspectArchive(fixture('7z-proto-names.7z'), optionsFor(cases['7z-proto-names.7z']));
    expect(r.status).to.not.equal('rejected');
    expect(Object.getOwnPropertyNames(Object.prototype).sort()).to.deep.equal(before);
    expect(({} as Record<string, unknown>).polluted).to.equal(undefined);
  });

  it('answers every corruption of a 7z header with a verdict, never an exception', async () => {
    const base = fixCrcs(Buffer.from(fixture('7z-lzma2-solid.7z')));
    const at = 32 + Number(base.readBigUInt64LE(12));
    const size = Number(base.readBigUInt64LE(20));
    let defused = 0;
    for (let p = at; p < at + size; p++) {
      for (const value of [0x00, 0xff, base[p] ^ 0x01]) {
        const b = Buffer.from(base);
        b[p] = value;
        fixCrcs(b);
        const r = await inspectArchive(b, { limits: { timeMs: 3000 } });
        expect(['clean', 'strippable', 'rejected']).to.include(r.status);
        if (r.status !== 'strippable') continue;
        const d = await disarmArchive(b, { limits: { timeMs: 3000 } });
        expect(d.status, `byte ${p} set to ${value}`).to.be.oneOf(['defused', 'rejected']);
        if (d.status === 'defused') defused++;
      }
    }
    expect(defused).to.be.greaterThan(0);
  });
});
