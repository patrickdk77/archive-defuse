import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ArchiveCategory, type ArchiveDetail, type ContainedFile, type ContainedFilePlugin, disarmArchive, inspectArchive } from '../src';
import { build, fixture, keepAll, kinds, must, of, pythonList, root } from './helpers/util';

/**
 * The patterns of published advisories against other archive readers, checked against GitHub's advisory database,
 * OSV and NVD, that the other test files do not already cover one by one. rules.test.ts covers traversal, absolute
 * names, drive letters, collisions, prototype names, links through links and permissions; limits.test.ts the bombs,
 * overlapping entries, nesting and sparse maps; codecs.test.ts the numbers and pax records; zip.test.ts the ZIP
 * structure checks taken over from office-defuse.
 */

const { tar, tarEntry, pax, zip, text } = build;
const keep = { filePlugins: [keepAll] };

/** A plugin that keeps every file and records the bytes it was shown, by name. */
function recording(): ContainedFilePlugin & { seen: Map<string, string> } {
  const seen = new Map<string, string>();
  return {
    kind: 'file',
    name: 'record',
    seen,
    accepts: () => true,
    async process(file: ContainedFile) {
      seen.set(file.name ?? '', Buffer.from(await file.source.read(0, file.size)).toString('latin1'));
      return 'passed';
    },
  };
}

/** A tar header with its checksum written again, after a test changed a byte of it. */
function fixTarChecksum(b: Buffer, at: number): void {
  b.write('        ', at + 148, 'latin1');
  let sum = 0;
  for (let i = at; i < at + 512; i++) sum += b[i];
  b.write(`${sum.toString(8).padStart(6, '0')}\0 `, at + 148, 'latin1');
}

describe('advisories against other archive readers', () => {
  it('removes links whose target is an absolute path (node-tar CVE-2026-23745, decompress CVE-2026-39243)', async () => {
    const bytes = tar(tarEntry({ name: 'etc', type: '2', link: '/etc/passwd' }), tarEntry({ name: 'hard', type: '1', link: '/etc/passwd' }), tarEntry({ name: 'ok.txt' }, 'ok'));
    const r = await disarmArchive(bytes, keep);
    expect(kinds(r.before)).to.include('LINK/OUTSIDE');
    expect(pythonList('tar', must(r.bytes, 'output')).map(([name]) => name)).to.deep.equal(['ok.txt']);
  });

  it('keeps the regular file, not the hard link to a host path, when both have one name (node-tar CVE-2018-20834, tar-fs CVE-2018-20835)', async () => {
    const r = await disarmArchive(tar(tarEntry({ name: 'x', type: '1', link: '/etc/passwd' }), tarEntry({ name: 'x' }, 'plain\n')), keep);
    expect(pythonList('tar', must(r.bytes, 'output')).map(([name, kind]) => [name, kind])).to.deep.equal([['x', 'file']]);
  });

  it('applies a pax size to the next file entry and not to a GNU long name between them (node-tar CVE-2026-53655, CVE-2025-62518)', async () => {
    const body = Buffer.alloc(600, 0x61);
    const bytes = tar(
      pax([['size', String(body.length)]]),
      tarEntry({ name: '././@LongLink', type: 'L', magic: 'ustar  \0' }, 'long/name.txt\0'),
      // The ustar size says 0, as a smuggling archive writes it. The pax size governs where the next header is.
      Buffer.concat([build.tarHeader({ name: 'long/name', size: 0, magic: 'ustar  \0' }), build.pad512(body)]),
      tarEntry({ name: 'after.txt' }, 'after'),
    );
    const seen = recording();
    const r = await disarmArchive(bytes, { filePlugins: [seen] });
    expect(r.status).to.not.equal('rejected');
    expect([...seen.seen.keys()]).to.deep.equal(['long/name.txt', 'after.txt']);
    expect(seen.seen.get('long/name.txt')?.length).to.equal(600);
  });

  it('emits the same entry the plugins were shown when names repeat (adm-zip GHSA-p634-w6r4-rjp2, pnpm CVE-2023-37478, Android CVE-2013-4787)', async () => {
    for (const [format, bytes] of [
      ['zip', zip([text('same.txt', 'first'), text('same.txt', 'second')])],
      ['tar', tar(tarEntry({ name: 'same.txt' }, 'first'), tarEntry({ name: 'same.txt' }, 'second'))],
    ] as const) {
      const seen = recording();
      const r = await disarmArchive(bytes, { filePlugins: [seen] });
      const out = pythonList(format, must(r.bytes, 'output'));
      expect([format, out.length, seen.seen.get('same.txt')]).to.deep.equal([format, 1, 'second']);
      const again = recording();
      await disarmArchive(must(r.bytes, 'output'), { filePlugins: [again] });
      expect([format, again.seen.get('same.txt')]).to.deep.equal([format, 'second']);
    }
  });

  it('removes a symbolic link named like a folder listed before it, and the files under it (node-tar CVE-2021-32803)', async () => {
    for (const link of ['/etc', '../..', 'other']) {
      const bytes = tar(tarEntry({ name: 'd/', type: '5' }), tarEntry({ name: 'd', type: '2', link }), tarEntry({ name: 'd/x.txt' }, 'x'), tarEntry({ name: 'other/', type: '5' }));
      const r = await disarmArchive(bytes, keep);
      expect([link, ...kinds(r.before).filter(k => k !== 'LINK/SYMLINK' && k !== 'LINK/OUTSIDE')]).to.deep.equal([link, 'NAME/FILE_DIRECTORY_CLASH', 'LINK/THROUGH_LINK']);
      expect(pythonList('tar', must(r.bytes, 'output')).map(([name]) => name)).to.deep.equal(['d/', 'other/']);
    }
  });

  it('follows a link whose name equals a folder only after compatibility normalization (node-tar CVE-2021-37712)', async () => {
    const r = await disarmArchive(tar(tarEntry({ name: '\ufb01le', type: '2', link: 'sub' }), tarEntry({ name: 'sub/', type: '5' }), tarEntry({ name: 'file/x.txt' }, 'x')), keep);
    expect(of(r.before, 'LINK/THROUGH_LINK').map(f => f.data?.name)).to.deep.equal(['file/x.txt']);
    expect(pythonList('tar', must(r.bytes, 'output')).map(([name]) => name)).to.not.include('file/x.txt');
  });

  it('drops times and owners fields that do not have their documented layout (Info-ZIP CVE-2014-8139, CVE-2014-9636)', async () => {
    const { extra, u16 } = build;
    const bad: Array<[string, Buffer, string]> = [
      ['NTFS times cut inside the reserved bytes', extra(0x000a, Buffer.alloc(2)), 'it ends inside its reserved bytes'],
      ['NTFS times whose attribute runs past the record', extra(0x000a, Buffer.concat([Buffer.alloc(4), u16(1), u16(24), Buffer.alloc(8)])), 'attribute 1 runs past the record'],
      ['NTFS times of the wrong size', extra(0x000a, Buffer.concat([Buffer.alloc(4), u16(1), u16(8), Buffer.alloc(8)])), 'its times attribute has 8 bytes, not 24'],
      ['an extended timestamp missing its time', extra(0x5455, Buffer.from([1])), 'its flags name a modification time it does not hold'],
      ['an extended timestamp longer than its flags', extra(0x5455, Buffer.concat([Buffer.from([1]), Buffer.alloc(8)])), 'its 9 bytes do not fit the times its flags name'],
      ['an old Unix field cut short', extra(0x5855, Buffer.alloc(6)), 'it has 6 bytes, not 8 or 12'],
      ['a Unix owners field of the wrong size', extra(0x7855, Buffer.alloc(2)), 'it has 2 bytes, not 0 or 4'],
      ['a new Unix owners field whose sizes do not add up', extra(0x7875, Buffer.from([1, 4, 0, 0, 0, 0, 4, 0])), 'its ID sizes do not add up to its length'],
      ['a new Unix owners field cut inside its user ID', extra(0x7875, Buffer.from([1, 200, 0])), 'it ends inside its user ID'],
    ];
    // With EXTRA_FIELD as info, another rule's rewrite keeps the field as it was.
    const info = { ...keep, actionOverrides: [{ category: 'STRUCTURE' as ArchiveCategory, detail: 'EXTRA_FIELD' as ArchiveDetail, action: 'info' as const }] };
    for (const [what, field, reason] of bad) {
      const bytes = zip([{ ...text('a.txt', 'hello'), centralExtra: field }, text('../b.txt', 'b')]);
      const r = await disarmArchive(bytes, keep);
      expect([what, of(r.before, 'STRUCTURE/EXTRA_FIELD')[0]?.data?.reason]).to.deep.equal([what, reason]);
      expect(Buffer.from(must(r.bytes, 'output')).indexOf(field), what).to.equal(-1);
      const kept = await disarmArchive(bytes, info);
      expect(Buffer.from(must(kept.bytes, 'output')).indexOf(field), what).to.be.greaterThan(-1);
    }
  });

  it('keeps well-formed times and owners fields, with the extended timestamp flags naming only the times it holds', async () => {
    const { extra, u16 } = build;
    const good = Buffer.concat([
      extra(0x5455, Buffer.from([3, 1, 2, 3, 4])),
      extra(0x000a, Buffer.concat([Buffer.alloc(4), u16(1), u16(24), Buffer.alloc(24, 1)])),
      extra(0x7875, Buffer.from([1, 4, 0xe8, 3, 0, 0, 4, 0xe8, 3, 0, 0])),
      extra(0x7855, Buffer.alloc(0)),
    ]);
    const bytes = zip([{ ...text('a.txt', 'hello'), centralExtra: good }, text('../b.txt', 'b')]);
    const r = await disarmArchive(bytes, keep);
    expect(kinds(r.before)).to.not.include('STRUCTURE/EXTRA_FIELD');
    const out = Buffer.from(must(r.bytes, 'output'));
    const fixed = Buffer.from(good);
    fixed[4] = 1;
    // The local header and the central directory each hold the fields once.
    let found = 0;
    for (let p = out.indexOf(fixed); p >= 0; p = out.indexOf(fixed, p + 1)) found++;
    expect(found).to.equal(2);
  });

  it('never starts a child process, so no entry name reaches a shell (bestzip CVE-2020-7730)', () => {
    const files: string[] = [];
    const walk = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        if (e.isDirectory()) walk(path.join(d, e.name));
        else if (e.name.endsWith('.ts')) files.push(path.join(d, e.name));
      }
    };
    walk(path.join(root, 'src'));
    expect(files.filter(f => /child_process|\bspawn\(|\bexecFile\(|\bfork\(/.test(fs.readFileSync(f, 'utf8')))).to.deep.equal([]);
  });

  it('answers every corruption of a ZIP header with a verdict, never an exception or a hang', async () => {
    const base = fixture('zip-clean.zip');
    const headers: number[] = [];
    for (const sig of [0x04034b50, 0x02014b50, 0x06054b50]) {
      for (let p = base.indexOf(build.u32(sig)); p >= 0; p = base.indexOf(build.u32(sig), p + 1)) headers.push(p);
    }
    for (const h of headers) {
      for (let p = h; p < Math.min(h + 46, base.length); p++) {
        for (const value of [0x00, 0xff, base[p] ^ 0x80]) {
          const b = Buffer.from(base);
          b[p] = value;
          const started = Date.now();
          const r = await inspectArchive(b, { ...keep, limits: { timeMs: 3000 } });
          expect(['clean', 'strippable', 'rejected'], `byte ${p}`).to.include(r.status);
          expect(Date.now() - started, `byte ${p}`).to.be.lessThan(3500);
        }
      }
    }
  });

  it('answers every corruption of a tar header with a verdict, with the checksum written again so the field is read', async () => {
    const base = fixture('tar-pax.tar');
    for (let h = 0; h + 512 <= base.length && base[h] !== 0; ) {
      for (let p = h; p < h + 512; p += 3) {
        if (p >= h + 148 && p < h + 156) continue;
        for (const value of [0x00, 0x37, 0x80, 0xff]) {
          const b = Buffer.from(base);
          b[p] = value;
          fixTarChecksum(b, h);
          const r = await inspectArchive(b, { ...keep, limits: { timeMs: 3000 } });
          expect(['clean', 'strippable', 'rejected'], `byte ${p}`).to.include(r.status);
        }
      }
      const size = Number.parseInt(
        base
          .toString('latin1', h + 124, h + 135)
          .replace(/\0.*$/, '')
          .trim() || '0',
        8,
      );
      h += 512 + Math.ceil(size / 512) * 512;
    }
  });
});
