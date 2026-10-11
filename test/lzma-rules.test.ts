import { expect } from 'chai';
import { allFindingSpecs, bufferSource, disarmArchive, inspectArchive, inspectArchiveSource } from '../src';
import { type ArchiveOptions, ArchiveCategory as C, ArchiveDetail as D } from '../src/types';
import { fixture, keepAll, list7z } from './helpers/lzma';
import { kinds } from './helpers/util';

const keep = (extra: ArchiveOptions = {}): ArchiveOptions => ({ filePlugins: [keepAll()], ...extra });
const info = (category: C, detail?: D) => ({ category, detail, action: 'info' as const });

describe('rules on xz, lzma and 7z files', () => {
  it('describes every kind in ASCII, with a known action', () => {
    for (const s of allFindingSpecs()) {
      expect(s.description.length, `${s.category}/${s.detail}`).to.be.greaterThan(5);
      expect(['reject', 'strip', 'info']).to.include(s.action);
      expect(s.description).to.match(/^[\x20-\x7e]+$/);
    }
  });

  it('applies each name rule on its own: with traversal allowed, the backslash fix still runs', async () => {
    const d = await disarmArchive(fixture('7z-traversal-backslash.7z'), keep({ actionOverrides: [info(C.Name, D.Traversal)] }));
    expect((await list7z(d.bytes as Uint8Array)).map(l => l.name)).to.deep.equal(['../../evil.txt', 'a/../../b.txt']);
  });

  it('applies each name rule on its own: with backslashes allowed, ".." segments still go', async () => {
    const d = await disarmArchive(fixture('7z-traversal-backslash.7z'), keep({ actionOverrides: [info(C.Name, D.Backslash)] }));
    expect((await list7z(d.bytes as Uint8Array)).map(l => l.name)).to.deep.equal(['evil.txt', 'a\\b.txt']);
  });

  it('keeps every duplicate when the duplicate rule allows them, each with the bytes the plugin saw', async () => {
    const d = await disarmArchive(fixture('7z-duplicate.7z'), keep({ actionOverrides: [info(C.Name, D.Duplicate)] }));
    const listed = await list7z(d.bytes as Uint8Array);
    expect(listed.map(l => l.name)).to.deep.equal(['same.txt', 'same.txt']);
    expect(listed[0].crc).to.not.equal(listed[1].crc);
  });

  it('removes data that fails its CRC or does not decode whatever the overrides say, as for a ZIP entry', async () => {
    for (const options of [keep(), keep({ actionOverrides: [info(C.Corrupted, D.EntryData)] })]) {
      const crc = await disarmArchive(fixture('7z-entry-crc.7z'), options);
      expect((await list7z(crc.bytes as Uint8Array)).map(l => l.name)).to.deep.equal(['good.txt']);
      const cut = await disarmArchive(fixture('7z-lzma-truncated.7z'), options);
      expect(cut.before.findings.filter(f => f.detail === D.EntryData).map(f => f.action)).to.deep.equal(['strip']);
      expect((await list7z(cut.bytes as Uint8Array)).map(l => l.name)).to.deep.equal([]);
    }
  });

  it('keeps the bytes before an archive when the leading-bytes rule allows them', async () => {
    const input = fixture('7z-leading-text.7z');
    const d = await disarmArchive(input, keep({ actionOverrides: [info(C.Structure, D.LeadingBytes)] }));
    expect(
      Buffer.from(d.bytes as Uint8Array)
        .subarray(0, 9)
        .toString(),
    ).to.equal('#!/bin/sh');
    const stripped = await disarmArchive(input, keep());
    expect(
      Buffer.from(stripped.bytes as Uint8Array)
        .subarray(0, 2)
        .toString('latin1'),
    ).to.equal('7z');
  });

  it('keeps bytes after the file when the trailing-bytes rule allows them', async () => {
    const d = await disarmArchive(fixture('xz-trailing.xz'), keep({ actionOverrides: [info(C.Structure, D.TrailingBytes)] }));
    expect(Buffer.from(d.bytes as Uint8Array).toString('latin1')).to.match(/appended data that is not xz$/);
  });

  it('removes an entry whose name and content disagree when the type rule strips', async () => {
    const r = await disarmArchive(fixture('7z-type-mismatch.7z'), keep({ actionOverrides: [{ category: C.Entry, detail: D.TypeMismatch, action: 'strip' }] }));
    expect((await list7z(r.bytes as Uint8Array)).map(l => l.name)).to.deep.equal([]);
  });

  it('clears setuid, setgid and the sticky bit only for the rules that strip', async () => {
    const d = await disarmArchive(fixture('7z-permissions.7z'), keep({ actionOverrides: [info(C.Permissions, D.Sticky)] }));
    const [entry] = await list7z(d.bytes as Uint8Array);
    expect(((entry.attrib ?? 0) >>> 16) & 0o7777).to.equal(0o1755);
  });

  it('reports links that leave the tree and paths through links', async () => {
    const r = await inspectArchive(fixture('7z-through-link.7z'), keep());
    expect(kinds(r)).to.include.members(['LINK/SYMLINK', 'LINK/OUTSIDE', 'LINK/THROUGH_LINK']);
    const d = await disarmArchive(fixture('7z-through-link.7z'), keep());
    expect((await list7z(d.bytes as Uint8Array)).map(l => l.name)).to.deep.equal([]);
  });

  it('skips the name rules for an archive that stores no names, and writes it without them', async () => {
    const d = await disarmArchive(fixture('7z-no-names.7z'), keep());
    expect([d.status, kinds(d.before).filter(k => k.startsWith('NAME/'))]).to.deep.equal(['clean', []]);
    expect((await list7z(d.bytes as Uint8Array)).map(l => l.name)).to.deep.equal([undefined, undefined]);
  });

  it('rejects without a score when the run could not inspect the file, whatever the overrides say', async () => {
    const r = await inspectArchive(fixture('7z-aes-nopw.7z'), keep({ actionOverrides: [info(C.Encrypted)] }));
    expect(r.status).to.equal('rejected');
    expect(r.score).to.equal(null);
    expect(r.risk).to.equal('UNKNOWN');
  });

  it('opens a solid encrypted folder with one password, so files that fail their CRCs do not restart it', async () => {
    // The first file has no CRC, so the empty password, tried after the caller's, also decodes it. Its second file has
    // a CRC, which only the right password matches, and the 38 after it fail theirs.
    const bytes = fixture('7z-aes-bad-crcs.7z');
    let read = 0;
    const source = bufferSource(bytes);
    const counting = {
      size: () => source.size(),
      read: async (o: number, n: number) => {
        const r = await source.read(o, n);
        read += r.length;
        return r;
      },
    };
    const r = await inspectArchiveSource(counting, keep({ password: 'pw' }));
    expect(r.findings.filter(f => f.detail === D.EntryData)).to.have.length(38);
    expect(read).to.be.lessThan(4 * bytes.length);
  });

  it('tries each password in order', async () => {
    const r = await inspectArchive(fixture('7z-aes.7z'), keep({ password: ['one', 'two', 'right password'] }));
    expect(r.status).to.equal('strippable');
    expect(kinds(r)).to.include('ENCRYPTED/DECRYPTED');
    const wrong = await inspectArchive(fixture('7z-aes.7z'), keep({ password: 'nope' }));
    expect(kinds(wrong)).to.include('ENCRYPTED/PASSWORD_REQUIRED');
  });

  it('writes a decrypted archive without encryption', async () => {
    const d = await disarmArchive(fixture('7z-aes.7z'), keep({ password: 'right password' }));
    const r = await inspectArchive(d.bytes as Uint8Array, keep());
    expect(r.status).to.equal('clean');
    expect(kinds(r)).to.not.include('ENCRYPTED/AES_256');
  });
});
