import { expect } from 'chai';
import { type ArchiveActionOverride, type ArchiveCategory, type ArchiveDetail, disarmArchive, inspectArchive } from '../src';
import { build, keepAll, kinds, must, of, pythonList } from './helpers/util';

const { zip, tar, tarEntry, pax, text } = build;
const keep = { filePlugins: [keepAll] };
const override = (category: string, detail: string, action: 'info' | 'strip' | 'reject'): ArchiveActionOverride => ({ category: category as ArchiveCategory, detail: detail as ArchiveDetail, action });

/** The names a defused ZIP holds, read back with Python's zipfile. */
async function zipNames(bytes: Buffer, options = {}): Promise<string[]> {
  const r = await disarmArchive(bytes, { ...keep, ...options });
  expect(r.status, JSON.stringify(r.before.findings.slice(-1))).to.not.equal('rejected');
  return pythonList('zip', must(r.bytes, 'output')).map(([name]) => name);
}

/** The names and kinds a defused tar holds, read back with Python's tarfile. */
async function tarMembers(bytes: Buffer, options = {}): Promise<Array<[string, string, string]>> {
  const r = await disarmArchive(bytes, { ...keep, ...options });
  expect(r.status, JSON.stringify(r.before.findings.slice(-1))).to.not.equal('rejected');
  return pythonList('tar', must(r.bytes, 'output'));
}

describe('name rules', () => {
  const cases: Array<[string, string, string[], string]> = [
    ['../../evil.txt', 'evil.txt', ['NAME/TRAVERSAL'], 'a name that climbs out'],
    ['a/b/../../../c.txt', 'a/b/c.txt', ['NAME/TRAVERSAL'], 'a climb in the middle of a name'],
    ['prefix/../prefix/target.txt', 'prefix/prefix/target.txt', ['NAME/TRAVERSAL'], 'a climb that would land back on another path'],
    ['..\\..\\evil.txt', 'evil.txt', ['NAME/TRAVERSAL', 'NAME/BACKSLASH'], 'backslash separators'],
    ['.. /x.txt', 'x.txt', ['NAME/TRAVERSAL'], 'a ".." part with a space Windows drops'],
    ['////etc/passwd', 'etc/passwd', ['NAME/ABSOLUTE'], 'every leading root'],
    ['C:..\\x.txt', 'x.txt', ['NAME/DRIVE_LETTER', 'NAME/TRAVERSAL', 'NAME/BACKSLASH'], 'a drive-relative climb'],
    ['C:some\\path.txt', 'some/path.txt', ['NAME/DRIVE_LETTER', 'NAME/BACKSLASH'], 'a drive-relative name'],
    ['\\\\?\\C:\\x.txt', 'x.txt', ['NAME/DRIVE_LETTER', 'NAME/ABSOLUTE', 'NAME/BACKSLASH'], 'a long-path drive prefix'],
    ['a/./b//c.txt', 'a/b/c.txt', ['NAME/EMPTY_SEGMENT'], 'empty and "." parts'],
    ['visible.txt\u0000hidden', 'visible.txt_hidden', ['NAME/CONTROL_CHARACTER'], 'a NUL inside a name'],
    ['bad\u202etxt.exe', 'bad_txt.exe', ['NAME/CONTROL_CHARACTER'], 'a right-to-left override'],
    ['NUL.txt', 'NUL_.txt', ['NAME/WINDOWS_RESERVED'], 'a Windows device name'],
    ['file.txt:stream', 'file.txt_stream', ['NAME/WINDOWS_RESERVED'], 'a colon'],
    ['dots...', 'dots___', ['NAME/WINDOWS_RESERVED'], 'trailing dots'],
  ];
  for (const [name, fixed, expected, what] of cases) {
    it(`fixes ${what}: ${JSON.stringify(name)} becomes ${JSON.stringify(fixed)}`, async () => {
      const bytes = zip([{ name: Buffer.from(name, 'utf8'), data: 'x', flags: 0x800 }]);
      const r = await inspectArchive(bytes, keep);
      for (const k of expected) expect(kinds(r), k).to.include(k);
      expect(await zipNames(bytes)).to.deep.equal([fixed]);
    });
  }

  it('removes an entry whose name has nothing left once fixed', async () => {
    const bytes = zip([text('../'), text('kept.txt')]);
    expect(await zipNames(bytes)).to.deep.equal(['kept.txt']);
  });

  it('applies each name rule on its own: with TRAVERSAL as info the ".." parts stay and ABSOLUTE still fixes the root', async () => {
    const bytes = zip([text('/../x.txt')]);
    const options = { actionOverrides: [override('NAME', 'TRAVERSAL', 'info')] };
    const r = await inspectArchive(bytes, { ...keep, ...options });
    expect(of(r, 'NAME/TRAVERSAL')[0].action).to.equal('info');
    expect(of(r, 'NAME/ABSOLUTE')[0].action).to.equal('strip');
    expect(await zipNames(bytes, options)).to.deep.equal(['../x.txt']);
  });

  it('keeps backslashes where they were when BACKSLASH is info and TRAVERSAL strips', async () => {
    const options = { actionOverrides: [override('NAME', 'BACKSLASH', 'info')] };
    expect(await zipNames(zip([text('a\\..\\b.txt')]), options)).to.deep.equal(['a\\b.txt']);
  });

  it('keeps the last of several entries with one name, as readers that overwrite do', async () => {
    const r = await disarmArchive(zip([text('same.txt', 'first\n'), text('same.txt', 'second\n')]), keep);
    const listed = pythonList('zip', must(r.bytes, 'output'));
    expect(listed.length).to.equal(1);
    const second = pythonList('zip', zip([text('same.txt', 'second\n')]))[0];
    expect(listed[0]).to.deep.equal(second);
  });

  it('finds collisions on the names the output would have, so a fixed name cannot land on another', async () => {
    const r = await inspectArchive(zip([text('../a.txt', 'one'), text('a.txt', 'two')]), keep);
    expect(kinds(r)).to.include.members(['NAME/TRAVERSAL', 'NAME/DUPLICATE']);
    expect(await zipNames(zip([text('../a.txt', 'one'), text('a.txt', 'two')]))).to.deep.equal(['a.txt']);
  });

  it('takes names equal after case folding, compatibility forms or a sharp s as colliding', async () => {
    for (const [a, b, k] of [
      ['FOO.txt', 'foo.txt', 'NAME/CASE_COLLISION'],
      ['stra\u00dfe.txt', 'STRASSE.txt', 'NAME/CASE_COLLISION'],
      ['\ufb01le.txt', 'file.txt', 'NAME/NORMALIZATION_COLLISION'],
    ]) {
      const r = await inspectArchive(
        zip([
          { ...text(a), flags: 0x800 },
          { ...text(b), flags: 0x800 },
        ]),
        keep,
      );
      expect(kinds(r), `${a} ${b}`).to.include(k);
    }
  });

  it('reports a name in the form of a Windows 8.3 alias of another name in its folder', async () => {
    const r = await inspectArchive(zip([text('docs/LONGFI~1.TXT'), text('docs/longfilename.txt')]), keep);
    expect(of(r, 'NAME/SHORT_NAME_COLLISION').map(f => f.data?.alias)).to.deep.equal(['LONGFI~1.TXT']);
    // A name that is its own 8.3 name has no alias.
    expect(kinds(await inspectArchive(zip([text('docs/READ~1.TXT'), text('docs/read.txt')]), keep))).to.not.include('NAME/SHORT_NAME_COLLISION');
  });

  it('removes a file that sits where a folder is needed, and a link named like a listed folder', async () => {
    const bytes = zip([text('docs'), text('docs/a.txt'), { name: 'dir/', data: '', method: 0 }, { name: 'dir', data: 'elsewhere', method: 0, mode: 0o120777 }]);
    const r = await inspectArchive(bytes, keep);
    expect(of(r, 'NAME/FILE_DIRECTORY_CLASH').map(f => f.data?.name)).to.deep.equal(['docs', 'dir']);
  });

  it('handles entries named like object prototype members as names only', async () => {
    const names = ['__proto__', 'constructor', 'prototype', 'toString', '__proto__/x.txt'];
    const bytes = zip(names.map(n => text(n)));
    const r = await inspectArchive(bytes, keep);
    expect(r.status).to.equal('strippable');
    expect(of(r, 'NAME/FILE_DIRECTORY_CLASH').map(f => f.data?.name)).to.deep.equal(['__proto__']);
    expect(({} as Record<string, unknown>).polluted).to.equal(undefined);
  });

  it('walks names with tens of thousands of parts in linear time', async () => {
    const long = `${'a/'.repeat(30_000)}x.txt`;
    const started = Date.now();
    const r = await inspectArchive(tar(pax([['path', long]]), tarEntry({ name: 'x.txt' }, 'x')), keep);
    expect(kinds(r)).to.include('NAME/TOO_LONG');
    expect(Date.now() - started).to.be.lessThan(5000);
  });
});

describe('link rules', () => {
  it('removes symbolic links that leave the tree, also through a chain of links, and keeps one that stays inside', async () => {
    const members = await tarMembers(
      tar(
        tarEntry({ name: 'a/', type: '5' }),
        tarEntry({ name: 'a/up', type: '2', link: '../../etc' }),
        tarEntry({ name: 'a/b', type: '2', link: '..' }),
        tarEntry({ name: 'a/c', type: '2', link: 'b/../..' }),
        tarEntry({ name: 'a/inside', type: '2', link: '../a/b' }),
        tarEntry({ name: 'a/loop', type: '2', link: 'loop' }),
      ),
    );
    expect(members.map(m => m[0])).to.deep.equal(['a/', 'a/b', 'a/inside']);
  });

  it('removes entries written through a symbolic link, by case-folded name too', async () => {
    const r = await inspectArchive(tar(tarEntry({ name: 'Link', type: '2', link: 'target' }), tarEntry({ name: 'link/file.txt' }, 'x')), keep);
    expect(of(r, 'LINK/THROUGH_LINK').map(f => f.data?.name)).to.deep.equal(['link/file.txt']);
  });

  it('removes a link that shares a name with a later regular file, keeping the file', async () => {
    const members = await tarMembers(tar(tarEntry({ name: 'x', type: '2', link: '/etc/passwd' }), tarEntry({ name: 'x' }, 'plain\n')));
    expect(members.map(m => [m[0], m[1]])).to.deep.equal([['x', 'file']]);
  });

  it('resolves a hard link from the top of the archive and renames it with its target', async () => {
    const members = await tarMembers(tar(tarEntry({ name: 'dir/da\u0007ta.txt' }, 'shared\n'), tarEntry({ name: 'copy.txt', type: '1', link: 'dir/da\u0007ta.txt' })));
    expect(members).to.deep.equal([
      ['dir/da_ta.txt', 'file', members[0][2]],
      ['copy.txt', 'link', 'dir/da_ta.txt'],
    ]);
  });

  it('removes a hard link when the file it names goes', async () => {
    const members = await tarMembers(tar(tarEntry({ name: 'dev', type: '3' }), tarEntry({ name: 'alias', type: '1', link: 'dev' })));
    expect(members).to.deep.equal([]);
  });

  it('removes a hard link deep in the tree whose target climbs out, and the data a hard link carries', async () => {
    const r = await inspectArchive(
      tar(tarEntry({ name: 'a/b/c/d/x', type: '1', link: '../../../../etc/passwd' }), tarEntry({ name: 'y.txt' }, 'y'), tarEntry({ name: 'z', type: '1', link: 'y.txt', size: 5 }, 'extra')),
      keep,
    );
    expect(kinds(r)).to.include.members(['LINK/OUTSIDE', 'LINK/DANGLING', 'STRUCTURE/NON_FILE_DATA']);
  });
});

describe('special files and permissions', () => {
  it('removes devices, named pipes and entries of unknown types, each by its own rule', async () => {
    const bytes = tar(
      tarEntry({ name: 'c', type: '3' }),
      tarEntry({ name: 'b', type: '4' }),
      tarEntry({ name: 'p', type: '6' }),
      tarEntry({ name: 'u', type: 'Q' }, 'q'),
      tarEntry({ name: 'f.txt' }, 'f'),
    );
    expect((await tarMembers(bytes)).map(m => m[0])).to.deep.equal(['f.txt']);
    const kept = await tarMembers(bytes, { actionOverrides: [override('SPECIAL', 'FIFO', 'info')] });
    expect(kept.map(m => m[0])).to.deep.equal(['p', 'f.txt']);
  });

  it('clears setuid, setgid and sticky bits, folders included, and keeps the rest of the mode', async () => {
    const r = await disarmArchive(tar(tarEntry({ name: 'd/', type: '5', mode: 0o3775 }), tarEntry({ name: 'd/x', mode: 0o4755 }, 'x'), tarEntry({ name: 'd/y', mode: 0o2711 }, 'y')), keep);
    expect(kinds(r.before)).to.include.members(['PERMISSIONS/SETUID', 'PERMISSIONS/SETGID', 'PERMISSIONS/STICKY']);
    const modes = await inspectModes(must(r.bytes, 'output'));
    expect(modes).to.deep.equal([0o775, 0o755, 0o711]);
  });

  it('drops a capability attribute and keeps other attributes', async () => {
    const r = await disarmArchive(
      tar(
        pax([
          ['SCHILY.xattr.security.capability', Buffer.from([1, 0, 0, 2])],
          ['SCHILY.xattr.user.note', 'kept'],
        ]),
        tarEntry({ name: 'ping' }, 'x'),
      ),
      keep,
    );
    const out = Buffer.from(must(r.bytes, 'output')).toString('latin1');
    expect(out).to.not.include('security.capability');
    expect(out).to.include('SCHILY.xattr.user.note=kept');
  });
});

/** The modes in a tar's headers, entry by entry, skipping pax headers. */
async function inspectModes(bytes: Uint8Array): Promise<number[]> {
  const modes: number[] = [];
  for (let at = 0; at + 512 <= bytes.length; at += 512) {
    const h = Buffer.from(bytes.subarray(at, at + 512));
    if (h.every(b => b === 0)) break;
    const size = Number.parseInt(h.toString('latin1', 124, 135), 8);
    const type = String.fromCharCode(h[156]);
    if (type !== 'x' && type !== 'g') modes.push(Number.parseInt(h.toString('latin1', 100, 107), 8));
    at += Math.ceil(size / 512) * 512;
  }
  return modes;
}
