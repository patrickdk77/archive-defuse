// Regenerates the test fixtures in test/fixtures. Run it with `node scripts/make-fixtures.js` on a Node with zstd. It
// needs no build and no other tool. Every archive is written here byte by byte, with fixed salts and times, so a rerun
// on the same Node writes the same bytes. The bzip2 and zstd streams are literals, so they do not depend on the Node.
// Each file is written on its own, under a name checked to stay inside the fixtures folder.
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const {
  B,
  u16,
  u32,
  u64,
  crc32,
  zipCrypto,
  winzipAes,
  zip,
  extra,
  FILE,
  text,
  octal,
  tarHeader,
  pad512,
  tarEntry,
  pax,
  tar,
  gzipMember,
  BZ,
  ZS,
  cab,
  deflate64Example,
  LZMA_TEXT,
  LZMA_ENTRY,
  XZ_ENTRY,
} = require('./builders');

const dir = path.join(__dirname, '..', 'test', 'fixtures');
fs.mkdirSync(dir, { recursive: true });
const realDir = fs.realpathSync(dir);
const written = new Set();

/** Writes one fixture. The name is a plain file name, and the path it resolves to must sit in the fixtures folder. */
function write(name, bytes) {
  if (!/^[a-z0-9][a-z0-9.-]*$/.test(name)) throw new Error(`Bad fixture name ${name}`);
  const target = path.resolve(realDir, name);
  if (path.dirname(target) !== realDir) throw new Error(`${name} leaves the fixtures folder`);
  if (fs.existsSync(target) && path.dirname(fs.realpathSync(target)) !== realDir) throw new Error(`${name} is a link out of the fixtures folder`);
  fs.writeFileSync(target, bytes);
  written.add(name);
}

// ---------------------------------------------------------------------------------------------------------------
// The fixtures.

const clean = zip([text('readme.txt'), { name: 'docs/', data: '', method: 0 }, text('docs/guide.txt')]);
write('zip-clean.zip', clean);
write('zip-traversal.zip', zip([text('../outside.txt'), text('docs/../../up-two.txt'), text('safe.txt')]));
write('zip-absolute.zip', zip([text('/etc/cron.d/job'), text('\\\\server\\share\\file.txt')]));
write('zip-drive-letter.zip', zip([text('C:/Windows/file.txt'), text('D:\\data\\file.txt')]));
write('zip-backslash.zip', zip([text('folder\\file.txt'), text('..\\..\\outside.txt')]));
write('zip-dot-segments.zip', zip([text('a/./b.txt'), text('a//c.txt'), text('.. /d.txt')]));
write('zip-control-characters.zip', zip([text('bell\x07.txt'), { ...text('report\u202etxt.exe', 'not really an executable'), flags: 0x800 }]));
write('zip-windows-reserved.zip', zip([text('CON.txt'), text('stream.txt:hidden'), text('trailing-dot.txt.')]));
write('zip-empty-name.zip', zip([text(''), text('kept.txt')]));
write('zip-duplicate.zip', zip([text('same.txt', 'first copy\n'), text('same.txt', 'second copy\n')]));
write('zip-case-collision.zip', zip([text('Readme.txt'), text('README.TXT')]));
write(
  'zip-normalization-collision.zip',
  zip([
    { ...text('cafe\u0301.txt'), flags: 0x800 },
    { ...text('caf\u00e9.txt'), flags: 0x800 },
  ]),
);
write('zip-file-directory-clash.zip', zip([text('docs'), text('docs/guide.txt')]));
write('zip-long-name.zip', zip([text(`${'n'.repeat(300)}.txt`)]));
write(
  'zip-symlink.zip',
  zip([
    { name: 'up', data: '../../etc/passwd', method: 0, mode: 0o120777 },
    { name: 'root', data: '/etc/passwd', method: 0, mode: 0o120777 },
    { name: 'inside', data: 'docs/guide.txt', method: 0, mode: 0o120777 },
    { ...text('docs/guide.txt'), mode: FILE },
  ]),
);
write(
  'zip-through-link.zip',
  zip([
    { name: 'tmp', data: '/tmp', method: 0, mode: 0o120777 },
    { ...text('tmp/dropped.txt'), mode: FILE },
  ]),
);
write(
  'zip-link-chain.zip',
  zip([
    { name: 'a/b', data: '..', method: 0, mode: 0o120777 },
    { name: 'a/c', data: 'b/../..', method: 0, mode: 0o120777 },
  ]),
);
write(
  'zip-special-files.zip',
  zip([
    { name: 'dev/null', data: '', method: 0, mode: 0o020666 },
    { name: 'dev/disk', data: '', method: 0, mode: 0o060660 },
    { name: 'pipe', data: '', method: 0, mode: 0o010644 },
    { name: 'socket', data: '', method: 0, mode: 0o140755 },
  ]),
);
write(
  'zip-setuid.zip',
  zip([
    { ...text('bin/tool'), mode: 0o104755 },
    { ...text('bin/group-tool'), mode: 0o102755 },
    { name: 'shared/', data: '', method: 0, mode: 0o042775 },
  ]),
);
{
  const data = B('This entry is encrypted with ZipCrypto.\n'.repeat(4));
  const deflated = zlib.deflateRawSync(data);
  const crc = crc32(data);
  write('zip-zipcrypto.zip', zip([{ name: 'secret.txt', data, flags: 1, payload: zipCrypto(deflated, 'correct horse', crc >>> 24) }]));
  write('zip-empty-password.zip', zip([{ name: 'secret.txt', data, flags: 1, payload: zipCrypto(deflated, '', crc >>> 24) }]));
  const aes = (strength, version) => ({
    name: `aes-${{ 1: 128, 2: 192, 3: 256 }[strength]}.txt`,
    data,
    flags: 1,
    method: 99,
    payload: winzipAes(deflated, 'battery staple', strength),
    crc: version === 2 ? 0 : crc,
    centralExtra: extra(0x9901, Buffer.concat([u16(version), B('AE'), Buffer.from([strength]), u16(8)])),
    localExtra: extra(0x9901, Buffer.concat([u16(version), B('AE'), Buffer.from([strength]), u16(8)])),
  });
  write('zip-aes.zip', zip([aes(3, 2), aes(1, 1)]));
  write('zip-strong-encryption.zip', zip([{ name: 'strong.txt', data, flags: 0x41, payload: deflated }]));
}
write('zip-unsupported-method.zip', zip([{ name: 'ppmd.bin', data: 'x', method: 98, payload: Buffer.from([7, 0, 0x5d, 0, 0, 1, 0, 0]) }]));
write(
  'zip-lzma-xz.zip',
  zip([
    { name: 'lzma.txt', data: LZMA_TEXT, method: 14, flags: 2, payload: LZMA_ENTRY },
    { name: 'xz.txt', data: LZMA_TEXT, method: 95, payload: XZ_ENTRY },
  ]),
);
{
  // Deflate64 that plain deflate cannot read, beside a deflate entry.
  const { payload, data } = deflate64Example();
  write('zip-deflate64.zip', zip([{ name: 'far-copy.bin', data, method: 9, payload }, text('readme.txt')]));
}
write(
  'zip-bzip2-zstd.zip',
  zip([
    { name: 'bzip2.txt', data: 'compressed with bzip2 inside a zip\n'.repeat(4), method: 12, payload: BZ.entry },
    { name: 'zstd.txt', data: 'compressed with zstd inside a zip\n'.repeat(4), method: 93, payload: ZS.entry },
  ]),
);
{
  // A second end record in the first one's comment: readers that check the comment length take it.
  const body = zip([text('readme.txt')]);
  const end = body.subarray(body.length - 22);
  const inner = Buffer.from(end);
  const outer = Buffer.concat([body.subarray(0, body.length - 2), u16(22), inner]);
  write('zip-several-end-records.zip', outer);
}
{
  // An entry whose stored data holds a central directory and an end record whose comment covers the rest of the file,
  // so readers that check the comment length can take it instead of the real one.
  const make = junk => zip([{ name: 'junk.bin', data: junk, method: 0 }, text('readme.txt')]);
  const probe = make(Buffer.alloc(200, 0x2e));
  const realEnd = probe.length - 22;
  const cdSize = probe.readUInt32LE(realEnd + 12);
  const cd = probe.subarray(probe.readUInt32LE(realEnd + 16), realEnd);
  const placeholder = Buffer.alloc(cdSize + 22, 0x2e);
  const first = make(placeholder);
  const at = first.indexOf(placeholder);
  const fakeEnd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(2), u16(2), u32(cdSize), u32(at), u16(first.length - (at + cdSize) - 22)]);
  write('zip-end-record-in-entry.zip', make(Buffer.concat([cd, fakeEnd])));
}
write('zip-local-mismatch.zip', zip([{ ...text('listed.txt'), local: { name: B('../hidden.txt') } }, text('other.txt')]));
{
  // Two directory entries share one local header and its data.
  const z = zip([text('shared.txt')]);
  const cdAt = z.indexOf(Buffer.from([0x50, 0x4b, 1, 2]));
  const record = z.subarray(cdAt, z.length - 22);
  const second = Buffer.from(record);
  const out = Buffer.concat([z.subarray(0, z.length - 22), second]);
  const endRecord = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(2), u16(2), u32(record.length * 2), u32(cdAt), u16(0)]);
  write('zip-overlap.zip', Buffer.concat([out, endRecord]));
}
write('zip-prepended.zip', zip([text('readme.txt')], { prefix: Buffer.concat([B('MZ'), Buffer.alloc(126, 0x90)]) }));
write('zip-offset-shift.zip', zip([text('readme.txt')], { prefix: B('#!/bin/sh\nexit 0\n'), shift: true }));
write('zip-trailing.zip', zip([text('readme.txt')], { trailing: B('appended bytes after the archive') }));
write('zip-pdf-polyglot.zip', zip([text('readme.txt')], { prefix: B('%PDF-1.4\n1 0 obj << >> endobj\n') }));
write('zip-hidden-data.zip', zip([text('first.txt'), { ...text('second.txt'), before: Buffer.concat([u32(0x04034b50), B('a local header no directory lists')]) }]));
write('zip-ratio-bomb.zip', zip([{ name: 'zeros.bin', data: Buffer.alloc(4 * 1024 * 1024), payload: zlib.deflateRawSync(Buffer.alloc(4 * 1024 * 1024), { level: 9 }) }]));
write('zip-size-lie.zip', zip([{ name: 'grows.bin', data: Buffer.alloc(2 * 1024 * 1024, 0x61), usize: 1000 }, text('kept.txt')]));
write('zip-bad-crc.zip', zip([{ ...text('damaged.txt'), crc: 0x12345678 }, text('kept.txt')]));
write('zip-comments.zip', zip([{ ...text('readme.txt'), comment: 'an entry comment' }], { comment: B('an archive comment') }));
write('zip-unicode-path.zip', zip([{ ...text('plain.txt'), centralExtra: extra(0x7075, Buffer.concat([Buffer.from([1]), u32(crc32(B('plain.txt'))), B('../other.txt')])) }]));
write('zip-cp437-name.zip', zip([{ name: Buffer.from([0x63, 0x61, 0x66, 0x82, 0x2e, 0x74, 0x78, 0x74]), data: 'a name in code page 437\n' }]));
write('zip-extra-field.zip', zip([{ ...text('readme.txt'), centralExtra: extra(0xcafe, Buffer.alloc(0)), localExtra: extra(0xcafe, Buffer.alloc(0)) }]));
{
  const data = B('a ZIP64 entry\n');
  const deflated = zlib.deflateRawSync(data);
  const z64 = extra(1, Buffer.concat([u64(data.length), u64(deflated.length)]));
  write('zip-zip64.zip', zip([{ name: 'big.txt', data, central: { csize: 0xffffffff, usize: 0xffffffff }, centralExtra: z64, local: { csize: 0xffffffff, usize: 0xffffffff }, localExtra: z64 }]));
  const descriptor = Buffer.concat([u32(0x08074b50), u32(crc32(data)), u32(deflated.length), u32(data.length)]);
  write('zip-data-descriptor.zip', zip([{ name: 'streamed.txt', data, flags: 8, local: { crc: 0, csize: 0, usize: 0 }, after: descriptor }]));
}
write('zip-directory-data.zip', zip([{ name: 'folder/', data: 'data in a folder entry', method: 0 }]));
write('zip-multi-disk.zip', zip([text('part.txt')], { end: { disk: 1 } }));
write('zip-truncated.zip', clean.subarray(0, Math.floor(clean.length / 2)));
write('zip-many-entries.zip', zip(Array.from({ length: 12 }, (_, i) => text(`file-${i}.txt`))));
write('zip-empty.zip', zip([]));
write('zip-type-mismatch.zip', zip([{ name: 'photo.jpg', data: Buffer.concat([B('MZ'), Buffer.alloc(64)]) }]));

// tar
const tarClean = tar(
  tarEntry({ name: 'project/', type: '5', mode: 0o755 }),
  tarEntry({ name: 'project/readme.txt' }, 'a plain file in a tar archive\n'),
  tarEntry({ name: 'project/link', type: '2', link: 'readme.txt', mode: 0o777 }),
);
write('tar-clean.tar', tarClean);
write('tar-v7.tar', tar(tarEntry({ name: 'old/', type: '\0', magic: Buffer.alloc(8) }), tarEntry({ name: 'old/file.txt', type: '\0', magic: Buffer.alloc(8) }, 'a v7 header has no magic\n')));
write(
  'tar-gnu-long-name.tar',
  tar(tarEntry({ name: '././@LongLink', type: 'L', magic: 'ustar  \0' }, `${'long/'.repeat(30)}file.txt\0`), tarEntry({ name: 'long/long/long', magic: 'ustar  \0' }, 'behind a GNU long name\n')),
);
write(
  'tar-pax.tar',
  tar(
    pax([['comment', 'a global comment']], 'g'),
    pax([
      ['path', `pax/${'deep/'.repeat(30)}caf\u00e9.txt`],
      ['SCHILY.xattr.user.note', 'kept'],
      ['mtime', '1704164646.5'],
    ]),
    tarEntry({ name: 'pax/fallback.txt' }, 'named by a pax record\n'),
  ),
);
write(
  'tar-pax-name-mismatch.tar',
  tar(
    pax([['path', '../escaped.txt']]),
    tarEntry({ name: 'innocent.txt' }, 'the pax name climbs out\n'),
    pax([['path', 'safe.txt']]),
    tarEntry({ name: '../../legacy.txt' }, 'old readers see a name that climbs out\n'),
  ),
);
write(
  'tar-hardlinks.tar',
  tar(
    tarEntry({ name: 'data/original.txt' }, 'the file the links share\n'),
    tarEntry({ name: 'data/second-name.txt', type: '1', link: 'data/original.txt' }),
    tarEntry({ name: 'data/to-nothing.txt', type: '1', link: 'data/missing.txt' }),
    tarEntry({ name: 'data/to-outside.txt', type: '1', link: '../../etc/shadow' }),
  ),
);
write('tar-symlink-escape.tar', tar(tarEntry({ name: 'etc', type: '2', link: '/etc' }), tarEntry({ name: 'etc/cron.d/job' }, '* * * * * root true\n')));
write(
  'tar-special-files.tar',
  tar(
    tarEntry({ name: 'dev/console', type: '3', major: 5, minor: 1 }),
    tarEntry({ name: 'dev/sda', type: '4', major: 8, minor: 0 }),
    tarEntry({ name: 'fifo', type: '6' }),
    tarEntry({ name: 'vendor-type', type: 'Z' }, 'a type no reader knows\n'),
  ),
);
write(
  'tar-setuid.tar',
  tar(tarEntry({ name: 'bin/', type: '5', mode: 0o2755 }), tarEntry({ name: 'bin/su', mode: 0o4755 }, 'not a real program\n'), tarEntry({ name: 'bin/sg', mode: 0o2755 }, 'not a real program\n')),
);
write('tar-capability.tar', tar(pax([['SCHILY.xattr.security.capability', Buffer.from([1, 0, 0, 2, 0, 0x20, 0, 0])]]), tarEntry({ name: 'ping' }, 'not a real program\n')));
{
  // GNU's old sparse format: a 64 KiB file with 512 bytes of data at 0 and at 32 KiB.
  const map = Buffer.concat([B(octal(0, 12)), B(octal(512, 12)), B(octal(32768, 12)), B(octal(512, 12))]);
  const extraBytes = Buffer.concat([map, Buffer.alloc(96 - map.length), Buffer.from([0]), B(octal(65536, 12))]);
  const data = Buffer.concat([Buffer.alloc(512, 0x61), Buffer.alloc(512, 0x62)]);
  write('tar-sparse-gnu.tar', tar(Buffer.concat([tarHeader({ name: 'sparse-old.bin', type: 'S', size: data.length, magic: 'ustar  \0', extra: extraBytes, extraAt: 386 }), data])));
  // Sparse format 1.0: the map heads the data.
  const map1 = pad512(B('2\n0\n512\n32768\n512\n'));
  write(
    'tar-sparse-pax.tar',
    tar(
      pax([
        ['GNU.sparse.major', '1'],
        ['GNU.sparse.minor', '0'],
        ['GNU.sparse.name', 'sparse-new.bin'],
        ['GNU.sparse.realsize', '65536'],
      ]),
      tarEntry({ name: 'GNUSparseFile.0/sparse-new.bin' }, Buffer.concat([map1, data])),
    ),
  );
}
{
  // GNU base-256 numbers for the size and the owner.
  const b256 = (v, len) => {
    const b = Buffer.alloc(len);
    b.writeUIntBE(v, len - 6, 6);
    b[0] |= 0x80;
    return b;
  };
  write('tar-base256.tar', tar(tarEntry({ name: 'base256.txt', size: b256(22, 12), uid: b256(4000000, 8), magic: 'ustar  \0' }, 'sized in base-256 form\n'.slice(0, 22))));
}
write('tar-trailing.tar', Buffer.concat([tarClean, B('bytes after the end of the archive')]));
write(
  'tar-hidden-entry.tar',
  Buffer.concat([
    tarEntry({ name: 'seen.txt' }, 'every reader sees this\n'),
    Buffer.alloc(512),
    tarEntry({ name: 'unseen.txt' }, 'readers that skip a lone zero block see this\n'),
    Buffer.alloc(1024),
  ]),
);
write('tar-truncated.tar', tarClean.subarray(0, 1024 + 10));
write('tar-pax-size-mismatch.tar', tar(pax([['size', '1024']]), tarEntry({ name: 'sized.txt', size: 23 }, Buffer.concat([B('the header says 23 byt\n'), Buffer.alloc(1001, 0x2e)]))));
write('tar-duplicate.tar', tar(tarEntry({ name: 'notes.txt' }, 'first version\n'), tarEntry({ name: 'notes.txt' }, 'second version\n')));
{
  const bad = tarHeader({ name: 'broken.txt' });
  bad[148] = 0x39;
  write('tar-damaged-header.tar', tar(tarEntry({ name: 'first.txt' }, 'fine\n'), bad, tarEntry({ name: 'after.txt' }, 'after the damage\n')));
}

// gzip, bzip2, zstd and Brotli
const tgz = gzipMember(tarClean, { name: 'project.tar' });
write('gzip-clean.txt.gz', gzipMember(B('plain text in a gzip file\n'.repeat(10)), { name: 'notes.txt' }));
write('gzip-tar.tar.gz', tgz);
write('gzip-members.gz', Buffer.concat([gzipMember(B('first member\n')), gzipMember(B('second member\n'))]));
write('gzip-trailing.gz', Buffer.concat([gzipMember(B('text\n')), B('bytes after the gzip member')]));
write('gzip-name-traversal.gz', gzipMember(B('text\n'), { name: '../../.bashrc' }));
write('gzip-extra-comment.gz', gzipMember(B('text\n'), { extra: Buffer.concat([B('AB'), u16(2), B('xy')]), comment: 'a gzip comment' }));
write('gzip-ratio-bomb.gz', gzipMember(Buffer.alloc(8 * 1024 * 1024)));
write('gzip-bad-crc.gz', gzipMember(B('text\n'), { crc: 1 }));
write('bzip2-clean.bz2', BZ.text);
write('bzip2-streams.bz2', Buffer.concat([BZ.one, BZ.two]));
write('bzip2-ratio-bomb.bz2', BZ.zeros);
{
  const bad = Buffer.from(BZ.text);
  bad[bad.length - 6] ^= 0x10;
  write('bzip2-bad-crc.bz2', bad);
}
write('zstd-clean.zst', ZS.text);
write('zstd-frames.zst', Buffer.concat([ZS.one, ZS.two]));
write('zstd-skippable.zst', Buffer.concat([Buffer.from([0x50, 0x2a, 0x4d, 0x18]), u32(12), B('hidden bytes'), ZS.text]));
write('zstd-ratio-bomb.zst', ZS.zeros);
write('brotli-clean.br', zlib.brotliCompressSync(B('plain text in a Brotli stream\n'.repeat(10)), { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }));
write('brotli-ratio-bomb.br', zlib.brotliCompressSync(Buffer.alloc(8 * 1024 * 1024), { params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 } }));

// Cabinets
write(
  'cab-clean.cab',
  cab([
    { type: 0, files: [{ name: 'stored.txt', data: 'stored in the cabinet\n' }] },
    {
      type: 1,
      files: [
        { name: 'docs/one.txt', data: 'compressed with MSZIP\n'.repeat(20) },
        { name: 'docs/two.txt', data: 'and a second file\n' },
      ],
    },
  ]),
);
write('cab-traversal.cab', cab([{ type: 1, files: [{ name: '..\\..\\Windows\\file.txt', data: 'climbs out\n' }] }]));
write('cab-lzx.cab', cab([{ type: 3 | (16 << 8), files: [{ name: 'lzx.bin', data: 'not decodable here\n' }] }]));
write('cab-continued.cab', cab([{ type: 0, files: [{ name: 'part.txt', data: 'continues in the next cabinet\n' }] }], { flags: 2 }));
write('cab-bad-checksum.cab', cab([{ type: 1, files: [{ name: 'damaged.txt', data: 'a block whose checksum is wrong\n' }] }], { badChecksum: true }));
write('cab-trailing.cab', cab([{ type: 0, files: [{ name: 'file.txt', data: 'text\n' }] }], { trailing: B('bytes after the cabinet') }));

// Nested: a ZIP holding a .tar.gz.
write('zip-nested.zip', zip([{ name: 'inner/project.tar.gz', data: tgz, method: 0 }, text('outer.txt')]));

// Any file left in the folder from an earlier run that this one did not write goes. The folders hold the fixtures
// other scripts write.
for (const name of fs.readdirSync(realDir)) {
  if (written.has(name) || name === 'manifest.json' || fs.lstatSync(path.join(realDir, name)).isDirectory()) continue;
  fs.rmSync(path.join(realDir, name));
}
console.log(`${written.size} fixtures in ${path.relative(process.cwd(), realDir) || '.'}`);
