// Builders for crafted archives, written byte by byte so each can break one rule of its format at a time. The fixture
// script writes test/fixtures with them, and the tests build archives of their own. They need no build and no tool.
const crypto = require('node:crypto');
const zlib = require('node:zlib');

const B = (s, enc = 'utf8') => Buffer.from(s, enc);
const u16 = v => Buffer.from([v & 0xff, (v >>> 8) & 0xff]);
const u32 = v => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0);
  return b;
};
const u64 = v => {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(v));
  return b;
};

const CRC = new Int32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC[n] = c;
}
function crc32(b, crc = 0) {
  let c = ~crc >>> 0;
  for (const x of b) c = CRC[(c ^ x) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

// ---------------------------------------------------------------------------------------------------------------
// ZIP

/** 2024-01-02 03:04:06 as a DOS time and date. */
const DOS_TIME = (3 << 11) | (4 << 5) | 3;
const DOS_DATE = ((2024 - 1980) << 9) | (1 << 5) | 2;

/** PKWARE's traditional encryption of `data` with a 12-byte header that ends in `check`. */
function zipCrypto(data, password, check) {
  let k0 = 0x12345678;
  let k1 = 0x23456789;
  let k2 = 0x34567890;
  const crcByte = (crc, b) => (CRC[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;
  const update = b => {
    k0 = crcByte(k0, b);
    k1 = (Math.imul((k1 + (k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    k2 = crcByte(k2, k1 >>> 24);
  };
  for (const b of B(password)) update(b);
  const header = Buffer.alloc(12, 0x41);
  header[11] = check;
  const plain = Buffer.concat([header, data]);
  const out = Buffer.alloc(plain.length);
  for (let i = 0; i < plain.length; i++) {
    const t = (k2 | 2) & 0xffff;
    out[i] = plain[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
    update(plain[i]);
  }
  return out;
}

/** WinZip AES: salt, password verifier, data in CTR mode with a little-endian counter from 1, and the HMAC-SHA1. */
function winzipAes(data, password, strength) {
  const n = { 1: 16, 2: 24, 3: 32 }[strength];
  const salt = Buffer.alloc({ 1: 8, 2: 12, 3: 16 }[strength], 0x5c);
  const k = crypto.pbkdf2Sync(B(password), salt, 1000, n * 2 + 2, 'sha1');
  const key = k.subarray(0, n);
  const ecb = crypto.createCipheriv(`aes-${n * 8}-ecb`, key, null);
  ecb.setAutoPadding(false);
  const counter = Buffer.alloc(16);
  const out = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i += 16) {
    for (let j = 0; j < 16; j++) {
      counter[j] = (counter[j] + 1) & 0xff;
      if (counter[j] !== 0) break;
    }
    const pad = ecb.update(counter);
    for (let j = 0; j < 16 && i + j < data.length; j++) out[i + j] = data[i + j] ^ pad[j];
  }
  const mac = crypto
    .createHmac('sha1', k.subarray(n, n * 2))
    .update(out)
    .digest()
    .subarray(0, 10);
  return Buffer.concat([salt, k.subarray(n * 2), out, mac]);
}

/**
 * A ZIP archive laid out from `entries`. Each entry has a name and data, and may set: method (8 deflate by default, 0
 * stored, or another number with `payload`), flags, payload (the stored bytes), mode (Unix permissions and type, which
 * makes the entry a Unix one), local and central (fields that differ from the entry's own), localExtra and
 * centralExtra, comment, before (bytes in front of the local header) and after (bytes after the data). The archive
 * may have a prefix, which `shift` leaves out of the offsets, a comment, and trailing bytes.
 */
function zip(entries, o = {}) {
  const prefix = o.prefix ?? Buffer.alloc(0);
  const parts = [prefix];
  let length = prefix.length;
  const put = b => {
    parts.push(b);
    length += b.length;
  };
  const central = [];
  for (const e of entries) {
    if (e.before) put(e.before);
    const data = Buffer.isBuffer(e.data) ? e.data : B(e.data ?? '');
    const method = e.method ?? 8;
    const payload = e.payload ?? (method === 8 ? zlib.deflateRawSync(data) : data);
    const name = Buffer.isBuffer(e.name) ? e.name : B(e.name);
    const own = { flags: e.flags ?? 0, method, crc: e.crc ?? crc32(data), csize: payload.length, usize: e.usize ?? data.length, name };
    const l = { ...own, ...e.local };
    const localExtra = e.localExtra ?? Buffer.alloc(0);
    const offset = length - (o.shift ? prefix.length : 0);
    put(
      Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(l.flags),
        u16(l.method),
        u16(DOS_TIME),
        u16(DOS_DATE),
        u32(l.crc),
        u32(l.csize),
        u32(l.usize),
        u16(l.name.length),
        u16(localExtra.length),
        l.name,
        localExtra,
      ]),
    );
    put(payload);
    if (e.after) put(e.after);
    const c = { ...own, offset, disk: 0, ...e.central };
    const centralExtra = e.centralExtra ?? Buffer.alloc(0);
    const comment = B(e.comment ?? '');
    const unix = e.mode !== undefined;
    central.push(
      Buffer.concat([
        u32(0x02014b50),
        u16(unix ? (3 << 8) | 30 : 20),
        u16(20),
        u16(c.flags),
        u16(c.method),
        u16(DOS_TIME),
        u16(DOS_DATE),
        u32(c.crc),
        u32(c.csize),
        u32(c.usize),
        u16(c.name.length),
        u16(centralExtra.length),
        u16(comment.length),
        u16(c.disk),
        u16(0),
        u32(unix ? (e.mode << 16) >>> 0 : name.at(-1) === 0x2f ? 0x10 : 0),
        u32(c.offset),
        c.name,
        centralExtra,
        comment,
      ]),
    );
  }
  const cd = Buffer.concat(central);
  const cdOffset = length - (o.shift ? prefix.length : 0);
  put(cd);
  const comment = o.comment ?? Buffer.alloc(0);
  const end = { disk: 0, count: entries.length, cdSize: cd.length, cdOffset, ...o.end };
  put(Buffer.concat([u32(0x06054b50), u16(end.disk), u16(0), u16(end.count), u16(end.count), u32(end.cdSize), u32(end.cdOffset), u16(comment.length), comment]));
  if (o.trailing) put(o.trailing);
  return Buffer.concat(parts);
}

const extra = (id, body) => Buffer.concat([u16(id), u16(body.length), body]);
const FILE = 0o100644;
const text = (name, body) => ({ name, data: body ?? `${name} holds plain text.\n` });

// ---------------------------------------------------------------------------------------------------------------
// tar

const octal = (v, width) => `${v.toString(8).padStart(width - 1, '0')}\0`;

/** A ustar header, with `fields` over the defaults. A field given as a Buffer goes in as it is. */
function tarHeader(fields) {
  const f = {
    name: '',
    mode: 0o644,
    uid: 1000,
    gid: 1000,
    size: 0,
    mtime: 1704164646,
    type: '0',
    link: '',
    magic: 'ustar\x0000',
    uname: 'user',
    gname: 'user',
    major: 0,
    minor: 0,
    prefix: '',
    ...fields,
  };
  const b = Buffer.alloc(512);
  const put = (v, at, len) => (Buffer.isBuffer(v) ? v : B(v)).copy(b, at, 0, len);
  put(f.name, 0, 100);
  put(typeof f.mode === 'number' ? octal(f.mode, 8) : f.mode, 100, 8);
  put(typeof f.uid === 'number' ? octal(f.uid, 8) : f.uid, 108, 8);
  put(typeof f.gid === 'number' ? octal(f.gid, 8) : f.gid, 116, 8);
  put(typeof f.size === 'number' ? octal(f.size, 12) : f.size, 124, 12);
  put(octal(f.mtime, 12), 136, 12);
  b.write('        ', 148, 'latin1');
  b.write(f.type, 156, 'latin1');
  put(f.link, 157, 100);
  put(f.magic, 257, 8);
  put(f.uname, 265, 32);
  put(f.gname, 297, 32);
  put(octal(f.major, 8), 329, 8);
  put(octal(f.minor, 8), 337, 8);
  put(f.prefix, 345, 155);
  if (f.extra) f.extra.copy(b, f.extraAt);
  let sum = 0;
  for (const x of b) sum += x;
  b.write(`${sum.toString(8).padStart(6, '0')}\0 `, 148, 'latin1');
  return b;
}
const pad512 = b => Buffer.concat([b, Buffer.alloc((512 - (b.length % 512)) % 512)]);
/** A tar entry: its header and its data padded to a block. `data` sets the size unless `fields.size` does. */
const tarEntry = (fields, data = Buffer.alloc(0)) => Buffer.concat([tarHeader({ size: data.length, ...fields }), pad512(Buffer.isBuffer(data) ? data : B(data))]);
function paxRecord(key, value) {
  const body = Buffer.concat([B(` ${key}=`), Buffer.isBuffer(value) ? value : B(value), B('\n')]);
  let len = body.length + 1;
  while (String(len).length + body.length !== len) len = String(len).length + body.length;
  return Buffer.concat([B(String(len)), body]);
}
const pax = (records, type = 'x') => tarEntry({ name: 'PaxHeaders/entry', type }, Buffer.concat(records.map(([k, v]) => paxRecord(k, v))));
/** The end of an archive, padded to GNU tar's 10,240-byte record. */
function tarEnd(body) {
  const withEnd = Buffer.concat([body, Buffer.alloc(1024)]);
  return Buffer.concat([withEnd, Buffer.alloc((10240 - (withEnd.length % 10240)) % 10240)]);
}
const tar = (...entries) => tarEnd(Buffer.concat(entries));

// ---------------------------------------------------------------------------------------------------------------
// gzip

/** One gzip member, with a name, a comment and an extra field when given. */
function gzipMember(data, o = {}) {
  const flags = (o.name !== undefined ? 0x08 : 0) | (o.comment !== undefined ? 0x10 : 0) | (o.extra ? 0x04 : 0);
  const head = Buffer.concat([Buffer.from([0x1f, 0x8b, 8, flags]), u32(1704164646), Buffer.from([0, 3])]);
  const parts = [head];
  if (o.extra) parts.push(u16(o.extra.length), o.extra);
  if (o.name !== undefined) parts.push(B(o.name, 'latin1'), Buffer.alloc(1));
  if (o.comment !== undefined) parts.push(B(o.comment, 'latin1'), Buffer.alloc(1));
  parts.push(zlib.deflateRawSync(data, { level: 9 }), u32(o.crc ?? crc32(data)), u32(data.length));
  return Buffer.concat(parts);
}

// ---------------------------------------------------------------------------------------------------------------
// Literal bzip2 and zstd streams, so the fixtures do not depend on the encoders of the Node that writes them.

const b64 = s => Buffer.from(s, 'base64');
const BZ = {
  text: b64('QlpoOTFBWSZTWUbFQcYAADHZgAAQQAAQABYhTFAgAFCAaAApVE8o9T00yTZME/kwTRNEyTZNE4TInhOEwTwnCei7kinChII2Kg4w'),
  zeros: b64('QlpoOTFBWSZTWaI9S1gAQEBAgMAAAAQACCAAMMwFKaYBANiAgHi7kinChIUR6lrA'),
  one: b64('QlpoOTFBWSZTWSoEXTgAAAJRgAAQQAAjIhwAIAAxADAgGmJzC0kIJx4u5IpwoSBUCLpw'),
  two: b64('QlpoOTFBWSZTWYRSkJQAAAXRgAAQQAAuA5wAIAAiANDQQNA0BQS9OE8eHi7kinChIQilISg='),
  entry: b64('QlpoOTFBWSZTWbZHfdAAABPZgAAQQAAQAD5j3JAgAFCmTEyDIwKqgaehGjT1MFSxQsQUIEEFzk9PTJsQSJJKmTUfGCpJgoXEn4u5IpwoSFsjvugA'),
};
const ZS = {
  text: b64('KLUv/WRUAMUAAIh6c3RkIHRleHQgaW5zaWRlCgEAgUidS4oOCHc='),
  zeros: b64(
    'KLUv/YRYAACAAFQAABAAAAEA+/85wAICABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAIAEAACABAAAgAQAAMAEAAP3/Zh',
  ),
  one: b64('KLUv/SQMYQAAZmlyc3QgZnJhbWUKDsLHKg=='),
  two: b64('KLUv/SQNaQAAc2Vjb25kIGZyYW1lCp45c6s='),
  entry: b64('KLUv/SSIVQEAJAJjb21wcmVzc2VkIHdpdGggenN0ZCBpbnNpZGUgYSB6aXAKAQAaJVVPidnFOQ=='),
};

// ---------------------------------------------------------------------------------------------------------------
// Cabinets

/** The cabinet checksum of `b`, continuing from `seed`. */
function cabChecksum(b, seed = 0) {
  let csum = seed >>> 0;
  const words = Math.floor(b.length / 4);
  for (let i = 0; i < words; i++) csum = (csum ^ b.readUInt32LE(i * 4)) >>> 0;
  const p = words * 4;
  const rest = b.length % 4;
  let ul = 0;
  if (rest === 3) ul = (b[p] << 16) | (b[p + 1] << 8) | b[p + 2];
  else if (rest === 2) ul = (b[p] << 8) | b[p + 1];
  else if (rest === 1) ul = b[p];
  return (csum ^ ul) >>> 0;
}

/**
 * A cabinet with one folder per entry of `folders`. A folder is { type: 0 stored, 1 MSZIP or another number, files:
 * [{ name, data }] }. `o` can set header flags, a wrong checksum and trailing bytes.
 */
function cab(folders, o = {}) {
  const blocks = folders.map(f => {
    const data = Buffer.concat(f.files.map(x => B(x.data)));
    const out = [];
    for (let at = 0; at < data.length || (at === 0 && data.length === 0 && false); at += 32768) {
      const raw = data.subarray(at, at + 32768);
      const body = f.type === 1 ? Buffer.concat([B('CK'), zlib.deflateRawSync(raw)]) : f.type === 0 ? raw : Buffer.alloc(raw.length, 0x55);
      const head = Buffer.concat([u16(body.length), u16(raw.length)]);
      const sum = o.badChecksum ? 0x12345678 : cabChecksum(head, cabChecksum(body));
      out.push(Buffer.concat([u32(sum), head, body]));
    }
    return out;
  });
  const files = [];
  folders.forEach((f, i) => {
    let offset = 0;
    for (const x of f.files) {
      const name = B(x.name.replace(/\//g, '\\'));
      files.push(Buffer.concat([u32(B(x.data).length), u32(offset), u16(x.folder ?? i), u16(DOS_DATE), u16(DOS_TIME), u16(0x20 | (/^[\x20-\x7e]*$/.test(x.name) ? 0 : 0x80)), name, Buffer.alloc(1)]));
      offset += B(x.data).length;
    }
  });
  const fileTable = Buffer.concat(files);
  const coffFiles = 36 + folders.length * 8;
  let at = coffFiles + fileTable.length;
  const folderTable = Buffer.concat(
    folders.map((f, i) => {
      const start = at;
      at += blocks[i].reduce((s, b) => s + b.length, 0);
      return Buffer.concat([u32(start), u16(blocks[i].length), u16(f.type)]);
    }),
  );
  const header = Buffer.concat([B('MSCF'), u32(0), u32(at), u32(0), u32(coffFiles), u32(0), Buffer.from([3, 1]), u16(folders.length), u16(files.length), u16(o.flags ?? 0), u16(0x1234), u16(0)]);
  return Buffer.concat([header, folderTable, fileTable, ...blocks.flat(), o.trailing ?? Buffer.alloc(0)]);
}

/**
 * A Deflate64 stream that only Deflate64 reads: a stored block of 40,000 bytes, then a fixed block with one match of
 * 1,000 bytes from 40,000 bytes back. The match takes length code 285 with 16 extra bits and distance code 30, which
 * deflate does not have. Returns the stream and the bytes it decodes to.
 */
function deflate64Example() {
  const stored = Buffer.alloc(40000);
  let x = 12345;
  for (let i = 0; i < stored.length; i++) {
    x = (Math.imul(x, 1103515245) + 12345) >>> 0;
    stored[i] = x >>> 24;
  }
  const out = [];
  let acc = 0;
  let n = 0;
  const put = (value, bits) => {
    for (let i = 0; i < bits; i++) {
      acc |= ((value >>> i) & 1) << n;
      if (++n === 8) {
        out.push(acc);
        acc = 0;
        n = 0;
      }
    }
  };
  // A Huffman code goes most significant bit first.
  const code = (value, bits) => {
    for (let i = bits - 1; i >= 0; i--) put((value >>> i) & 1, 1);
  };
  const flush = () => {
    if (n > 0) put(0, 8 - n);
  };
  put(0, 1);
  put(0, 2);
  flush();
  put(stored.length, 16);
  put(~stored.length & 0xffff, 16);
  out.push(...stored);
  put(1, 1);
  put(1, 2);
  code(0xc0 + 5, 8);
  put(1000 - 3, 16);
  code(30, 5);
  put(40000 - 32769, 14);
  code(0, 7);
  flush();
  return { payload: Buffer.from(out), data: Buffer.concat([stored, stored.subarray(0, 1000)]) };
}

/**
 * A text file as ZIP method 14 (LZMA, with the end marker flag 2 set) and method 95 (XZ) store it. Python's zipfile
 * wrote the LZMA payload and its lzma module the xz stream; 7-Zip reads both.
 */
const LZMA_TEXT = Array.from({ length: 80 }, (_, i) => `line ${i % 9} of an LZMA entry, with words that repeat: alpha beta gamma\n`).join('');
const LZMA_ENTRY = Buffer.from(
  'CQQFAF0AAIAAADYaSh8IoCYDTQad8APc0TAfhCgK0S0I31djP/UIWhBYm6D6Lc9ASbwaWciXSsqr+8R9mB+OFrhPmQaZikOEAKMYKJJwC1AsODUigXMsi5KGUeeK+gHuQqWWw0H5TQwP5tWNVGQkr9CjapjWmCtBrOHzmzUORcX/8gc8oA==',
  'base64',
);
const XZ_ENTRY = Buffer.from(
  '/Td6WFoAAATm1rRGAgAhARYAAAB0L+Wj4BSfAHZdADYaSh8IoCYDTQad8APc0TAfhCgK0S0I31djP/UIWhBYm6D6Lc9ASbwaWciXSsqr+8R9mB+OFrhPmQaZikOEAKMYKJJwC1AsODUigXMsi5KGUeeK+gHuQqWWw0H5TQwP5tWNVGQkr9CjapjWmCtBrOHzmxbhEgAAAABXbLRdpZRxYgABkgGgKQAATy5s1LHEZ/sCAAAAAARZWg==',
  'base64',
);

module.exports = {
  deflate64Example,
  LZMA_TEXT,
  LZMA_ENTRY,
  XZ_ENTRY,
  B,
  u16,
  u32,
  u64,
  crc32,
  DOS_TIME,
  DOS_DATE,
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
  paxRecord,
  pax,
  tarEnd,
  tar,
  gzipMember,
  BZ,
  ZS,
  cabChecksum,
  cab,
};
