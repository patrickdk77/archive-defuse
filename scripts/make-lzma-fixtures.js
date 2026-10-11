// Writes the crafted xz, lzma and 7z fixtures in test/fixtures/lzma/cases and their manifest. Copied from lzma-defuse
// scripts/make-fixtures.js when it merged into this package. Python's lzma module compresses the data,
// and the xz and 7z containers around it are built here byte by byte, so each fixture can carry exactly the fault it
// tests. Run with: node scripts/make-lzma-fixtures.js. The output is the same on every run.

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const { spawnSync } = require('node:child_process');
const { deflate64Example } = require('./builders');

const OUT = path.join(__dirname, '..', 'test', 'fixtures', 'lzma', 'cases');

// ---------- helpers ----------

const TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  TABLE[n] = c >>> 0;
}
function crc32(b) {
  let c = 0xffffffff;
  for (const x of b) c = TABLE[(c ^ x) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}
const u32 = v => {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v >>> 0);
  return b;
};
const u64 = v => {
  const b = Buffer.alloc(8);
  b.writeUInt32LE(v % 2 ** 32, 0);
  b.writeUInt32LE(Math.floor(v / 2 ** 32), 4);
  return b;
};
const cat = (...parts) => Buffer.concat(parts.map(p => (Buffer.isBuffer(p) ? p : Buffer.from(p))));

/** Deterministic pseudo-random bytes. */
function prng(seed, n) {
  let s = seed >>> 0;
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i++) {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    out[i] = ((t ^ (t >>> 14)) >>> 0) & 0xff;
  }
  return out;
}

const text = (n, seed = 1) => {
  const words = ['alpha', 'beta', 'gamma', 'delta', 'lzma', 'defuse', 'block', 'stream', 'index', 'check'];
  const r = prng(seed, n);
  let s = '';
  for (let i = 0; s.length < n; i++) s += `${words[r[i % n] % words.length]}${r[(i + 1) % n] % 7 === 0 ? '\n' : ' '}`;
  return Buffer.from(s.slice(0, n));
};

/** Code-like bytes with x86 calls and jumps, ARM branches and others, for the branch filters to convert. */
function codeLike(n, seed) {
  const b = prng(seed, n);
  for (let i = 0; i + 8 < n; i += 16) {
    b[i] = 0xe8;
    b[i + 3] = 0x00;
    b[i + 4] = 0x00;
    b[i + 7] = 0xeb;
    b[i + 8] = 0x48;
    b[i + 11] = 0x01;
  }
  return b;
}

/** Runs Python's lzma module on `input`. Only data and filter numbers go to it. */
function py(code, input) {
  const r = spawnSync('python3', ['-I', '-c', `import lzma,sys\nd=sys.stdin.buffer.read()\n${code}\nsys.stdout.buffer.write(o)`], { input, maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error(`python3 failed: ${r.stderr}`);
  return r.stdout;
}
const pyFilters = filters => `[${filters.join(',')}]`;
const rawLzma1 = (data, dict = 1 << 16, lc = 3, lp = 0, pb = 2) =>
  py(`o=lzma.compress(d,format=lzma.FORMAT_RAW,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':${dict},'lc':${lc},'lp':${lp},'pb':${pb}}])`, data);
const rawLzma2 = (data, before = [], dict = 1 << 16) => py(`o=lzma.compress(d,format=lzma.FORMAT_RAW,filters=${pyFilters([...before, `{'id':lzma.FILTER_LZMA2,'dict_size':${dict}}`])})`, data);
const xzPy = (data, check = 'CHECK_CRC64', before = []) =>
  py(`o=lzma.compress(d,format=lzma.FORMAT_XZ,check=lzma.${check},filters=${pyFilters([...before, "{'id':lzma.FILTER_LZMA2,'dict_size':1<<16}"])})`, data);
const alonePy = data => py("o=lzma.compress(d,format=lzma.FORMAT_ALONE,filters=[{'id':lzma.FILTER_LZMA1,'dict_size':1<<16}])", data);
/** Runs Python's bz2 module on `input`. */
function bzip2Py(input) {
  const r = spawnSync('python3', ['-I', '-c', 'import bz2,sys\nsys.stdout.buffer.write(bz2.compress(sys.stdin.buffer.read(),9))'], { input, maxBuffer: 1 << 28 });
  if (r.status !== 0) throw new Error(`python3 failed: ${r.stderr}`);
  return r.stdout;
}

// ---------- xz builder ----------

function vli(v) {
  const out = [];
  let n = v;
  while (n >= 0x80) {
    out.push((n % 0x80) | 0x80);
    n = Math.floor(n / 0x80);
  }
  out.push(n);
  return Buffer.from(out);
}

const XZ_MAGIC = Buffer.from([0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00]);
const CHECK_SIZE = { 0: 0, 1: 4, 4: 8, 10: 32 };
function checkOf(id, data) {
  if (id === 0) return Buffer.alloc(0);
  if (id === 1) return u32(crc32(data));
  if (id === 10) return crypto.createHash('sha256').update(data).digest();
  if (id === 4) {
    // CRC-64/XZ, bit by bit with BigInt, slow and plain.
    let c = 0xffffffffffffffffn;
    for (const x of data) {
      c ^= BigInt(x);
      for (let k = 0; k < 8; k++) c = c & 1n ? (c >> 1n) ^ 0xc96c5795d7870f42n : c >> 1n;
    }
    c ^= 0xffffffffffffffffn;
    const b = Buffer.alloc(8);
    b.writeBigUInt64LE(c);
    return b;
  }
  return Buffer.alloc(CHECK_SIZE[id] ?? 4, 0x55);
}

/**
 * One xz stream. Each block gives its filters, its LZMA2 data and the data it decodes to. Options change single
 * fields so a fixture can carry one fault.
 */
function xzStream({ check = 4, blocks = [], flags, footerFlags, badHeaderCrc, badFooterCrc, backwardDelta = 0, indexRecords, indexPad, badIndexCrc, footerMagic }) {
  const sflags = flags ?? Buffer.from([0, check]);
  const parts = [XZ_MAGIC, sflags, u32(badHeaderCrc ? 0 : crc32(sflags))];
  const records = [];
  for (const b of blocks) {
    const filters = b.filters ?? [{ id: 0x21, props: Buffer.from([16]) }];
    let body = Buffer.from([b.flags ?? (filters.length - 1) | (b.comp !== undefined ? 0x40 : 0) | (b.uncomp !== undefined ? 0x80 : 0)]);
    if (b.comp !== undefined) body = cat(body, b.compVli ?? vli(b.comp));
    if (b.uncomp !== undefined) body = cat(body, b.uncompVli ?? vli(b.uncomp));
    for (const f of filters) body = cat(body, vli(f.id), vli(f.props.length), f.props);
    body = cat(body, b.headerPad ?? Buffer.alloc(0));
    const size = Math.ceil((body.length + 1 + 4) / 4) * 4;
    const head = cat(Buffer.from([size / 4 - 1]), body, Buffer.alloc(size - 4 - 1 - body.length));
    const header = cat(head, u32(b.badHeaderCrc ? 0 : crc32(head)));
    const pad = (4 - ((header.length + b.data.length) % 4)) % 4;
    const padding = Buffer.alloc(pad, b.padByte ?? 0);
    const ck = b.check ?? checkOf(check, b.decoded);
    parts.push(header, b.data, padding, ck);
    records.push([header.length + b.data.length + ck.length, b.decoded.length]);
  }
  const recs = indexRecords ?? records;
  let index = cat(Buffer.from([0]), vli(recs.length), ...recs.flatMap(([a, c]) => [vli(a), vli(c)]));
  index = cat(index, Buffer.alloc((4 - (index.length % 4)) % 4, indexPad ?? 0));
  index = cat(index, u32(badIndexCrc ? 0 : crc32(index)));
  const fflags = footerFlags ?? sflags;
  const fbody = cat(u32(index.length / 4 - 1 + backwardDelta), fflags);
  parts.push(index, u32(badFooterCrc ? 0 : crc32(fbody)), fbody, footerMagic ?? Buffer.from('YZ'));
  return cat(...parts);
}

/** A block of LZMA2 data made by Python, with optional filters before LZMA2. */
function xzBlock(decoded, filters = [], extra = {}) {
  const pyFil = filters.map(f => f.py);
  const data = rawLzma2(decoded, pyFil);
  return { data, decoded, filters: [...filters.map(f => ({ id: f.id, props: f.props ?? Buffer.alloc(0) })), { id: 0x21, props: Buffer.from([16]) }], ...extra };
}

// ---------- branch encoders the Python module lacks, ported from XZ for Java ----------

function arm64Encode(buf, start = 0) {
  const b = Buffer.from(buf);
  for (let i = 0; i + 4 <= b.length; i += 4) {
    const top = b[i + 3];
    if ((top & 0xfc) === 0x94) {
      const instr = b.readInt32LE(i);
      const pc = ((start + i) >>> 2) | 0;
      b.writeUInt32LE((0x94000000 | ((instr + pc) & 0x03ffffff)) >>> 0, i);
    } else if ((top & 0x9f) === 0x90) {
      let instr = b.readInt32LE(i);
      const src = ((instr >>> 29) & 3) | ((instr >>> 3) & 0x001ffffc);
      if (((src + 0x00020000) & 0x001c0000) !== 0) continue;
      const dest = (src + ((start + i) >>> 12)) | 0;
      instr &= 0x9000001f;
      instr |= (dest & 3) << 29;
      instr |= (dest & 0x0003fffc) << 3;
      instr |= -(dest & 0x00020000) & 0x00e00000;
      b.writeUInt32LE(instr >>> 0, i);
    }
  }
  return b;
}

function riscvEncode(buf, start = 0) {
  const b = Buffer.from(buf);
  for (let i = 0; i + 8 <= b.length; i += 2) {
    let inst = b[i];
    if (inst === 0xef) {
      const b1 = b[i + 1];
      if ((b1 & 0x0d) !== 0) continue;
      const b2 = b[i + 2];
      const b3 = b[i + 3];
      const pc = start + i;
      let addr = ((b1 & 0xf0) << 8) | ((b2 & 0x0f) << 16) | ((b2 & 0x10) << 7) | ((b2 & 0xe0) >>> 4) | ((b3 & 0x7f) << 4) | ((b3 & 0x80) << 13);
      addr = (addr + pc) | 0;
      b[i + 1] = (b1 & 0x0f) | ((addr >>> 13) & 0xf0);
      b[i + 2] = (addr >>> 9) & 0xff;
      b[i + 3] = (addr >>> 1) & 0xff;
      i += 2;
    } else if ((inst & 0x7f) === 0x17) {
      inst |= b[i + 1] << 8;
      inst |= b[i + 2] << 16;
      inst |= b[i + 3] << 24;
      if ((inst & 0xe80) !== 0) {
        const inst2 = b.readInt32LE(i + 4);
        if ((((inst << 8) ^ inst2) & 0xf8003) !== 3) {
          i += 4;
          continue;
        }
        let addr = (inst & 0xfffff000) + (inst2 >> 20);
        addr = (addr + start + i) | 0;
        inst = 0x17 | (2 << 7) | (inst2 << 12);
        b.writeUInt32LE(inst >>> 0, i);
        b.writeUInt32BE(addr >>> 0, i + 4);
      } else {
        const fakeRs1 = inst >>> 27;
        if (((inst - 0x3100) & 0x3f80) >= (fakeRs1 & 0x1d)) {
          i += 2;
          continue;
        }
        const fakeAddr = b.readInt32LE(i + 4);
        const fakeInst2 = (inst >>> 12) | (fakeAddr << 20);
        inst = 0x17 | (fakeRs1 << 7) | (fakeAddr & 0xfffff000);
        b.writeUInt32LE(inst >>> 0, i);
        b.writeUInt32LE(fakeInst2 >>> 0, i + 4);
      }
      i += 6;
    }
  }
  return b;
}

function arm64Code(n, seed) {
  const b = prng(seed, n);
  for (let i = 0; i + 4 <= n; i += 8) {
    b[i + 3] = 0x94 | (b[i + 3] & 3);
    b[i + 7] = 0x90 | (b[i + 7] & 0x60);
  }
  return b;
}

function riscvCode(n, seed) {
  const b = prng(seed, n);
  for (let i = 0; i + 16 <= n; i += 16) {
    b[i] = 0xef;
    b[i + 1] = 0x00 | (b[i + 1] & 0xf0);
    b[i + 4] = 0x97;
    b[i + 5] = 0x02;
    b[i + 8] = 0x83;
    b[i + 9] = 0xa2 | (b[i + 9] & 0x00);
    b[i + 10] = 0x02 | (b[i + 10] & 0xf0);
  }
  return b;
}

// ---------- BCJ2 encoder ----------

/** Splits x86 code into BCJ2's four streams, converting every call and jump whose target lands inside the data. */
function bcj2Encode(data) {
  const probs = new Uint16Array(258).fill(1024);
  const main = [];
  const call = [];
  const jump = [];
  const rc = [];
  let low = 0;
  let range = 0xffffffff;
  let cache = 0;
  let cacheSize = 1;
  const shiftLow = () => {
    if (low < 0xff000000 || low >= 0x100000000) {
      const carry = low >= 0x100000000 ? 1 : 0;
      let temp = cache;
      do {
        rc.push((temp + carry) & 0xff);
        temp = 0xff;
      } while (--cacheSize !== 0);
      cache = Math.floor(low / 2 ** 24) & 0xff;
    }
    cacheSize++;
    low = (low % 2 ** 24) * 256;
  };
  const encodeBit = (at, v) => {
    const p = probs[at];
    const bound = (range >>> 11) * p;
    if (v === 0) {
      range = bound;
      probs[at] = p + ((2048 - p) >>> 5);
    } else {
      low += bound;
      range = (range - bound) >>> 0;
      probs[at] = p - (p >>> 5);
    }
    while (range < 2 ** 24) {
      range = (range << 8) >>> 0;
      shiftLow();
    }
  };
  let prev = 0;
  let i = 0;
  while (i < data.length) {
    const b = data[i];
    main.push(b);
    i++;
    const isJ = (b & 0xfe) === 0xe8 || (prev === 0x0f && (b & 0xf0) === 0x80);
    if (!isJ) {
      prev = b;
      continue;
    }
    if (i === data.length) break;
    const index = b === 0xe8 ? prev : b === 0xe9 ? 256 : 257;
    let convert = false;
    let dest = 0;
    if (i + 4 <= data.length) {
      const rel = data.readInt32LE(i);
      dest = (rel + i + 4) >>> 0;
      convert = dest < data.length;
    }
    encodeBit(index, convert ? 1 : 0);
    if (convert) {
      const t = Buffer.alloc(4);
      t.writeUInt32BE(dest);
      (b === 0xe8 ? call : jump).push(...t);
      prev = data[i + 3];
      i += 4;
    } else prev = b;
  }
  for (let k = 0; k < 5; k++) shiftLow();
  return { main: Buffer.from(main), call: Buffer.from(call), jump: Buffer.from(jump), rc: Buffer.from(rc) };
}

function x86Code(n, seed) {
  const b = prng(seed, n);
  for (let i = 0; i + 24 <= n; i += 24) {
    b[i] = 0xe8;
    b.writeInt32LE(((b[i + 1] * 7) % 200) - 100, i + 1);
    b[i + 10] = 0xe9;
    b.writeInt32LE(((b[i + 11] * 5) % 300) - 150, i + 11);
    b[i + 18] = 0x0f;
    b[i + 19] = 0x85;
    b.writeInt32LE(((b[i + 20] * 3) % 100) - 50, i + 20);
  }
  return b;
}

// ---------- 7z builder ----------

function num(v) {
  if (v < 0x80) return Buffer.from([v]);
  const bytes = [];
  let n = v;
  for (let i = 0; i < 8; i++) {
    bytes.push(n % 256);
    n = Math.floor(n / 256);
  }
  for (let extra = 1; extra <= 8; extra++) {
    const high = Math.floor(v / 2 ** (8 * extra));
    if (extra === 8 || high < 2 ** (7 - extra)) return Buffer.from([((0xff << (8 - extra)) & 0xff) | (extra === 8 ? 0 : high), ...bytes.slice(0, extra)]);
  }
  throw new Error('number too large');
}
function bits(arr) {
  const out = Buffer.alloc(Math.ceil(arr.length / 8));
  arr.forEach((b, i) => {
    if (b) out[i >> 3] |= 0x80 >> (i & 7);
  });
  return out;
}
const prop = (id, body) => cat(num(id), num(body.length), body);

function coderBytes(c) {
  const id = Buffer.from(c.id, 'hex');
  const complex = c.numIn !== undefined && (c.numIn !== 1 || c.numOut !== 1);
  let flags = id.length | (complex ? 0x10 : 0) | (c.props ? 0x20 : 0);
  if (c.flags !== undefined) flags = c.flags;
  let b = cat(Buffer.from([flags]), id);
  if (complex) b = cat(b, num(c.numIn), num(c.numOut));
  if (c.props) b = cat(b, num(c.props.length), c.props);
  return b;
}

function folderBytes(f) {
  let b = cat(num(f.coders.length), ...f.coders.map(coderBytes));
  for (const bp of f.bindPairs ?? []) b = cat(b, num(bp[0]), num(bp[1]));
  if (f.packedStreams && f.packedStreams.length > 1) b = cat(b, ...f.packedStreams.map(num));
  return b;
}

/** A streams info: pack info, unpack info with folders, substreams. */
function streamsInfo({ packPos = 0, packSizes, folders, sub, packCrcs }) {
  const parts = [];
  if (packSizes) {
    parts.push(Buffer.from([0x06]), num(packPos), num(packSizes.length), Buffer.from([0x09]), ...packSizes.map(num));
    if (packCrcs) parts.push(Buffer.from([0x0a, 1]), ...packCrcs.map(u32));
    parts.push(Buffer.from([0x00]));
  }
  if (folders) {
    parts.push(Buffer.from([0x07, 0x0b]), num(folders.length), Buffer.from([0]), ...folders.map(folderBytes), Buffer.from([0x0c]));
    for (const f of folders) parts.push(...f.unpackSizes.map(num));
    if (folders.some(f => f.crc !== undefined)) {
      const all = folders.every(f => f.crc !== undefined);
      parts.push(Buffer.from([0x0a, all ? 1 : 0]), all ? Buffer.alloc(0) : bits(folders.map(f => f.crc !== undefined)), ...folders.filter(f => f.crc !== undefined).map(f => u32(f.crc)));
    }
    parts.push(Buffer.from([0x00]));
  }
  if (sub) parts.push(sub);
  parts.push(Buffer.from([0x00]));
  return cat(...parts);
}

/** Substream info: counts per folder, sizes of all but the last of each, and CRCs of all. */
function subStreams(counts, sizes, crcs) {
  const parts = [Buffer.from([0x08])];
  if (counts) parts.push(Buffer.from([0x0d]), ...counts.map(num));
  if (sizes?.length) parts.push(Buffer.from([0x09]), ...sizes.map(num));
  // A null CRC leaves that file without one.
  if (crcs?.some(c => c === null)) parts.push(Buffer.from([0x0a, 0]), bits(crcs.map(c => c !== null)), ...crcs.filter(c => c !== null).map(u32));
  else if (crcs) parts.push(Buffer.from([0x0a, 1]), ...crcs.map(u32));
  parts.push(Buffer.from([0x00]));
  return cat(...parts);
}

const utf16z = s => Buffer.from(`${s}\0`, 'utf16le');

/** The files info for `files`, each {name, dir, empty, anti, attrib, mtime}. */
function filesInfo(files, extra = []) {
  const parts = [Buffer.from([0x05]), num(files.length)];
  const empty = files.map(f => f.dir || f.empty || f.anti);
  if (empty.some(Boolean)) {
    parts.push(prop(0x0e, bits(empty)));
    const ef = files.filter((_, i) => empty[i]);
    if (ef.some(f => f.empty)) parts.push(prop(0x0f, bits(ef.map(f => f.empty === true))));
    if (ef.some(f => f.anti)) parts.push(prop(0x10, bits(ef.map(f => f.anti === true))));
  }
  if (files.some(f => f.name !== undefined)) parts.push(prop(0x11, cat(Buffer.from([0]), ...files.map(f => (Buffer.isBuffer(f.name) ? f.name : utf16z(f.name ?? ''))))));
  if (files.some(f => f.mtime)) parts.push(prop(0x14, cat(Buffer.from([1, 0]), ...files.map(f => f.mtime ?? Buffer.alloc(8)))));
  if (files.some(f => f.attrib !== undefined)) {
    const all = files.every(f => f.attrib !== undefined);
    parts.push(
      prop(
        0x15,
        cat(Buffer.from([all ? 1 : 0]), all ? Buffer.alloc(0) : bits(files.map(f => f.attrib !== undefined)), Buffer.from([0]), ...files.filter(f => f.attrib !== undefined).map(f => u32(f.attrib))),
      ),
    );
  }
  parts.push(...extra, Buffer.from([0x00]));
  return cat(...parts);
}

/** A whole archive from packed streams and a header body. */
function sevenZip({ packs = [], header, prefix = Buffer.alloc(0), gap = Buffer.alloc(0), suffix = Buffer.alloc(0), start, startCrc, version = [0, 4] }) {
  const packed = cat(...packs);
  const nextOffset = packed.length + gap.length;
  const st = start ?? cat(u64(nextOffset), u64(header.length), u32(crc32(header)));
  const sig = cat(Buffer.from([0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]), Buffer.from(version), u32(startCrc ?? crc32(st)), st);
  return cat(prefix, sig, packed, gap, header, suffix);
}

/** A plain header with main streams and files. */
const plainHeader = (streams, files) => cat(Buffer.from([0x01]), streams ? cat(Buffer.from([0x04]), streams) : Buffer.alloc(0), files, Buffer.from([0x00]));

/** One folder per file, every file stored with the Copy coder. */
function copyArchive(files, opts = {}) {
  const withData = files.filter(f => !f.dir && !f.empty && !f.anti);
  const packs = withData.map(f => f.data);
  const streams = withData.length
    ? streamsInfo({
        packSizes: packs.map(p => p.length),
        folders: withData.map(f => ({ coders: [{ id: '00' }], unpackSizes: [f.data.length] })),
        sub: subStreams(
          null,
          null,
          withData.map(f => crc32(f.data)),
        ),
      })
    : null;
  return sevenZip({ packs, header: plainHeader(streams, filesInfo(files, opts.extraFileProps)), ...opts });
}

/** A solid archive: one folder with one coder chain, holding every file. */
function solidArchive(files, folder, packs) {
  const withData = files.filter(x => !x.dir && !x.empty && !x.anti);
  const total = withData.reduce((n, x) => n + x.data.length, 0);
  const sizes = withData.slice(0, -1).map(x => x.data.length);
  const f = { ...folder, unpackSizes: folder.unpackSizes ?? [total] };
  const streams = streamsInfo({
    packSizes: packs.map(p => p.length),
    folders: [f],
    sub: subStreams(
      [withData.length],
      sizes,
      withData.map(x => (x.crc === undefined ? crc32(x.data) : x.crc)),
    ),
  });
  return sevenZip({ packs, header: plainHeader(streams, filesInfo(files)) });
}

function lzmaProps(dict = 1 << 16, lc = 3, lp = 0, pb = 2) {
  return cat(Buffer.from([(pb * 5 + lp) * 9 + lc]), u32(dict));
}

/** 7zAES: key from SHA-256 over 2^power rounds of salt, UTF-16LE password and a counter; AES-256-CBC, zero padded. */
function aesEncrypt(data, password, power, salt, iv) {
  const pw = Buffer.from(password, 'utf16le');
  const h = crypto.createHash('sha256');
  const ctr = Buffer.alloc(8);
  for (let r = 0; r < 2 ** power; r++) {
    ctr.writeUInt32LE(r % 2 ** 32, 0);
    ctr.writeUInt32LE(Math.floor(r / 2 ** 32), 4);
    h.update(salt);
    h.update(pw);
    h.update(ctr);
  }
  const key = h.digest();
  const padded = cat(data, Buffer.alloc((16 - (data.length % 16)) % 16));
  const c = crypto.createCipheriv('aes-256-cbc', key, iv);
  c.setAutoPadding(false);
  const enc = cat(c.update(padded), c.final());
  const props = cat(Buffer.from([0xc0 | power, ((salt.length - 1) << 4) | (iv.length - 1)]), salt, iv);
  return { enc, props };
}

// ---------- fixtures ----------

const cases = {};
function add(name, bytes, expect) {
  fs.writeFileSync(path.join(OUT, name), bytes);
  cases[name] = expect;
}

fs.rmSync(OUT, { recursive: true, force: true });
fs.mkdirSync(OUT, { recursive: true });

const hello = text(5000, 7);
const small = Buffer.from('plain text inside a 7z entry\n');

// xz: checks, filters, structure
add('xz-crc64.xz', xzPy(hello, 'CHECK_CRC64'), { status: 'clean', content: crc32(hello) });
add('xz-crc32.xz', xzPy(hello, 'CHECK_CRC32'), { status: 'clean', content: crc32(hello) });
add('xz-sha256.xz', xzPy(hello, 'CHECK_SHA256'), { status: 'clean', content: crc32(hello) });
add('xz-no-check.xz', xzPy(hello, 'CHECK_NONE'), { status: 'clean', findings: ['STRUCTURE/NO_CHECK'] });
add('xz-empty.xz', xzPy(Buffer.alloc(0)), { status: 'clean', entries: 1 });
for (const [name, f] of [
  ['x86', "{'id':lzma.FILTER_X86}"],
  ['powerpc', "{'id':lzma.FILTER_POWERPC}"],
  ['ia64', "{'id':lzma.FILTER_IA64}"],
  ['arm', "{'id':lzma.FILTER_ARM}"],
  ['armthumb', "{'id':lzma.FILTER_ARMTHUMB}"],
  ['sparc', "{'id':lzma.FILTER_SPARC}"],
  ['delta', "{'id':lzma.FILTER_DELTA,'dist':4}"],
]) {
  const data = name === 'delta' ? Buffer.from(Array.from({ length: 20000 }, (_, i) => (i * 3 + (i >> 2)) & 0xff)) : codeLike(40000, name.length);
  add(`xz-filter-${name}.xz`, xzPy(data, 'CHECK_CRC32', [f]), { status: 'clean', content: crc32(data) });
}
{
  const data = codeLike(40000, 3);
  add('xz-filter-x86-start.xz', xzPy(data, 'CHECK_CRC32', ["{'id':lzma.FILTER_X86,'start_offset':4096}"]), { status: 'clean', content: crc32(data) });
  add('xz-three-deltas.xz', xzPy(data, 'CHECK_CRC32', ["{'id':lzma.FILTER_DELTA,'dist':1}", "{'id':lzma.FILTER_DELTA,'dist':2}", "{'id':lzma.FILTER_DELTA,'dist':7}"]), {
    status: 'clean',
    content: crc32(data),
  });
}
{
  const data = arm64Code(30000, 11);
  const block = {
    data: rawLzma2(arm64Encode(data)),
    decoded: data,
    filters: [
      { id: 0x0a, props: Buffer.alloc(0) },
      { id: 0x21, props: Buffer.from([16]) },
    ],
  };
  add('xz-filter-arm64.xz', xzStream({ check: 1, blocks: [block] }), { status: 'clean', content: crc32(data) });
  const start = 0xfffff000;
  const block2 = {
    data: rawLzma2(arm64Encode(data, start)),
    decoded: data,
    filters: [
      { id: 0x0a, props: u32(start) },
      { id: 0x21, props: Buffer.from([16]) },
    ],
  };
  add('xz-filter-arm64-start.xz', xzStream({ check: 1, blocks: [block2] }), { status: 'clean', content: crc32(data) });
  const rv = riscvCode(30000, 13);
  const block3 = {
    data: rawLzma2(riscvEncode(rv)),
    decoded: rv,
    filters: [
      { id: 0x0b, props: Buffer.alloc(0) },
      { id: 0x21, props: Buffer.from([16]) },
    ],
  };
  add('xz-filter-riscv.xz', xzStream({ check: 1, blocks: [block3] }), { status: 'clean', content: crc32(rv) });
}
{
  const a = text(3000, 2);
  const b = text(4000, 3);
  const both = cat(a, b);
  add('xz-two-blocks.xz', xzStream({ check: 4, blocks: [xzBlock(a), xzBlock(b)] }), { status: 'clean', content: crc32(both) });
  add('xz-block-sizes.xz', xzStream({ check: 1, blocks: [{ ...xzBlock(a), comp: rawLzma2(a).length, uncomp: a.length }] }), { status: 'clean', content: crc32(a) });
  add('xz-block-size-wrong.xz', xzStream({ check: 1, blocks: [{ ...xzBlock(a), uncomp: a.length + 5 }] }), { status: 'strippable', findings: ['STRUCTURE/SIZE_MISMATCH'] });
  const s1 = xzStream({ check: 4, blocks: [xzBlock(a)] });
  const s2 = xzStream({ check: 1, blocks: [xzBlock(b)] });
  // Some readers stop after the first stream, so the rewrite writes one.
  add('xz-two-streams.xz', cat(s1, s2), { status: 'strippable', findings: ['STRUCTURE/MULTIPLE_STREAMS'], content: crc32(both) });
  add('xz-stream-padding.xz', cat(s1, Buffer.alloc(8), s2, Buffer.alloc(4)), { status: 'strippable', findings: ['STRUCTURE/STREAM_PADDING', 'STRUCTURE/MULTIPLE_STREAMS'] });
  add('xz-bad-padding.xz', cat(s1, Buffer.alloc(5), s2), { status: 'strippable', findings: ['STRUCTURE/BAD_PADDING'] });
  add('xz-trailing.xz', cat(s1, Buffer.from('appended data that is not xz')), { status: 'strippable', findings: ['STRUCTURE/TRAILING_BYTES'] });
  add('xz-trailing-zip.xz', cat(s1, Buffer.from('PK\x05\x06'), Buffer.alloc(18)), { status: 'strippable', findings: ['STRUCTURE/TRAILING_BYTES', 'STRUCTURE/POLYGLOT'] });
  add('xz-index-count.xz', xzStream({ check: 4, blocks: [xzBlock(a)], indexRecords: [] }), { status: 'strippable', findings: ['STRUCTURE/INDEX_MISMATCH'] });
  add('xz-index-size.xz', xzStream({ check: 4, blocks: [xzBlock(a)], indexRecords: [[999, a.length]] }), { status: 'strippable', findings: ['STRUCTURE/INDEX_MISMATCH'] });
  add('xz-index-huge.xz', xzStream({ check: 4, blocks: [xzBlock(a)], indexRecords: [[2 ** 53, 2 ** 62]] }), { status: 'strippable', findings: ['STRUCTURE/INDEX_MISMATCH'] });
  add('xz-index-padding.xz', xzStream({ check: 4, blocks: [xzBlock(a)], indexPad: 1 }), { status: 'strippable', findings: ['STRUCTURE/BAD_PADDING'] });
  add('xz-backward-size.xz', xzStream({ check: 4, blocks: [xzBlock(a)], backwardDelta: 1 }), { status: 'strippable', findings: ['STRUCTURE/INDEX_MISMATCH'] });
  add('xz-footer-flags.xz', xzStream({ check: 4, blocks: [xzBlock(a)], footerFlags: Buffer.from([0, 1]) }), { status: 'strippable', findings: ['STRUCTURE/HEADER_MISMATCH'] });
  {
    // A block whose compressed data needs padding, with a padding byte that is not zero.
    let n = 3001;
    let blk = xzBlock(text(n, 4));
    while ((12 + blk.data.length) % 4 === 0) blk = xzBlock(text(++n, 4));
    add('xz-block-padding.xz', xzStream({ check: 4, blocks: [{ ...blk, padByte: 1 }] }), { status: 'strippable', findings: ['STRUCTURE/BAD_PADDING'] });
  }
  add('xz-unknown-check.xz', xzStream({ check: 2, blocks: [xzBlock(a)] }), { status: 'strippable', findings: ['STRUCTURE/UNKNOWN_CHECK'] });
  add('xz-bad-check.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), check: Buffer.alloc(8) }] }), { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  add('xz-bad-header-crc.xz', xzStream({ check: 4, blocks: [xzBlock(a)], badHeaderCrc: true }), { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  add('xz-bad-block-header-crc.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), badHeaderCrc: true }] }), { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  add('xz-bad-index-crc.xz', xzStream({ check: 4, blocks: [xzBlock(a)], badIndexCrc: true }), { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  add('xz-bad-footer-magic.xz', xzStream({ check: 4, blocks: [xzBlock(a)], footerMagic: Buffer.from('ZY') }), { status: 'rejected', findings: ['CORRUPTED/UNPARSEABLE'] });
  add('xz-truncated.xz', s1.subarray(0, s1.length - 20), { status: 'rejected', findings: ['CORRUPTED/TRUNCATED'] });
  const lz = rawLzma2(a);
  const broken = Buffer.from(lz);
  broken[40] ^= 0xff;
  broken[41] ^= 0x55;
  add('xz-data-error.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), data: broken }] }), { status: 'rejected', findings: ['CORRUPTED/DATA_ERROR'] });
  add(
    'xz-unknown-filter.xz',
    xzStream({
      check: 4,
      blocks: [
        {
          ...xzBlock(a),
          filters: [
            { id: 0x7f, props: Buffer.alloc(0) },
            { id: 0x21, props: Buffer.from([16]) },
          ],
        },
      ],
    }),
    {
      status: 'rejected',
      findings: ['COMPRESSION/UNSUPPORTED_METHOD'],
    },
  );
  add('xz-delta-last.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), filters: [{ id: 0x03, props: Buffer.from([0]) }] }] }), { status: 'rejected', findings: ['COMPRESSION/UNSUPPORTED_FEATURE'] });
  add('xz-reserved-flags.xz', xzStream({ check: 4, flags: Buffer.from([0, 0x14]), blocks: [xzBlock(a)] }), { status: 'rejected', findings: ['COMPRESSION/UNSUPPORTED_FEATURE'] });
  add('xz-vli-zero.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), uncomp: a.length, uncompVli: Buffer.from([0x80 | (a.length & 0x7f), (a.length >> 7) & 0x7f, 0x80, 0x00]) }] }), {
    status: 'rejected',
    findings: ['CORRUPTED/UNPARSEABLE'],
  });
  add('xz-big-dictionary.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), filters: [{ id: 0x21, props: Buffer.from([40]) }] }] }), { status: 'rejected', findings: ['LIMIT/DICTIONARY_SIZE'] });
  add('xz-declared-huge.xz', xzStream({ check: 4, blocks: [{ ...xzBlock(a), uncomp: 2 ** 40 }] }), { status: 'rejected', findings: ['LIMIT/DECOMPRESSED_SIZE'] });
  // A degenerate LZMA2 stream: chunks of nothing but stored bytes, with no end marker.
  add('xz-lzma2-no-end.xz', xzStream({ check: 0, blocks: [{ data: Buffer.from([0x01, 0x00, 0x00, 0x41]), decoded: Buffer.from('A'), check: Buffer.alloc(0), comp: 4 }] }), {
    status: 'rejected',
    findings: ['CORRUPTED/TRUNCATED'],
  });
}
{
  const zeros = Buffer.alloc(16 * 1024 * 1024);
  add('xz-bomb.xz', xzPy(zeros), { status: 'rejected', findings: ['LIMIT/RATIO'] });
  const inner = xzPy(zeros);
  add('xz-nested-bomb.xz', xzPy(xzPy(inner)), { status: 'clean', nested: true });
  const tar = py(
    "import tarfile,io\nb=io.BytesIO()\nt=tarfile.open(fileobj=b,mode='w',format=tarfile.USTAR_FORMAT)\ni=tarfile.TarInfo('dir/file.txt')\ni.size=len(d)\ni.mtime=0\nt.addfile(i,io.BytesIO(d))\nt.close()\no=b.getvalue()",
    hello,
  );
  add('xz-tar.txz', xzPy(tar), { status: 'clean', sniffed: 'application/x-tar' });
}

// .lzma
{
  const a = text(4000, 5);
  const alone = alonePy(a);
  add('lzma-unknown-size.lzma', alone, { status: 'clean', content: crc32(a) });
  const known = Buffer.from(alone);
  known.writeUInt32LE(a.length, 5);
  known.writeUInt32LE(0, 9);
  add('lzma-known-size-eopm.lzma', known, { status: 'clean', content: crc32(a) });
  const bigger = Buffer.from(known);
  bigger.writeUInt32LE(a.length + 100, 5);
  add('lzma-size-too-big.lzma', bigger, { status: 'strippable', findings: ['STRUCTURE/SIZE_MISMATCH'] });
  const smaller = Buffer.from(known);
  smaller.writeUInt32LE(a.length - 100, 5);
  add('lzma-size-too-small.lzma', smaller, { status: 'rejected', findings: ['CORRUPTED/DATA_ERROR'] });
  add('lzma-truncated.lzma', alone.subarray(0, alone.length - 10), { status: 'rejected', findings: ['CORRUPTED/TRUNCATED'] });
  add('lzma-trailing.lzma', cat(alone, Buffer.from('junk after the end of the data')), { status: 'strippable', findings: ['STRUCTURE/TRAILING_BYTES'] });
  const raw = rawLzma1(a, 1 << 16, 3, 0, 2);
  add('lzma-raw-known.lzma', cat(lzmaProps(1 << 16), u64(a.length), raw), { status: 'clean', content: crc32(a) });
  add('lzma-big-dictionary.lzma', cat(Buffer.from([0x5d]), u32(2 ** 31), Buffer.alloc(8, 0xff), raw), { status: 'rejected', findings: ['LIMIT/DICTIONARY_SIZE'] });
  add('lzma-declared-huge.lzma', cat(Buffer.from([0x5d]), u32(1 << 16), u64(2 ** 38 - 1), raw), { status: 'rejected', findings: ['LIMIT/DECOMPRESSED_SIZE'] });
  add('lzma-bomb.lzma', alonePy(Buffer.alloc(16 * 1024 * 1024)), { status: 'rejected', findings: ['LIMIT/RATIO'] });
}

// 7z: coders
{
  const a = text(6000, 21);
  const b = text(3000, 22);
  const files = [
    { name: 'docs/a.txt', data: a, attrib: 0x20, mtime: u64(132000000000000000) },
    { name: 'docs/b.txt', data: b, attrib: 0x20 },
    { name: 'docs', dir: true, attrib: 0x10 },
    { name: 'empty.txt', empty: true, attrib: 0x20 },
  ];
  add('7z-copy.7z', copyArchive(files), { status: 'clean', entries: 4 });
  const both = cat(a, b);
  add('7z-lzma-solid.7z', solidArchive(files, { coders: [{ id: '030101', props: lzmaProps() }] }, [rawLzma1(both)]), { status: 'clean', entries: 4 });
  add('7z-lzma2-solid.7z', solidArchive(files, { coders: [{ id: '21', props: Buffer.from([16]) }] }, [rawLzma2(both)]), { status: 'clean', entries: 4 });
  add('7z-deflate.7z', solidArchive(files, { coders: [{ id: '040108' }] }, [zlib.deflateRawSync(both, { level: 9 })]), { status: 'clean', entries: 4 });
  {
    // Deflate64 that plain deflate cannot read: a match from 40,000 bytes back, 1,000 bytes long.
    const { payload, data } = deflate64Example();
    add('7z-deflate64.7z', solidArchive([{ name: 'far-copy.bin', data, attrib: 0x20 }], { coders: [{ id: '040109' }] }, [payload]), {
      status: 'clean',
      entries: 1,
      names: ['far-copy.bin'],
      kept: [crc32(data)],
    });
  }
  add('7z-empty-id-copy.7z', solidArchive(files, { coders: [{ id: '' }] }, [both]), { status: 'clean', entries: 4 });
  const code = codeLike(30000, 31);
  const code2 = codeLike(20000, 32);
  const cfiles = [
    { name: 'prog.bin', data: code },
    { name: 'prog2.bin', data: code2 },
  ];
  const cboth = cat(code, code2);
  for (const [name, ids, pyF] of [
    ['x86', ['03030103', '04'], "{'id':lzma.FILTER_X86}"],
    ['powerpc', ['03030205'], "{'id':lzma.FILTER_POWERPC}"],
    ['ia64', ['03030401'], "{'id':lzma.FILTER_IA64}"],
    ['arm', ['03030501'], "{'id':lzma.FILTER_ARM}"],
    ['armthumb', ['03030701'], "{'id':lzma.FILTER_ARMTHUMB}"],
    ['sparc', ['03030805'], "{'id':lzma.FILTER_SPARC}"],
    ['delta', ['03'], "{'id':lzma.FILTER_DELTA,'dist':2}"],
  ]) {
    for (const id of ids) {
      const coder = { id, props: name === 'delta' ? Buffer.from([1]) : undefined };
      const folder = { coders: [coder, { id: '21', props: Buffer.from([16]) }], bindPairs: [[0, 1]], unpackSizes: [cboth.length, cboth.length] };
      add(`7z-${name}${id.length === 2 && name !== 'delta' ? '-short-id' : ''}.7z`, solidArchive(cfiles, folder, [rawLzma2(cboth, [pyF])]), { status: 'clean', entries: 2 });
    }
  }
  const arm = arm64Code(20000, 33);
  add(
    '7z-arm64.7z',
    solidArchive([{ name: 'a64.bin', data: arm }], { coders: [{ id: '0a' }, { id: '21', props: Buffer.from([16]) }], bindPairs: [[0, 1]], unpackSizes: [arm.length, arm.length] }, [
      rawLzma2(arm64Encode(arm)),
    ]),
    { status: 'clean', entries: 1 },
  );
  const rv = riscvCode(20000, 34);
  add(
    '7z-riscv.7z',
    solidArchive([{ name: 'rv.bin', data: rv }], { coders: [{ id: '0b' }, { id: '21', props: Buffer.from([16]) }], bindPairs: [[0, 1]], unpackSizes: [rv.length, rv.length] }, [
      rawLzma2(riscvEncode(rv)),
    ]),
    { status: 'clean', entries: 1 },
  );
  // BCJ2: main, call and jump streams through LZMA, the range coder stream stored.
  const x86 = x86Code(40000, 35);
  const s = bcj2Encode(x86);
  const pm = rawLzma1(s.main);
  const pc = rawLzma1(s.call.length ? s.call : Buffer.alloc(0));
  const pj = rawLzma1(s.jump.length ? s.jump : Buffer.alloc(0));
  const bcj2Folder = {
    coders: [
      { id: '0303011b', numIn: 4, numOut: 1 },
      { id: '030101', props: lzmaProps() },
      { id: '030101', props: lzmaProps() },
      { id: '030101', props: lzmaProps() },
    ],
    bindPairs: [
      [0, 1],
      [1, 2],
      [2, 3],
    ],
    packedStreams: [4, 5, 6, 3],
    unpackSizes: [x86.length, s.main.length, s.call.length, s.jump.length],
  };
  add('7z-bcj2.7z', solidArchive([{ name: 'x86.exe', data: x86 }], bcj2Folder, [pm, pc, pj, s.rc]), { status: 'clean', entries: 1, content: crc32(x86) });
  // 7zAES over LZMA, with the key from a password.
  const salt = Buffer.from('0123456789abcdef');
  const iv = Buffer.from('fedcba9876543210');
  const packedA = rawLzma1(both);
  const { enc, props } = aesEncrypt(packedA, 'right password', 19, salt, iv);
  const aesFolder = {
    coders: [
      { id: '030101', props: lzmaProps() },
      { id: '06f10701', props },
    ],
    bindPairs: [[0, 1]],
    unpackSizes: [both.length, packedA.length],
  };
  add('7z-aes.7z', solidArchive(files, aesFolder, [enc]), { status: 'strippable', password: ['wrong', 'right password'], findings: ['ENCRYPTED/DECRYPTED', 'ENCRYPTED/AES_256'], entries: 4 });
  // An encrypted header: the header itself goes through LZMA and 7zAES.
  {
    const files2 = [{ name: 'secret-name.txt', data: small }];
    const realHeader = plainHeader(
      streamsInfo({ packSizes: [small.length], folders: [{ coders: [{ id: '00' }], unpackSizes: [small.length] }], sub: subStreams(null, null, [crc32(small)]) }),
      filesInfo(files2),
    );
    const hp = rawLzma1(realHeader);
    const he = aesEncrypt(hp, 'hdr', 6, salt, iv);
    const enHeader = cat(
      Buffer.from([0x17]),
      streamsInfo({
        packPos: small.length,
        packSizes: [he.enc.length],
        folders: [
          {
            coders: [
              { id: '030101', props: lzmaProps() },
              { id: '06f10701', props: he.props },
            ],
            bindPairs: [[0, 1]],
            unpackSizes: [realHeader.length, hp.length],
            crc: crc32(realHeader),
          },
        ],
      }),
    );
    const archive = sevenZip({ packs: [small, he.enc], header: enHeader });
    add('7z-encrypted-header.7z', archive, { status: 'strippable', password: 'hdr', findings: ['ENCRYPTED/HEADER'], entries: 1 });
    add('7z-encrypted-header-nopw.7z', archive, { status: 'rejected', findings: ['ENCRYPTED/PASSWORD_REQUIRED'] });
    // A plain encoded header, LZMA only.
    const plainEnc = cat(
      Buffer.from([0x17]),
      streamsInfo({ packPos: small.length, packSizes: [hp.length], folders: [{ coders: [{ id: '030101', props: lzmaProps() }], unpackSizes: [realHeader.length], crc: crc32(realHeader) }] }),
    );
    add('7z-encoded-header.7z', sevenZip({ packs: [small, hp], header: plainEnc }), { status: 'clean', entries: 1 });
    const hugeEnc = cat(
      Buffer.from([0x17]),
      streamsInfo({ packPos: small.length, packSizes: [hp.length], folders: [{ coders: [{ id: '030101', props: lzmaProps() }], unpackSizes: [2 ** 40], crc: crc32(realHeader) }] }),
    );
    add('7z-encoded-header-huge.7z', sevenZip({ packs: [small, hp], header: hugeEnc }), { status: 'rejected', findings: ['LIMIT/TOTAL_DECOMPRESSED_SIZE'] });
  }
  add('7z-aes-nopw.7z', solidArchive(files, aesFolder, [enc]), { status: 'rejected', findings: ['ENCRYPTED/PASSWORD_REQUIRED'] });
  {
    // A solid encrypted folder of 40 files: the first with no CRC, so any password decodes it, the second with its
    // CRC, and the rest with CRCs that do not match. The folder opens with one password, checked against the second
    // file, so a file that fails its CRC does not send the reader back to the start of the folder with another.
    const many = Array.from({ length: 40 }, (_, i) => ({ name: `f${i}.txt`, data: text(4096, 100 + i), crc: i === 0 ? null : i === 1 ? undefined : 0 }));
    const plain = cat(...many.map(m => m.data));
    const sealed = aesEncrypt(plain, 'pw', 4, salt, iv);
    const folder = { coders: [{ id: '06f10701', props: sealed.props }], unpackSizes: [plain.length] };
    add('7z-aes-bad-crcs.7z', solidArchive(many, folder, [sealed.enc]), {
      status: 'strippable',
      password: 'pw',
      findings: ['CORRUPTED/ENTRY_DATA', 'ENCRYPTED/DECRYPTED'],
      names: ['f0.txt', 'f1.txt'],
    });
  }
  {
    // Key derivation over 2^30 rounds, which no reader finishes in reasonable time. The data is never decrypted.
    const bigProps = cat(Buffer.from([0xc0 | 30, ((salt.length - 1) << 4) | (iv.length - 1)]), salt, iv);
    const f = { ...aesFolder, coders: [aesFolder.coders[0], { id: '06f10701', props: bigProps }] };
    add('7z-aes-cycles-power-30.7z', solidArchive(files, f, [enc]), { status: 'rejected', password: 'x', findings: ['COMPRESSION/UNSUPPORTED_FEATURE'] });
  }
  add('7z-ppmd.7z', solidArchive(files, { coders: [{ id: '030401', props: Buffer.from([6, 0, 0, 0, 1]) }] }, [both]), { status: 'rejected', findings: ['COMPRESSION/UNSUPPORTED_METHOD'] });
  add('7z-bzip2.7z', solidArchive(files, { coders: [{ id: '040202' }] }, [bzip2Py(both)]), { status: 'clean', entries: 4 });
  add('7z-bzip2-corrupt.7z', solidArchive(files, { coders: [{ id: '040202' }] }, [both]), { status: 'strippable', findings: ['CORRUPTED/ENTRY_DATA'] });
  // Data errors in entries: a CRC that does not match, and a folder that does not decode.
  const badCrc = copyArchive([
    { name: 'good.txt', data: a },
    { name: 'bad.txt', data: b },
  ]);
  const flip = Buffer.from(badCrc);
  flip[32 + a.length + 10] ^= 0x20;
  add('7z-entry-crc.7z', flip, { status: 'strippable', findings: ['CORRUPTED/ENTRY_DATA'], entries: 2 });
  const lz = Buffer.from(rawLzma1(both));
  lz[30] ^= 0xff;
  lz[31] ^= 0xff;
  add('7z-folder-data-error.7z', solidArchive(files, { coders: [{ id: '030101', props: lzmaProps() }] }, [lz]), { status: 'strippable', findings: ['CORRUPTED/ENTRY_DATA'] });
  add('7z-truncated.7z', copyArchive(files).subarray(0, 200), { status: 'rejected', findings: ['CORRUPTED/TRUNCATED'] });
  const hdrCrc = Buffer.from(copyArchive(files));
  hdrCrc[hdrCrc.length - 3] ^= 1;
  add('7z-header-crc.7z', hdrCrc, { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  const startCrc = Buffer.from(copyArchive(files));
  startCrc[8] ^= 1;
  add('7z-start-header-crc.7z', startCrc, { status: 'rejected', findings: ['CORRUPTED/CHECK_FAILED'] });
  add('7z-not-7z.7z', Buffer.from('this is plain text and no archive at all'), { status: 'rejected', findings: ['CORRUPTED/UNPARSEABLE'] });
  // An empty start header, as an interrupted write leaves it, with the header at the end.
  {
    const whole = Buffer.from(copyArchive(files));
    whole.fill(0, 8, 32);
    add('7z-empty-start-header.7z', whole, { status: 'strippable', findings: ['STRUCTURE/EMPTY_START_HEADER'], entries: 4 });
  }
  add('7z-empty.7z', sevenZip({ header: Buffer.alloc(0), start: Buffer.alloc(20) }), { status: 'clean', entries: 0 });
  add(
    '7z-dirs-only.7z',
    copyArchive([
      { name: 'a', dir: true },
      { name: 'a/b', dir: true },
      { name: 'a/empty', empty: true },
    ]),
    { status: 'clean', entries: 3 },
  );
  add('7z-no-names.7z', copyArchive([{ data: a }, { data: b }]), { status: 'clean', entries: 2 });
  add('7z-unknown-property.7z', copyArchive([{ name: 'a.txt', data: a }], { extraFileProps: [prop(0x18, cat(Buffer.from([1, 0]), u64(0)))] }), {
    status: 'strippable',
    findings: ['STRUCTURE/UNKNOWN_PROPERTY'],
  });
  add(
    '7z-archive-properties.7z',
    (() => {
      const streams = streamsInfo({ packSizes: [a.length], folders: [{ coders: [{ id: '00' }], unpackSizes: [a.length] }], sub: subStreams(null, null, [crc32(a)]) });
      // A property ID of eight bytes, as 7-Zip reads IDs as numbers.
      const archiveProps = cat(Buffer.from([0x02]), Buffer.from([0xff, 1, 0, 0x9a, 0x78, 0x56, 0x34, 0x12, 0x3f]), num(3), Buffer.from([0, 1, 2]), Buffer.from([0]));
      return sevenZip({ packs: [a], header: cat(Buffer.from([0x01]), archiveProps, Buffer.from([0x04]), streams, filesInfo([{ name: 'a.txt', data: a }]), Buffer.from([0])) });
    })(),
    { status: 'strippable', findings: ['STRUCTURE/UNKNOWN_PROPERTY'] },
  );
  // Structure around and between the parts of the archive.
  add('7z-sfx-prefix.7z', copyArchive(files, { prefix: cat(Buffer.from('MZ'), Buffer.alloc(300, 0x90)) }), { status: 'strippable', findings: ['STRUCTURE/LEADING_BYTES', 'STRUCTURE/POLYGLOT'] });
  add('7z-leading-text.7z', copyArchive(files, { prefix: Buffer.from('#!/bin/sh\nexit 0\n') }), { status: 'strippable', findings: ['STRUCTURE/LEADING_BYTES'] });
  add('7z-trailing.7z', copyArchive(files, { suffix: Buffer.from('trailing bytes after the header') }), { status: 'strippable', findings: ['STRUCTURE/TRAILING_BYTES'] });
  add('7z-hidden-gap.7z', copyArchive(files, { gap: Buffer.from('bytes between the packed streams and the header') }), { status: 'strippable', findings: ['STRUCTURE/HIDDEN_DATA'] });
  add('7z-pdf-polyglot.7z', copyArchive([{ name: 'x.txt', data: Buffer.from('%PDF-1.7\n1 0 obj\n<<>>\nendobj\n') }]), { status: 'strippable', findings: ['STRUCTURE/POLYGLOT'] });
  {
    // The header claims to start inside the packed stream.
    const archive = Buffer.from(copyArchive([{ name: 'a.txt', data: a }]));
    const header = archive.subarray(32 + a.length);
    const st = cat(u64(a.length - header.length), u64(header.length), u32(crc32(header)));
    const moved = Buffer.from(archive.subarray(0, 32 + a.length));
    header.copy(moved, 32 + a.length - header.length);
    st.copy(moved, 12);
    moved.writeUInt32LE(crc32(st), 8);
    add('7z-overlap.7z', moved, { status: 'strippable', findings: ['STRUCTURE/OVERLAP'] });
  }
}

// 7z: names, links, kinds, permissions
{
  const d = small;
  const named = names => copyArchive(names.map(n => ({ name: n, data: d })));
  add('7z-traversal.7z', named(['../../etc/passwd', 'a/../../b.txt', 'ok.txt']), { status: 'strippable', findings: ['NAME/TRAVERSAL'], names: ['etc/passwd', 'a/b.txt', 'ok.txt'] });
  add('7z-traversal-backslash.7z', named(['..\\..\\evil.txt', 'a\\..\\..\\b.txt']), { status: 'strippable', findings: ['NAME/TRAVERSAL', 'NAME/BACKSLASH'], names: ['evil.txt', 'a/b.txt'] });
  add('7z-absolute.7z', named(['/etc/cron.d/x', '\\windows\\x.dll']), { status: 'strippable', findings: ['NAME/ABSOLUTE'], names: ['etc/cron.d/x', 'windows/x.dll'] });
  add('7z-drive-letter.7z', named(['C:\\Windows\\x.dll', 'D:rel.txt']), { status: 'strippable', findings: ['NAME/DRIVE_LETTER'], names: ['Windows/x.dll', 'rel.txt'] });
  add('7z-control-chars.7z', named(['bad\u0007name.txt', 'exe\u202Etxt.exe']), { status: 'strippable', findings: ['NAME/CONTROL_CHARACTER'], names: ['bad_name.txt', 'exe_txt.exe'] });
  add('7z-lone-surrogate.7z', copyArchive([{ name: cat(Buffer.from([0x61, 0, 0x00, 0xd8, 0x62, 0]), Buffer.from([0, 0])), data: d }]), {
    status: 'strippable',
    findings: ['NAME/ENCODING'],
    names: ['a\ufffdb'],
  });
  add('7z-embedded-nul.7z', copyArchive([{ name: Buffer.from('e\0vil.txt\0', 'utf16le'), data: d }]), { status: 'rejected', findings: ['CORRUPTED/UNPARSEABLE'] });
  add(
    '7z-duplicate.7z',
    copyArchive([
      { name: 'same.txt', data: Buffer.from('first content\n') },
      { name: 'same.txt', data: Buffer.from('second content\n') },
    ]),
    {
      status: 'strippable',
      findings: ['NAME/DUPLICATE'],
      // Readers that overwrite keep the last copy, and so does the rewrite.
      names: ['same.txt'],
      kept: [crc32(Buffer.from('second content\n'))],
    },
  );
  add('7z-case-collision.7z', named(['Readme.TXT', 'README.txt']), { status: 'strippable', findings: ['NAME/CASE_COLLISION'], names: ['README.txt'] });
  add('7z-nfkd-collision.7z', named(['\ufb01le.txt', 'file.txt', 'cafe\u0301.txt', 'caf\u00e9.txt']), {
    status: 'strippable',
    findings: ['NAME/NORMALIZATION_COLLISION'],
    names: ['file.txt', 'caf\u00e9.txt'],
  });
  // The file goes where a folder is needed.
  add('7z-file-dir-clash.7z', named(['a', 'a/b.txt']), { status: 'strippable', findings: ['NAME/FILE_DIRECTORY_CLASH'], names: ['a/b.txt'] });
  add('7z-proto-names.7z', named(['__proto__', 'constructor', 'toString', 'hasOwnProperty', '__proto__/x']), {
    status: 'strippable',
    findings: ['NAME/FILE_DIRECTORY_CLASH'],
    names: ['constructor', 'toString', 'hasOwnProperty', '__proto__/x'],
  });
  const unix = (mode, extra = 0) => (0x8000 | (mode << 16) | extra) >>> 0;
  const link = (name, target) => ({ name, data: Buffer.from(target), attrib: unix(0o120777) });
  // A link that stays inside the tree stays.
  add('7z-symlink.7z', copyArchive([link('lib/current', 'v1'), { name: 'lib/v1', data: d }]), { status: 'clean', findings: ['LINK/SYMLINK'], names: ['lib/current', 'lib/v1'] });
  add('7z-symlink-escape.7z', copyArchive([link('up', '../../../etc'), link('abs', '/etc/passwd'), link('ok', 'file.txt'), { name: 'file.txt', data: d }]), {
    status: 'strippable',
    findings: ['LINK/OUTSIDE'],
    keepLinks: true,
    names: ['ok', 'file.txt'],
  });
  add('7z-symlink-chain.7z', copyArchive([link('a/b', '../c'), link('c', '../..'), link('a/x', 'b/y')]), { status: 'strippable', findings: ['LINK/OUTSIDE'], keepLinks: true });
  add('7z-symlink-loop.7z', copyArchive([link('p', 'q/x'), link('q', 'p')]), { status: 'strippable', findings: ['LINK/OUTSIDE'], keepLinks: true });
  add('7z-through-link.7z', copyArchive([link('dir', '/tmp'), { name: 'dir/payload.sh', data: d }]), { status: 'strippable', findings: ['LINK/THROUGH_LINK'], keepLinks: true });
  // A reparse point holds a reparse buffer, not a path, so where it leads cannot be read.
  add('7z-reparse-point.7z', copyArchive([{ name: 'junction', data: Buffer.from('reparse data'), attrib: 0x400 | 0x20 }]), { status: 'strippable', findings: ['LINK/SYMLINK', 'LINK/OUTSIDE'] });
  add(
    '7z-special-files.7z',
    copyArchive([
      { name: 'dev', empty: true, attrib: unix(0o020644) },
      { name: 'fifo', empty: true, attrib: unix(0o010644) },
      { name: 'sock', empty: true, attrib: unix(0o140644) },
    ]),
    {
      status: 'strippable',
      findings: ['SPECIAL/DEVICE', 'SPECIAL/FIFO', 'SPECIAL/SOCKET'],
      names: [],
    },
  );
  add(
    '7z-anti.7z',
    copyArchive([
      { name: 'deleted.txt', anti: true },
      { name: 'kept.txt', data: d },
    ]),
    { status: 'strippable', findings: ['SPECIAL/ANTI_ITEM'], names: ['kept.txt'] },
  );
  add('7z-permissions.7z', copyArchive([{ name: 'tool', data: d, attrib: unix(0o107755) }]), {
    status: 'strippable',
    findings: ['PERMISSIONS/SETUID', 'PERMISSIONS/SETGID', 'PERMISSIONS/STICKY'],
    attribs: [unix(0o100755)],
  });
  add('7z-type-mismatch.7z', named(['picture.png']), { status: 'clean', findings: ['ENTRY/TYPE_MISMATCH'] });
  add('7z-times.7z', copyArchive([{ name: 't.txt', data: d, mtime: u64(132000000000000000) }]), { status: 'strippable', stripMetadata: true, findings: ['METADATA/STRIPPED'] });
}

// 7z: limits, and headers that declare more than they hold
{
  const d = small;
  const one = { coders: [{ id: '00' }], unpackSizes: [d.length] };
  const files1 = filesInfo([{ name: 'a.txt', data: d }]);
  const header = streams => plainHeader(streams, files1);
  add('7z-many-entries.7z', copyArchive(Array.from({ length: 50 }, (_, i) => ({ name: `f${i}.txt`, data: d }))), { status: 'rejected', limits: { entries: 10 }, findings: ['LIMIT/ENTRY_COUNT'] });
  add('7z-declared-huge.7z', sevenZip({ packs: [d], header: header(streamsInfo({ packSizes: [d.length], folders: [{ coders: [{ id: '00' }], unpackSizes: [2 ** 40] }] })) }), {
    status: 'rejected',
    findings: ['LIMIT/TOTAL_DECOMPRESSED_SIZE'],
  });
  add('7z-entry-huge.7z', sevenZip({ packs: [d], header: header(streamsInfo({ packSizes: [d.length], folders: [{ coders: [{ id: '00' }], unpackSizes: [2 ** 30] }] })) }), {
    status: 'rejected',
    findings: ['LIMIT/DECOMPRESSED_SIZE'],
  });
  add(
    '7z-big-dictionary.7z',
    sevenZip({ packs: [d], header: header(streamsInfo({ packSizes: [d.length], folders: [{ coders: [{ id: '030101', props: lzmaProps(2 ** 31) }], unpackSizes: [2 ** 30] }] })) }),
    {
      status: 'rejected',
      limits: { decompressedBytes: 2 ** 31 },
      findings: ['LIMIT/DICTIONARY_SIZE'],
    },
  );
  // Bind pairs where a coder reads its own output and feeds nothing the folder outputs.
  add(
    '7z-coder-loop.7z',
    sevenZip({ packs: [d], header: header(streamsInfo({ packSizes: [d.length], folders: [{ coders: [{ id: '00' }, { id: '00' }], bindPairs: [[0, 0]], unpackSizes: [d.length, d.length] }] })) }),
    {
      status: 'rejected',
      findings: ['CORRUPTED/UNPARSEABLE'],
    },
  );
  // Counts that ask for huge allocations from a small file.
  const bigCount = cat(Buffer.from([0x06]), num(0), num(2 ** 40), Buffer.from([0x09]), num(1), Buffer.from([0x00, 0x00]));
  add('7z-huge-pack-count.7z', sevenZip({ packs: [d], header: cat(Buffer.from([0x01, 0x04]), bigCount, files1, Buffer.from([0])) }), { status: 'rejected', findings: ['CORRUPTED/UNPARSEABLE'] });
  const bigFolders = cat(Buffer.from([0x07, 0x0b]), num(2 ** 40), Buffer.from([0]), Buffer.from([0x00]));
  add('7z-huge-folder-count.7z', sevenZip({ packs: [d], header: cat(Buffer.from([0x01, 0x04]), bigFolders, Buffer.from([0]), files1, Buffer.from([0])) }), {
    status: 'rejected',
    findings: ['CORRUPTED/UNPARSEABLE'],
  });
  add('7z-huge-file-count.7z', sevenZip({ packs: [], header: cat(Buffer.from([0x01, 0x05]), num(2 ** 40), Buffer.from([0, 0])) }), { status: 'rejected', findings: ['LIMIT/ENTRY_COUNT'] });
  add(
    '7z-huge-coder-count.7z',
    sevenZip({
      packs: [d],
      header: cat(Buffer.from([0x01, 0x04, 0x06]), num(0), num(1), Buffer.from([0x09]), num(d.length), Buffer.from([0x00, 0x07, 0x0b, 0x01, 0x00]), num(2 ** 30), Buffer.from([0x01, 0x00])),
    }),
    {
      status: 'rejected',
      findings: ['CORRUPTED/UNPARSEABLE'],
    },
  );
  add('7z-huge-property-size.7z', sevenZip({ packs: [], header: cat(Buffer.from([0x01, 0x05, 0x01, 0x11]), num(2 ** 50), Buffer.from([0])) }), {
    status: 'rejected',
    findings: ['CORRUPTED/UNPARSEABLE'],
  });
  // A huge substream count.
  const subHuge = cat(Buffer.from([0x08, 0x0d]), num(0x7fffffff), Buffer.from([0x00]));
  add('7z-huge-substreams.7z', sevenZip({ packs: [d], header: header(streamsInfo({ packSizes: [d.length], folders: [one], sub: subHuge })) }), { status: 'rejected', findings: ['LIMIT/ENTRY_COUNT'] });
  // Two EmptyStream properties that describe the entries two ways.
  const twoEmpty = cat(Buffer.from([0x05]), num(2), prop(0x0e, bits([true, false])), prop(0x0e, bits([true, true])), prop(0x0f, bits([true, true])), Buffer.from([0]));
  add(
    '7z-two-empty-stream.7z',
    sevenZip({ packs: [d], header: cat(Buffer.from([0x01, 0x04]), streamsInfo({ packSizes: [d.length], folders: [one], sub: subStreams(null, null, [crc32(d)]) }), twoEmpty, Buffer.from([0])) }),
    {
      status: 'rejected',
      findings: ['CORRUPTED/UNPARSEABLE'],
    },
  );
  // A degenerate LZMA stream: a valid start that stops halfway through.
  const lz = rawLzma1(text(20000, 9));
  add('7z-lzma-truncated.7z', solidArchive([{ name: 't.txt', data: text(20000, 9) }], { coders: [{ id: '030101', props: lzmaProps() }] }, [lz.subarray(0, 100)]), {
    status: 'strippable',
    findings: ['CORRUPTED/ENTRY_DATA'],
  });
}

const manifest = { generatedBy: 'scripts/make-lzma-fixtures.js', cases };
// Names outside ASCII are written as JSON escapes, so the manifest stays ASCII.
const json = JSON.stringify(manifest, null, 2).replace(/[\u0080-\uffff]/g, c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`);
fs.writeFileSync(path.join(OUT, 'manifest.json'), `${json}\n`);
console.log(`${Object.keys(cases).length} fixtures in ${path.relative(process.cwd(), OUT)}`);
