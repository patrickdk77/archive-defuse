// Regenerates test/fixtures/deflate64: raw Deflate64 streams written by /usr/bin/7z, plus manifest.json with the SHA-256 and
// size of each stream's decoded output. Inputs come from a seeded PRNG, so a rerun builds the same inputs.
// Usage: node scripts/make-deflate64-fixtures.js
const { execFileSync } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const out = path.join(__dirname, '..', 'test', 'fixtures', 'deflate64');

/** xorshift32, so the inputs do not depend on the Node version. */
function prng(seed) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s >>>= 0;
    s ^= s >>> 17;
    s ^= s << 5;
    s >>>= 0;
    return s;
  };
}

function randomBytes(seed, n) {
  const next = prng(seed);
  const b = Buffer.alloc(n);
  for (let i = 0; i < n; i++) b[i] = next() & 0xff;
  return b;
}

const WORDS = 'the of and to in is was for on that with as by at from his her an were which this be are not or have had it but its one all also first new more two can'.split(' ');
function text(seed, n) {
  const next = prng(seed);
  const parts = [];
  let len = 0;
  while (len < n) {
    const w = WORDS[next() % WORDS.length] + ((next() & 15) === 0 ? '.\n' : ' ');
    parts.push(w);
    len += w.length;
  }
  return Buffer.from(parts.join('')).subarray(0, n);
}

function runs(seed, n) {
  const next = prng(seed);
  const b = Buffer.alloc(n);
  let i = 0;
  while (i < n) {
    const len = 1 + (next() % 70000);
    b.fill(next() & 0xff, i, Math.min(n, i + len));
    i += len;
  }
  return b;
}

/** Copies more than 32 KiB back: X, 52 KiB of text, X again (distance code 31); Z, 30 KiB of text, Z (code 30). */
function far() {
  const x = randomBytes(11, 4096);
  const z = randomBytes(12, 4096);
  return Buffer.concat([x, text(13, 53248), x, z, text(14, 30720), z]);
}

/** Over 1 MiB: a 4 KiB random block repeated 300 times, one byte changed in each copy. */
function big() {
  const seed = randomBytes(21, 4096);
  const next = prng(22);
  const parts = [];
  for (let i = 0; i < 300; i++) {
    const c = Buffer.from(seed);
    c[next() % 4096] = next() & 0xff;
    parts.push(c);
  }
  return Buffer.concat(parts);
}

const inputs = {
  text: text(1, 80000),
  random: randomBytes(2, 20000),
  runs: runs(3, 300000),
  far: far(),
  big: big(),
  empty: Buffer.alloc(0),
};

/** The raw method-9 stream of the first entry of a ZIP, from its local header. */
function rawStream(zip) {
  if (zip.readUInt32LE(0) !== 0x04034b50) throw new Error('no local header');
  const flags = zip.readUInt16LE(6);
  const method = zip.readUInt16LE(8);
  if (method !== 9) throw new Error(`method ${method}, not 9`);
  let size = zip.readUInt32LE(18);
  const nameLen = zip.readUInt16LE(26);
  const extraLen = zip.readUInt16LE(28);
  const start = 30 + nameLen + extraLen;
  if (size === 0xffffffff) {
    let p = 30 + nameLen;
    const end = p + extraLen;
    size = -1;
    while (p + 4 <= end) {
      const id = zip.readUInt16LE(p);
      const len = zip.readUInt16LE(p + 2);
      if (id === 1) size = Number(zip.readBigUInt64LE(p + 4 + 8));
      p += 4 + len;
    }
    if (size < 0) throw new Error('no zip64 size');
  }
  if (flags & 8 && size === 0) throw new Error('size only in a data descriptor');
  return zip.subarray(start, start + size);
}

const work = fs.mkdtempSync(path.join(os.tmpdir(), 'd64-'));
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const manifest = {};
try {
  for (const [name, data] of Object.entries(inputs)) {
    for (const level of [1, 9]) {
      const zip = path.join(work, `${name}-${level}.zip`);
      const args = ['a', '-tzip', '-mm=Deflate64', `-mx=${level}`];
      // From stdin 7z always writes method 9; from a named file it stores an empty or incompressible file with method 0.
      execFileSync('7z', [...args, '-si', zip], { input: data, stdio: ['pipe', 'ignore', 'inherit'] });
      const stream = rawStream(fs.readFileSync(zip));
      const id = `${name}-mx${level}`;
      fs.writeFileSync(path.join(out, `${id}.d64`), stream);
      manifest[id] = { size: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') };
    }
  }
} finally {
  fs.rmSync(work, { recursive: true, force: true });
}
fs.writeFileSync(path.join(out, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
