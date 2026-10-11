// The two ways a ZIP entry is commonly encrypted: PKWARE's traditional stream cipher, which is our own code, and
// WinZip's AES, built only from what OpenSSL's default provider keeps: AES-ECB for the counter mode and HMAC-SHA1
// for the key derivation and the authentication code.
import * as crypto from 'node:crypto';
import { DataError } from './errors';

const CRC = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  CRC[n] = c >>> 0;
}
const crcByte = (crc: number, b: number) => (CRC[(crc ^ b) & 0xff] ^ (crc >>> 8)) >>> 0;

/** The three keys of PKWARE's traditional encryption. */
export class ZipCryptoKeys {
  private k0 = 0x12345678;
  private k1 = 0x23456789;
  private k2 = 0x34567890;
  constructor(password: Uint8Array) {
    for (const b of password) this.update(b);
  }
  private update(b: number): void {
    this.k0 = crcByte(this.k0, b);
    this.k1 = (Math.imul((this.k1 + (this.k0 & 0xff)) >>> 0, 134775813) + 1) >>> 0;
    this.k2 = crcByte(this.k2, this.k1 >>> 24);
  }
  /** Decrypts `data` into a new buffer, moving the keys along. */
  decrypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const t = (this.k2 | 2) & 0xffff;
      const p = data[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
      out[i] = p;
      this.update(p);
    }
    return out;
  }
  /** Encrypts `data` into a new buffer, moving the keys along. */
  encrypt(data: Uint8Array): Uint8Array {
    const out = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) {
      const t = (this.k2 | 2) & 0xffff;
      out[i] = data[i] ^ ((Math.imul(t, t ^ 1) >>> 8) & 0xff);
      this.update(data[i]);
    }
    return out;
  }
}

/** True when the 12-byte header decrypts with `password` to end in `check`, the byte a writer puts there. */
export function zipCryptoOpens(header: Uint8Array, password: Uint8Array, check: number): boolean {
  return new ZipCryptoKeys(password).decrypt(header)[11] === check;
}

/** The stored bytes of a traditionally encrypted entry, decrypted, without the 12-byte header. */
export async function* zipCryptoDecrypt(chunks: AsyncIterable<Uint8Array>, password: Uint8Array): AsyncGenerator<Uint8Array> {
  const keys = new ZipCryptoKeys(password);
  let header = 12;
  for await (const c of chunks) {
    const plain = keys.decrypt(c);
    if (header >= plain.length) {
      header -= plain.length;
      continue;
    }
    yield plain.subarray(header);
    header = 0;
  }
  if (header) throw new DataError('An encrypted entry is shorter than its encryption header', true);
}

/** Salt length by AES strength, as WinZip's AE-1 and AE-2 define them. */
export const AES_SALT: Record<number, number> = { 1: 8, 2: 12, 3: 16 };
const AES_BITS: Record<number, 128 | 192 | 256> = { 1: 128, 2: 192, 3: 256 };
/** The only cipher names this module hands to OpenSSL, by key size. */
const AES_ECB: Record<number, string> = { 128: 'aes-128-ecb', 192: 'aes-192-ecb', 256: 'aes-256-ecb' };
export const aesBits = (strength: number): 128 | 192 | 256 | undefined => AES_BITS[strength];

/**
 * HMAC-SHA1 with the key's two padded blocks hashed once, as RFC 2104 defines it. Each message then costs two copies
 * of the started hashes instead of a new HMAC that hashes the key again.
 */
class HmacSha1 {
  private readonly inner: crypto.Hash;
  private readonly outer: crypto.Hash;
  constructor(key: Uint8Array) {
    const k = Buffer.alloc(64);
    (key.length > 64 ? crypto.createHash('sha1').update(key).digest() : Buffer.from(key)).copy(k);
    this.inner = crypto.createHash('sha1').update(Buffer.from(k.map(b => b ^ 0x36)));
    this.outer = crypto.createHash('sha1').update(Buffer.from(k.map(b => b ^ 0x5c)));
  }
  digest(...parts: Uint8Array[]): Buffer {
    const inner = this.inner.copy();
    for (const p of parts) inner.update(p);
    return this.outer.copy().update(inner.digest()).digest();
  }
}

/** PBKDF2 with HMAC-SHA1, as RFC 8018 defines it. */
export function pbkdf2Sha1(password: Uint8Array, salt: Uint8Array, iterations: number, length: number): Buffer {
  const hmac = new HmacSha1(password);
  const blocks = Math.ceil(length / 20);
  const out = Buffer.alloc(blocks * 20);
  for (let i = 1; i <= blocks; i++) {
    const index = Buffer.alloc(4);
    index.writeUInt32BE(i);
    let u = hmac.digest(salt, index);
    const t = Buffer.from(u);
    for (let j = 1; j < iterations; j++) {
      u = hmac.digest(u);
      for (let k = 0; k < 20; k++) t[k] ^= u[k];
    }
    t.copy(out, (i - 1) * 20);
  }
  return out.subarray(0, length);
}

export interface AesKeys {
  key: Buffer;
  hmacKey: Buffer;
  verifier: Buffer;
}

/** WinZip's keys from a password and salt: 1,000 rounds of PBKDF2 with HMAC-SHA1. */
export function aesKeys(password: Uint8Array, salt: Uint8Array, bits: 128 | 192 | 256): AesKeys {
  const n = bits / 8;
  const k = pbkdf2Sha1(password, salt, 1000, n * 2 + 2);
  return { key: k.subarray(0, n), hmacKey: k.subarray(n, n * 2), verifier: k.subarray(n * 2) };
}

/** AES in counter mode with WinZip's counter, a 128-bit little-endian number that starts at 1, built on AES-ECB. */
export class AesCtr {
  private readonly counter = Buffer.alloc(16);
  private pad = Buffer.alloc(0);
  private readonly ecb: crypto.Cipher;
  constructor(key: Buffer) {
    const name = AES_ECB[key.length * 8];
    if (name === undefined) throw new Error(`No AES cipher for a ${key.length}-byte key`);
    this.ecb = crypto.createCipheriv(name, key, null);
    this.ecb.setAutoPadding(false);
  }
  private nextBlocks(count: number): Buffer {
    const blocks = Buffer.alloc(count * 16);
    for (let b = 0; b < count; b++) {
      for (let i = 0; i < 16; i++) {
        this.counter[i] = (this.counter[i] + 1) & 0xff;
        if (this.counter[i] !== 0) break;
      }
      this.counter.copy(blocks, b * 16);
    }
    return this.ecb.update(blocks);
  }
  /** XORs `data` with the key stream, which is how this mode both encrypts and decrypts. */
  apply(data: Uint8Array): Buffer {
    if (this.pad.length < data.length) this.pad = Buffer.concat([this.pad, this.nextBlocks(Math.ceil((data.length - this.pad.length) / 16))]);
    const out = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) out[i] = data[i] ^ this.pad[i];
    this.pad = this.pad.subarray(data.length);
    return out;
  }
}

/**
 * The encrypted data of an AES entry, already without its salt, verifier and authentication code, decrypted. The
 * HMAC-SHA1 of the encrypted bytes must match the first ten bytes of `mac`.
 */
export async function* aesDecrypt(chunks: AsyncIterable<Uint8Array>, keys: AesKeys, mac: Uint8Array): AsyncGenerator<Uint8Array> {
  const ctr = new AesCtr(keys.key);
  const hmac = crypto.createHmac('sha1', keys.hmacKey);
  for await (const c of chunks) {
    hmac.update(c);
    yield ctr.apply(c);
  }
  if (Buffer.compare(hmac.digest().subarray(0, 10), Buffer.from(mac)) !== 0) throw new DataError('An AES entry does not match its authentication code, so its data or the password is wrong');
}

/** True when the HMAC-SHA1 of the encrypted bytes matches `mac`, without decrypting them. */
export async function aesAuthentic(chunks: AsyncIterable<Uint8Array>, hmacKey: Buffer, mac: Uint8Array): Promise<boolean> {
  const hmac = crypto.createHmac('sha1', hmacKey);
  for await (const c of chunks) hmac.update(c);
  return Buffer.compare(hmac.digest().subarray(0, 10), Buffer.from(mac)) === 0;
}

/** The ways a password's text can become the bytes a writer used: UTF-8, and Latin-1 when that differs. */
export function passwordBytes(password: string): Uint8Array[] {
  const utf8 = Buffer.from(password, 'utf8');
  const out: Uint8Array[] = [utf8];
  if ([...password].every(ch => ch.charCodeAt(0) < 0x100)) {
    const latin1 = Buffer.from(password, 'latin1');
    if (!latin1.equals(utf8)) out.push(latin1);
  }
  return out;
}
