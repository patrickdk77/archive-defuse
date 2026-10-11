import * as crypto from 'node:crypto';
import { checkTime, DataError, ParseError, UnsupportedError } from './errors';

/** The properties of a 7zAES coder. */
export interface AesProps {
  /** 2^numCyclesPower rounds of SHA-256 derive the key, or 0x3F for none. */
  numCyclesPower: number;
  salt: Uint8Array;
  iv: Uint8Array;
}

/**
 * The most rounds of key derivation this package runs. A file could ask for 2^62, which no reader finishes, and 2^24
 * already takes seconds.
 */
const MAX_CYCLES_POWER = 24;

/** Reads a 7zAES coder's properties: a byte of flags and power, a byte of sizes, then the salt and the IV. */
export function parseAesProps(p: Uint8Array): AesProps {
  if (p.length < 1) throw new ParseError('7zAES properties are missing');
  const b0 = p[0];
  const numCyclesPower = b0 & 0x3f;
  if (numCyclesPower > MAX_CYCLES_POWER && numCyclesPower !== 0x3f) {
    throw new UnsupportedError(`7zAES key derivation over 2^${numCyclesPower} rounds`, false, { reason: `key derivation over 2^${numCyclesPower} rounds` });
  }
  if ((b0 & 0xc0) === 0) {
    if (p.length !== 1) throw new ParseError('7zAES properties are longer than they say');
    return { numCyclesPower, salt: new Uint8Array(0), iv: new Uint8Array(16) };
  }
  if (p.length < 2) throw new ParseError('7zAES properties are cut short');
  const b1 = p[1];
  const saltSize = ((b0 >>> 7) & 1) + (b1 >>> 4);
  const ivSize = ((b0 >>> 6) & 1) + (b1 & 0x0f);
  // The properties must hold exactly the salt and IV their sizes give.
  if (p.length !== 2 + saltSize + ivSize) throw new ParseError('7zAES properties do not match their sizes');
  const iv = new Uint8Array(16);
  iv.set(p.subarray(2 + saltSize, 2 + saltSize + ivSize));
  return { numCyclesPower, salt: p.slice(2, 2 + saltSize), iv };
}

/** The password as 7-Zip hashes it: UTF-16LE without a terminator. */
const passwordBytes = (password: string) => Buffer.from(password, 'utf16le');

/**
 * The AES-256 key 7-Zip derives from a password: SHA-256 over 2^numCyclesPower repetitions of salt, password and an
 * 8-byte little-endian round counter. Rounds go to the hash in batches, which is the same input in fewer calls.
 */
export function deriveKey(password: string, props: AesProps, deadline: number | undefined): Buffer {
  const pw = passwordBytes(password);
  if (props.numCyclesPower === 0x3f) {
    const key = Buffer.alloc(32);
    const raw = Buffer.concat([props.salt, pw]);
    raw.copy(key, 0, 0, Math.min(32, raw.length));
    return key;
  }
  if (props.numCyclesPower > MAX_CYCLES_POWER) {
    throw new UnsupportedError(`7zAES key derivation over 2^${props.numCyclesPower} rounds`, false, { reason: `key derivation over 2^${props.numCyclesPower} rounds` });
  }
  const unit = props.salt.length + pw.length + 8;
  const rounds = 2 ** props.numCyclesPower;
  const perBatch = Math.max(1, Math.min(rounds, Math.floor((1 << 20) / unit)));
  const batch = Buffer.alloc(perBatch * unit);
  for (let k = 0; k < perBatch; k++) {
    const at = k * unit;
    batch.set(props.salt, at);
    batch.set(pw, at + props.salt.length);
  }
  const hash = crypto.createHash('sha256');
  for (let done = 0; done < rounds; ) {
    checkTime(deadline);
    const n = Math.min(perBatch, rounds - done);
    for (let k = 0; k < n; k++) {
      const at = k * unit + props.salt.length + pw.length;
      const round = done + k;
      batch.writeUInt32LE(round % 0x100000000, at);
      batch.writeUInt32LE(Math.floor(round / 0x100000000), at + 4);
    }
    hash.update(batch.subarray(0, n * unit));
    done += n;
  }
  return hash.digest();
}

/** Decrypts AES-256-CBC as 7zAES uses it, with no padding: the coder's declared size cuts the last block. */
export async function* decryptAes(input: AsyncIterable<Uint8Array>, key: Buffer, iv: Uint8Array): AsyncGenerator<Uint8Array> {
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  decipher.setAutoPadding(false);
  for await (const chunk of input) {
    const out = decipher.update(chunk);
    if (out.length) yield out;
  }
  let last: Buffer;
  try {
    last = decipher.final();
  } catch {
    throw new DataError('encrypted data is not a whole number of AES blocks');
  }
  if (last.length) yield last;
}
