import * as crypto from 'node:crypto';
import { crc32 } from './crc32';

// CRC-64 with the ECMA-182 polynomial, reflected, as xz uses it. Node has no CRC-64, so this table is the only one.
const POLY_HI = 0xc96c5795;
const POLY_LO = 0xd7870f42;
const TABLE_HI = new Uint32Array(256);
const TABLE_LO = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let lo = n;
  let hi = 0;
  for (let k = 0; k < 8; k++) {
    const carry = lo & 1;
    lo = ((lo >>> 1) | (hi << 31)) >>> 0;
    hi >>>= 1;
    if (carry) {
      lo = (lo ^ POLY_LO) >>> 0;
      hi = (hi ^ POLY_HI) >>> 0;
    }
  }
  TABLE_HI[n] = hi;
  TABLE_LO[n] = lo;
}

/** A running CRC-64 as xz computes it. */
export class Crc64 {
  private hi = 0xffffffff;
  private lo = 0xffffffff;

  update(bytes: Uint8Array): void {
    let hi = this.hi;
    let lo = this.lo;
    for (const b of bytes) {
      const i = (lo ^ b) & 0xff;
      lo = (((lo >>> 8) | (hi << 24)) ^ TABLE_LO[i]) >>> 0;
      hi = ((hi >>> 8) ^ TABLE_HI[i]) >>> 0;
    }
    this.hi = hi;
    this.lo = lo;
  }

  /** The 8 bytes, little-endian, as xz stores them. */
  digest(): Uint8Array {
    const out = Buffer.alloc(8);
    out.writeUInt32LE(~this.lo >>> 0, 0);
    out.writeUInt32LE(~this.hi >>> 0, 4);
    return out;
  }
}

/** The integrity check of an xz block, by check ID. */
export interface Check {
  update(bytes: Uint8Array): void;
  /** The bytes as the block stores them. */
  digest(): Uint8Array;
}

/** xz check IDs this package computes. */
export const CHECK_NONE = 0x00;
export const CHECK_CRC32 = 0x01;
export const CHECK_CRC64 = 0x04;
export const CHECK_SHA256 = 0x0a;

/** Size in bytes of each xz check ID, including the ones reserved for future use. */
const CHECK_SIZES = [0, 4, 4, 4, 8, 8, 8, 16, 16, 16, 32, 32, 32, 64, 64, 64];

export function checkSize(id: number): number {
  return CHECK_SIZES[id & 0x0f];
}

export function checkName(id: number): string {
  return id === CHECK_NONE ? 'none' : id === CHECK_CRC32 ? 'CRC32' : id === CHECK_CRC64 ? 'CRC64' : id === CHECK_SHA256 ? 'SHA-256' : `check ID ${id}`;
}

/** A check of a known ID, or undefined for an ID this package cannot compute. */
export function makeCheck(id: number): Check | undefined {
  if (id === CHECK_NONE) return { update: () => undefined, digest: () => new Uint8Array(0) };
  if (id === CHECK_CRC32) {
    let c = 0;
    return {
      update: b => {
        c = crc32(b, c);
      },
      digest: () => {
        const out = Buffer.alloc(4);
        out.writeUInt32LE(c, 0);
        return out;
      },
    };
  }
  if (id === CHECK_CRC64) return new Crc64();
  if (id === CHECK_SHA256) {
    const h = crypto.createHash('sha256');
    return { update: b => h.update(b), digest: () => h.digest() };
  }
  return undefined;
}
