// Copied from office-defuse src/crc32.ts.
import * as zlib from 'node:zlib';

const TABLE = new Uint32Array(256);
for (let n = 0; n < 256; n++) {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  TABLE[n] = c >>> 0;
}

/** Continues a CRC-32, the one ZIP uses, over `bytes`, with a lookup table. Start from 0. */
export function tableCrc32(bytes: Uint8Array, crc = 0): number {
  let c = ~crc >>> 0;
  for (const b of bytes) c = TABLE[(c ^ b) & 0xff] ^ (c >>> 8);
  return ~c >>> 0;
}

/**
 * Continues a CRC-32, the one ZIP uses, over `bytes`. Start from 0. This is zlib.crc32 where Node has it, about 50
 * times faster, and the table otherwise. Node 18 and early releases of Node 20 and 22 lack it. The choice is made
 * once, when the module loads.
 */
export const crc32: (bytes: Uint8Array, crc?: number) => number = (zlib as { crc32?: (bytes: Uint8Array, crc?: number) => number }).crc32 ?? tableCrc32;
