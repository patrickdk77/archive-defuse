// The signatures of xz, 7z and .lzma files. Copied from lzma-defuse src/sniff.ts when it merged into this package.
import { crc32 } from './crc32';

export const XZ_MAGIC = [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00];
export const SEVENZIP_MAGIC = [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c];

const startsWith = (b: Uint8Array, at: number, bytes: number[]) => b.length >= at + bytes.length && bytes.every((x, i) => b[at + i] === x);

/**
 * True when the 13 bytes at `at` are a header liblzma's .lzma decoder takes when it has to guess the format: valid
 * properties with lc + lp at most 4, a dictionary of 2^n or 2^n + 2^(n-1) bytes, a size that is unknown or below 256
 * GiB, and a first byte of 0 in the range coder data that follows.
 */
export function looksLikeLzma(b: Uint8Array, at = 0): boolean {
  if (b.length < at + 14) return false;
  const props = b[at];
  if (props >= 9 * 5 * 5) return false;
  const lc = props % 9;
  const lp = Math.floor(props / 9) % 5;
  if (lc + lp > 4) return false;
  const view = new DataView(b.buffer, b.byteOffset + at, 13);
  const dict = view.getUint32(1, true);
  if (dict !== 0xffffffff) {
    // 2^n or 2^n + 2^(n-1): the highest set bit, plus at most the one below it.
    let d = dict - 1;
    d |= d >>> 2;
    d |= d >>> 3;
    d |= d >>> 4;
    d |= d >>> 8;
    d |= d >>> 16;
    if ((d >>> 0) + 1 !== dict && dict !== 0) return false;
  }
  const low = view.getUint32(5, true);
  const high = view.getUint32(9, true);
  if (!(low === 0xffffffff && high === 0xffffffff) && high >= 1 << 6) return false;
  return b[at + 13] === 0x00;
}

/** True when a 7z signature header sits at `at`: the signature, version 0 and a start header whose CRC matches. */
export function sevenZipHeaderAt(b: Uint8Array, at: number): boolean {
  if (!startsWith(b, at, SEVENZIP_MAGIC) || b.length < at + 32 || b[at + 6] !== 0) return false;
  const stored = new DataView(b.buffer, b.byteOffset + at + 8, 4).getUint32(0, true);
  return crc32(b.subarray(at + 12, at + 32)) === stored;
}

/** How far into a file a 7z signature header is looked for, as self-extracting archives put a program first. */
export const SEVENZIP_SEARCH = 1024 * 1024;

/**
 * The format of a file from its first bytes: xz and 7z by their signatures at the start, then .lzma by its header.
 * `head` should hold the first SEVENZIP_SEARCH bytes when a 7z archive may follow other data.
 */
export function detectLzmaFormat(head: Uint8Array): { format: 'xz' | '7z' | 'lzma'; offset: number } | undefined {
  if (startsWith(head, 0, XZ_MAGIC)) return { format: 'xz', offset: 0 };
  if (startsWith(head, 0, SEVENZIP_MAGIC)) return { format: '7z', offset: 0 };
  if (looksLikeLzma(head)) return { format: 'lzma', offset: 0 };
  // A 7z archive after other data, such as the program of a self-extracting archive.
  const limit = Math.min(head.length, SEVENZIP_SEARCH) - 32;
  for (let at = head.indexOf(0x37, 1); at >= 0 && at <= limit; at = head.indexOf(0x37, at + 1)) {
    if (sevenZipHeaderAt(head, at)) return { format: '7z', offset: at };
  }
  return undefined;
}
