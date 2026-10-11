/** Code page 437, the ZIP format's default for names without the UTF-8 flag: the characters for bytes 0x80 to 0xFF. */
const CP437_HIGH = [
  0x00c7, 0x00fc, 0x00e9, 0x00e2, 0x00e4, 0x00e0, 0x00e5, 0x00e7, 0x00ea, 0x00eb, 0x00e8, 0x00ef, 0x00ee, 0x00ec, 0x00c4, 0x00c5, 0x00c9, 0x00e6, 0x00c6, 0x00f4, 0x00f6, 0x00f2, 0x00fb, 0x00f9,
  0x00ff, 0x00d6, 0x00dc, 0x00a2, 0x00a3, 0x00a5, 0x20a7, 0x0192, 0x00e1, 0x00ed, 0x00f3, 0x00fa, 0x00f1, 0x00d1, 0x00aa, 0x00ba, 0x00bf, 0x2310, 0x00ac, 0x00bd, 0x00bc, 0x00a1, 0x00ab, 0x00bb,
  0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514, 0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f,
  0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c, 0x2567, 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584, 0x258c, 0x2590, 0x2580,
  0x03b1, 0x00df, 0x0393, 0x03c0, 0x03a3, 0x03c3, 0x00b5, 0x03c4, 0x03a6, 0x0398, 0x03a9, 0x03b4, 0x221e, 0x03c6, 0x03b5, 0x2229, 0x2261, 0x00b1, 0x2265, 0x2264, 0x2320, 0x2321, 0x00f7, 0x2248,
  0x00b0, 0x2219, 0x00b7, 0x221a, 0x207f, 0x00b2, 0x25a0, 0x00a0,
];

/** Bytes read as code page 437. */
export function cp437(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += String.fromCharCode(b < 0x80 ? b : CP437_HIGH[b - 0x80]);
  return s;
}

const utf8Strict = new TextDecoder('utf-8', { fatal: true });

/** Bytes read as UTF-8, or undefined when they are not valid UTF-8. */
export function utf8OrUndefined(bytes: Uint8Array): string | undefined {
  try {
    return utf8Strict.decode(bytes);
  } catch {
    return undefined;
  }
}

export const isAscii = (bytes: Uint8Array) => bytes.every(b => b < 0x80);

/** Control characters, and the characters that reorder text, which can make "exe.txt" show as "txt.exe". */
export const CONTROL = /[\p{Cc}\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/gu;

/** Names Windows gives to devices, in any case and with any extension. */
const RESERVED_DEVICE = /^(con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]|conin\$|conout\$)(\..*)?$/i;
/** Characters Windows does not allow in a name. The colon also opens an alternate data stream on NTFS. */
const RESERVED_CHARS = /[<>:"|?*]/g;

/** `s` without the characters in `chars` at its end. A loop, since a pattern such as /x+$/ backtracks on long runs. */
export function trimEnd(s: string, chars: string): string {
  let end = s.length;
  while (end > 0 && chars.includes(s[end - 1])) end--;
  return s.slice(0, end);
}

/** True when a path segment is one Windows cannot create as written. "." and ".." are other rules' business. */
export function windowsReserved(segment: string): boolean {
  if (segment === '.' || segment === '..' || segment === '') return false;
  return RESERVED_DEVICE.test(segment) || /[<>:"|?*]/.test(segment) || /[. ]$/.test(segment);
}

/** The segment as Windows can create it: reserved characters and a trailing dot or space become "_", and a device name gets "_" after it. */
export function windowsSafe(segment: string): string {
  if (!windowsReserved(segment)) return segment;
  const replaced = segment.replace(RESERVED_CHARS, '_');
  const kept = trimEnd(replaced, '. ');
  let s = kept + '_'.repeat(replaced.length - kept.length);
  if (RESERVED_DEVICE.test(s)) s = s.replace(/^([^.]*)/, '$1_');
  return s;
}
