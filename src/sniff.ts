// Copied from pdf-defuse src/sniff.ts. Changed: sniffType tries the signatures at the start of the file before a PDF
// header further in, as file-defuse does, and knows the archive formats and RTF. The extension table and the families
// know them too. extensionOf trims trailing dots and spaces with a loop, since /[. ]+$/ backtracks on long runs.
import { looksLikeLzma } from './lzma-sniff';
import { trimEnd } from './names';

/** The value of an octal field of a tar header: digits after any spaces, up to a space or NUL. */
function octal(b: Uint8Array, start: number, length: number): number | undefined {
  let i = start;
  const end = start + length;
  while (i < end && b[i] === 0x20) i++;
  let v = 0;
  let digits = 0;
  for (; i < end && b[i] >= 0x30 && b[i] <= 0x37; i++, digits++) v = v * 8 + (b[i] - 0x30);
  if (digits === 0) return undefined;
  for (; i < end; i++) if (b[i] !== 0x20 && b[i] !== 0) return undefined;
  return v;
}

/**
 * True when `block` is a tar header: its checksum field matches the sum of its bytes, counted unsigned or, as some old
 * writers did, signed, with the field itself counted as spaces. An all-zero block is the end of an archive, not a header.
 */
export function isTarHeader(block: Uint8Array): boolean {
  if (block.length < 512) return false;
  const stored = octal(block, 148, 8);
  if (stored === undefined) return false;
  let unsigned = 0;
  let signed = 0;
  for (let i = 0; i < 512; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : block[i];
    unsigned += b;
    signed += b > 127 ? b - 256 : b;
  }
  return unsigned !== 8 * 0x20 && (stored === unsigned || stored === signed);
}

const at = (b: Uint8Array, offset: number, bytes: number[]) => bytes.every((x, i) => b[offset + i] === x);

/** Identifies a file type from its first bytes. Returns a MIME type or undefined. */
export function sniffType(head: Uint8Array): string | undefined {
  const b = Buffer.from(head.buffer, head.byteOffset, head.byteLength);
  const s = b.subarray(0, 1024).toString('latin1');
  if (s.startsWith('%PDF-')) return 'application/pdf';
  if (b[0] === 0x50 && b[1] === 0x4b && (b[2] === 0x03 || b[2] === 0x05 || b[2] === 0x07)) return 'application/zip';
  if (b[0] === 0x1f && b[1] === 0x8b) return 'application/gzip';
  if (s.startsWith('BZh') && b[3] >= 0x31 && b[3] <= 0x39) return 'application/x-bzip2';
  if (at(b, 0, [0x28, 0xb5, 0x2f, 0xfd]) || (at(b, 1, [0x2a, 0x4d, 0x18]) && (b[0] & 0xf0) === 0x50)) return 'application/zstd';
  if (s.startsWith('MSCF\0\0\0\0')) return 'application/vnd.ms-cab-compressed';
  if (s.startsWith('{\\rt')) return 'application/rtf';
  if (at(b, 0, [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c])) return 'application/x-7z-compressed';
  if (at(b, 0, [0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00])) return 'application/x-xz';
  if (b[0] === 0x89 && s.startsWith('\x89PNG')) return 'image/png';
  if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return 'image/jpeg';
  if (s.startsWith('GIF87a') || s.startsWith('GIF89a')) return 'image/gif';
  if (b[0] === 0xd0 && b[1] === 0xcf && b[2] === 0x11 && b[3] === 0xe0) return 'application/x-ole-storage';
  if (s.startsWith('MZ')) return 'application/x-msdownload';
  if (s.startsWith('\x7fELF')) return 'application/x-executable';
  if (isTarHeader(b)) return 'application/x-tar';
  // Zeros pass the .lzma header test, and zero padding is no format.
  if (looksLikeLzma(b) && !b.subarray(0, 13).every(x => x === 0)) return 'application/x-lzma';
  // PDF readers accept the header anywhere in the first 1024 bytes.
  if (s.includes('%PDF-')) return 'application/pdf';
  const text = s.replace(/^\xef\xbb\xbf/, '').trimStart();
  if (/^<svg[\s>/]/i.test(text) || (/^<\?xml/i.test(text) && /<svg[\s>/]/i.test(s))) return 'image/svg+xml';
  if (/^<\?xml/i.test(text)) return 'application/xml';
  if (/^<!doctype html|^<html[\s>]/i.test(text)) return 'text/html';
  return undefined;
}

const EXT: Record<string, string> = {
  pdf: 'application/pdf',
  zip: 'application/zip',
  docx: 'application/zip',
  xlsx: 'application/zip',
  pptx: 'application/zip',
  odt: 'application/zip',
  ods: 'application/zip',
  odp: 'application/zip',
  epub: 'application/zip',
  jar: 'application/zip',
  png: 'image/png',
  jpg: 'image/jpeg',
  jpeg: 'image/jpeg',
  gif: 'image/gif',
  svg: 'image/svg+xml',
  xml: 'application/xml',
  html: 'text/html',
  htm: 'text/html',
  doc: 'application/x-ole-storage',
  xls: 'application/x-ole-storage',
  ppt: 'application/x-ole-storage',
  msg: 'application/x-ole-storage',
  exe: 'application/x-msdownload',
  dll: 'application/x-msdownload',
  csv: 'text/csv',
  tsv: 'text/tab-separated-values',
  tab: 'text/tab-separated-values',
  json: 'application/json',
  gz: 'application/gzip',
  tgz: 'application/gzip',
  bz2: 'application/x-bzip2',
  tbz: 'application/x-bzip2',
  tbz2: 'application/x-bzip2',
  zst: 'application/zstd',
  tzst: 'application/zstd',
  tar: 'application/x-tar',
  cab: 'application/vnd.ms-cab-compressed',
  '7z': 'application/x-7z-compressed',
  xz: 'application/x-xz',
  txz: 'application/x-xz',
  lzma: 'application/x-lzma',
  tlz: 'application/x-lzma',
  br: 'application/x-brotli',
  rtf: 'application/rtf',
};

/** Maps MIME types that share a container format, and common aliases of one type, onto one family. */
export function family(mime: string): string {
  const m = mime.toLowerCase().split(';')[0].trim();
  if (m === 'image/jpg' || m === 'image/pjpeg') return 'image/jpeg';
  if (m === 'image/x-png') return 'image/png';
  if (m === 'application/x-pdf') return 'application/pdf';
  if (
    m === 'application/zip' ||
    m === 'application/x-zip-compressed' ||
    m === 'application/x-zip' ||
    m.includes('openxmlformats') ||
    m.includes('opendocument') ||
    m === 'application/epub+zip' ||
    m === 'application/java-archive'
  )
    return 'zip';
  if (m === 'application/x-gzip' || m === 'application/gzip') return 'gzip';
  if (m === 'application/x-bzip2' || m === 'application/x-bzip') return 'bzip2';
  if (m === 'application/zstd' || m === 'application/x-zstd') return 'zstd';
  if (m === 'image/svg+xml') return 'svg';
  if (m === 'application/xml' || m === 'text/xml') return 'xml';
  if (m === 'application/msword' || m === 'application/vnd.ms-excel' || m === 'application/vnd.ms-powerpoint' || m === 'application/x-ole-storage' || m === 'application/vnd.ms-outlook') return 'ole';
  return m;
}

/**
 * A file name's extension, lowercased. Windows drops trailing dots and spaces when it saves a file, so the extension
 * of "page.html." is html.
 */
export function extensionOf(name?: string): string | undefined {
  return /\.([^./\\]+)$/.exec(trimEnd(name ?? '', '. '))?.[1].toLowerCase();
}

export function typeFromName(name?: string): string | undefined {
  const ext = extensionOf(name);
  // Only the table's own entries: "x.constructor" names no type.
  return ext !== undefined && Object.hasOwn(EXT, ext) ? EXT[ext] : undefined;
}

/** Families sniffType has a signature for. Content that claims one of them and matches no signature is not what it claims. */
const SNIFFABLE = new Set([
  'application/pdf',
  'zip',
  'image/png',
  'image/jpeg',
  'image/gif',
  'ole',
  'application/x-msdownload',
  'application/x-executable',
  'svg',
  'xml',
  'text/html',
  'gzip',
  'bzip2',
  'zstd',
  'application/x-tar',
  'application/vnd.ms-cab-compressed',
  'application/x-7z-compressed',
  'application/x-xz',
  'application/x-lzma',
]);

/**
 * True when any two of the declared type, the name's extension and the sniffed content contradict each other, or
 * when the declared type or the name claims a type sniffType recognizes and the content matched no signature.
 */
export function typesDisagree(declared: string | undefined, name: string | undefined, sniffed: string | undefined): boolean {
  const claimed = [declared, typeFromName(name)].filter((t): t is string => t !== undefined && t !== '' && family(t) !== 'application/octet-stream').map(family);
  const all = sniffed ? [...claimed, family(sniffed)] : claimed;
  const same = (a: string, b: string) => a === b || (a === 'svg' && b === 'xml') || (a === 'xml' && b === 'svg');
  if (all.some(a => all.some(b => !same(a, b)))) return true;
  return !sniffed && claimed.some(f => SNIFFABLE.has(f));
}
