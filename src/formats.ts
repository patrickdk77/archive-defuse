import { CabArchive, isCab } from './cab';
import { StopError } from './errors';
import type { TempDir } from './io';
import { LzmaArchive, SevenZipArchive, XzArchive } from './lzma-formats';
import { detectLzmaFormat, looksLikeLzma, SEVENZIP_MAGIC, SEVENZIP_SEARCH, XZ_MAGIC } from './lzma-sniff';
import type { Archive, Entry } from './model';
import { BrotliArchive, Bzip2Archive, GzipArchive, isBzip2, isGzip, looksLikeBrotli, ZstdArchive } from './single';
import type { Limits } from './stream-meter';
import { isTar, TarArchive } from './tar';
import { type ArchiveFormat, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';
import { hasZipEnd, ZipArchive } from './zip';
import { isZstdMagic } from './zstd';

const isZipStart = (b: Uint8Array) => b.length >= 4 && b[0] === 0x50 && b[1] === 0x4b && ((b[2] === 3 && b[3] === 4) || (b[2] === 5 && b[3] === 6) || (b[2] === 7 && b[3] === 8));

const startsWith = (b: Uint8Array, bytes: number[]) => b.length >= bytes.length && bytes.every((x, i) => b[i] === x);

/** Formats with a signature that no package of the family reads. */
function otherFormat(b: Uint8Array): string | undefined {
  const s = Buffer.from(b.subarray(0, 8)).toString('latin1');
  if (s.startsWith('Rar!\x1a\x07')) return 'RAR';
  return undefined;
}

/**
 * The format the content has, from its first bytes. A file that starts with no signature of ours can still be a ZIP
 * archive with data in front, which its end record shows, or Brotli, which has no signature and is tried last.
 */
export async function detect(source: ByteSource): Promise<ArchiveFormat | undefined> {
  const size = await source.size();
  const head = await source.read(0, Math.min(1024, size));
  if (isZipStart(head)) return 'zip';
  if (startsWith(head, XZ_MAGIC)) return 'xz';
  if (startsWith(head, SEVENZIP_MAGIC)) return '7z';
  if (isGzip(head)) return 'gzip';
  if (isBzip2(head)) return 'bzip2';
  if (isZstdMagic(head)) return 'zstd';
  if (isCab(head)) return 'cab';
  if (isTar(head)) return 'tar';
  // An archive with no entries is its two end blocks, and a tar writer pads it with more zeros.
  if (size >= 1024 && size % 512 === 0 && head.every(b => b === 0)) return 'tar';
  if (otherFormat(head) !== undefined) return undefined;
  // An .lzma header has no magic, and 14 zero bytes pass liblzma's own test, so a ZIP found from its end comes first.
  if (await hasZipEnd(source)) return 'zip';
  if (looksLikeLzma(head)) return 'lzma';
  // A 7z archive after other data, such as the program of a self-extracting archive.
  if (detectLzmaFormat(await source.read(0, Math.min(size, SEVENZIP_SEARCH)))?.format === '7z') return '7z';
  if (await looksLikeBrotli(source)) return 'brotli';
  return undefined;
}

/** Opens the archive in the format `detect` found. A file in no format of ours throws the UNPARSEABLE refusal. */
export async function openArchive(source: ByteSource, limits: Limits, deadline: number | undefined, passwords: string[], temp?: { dir: TempDir; threshold: number }): Promise<Archive<Entry>> {
  const format = await detect(source);
  switch (format) {
    case 'zip': {
      const zip = await ZipArchive.open(source, limits, deadline);
      if (temp) zip.decoders = { temp: temp.dir, threshold: temp.threshold, limits };
      return zip;
    }
    case 'tar':
      return TarArchive.open(source, limits, deadline);
    case 'gzip':
      return GzipArchive.open(source);
    case 'bzip2':
      return Bzip2Archive.open(source);
    case 'zstd':
      return ZstdArchive.open(source, deadline);
    case 'brotli':
      return BrotliArchive.open(source);
    case 'cab':
      return CabArchive.open(source, limits, deadline);
    case '7z':
      return SevenZipArchive.open(source, limits, deadline, passwords);
    case 'xz':
      return XzArchive.open(source, limits);
    case 'lzma':
      return LzmaArchive.open(source, limits);
    default: {
      const other = otherFormat(await source.read(0, 8));
      const reason = other ? `a ${other} file, which this package does not read` : 'not an archive this package reads';
      throw new StopError(C.Corrupted, D.Unparseable, reason, { reason });
    }
  }
}
