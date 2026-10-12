import { DEFAULT_LIMITS } from './engine';
import { checkTime, isIoError, stopsTree } from './errors';
import { type Selection, select } from './formats';
import { bufferSource } from './io';
import { typeFromName } from './sniff';
import type { ArchiveFormat, ByteSource, DetectOptions, FormatDetection } from './types';
import { ZipArchive } from './zip';

/** Each format's MIME type and extension, the names sniff.ts gives them. */
const TYPES: Record<ArchiveFormat, { mimeType: string; extension: string }> = {
  zip: { mimeType: 'application/zip', extension: 'zip' },
  tar: { mimeType: 'application/x-tar', extension: 'tar' },
  gzip: { mimeType: 'application/gzip', extension: 'gz' },
  bzip2: { mimeType: 'application/x-bzip2', extension: 'bz2' },
  zstd: { mimeType: 'application/zstd', extension: 'zst' },
  brotli: { mimeType: 'application/x-brotli', extension: 'br' },
  cab: { mimeType: 'application/vnd.ms-cab-compressed', extension: 'cab' },
  '7z': { mimeType: 'application/x-7z-compressed', extension: '7z' },
  xz: { mimeType: 'application/x-xz', extension: 'xz' },
  lzma: { mimeType: 'application/x-lzma', extension: 'lzma' },
};

/**
 * `source` without its close(), checking the deadline before every call and keeping the first error any call throws.
 * The Brotli test catches every error, so the kept one is how a failed read or the deadline still gets out.
 */
function watch(source: ByteSource, deadline: number | undefined): { source: ByteSource; failed: { error?: unknown } } {
  const failed: { error?: unknown } = {};
  const keep = async <T>(op: () => Promise<T>): Promise<T> => {
    try {
      checkTime(deadline);
      return await op();
    } catch (e) {
      failed.error ??= e;
      throw e;
    }
  };
  return { source: { size: () => keep(() => source.size()), read: (offset, length) => keep(() => source.read(offset, length)) }, failed };
}

const BROTLI_TYPES = new Set(['application/x-brotli', 'application/brotli']);
const saysBrotli = (o: DetectOptions) => typeFromName(o.name) === 'application/x-brotli' || BROTLI_TYPES.has((o.declaredType ?? '').toLowerCase().split(';')[0].trim());

/**
 * Whether archive-defuse reads `source`, and in which format: what the inspection's own format selection picks, from
 * the content alone, except that Brotli, which has no signature, counts only when the name or the declared type says
 * Brotli. A format detected only to be rejected, such as RAR, is not claimed. A ZIP archive found from its end record starts where the ZIP reader finds its first entry, or at
 * 0 when the reader cannot open it. The source stays open.
 */
export async function detectArchiveSource(source: ByteSource, options: DetectOptions = {}): Promise<FormatDetection | undefined> {
  const watched = watch(source, options.deadline);
  const pass = (e: unknown) => {
    if (watched.failed.error !== undefined) throw watched.failed.error;
    if (stopsTree(e) || isIoError(e)) throw e;
  };
  let picked: Selection | undefined;
  try {
    checkTime(options.deadline);
    picked = await select(watched.source);
    pass(undefined);
  } catch (e) {
    pass(e);
    // Any other failure, as in an inspection, means archive-defuse does not read the file.
    return undefined;
  }
  if (picked === undefined) return undefined;
  // Brotli has no signature, and a one-byte file such as "7" decodes as an empty stream. Without a name or declared
  // type that says Brotli, archive-defuse cannot know the file is one, so it does not claim it.
  if (picked.format === 'brotli' && !saysBrotli(options)) return undefined;
  let offset = picked.offset;
  if (offset === undefined) {
    try {
      offset = (await ZipArchive.open(watched.source, DEFAULT_LIMITS, options.deadline)).start;
      pass(undefined);
    } catch (e) {
      pass(e);
      // The selection picked ZIP, so the file is one, which the inspection rejects with its own finding.
      offset = 0;
    }
  }
  const found: FormatDetection = { ...TYPES[picked.format], offset };
  if (picked.heuristic !== undefined) found.heuristic = picked.heuristic;
  return found;
}

/** `detectArchiveSource` over bytes in memory. */
export function detectArchive(bytes: Uint8Array, options: DetectOptions = {}): Promise<FormatDetection | undefined> {
  return detectArchiveSource(bufferSource(bytes), options);
}
