// Reading archives and compressed files as a library: list the entries of any format this package reads and read
// their content, under the same limits the inspection uses. Nothing here applies the rules or writes files; the names
// are as the archive gives them.
import { limitsOf, makeMeter, passwordsOf } from './engine';
import { CheckError, DataError, StopError, stopsTree, UnsupportedError } from './errors';
import { openArchive as openFormat } from './formats';
import { bufferSource, TempDir } from './io';
import type { Archive, Entry, EntryKind } from './model';
import type { ArchiveFormat, ArchiveLimits, ByteSource } from './types';

/** One entry of an archive, as `openArchive` lists it. */
export interface ArchiveReaderEntry {
  /** Position in the archive's own order. */
  index: number;
  /**
   * The name as the archive gives it, decoded, with no rule applied: it can climb out with "..", be absolute or repeat
   * another entry's name. Folders end in "/". The one entry of a compressed file has the name the file stores, or "".
   */
  name: string;
  kind: EntryKind;
  /** Decoded size the headers declare, or undefined for a compressed file, whose size is known only once read. */
  size?: number;
  /** Permission bits, when the format records them. */
  mode?: number;
  /** A link's target, when the entry is a link. */
  linkTarget?: string;
  /** True when the entry is encrypted. */
  encrypted: boolean;
}

export interface OpenArchiveOptions {
  /** Folder for temporary files, which an XZ entry of a ZIP archive needs. Defaults to `os.tmpdir()`. */
  tempDir?: string;
  /** Bytes an XZ entry of a ZIP archive holds in memory before a temporary file takes over. Default 8 MiB. */
  memoryThreshold?: number;
  /** One password or a list, tried in order on each encrypted entry, then the empty password. */
  password?: string | string[];
  /** The limits of `inspectArchive`, with its defaults: every read counts toward them, and the total is shared. */
  limits?: ArchiveLimits;
}

/** An archive opened for reading. */
export interface ArchiveReader {
  format: ArchiveFormat;
  entries: ArchiveReaderEntry[];
  /** The first entry with this exact name, or undefined. */
  find(name: string): ArchiveReaderEntry | undefined;
  /** An entry's content, decrypted and decoded, checked against its size and CRC as it goes. */
  stream(entry: ArchiveReaderEntry | string): AsyncIterable<Uint8Array>;
  /** An entry's whole content. */
  bytes(entry: ArchiveReaderEntry | string): Promise<Buffer>;
  /** An entry's whole content as text, UTF-8 unless `encoding` says otherwise. */
  text(entry: ArchiveReaderEntry | string, encoding?: BufferEncoding): Promise<string>;
  /** Closes the source. */
  close(): Promise<void>;
}

/**
 * Thrown when an archive cannot be read: not a format this package reads, a limit, a missing password, or data that
 * does not decode. `category` and `detail` name the finding `inspectArchive` would report.
 */
export class ArchiveReadError extends Error {
  constructor(
    message: string,
    readonly category: string,
    readonly detail: string,
    readonly data?: Record<string, string | number>,
  ) {
    super(message);
  }
}

/** The error a reader throws for what stopped it. Time and nesting limits and I/O errors pass as they are. */
function readError(e: unknown): unknown {
  if (stopsTree(e) || e instanceof ArchiveReadError) return e;
  if (e instanceof StopError) return new ArchiveReadError(e.message, e.category, e.detail, e.data);
  if (e instanceof CheckError) return new ArchiveReadError(e.message, 'CORRUPTED', 'CHECK_FAILED', { check: e.check });
  if (e instanceof DataError) return new ArchiveReadError(e.message, 'CORRUPTED', e.truncated ? 'TRUNCATED' : 'DATA_ERROR');
  if (e instanceof UnsupportedError) return new ArchiveReadError(e.message, 'COMPRESSION', e.method ? 'UNSUPPORTED_METHOD' : 'UNSUPPORTED_FEATURE');
  return e;
}

const hasContent = (e: Entry) => e.kind === 'file' || e.kind === 'other';

/**
 * Opens an archive or a compressed file for reading. The format comes from the content, as for `inspectArchive`. The
 * entries are listed at once; content is read only when asked for. The source is closed by `close()`, or at once when
 * opening fails.
 */
export async function openArchive(input: Uint8Array | ByteSource, options: OpenArchiveOptions = {}): Promise<ArchiveReader> {
  const source = input instanceof Uint8Array ? bufferSource(input) : input;
  const limits = limitsOf({ limits: options.limits });
  const deadline = options.limits?.timeMs !== undefined ? Date.now() + options.limits.timeMs : undefined;
  const passwords = passwordsOf({ password: options.password });
  const totals = { decoded: 0 };
  const temp = new TempDir(options.tempDir);
  let archive: Archive<Entry>;
  try {
    const size = await source.size();
    if (limits.fileSize !== undefined && size > limits.fileSize) throw new ArchiveReadError('The file exceeds the file size limit', 'LIMIT', 'FILE_SIZE', { size });
    archive = await openFormat(source, limits, deadline, passwords, { dir: temp, threshold: options.memoryThreshold ?? 8 * 1024 * 1024 });
    // ZIP and 7z keep a symbolic link's target as its content.
    if (archive.linkTarget) {
      for (const e of archive.entries) {
        if (e.kind !== 'symlink' || e.broken || e.linkTarget !== undefined) continue;
        try {
          e.linkTarget = await archive.linkTarget(e, makeMeter(e, limits, deadline, totals));
        } catch (err) {
          if (!(err instanceof DataError)) throw err;
        }
      }
    }
  } catch (e) {
    await source.close?.();
    await temp.cleanup();
    throw readError(e);
  }
  const opened = archive;
  const listed: ArchiveReaderEntry[] = opened.entries.map(e => ({
    index: e.index,
    name: e.name,
    kind: e.kind,
    size: opened.single ? undefined : e.size,
    mode: e.mode,
    linkTarget: e.linkTarget,
    encrypted: e.encryption !== undefined,
  }));
  const entryOf = (which: ArchiveReaderEntry | string): Entry => {
    const listedEntry = typeof which === 'string' ? listed.find(l => l.name === which) : which;
    const e = listedEntry === undefined ? undefined : opened.entries[listedEntry.index];
    if (!e) throw new ArchiveReadError(`No entry ${JSON.stringify(typeof which === 'string' ? which : which.name)}`, 'ENTRY', 'NOT_FOUND');
    if (!hasContent(e)) throw new ArchiveReadError(`Entry ${JSON.stringify(e.name)} is a ${e.kind}, which has no content`, 'ENTRY', 'NO_CONTENT');
    return e;
  };
  /** The passwords that open an encrypted entry, in the order to try them; undefined alone for a plain one. */
  async function* keys(e: Entry): AsyncGenerator<string | undefined> {
    if (!e.encryption) {
      yield undefined;
      return;
    }
    if (e.encryption.kind === 'unsupported') throw new ArchiveReadError(`Entry ${JSON.stringify(e.name)} uses ${e.encryption.reason}`, 'ENCRYPTED', 'UNSUPPORTED');
    let any = false;
    for (const p of passwords) {
      if (await opened.unlock(e, p)) {
        any = true;
        yield p;
      }
    }
    if (!any) throw new ArchiveReadError(`No password opens entry ${JSON.stringify(e.name)}`, 'ENCRYPTED', 'PASSWORD_REQUIRED');
  }
  async function* stream(which: ArchiveReaderEntry | string): AsyncGenerator<Uint8Array> {
    const e = entryOf(which);
    if (e.broken) throw new ArchiveReadError(`Entry ${JSON.stringify(e.name)} cannot be read: ${e.broken}`, 'CORRUPTED', 'ENTRY_DATA');
    try {
      // A stream cannot take back what it gave, so it reads with the first password that opens the entry.
      for await (const password of keys(e)) {
        yield* opened.read(e, makeMeter(e, limits, deadline, totals), password);
        return;
      }
    } catch (err) {
      throw readError(err);
    }
  }
  async function bytes(which: ArchiveReaderEntry | string): Promise<Buffer> {
    const e = entryOf(which);
    if (e.broken) throw new ArchiveReadError(`Entry ${JSON.stringify(e.name)} cannot be read: ${e.broken}`, 'CORRUPTED', 'ENTRY_DATA');
    let failure: unknown;
    try {
      // A ZipCrypto header can pass for a wrong password, so a password whose data fails gives way to the next.
      for await (const password of keys(e)) {
        const meter = makeMeter(e, limits, deadline, totals);
        const parts: Uint8Array[] = [];
        try {
          for await (const c of opened.read(e, meter, password)) parts.push(c);
          return Buffer.concat(parts);
        } catch (err) {
          totals.decoded -= meter.total;
          if (!(err instanceof DataError) || e.encryption === undefined) throw err;
          failure = err;
        }
      }
    } catch (err) {
      throw readError(err);
    }
    throw readError(failure);
  }
  return {
    format: opened.format,
    entries: listed,
    find: name => listed.find(l => l.name === name),
    stream,
    bytes,
    text: async (which, encoding = 'utf8') => (await bytes(which)).toString(encoding),
    close: async () => {
      try {
        await source.close?.();
      } finally {
        await temp.cleanup();
      }
    },
  };
}

/**
 * Decodes a compressed file, such as gzip, bzip2, zstd, Brotli, xz or .lzma, to its content. An archive of several
 * entries throws; `openArchive` reads those.
 */
export async function decompress(input: Uint8Array | ByteSource, options: OpenArchiveOptions = {}): Promise<Buffer> {
  const reader = await openArchive(input, options);
  try {
    const formats: ArchiveFormat[] = ['gzip', 'bzip2', 'zstd', 'brotli', 'xz', 'lzma'];
    if (!formats.includes(reader.format)) throw new ArchiveReadError(`A ${reader.format} archive holds entries; openArchive reads them`, 'FORMAT', 'NOT_SINGLE');
    return await reader.bytes(reader.entries[0]);
  } finally {
    await reader.close();
  }
}
