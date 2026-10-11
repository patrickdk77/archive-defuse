import * as stream from 'node:stream';
import * as zlib from 'node:zlib';
import { DataError } from './errors';

type ZlibStream = stream.Transform & { bytesWritten: number };

/**
 * Node's zstd streams, where the running Node has them. Node 18, Node 20 and early releases of Node 22 do not. The
 * choice is made once, when the module loads. Without them this package reads and writes no zstd data, and has no
 * code of its own for it.
 */
type ZstdFactory = (options?: { params?: Record<number, number> }) => ZlibStream;
const zstd = zlib as unknown as { createZstdDecompress?: ZstdFactory; createZstdCompress?: ZstdFactory };
export const zstdDecompressor: ZstdFactory | undefined = zstd.createZstdDecompress;
export const zstdCompressor: ZstdFactory | undefined = zstd.createZstdCompress;

/**
 * True for an error zlib, Brotli or zstd gave for corrupt or cut-short input. Their errors carry a numeric errno, and
 * an I/O error or a limit thrown on the input side keeps its own code.
 */
function isCodecError(e: unknown): boolean {
  const { code, errno } = (e ?? {}) as { code?: unknown; errno?: unknown };
  if (code === 'ERR_ZLIB_INITIALIZATION_FAILED') return true;
  return typeof code === 'string' && typeof errno === 'number' && (code.startsWith('Z_') || code.startsWith('ZSTD_') || code.startsWith('ERR_'));
}

/** How much of its input a transform has used. It grows as the transform works and ends at the total. */
export interface Consumed {
  bytes: number;
}

/**
 * Runs `chunks` through a zlib, Brotli or zstd transform and yields what comes out. A corrupt or cut-short stream
 * throws DataError. `consumed.bytes` follows the input the transform has used, which ends less than it was given when
 * its stream ends before the input does.
 */
export async function* through(transform: ZlibStream, chunks: AsyncIterable<Uint8Array>, consumed?: Consumed): AsyncGenerator<Uint8Array> {
  const src = stream.Readable.from(chunks);
  src.on('error', err => transform.destroy(err));
  src.pipe(transform);
  try {
    for await (const c of transform as AsyncIterable<Buffer>) {
      if (consumed) consumed.bytes = transform.bytesWritten;
      yield c;
    }
  } catch (err) {
    if (isCodecError(err)) throw new DataError((err as Error).message, /unexpected end/i.test((err as Error).message));
    throw err;
  } finally {
    if (consumed) consumed.bytes = transform.bytesWritten;
    src.destroy();
    transform.destroy();
  }
}

/** Raw deflate data, decoded. */
export function inflateRaw(chunks: AsyncIterable<Uint8Array>, consumed?: Consumed): AsyncGenerator<Uint8Array> {
  return through(zlib.createInflateRaw() as ZlibStream, chunks, consumed);
}

/** Bytes compressed as raw deflate, at zlib's level 6 or `level`. Level 0 writes stored blocks. */
export function deflateRaw(chunks: AsyncIterable<Uint8Array>, level = 6): AsyncGenerator<Uint8Array> {
  return through(zlib.createDeflateRaw({ level }) as ZlibStream, chunks);
}

/** Brotli data, decoded. */
export function brotliDecode(chunks: AsyncIterable<Uint8Array>, consumed?: Consumed): AsyncGenerator<Uint8Array> {
  return through(zlib.createBrotliDecompress() as ZlibStream, chunks, consumed);
}

/** Bytes compressed as one Brotli stream. */
export function brotliEncode(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
  return through(zlib.createBrotliCompress() as ZlibStream, chunks);
}

/** Yields `chunks` while counting them, and calls `each` with the running total before each one. */
export async function* counted(chunks: AsyncIterable<Uint8Array>, each: (total: number) => void): AsyncGenerator<Uint8Array> {
  let total = 0;
  for await (const c of chunks) {
    total += c.length;
    each(total);
    yield c;
  }
}

/** One chunk as an async iterable. */
export async function* once(b: Uint8Array): AsyncGenerator<Uint8Array> {
  yield b;
}

/** Every chunk, joined. Only for data the caller has already bounded. */
export async function collect(chunks: AsyncIterable<Uint8Array>): Promise<Buffer> {
  const parts: Uint8Array[] = [];
  for await (const c of chunks) parts.push(c);
  return Buffer.concat(parts);
}
