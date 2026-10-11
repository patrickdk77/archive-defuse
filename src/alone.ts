import { DataError, StopError } from './errors';
import type { Reader } from './io';
import { decodeHeader, HEADER_SIZE, UNKNOWN_SIZE } from './lzma1/header';
import { effectiveDictSize, Lzma1Stream } from './lzma1-stream';
import type { Note } from './model';
import type { Limits, StreamCounter as Meter } from './stream-meter';
import { ArchiveCategory as C, ArchiveDetail as D } from './types';

/** What reading an .lzma file found out, beyond its content. */
export interface AloneInfo {
  notes: Note[];
  /** Offset of the first byte after the LZMA data, when the file goes on past it. */
  trailingAt?: number;
}

export interface AloneEnv {
  reader: Reader;
  size: number;
  limits: Limits;
  meter: Meter;
}

/** Bytes of input decoded per step. LZMA decodes to at most about 7,000 times its input. */
const SLICE = 1024;

/**
 * Decodes an .lzma file: a 13-byte header with the properties, the dictionary size and the decoded size or all ones
 * for unknown, then raw LZMA data. An end marker before the declared size is a size mismatch; data that goes on past
 * it, or a stream without its end marker when the size is unknown, does not decode.
 */
export async function* readAlone(env: AloneEnv, info: AloneInfo): AsyncGenerator<Uint8Array> {
  const { reader, size, meter } = env;
  const head = await reader.read(0, HEADER_SIZE);
  if (head.length < HEADER_SIZE) throw new DataError('the file ends in its header', true);
  let header: ReturnType<typeof decodeHeader>;
  try {
    header = decodeHeader(head);
  } catch (e) {
    throw new DataError(String((e as Error).message).replace(/^(Corrupted|Unsupported) input: /, ''));
  }
  const declared = header.uncompressedSize === UNKNOWN_SIZE ? undefined : header.uncompressedSize;
  if (declared !== undefined && declared > env.limits.decompressedBytes) {
    throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: env.limits.decompressedBytes, declared });
  }
  const need = effectiveDictSize(header.dictSize, declared);
  if (need > env.limits.dictionaryBytes) throw new StopError(C.Limit, D.DictionarySize, 'Dictionary size limit exceeded', { limit: env.limits.dictionaryBytes, dictionary: need });
  const out: Uint8Array[] = [];
  const stream = new Lzma1Stream(header, declared, chunk => out.push(chunk.slice()), true);
  let pos = HEADER_SIZE;
  while (!stream.done && pos < size) {
    const chunk = await reader.read(pos, 65536);
    // Once the data ends, the rest of the chunk goes to the stream for the end-marker check.
    for (let p = 0; p < chunk.length; p += SLICE) {
      if (!stream.done) meter.packed(Math.min(SLICE, chunk.length - p));
      stream.write(chunk.subarray(p, p + SLICE));
      for (const c of out.splice(0)) {
        meter.add(c.length);
        yield c;
      }
    }
    pos += chunk.length;
  }
  // The end-marker check needs a few bytes past the end of the data.
  if (stream.done && pos < size) stream.write(await reader.read(pos, 256));
  stream.end();
  for (const c of out.splice(0)) {
    meter.add(c.length);
    yield c;
  }
  if (declared !== undefined && stream.decoded < declared) {
    info.notes.push({ category: C.Structure, detail: D.SizeMismatch, data: { reason: 'an end marker comes before the declared size', declared, actual: stream.decoded } });
  }
  const end = HEADER_SIZE + stream.consumed;
  if (end < size) info.trailingAt = end;
}
