// ZIP entries compressed with LZMA (method 14) and XZ (method 95), decoded with the LZMA code this package carries.
import type { Consumed } from './codecs';
import { lzmaError } from './coders';
import { DataError, StopError } from './errors';
import { Reader, SpillSink, type TempDir } from './io';
import { decodeProps, effectiveDictSize, Lzma1Stream } from './lzma1-stream';
import type { Meter } from './model';
import type { Limits, StreamCounter } from './stream-meter';
import { ArchiveCategory as C, ArchiveDetail as D } from './types';
import { readXz, type XzInfo } from './xz';

/** Input handed to the LZMA decoder per step, so one step decodes a bounded amount. */
const SLICE = 1024;
/** APPNOTE 5.8.8: two version bytes, a two-byte properties size, then the five bytes of LZMA properties. */
const HEADER = 9;

const concat = (a: Uint8Array, b: Uint8Array) => {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
};

/**
 * Decodes a method 14 entry: the LZMA header APPNOTE 5.8.8 gives, then raw LZMA data of the entry's size, which may
 * end with an end marker. `consumed.bytes` follows the input the data took, so the caller can see bytes after it.
 */
export async function* zipLzma(chunks: AsyncIterable<Uint8Array>, size: number, consumed: Consumed, dictionaryBytes: number): AsyncGenerator<Uint8Array> {
  const it = chunks[Symbol.asyncIterator]();
  let head: Uint8Array = new Uint8Array(0);
  try {
    while (head.length < HEADER) {
      const r = await it.next();
      if (r.done) throw new DataError('the LZMA header is cut short', true);
      head = concat(head, r.value);
    }
    const propsSize = head[2] | (head[3] << 8);
    if (propsSize !== 5) throw new DataError(`LZMA properties of ${propsSize} bytes, not 5`);
    const dict = (head[5] | (head[6] << 8) | (head[7] << 16) | (head[8] << 24)) >>> 0;
    const need = effectiveDictSize(dict, size);
    if (need > dictionaryBytes) throw new StopError(C.Limit, D.DictionarySize, 'Dictionary size limit exceeded', { limit: dictionaryBytes, dictionary: need });
    const out: Uint8Array[] = [];
    let stream: Lzma1Stream;
    try {
      stream = new Lzma1Stream(decodeProps(head[4], dict), size, c => out.push(c.slice()), true);
    } catch (e) {
      throw lzmaError(e);
    }
    let fed = HEADER;
    consumed.bytes = HEADER;
    let rest = head.subarray(HEADER);
    for (;;) {
      for (let p = 0; p < rest.length; p += SLICE) {
        const piece = rest.subarray(p, p + SLICE);
        try {
          stream.write(piece);
        } catch (e) {
          throw lzmaError(e);
        }
        fed += piece.length;
        if (!stream.done) consumed.bytes = fed;
        yield* out.splice(0);
      }
      const r = await it.next();
      if (r.done) break;
      rest = r.value;
    }
    try {
      stream.end();
    } catch (e) {
      throw lzmaError(e);
    }
    yield* out.splice(0);
    consumed.bytes = HEADER + stream.consumed;
  } finally {
    await it.return?.();
  }
}

/** The engine's meter in the shape the xz reader counts through. */
function counter(meter: Meter): StreamCounter {
  let decoded = 0;
  let compressed = 0;
  return {
    get decoded() {
      return decoded;
    },
    get compressed() {
      return compressed;
    },
    tick: () => meter.time(),
    packed: n => {
      compressed += n;
    },
    add: n => {
      decoded += n;
      meter.add(decoded, compressed);
    },
  };
}

/**
 * Decodes a method 95 entry, which holds a whole xz file. The xz reader reads by offset, so the entry's compressed
 * bytes go to memory or a temporary file first. A file that goes on past its streams, or that has notes the xz reader
 * makes, such as bad padding, does not decode: an entry is one xz file and nothing else.
 */
export async function* zipXz(chunks: AsyncIterable<Uint8Array>, consumed: Consumed, meter: Meter, temp: TempDir, threshold: number, limits: Limits): AsyncGenerator<Uint8Array> {
  const spill = new SpillSink(temp, threshold);
  try {
    for await (const c of chunks) {
      meter.time();
      await spill.write(c);
    }
    await spill.close();
    const source = spill.source();
    try {
      const info: XzInfo = { streams: 0, checks: [], notes: [] };
      yield* readXz({ reader: new Reader(source, spill.length), size: spill.length, limits, meter: counter(meter) }, info);
      const end = info.trailingAt ?? spill.length;
      consumed.bytes = end;
      // Padding between streams and a stream with no check are well formed; the entry's CRC covers the data.
      const faults = info.notes.filter(n => n.detail !== D.StreamPadding && n.detail !== D.NoCheck);
      if (faults.length) throw new DataError(`the xz data is not well formed: ${faults.map(n => `${n.category}/${n.detail}`).join(', ')}`);
    } finally {
      await source.close?.();
    }
  } finally {
    await spill.dispose();
  }
}
