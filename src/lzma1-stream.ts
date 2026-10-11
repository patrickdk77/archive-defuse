import { DataError } from './errors';
import { LzDecoder } from './lzma1/lz-decoder';
import { LzmaDecoder } from './lzma1/lzma-decoder';
import { RANGE_DECODER_INIT_SIZE, RangeDecoder } from './lzma1/range-decoder';

/**
 * Upper bound of input bytes a single LZMA symbol can consume, as lzma1's alone-decoder.ts defines it. Decoding pauses
 * while fewer are left, so a symbol never runs out of input halfway.
 */
const INPUT_MARGIN = 64;
const DICT_SIZE_MIN = 1 << 12;
/** Bytes after the end of the data kept for the end-marker probe. The marker and the range coder flush fit in 16. */
const PROBE_KEEP = 256;

export interface Lzma1Props {
  lc: number;
  lp: number;
  pb: number;
  dictSize: number;
}

/** Splits the properties byte of an LZMA header or 7z coder: (pb * 5 + lp) * 9 + lc. */
export function decodeProps(byte: number, dictSize: number): Lzma1Props {
  if (byte >= 9 * 5 * 5) throw new DataError('invalid LZMA properties');
  return { lc: byte % 9, lp: Math.floor(byte / 9) % 5, pb: Math.floor(byte / 45), dictSize };
}

/** The dictionary a stream allocates at most: what the properties say, but no more than the data when its size is known. */
export function effectiveDictSize(dictSize: number, size: number | undefined): number {
  const d = Math.max(dictSize, DICT_SIZE_MIN);
  return size === undefined ? d : Math.max(Math.min(d, size), 1);
}

/**
 * Decodes raw LZMA1 data that arrives in pieces, built from lzma1's decoder like its AloneDecoder, with what this
 * package needs to judge the end of the data: where it ended, whether an end marker ended it, and what follows.
 *
 * With a known size, decoding stops after that many bytes. `probe` then checks what the range coder holds next: a
 * finished coder ends the data, an end marker may follow, and anything else means the data goes on past the size.
 * Without a known size the data must end with an end marker.
 */
export class Lzma1Stream {
  private readonly lz: LzDecoder;
  private readonly lzma: LzmaDecoder;
  private readonly rc = new RangeDecoder();
  private readonly size: number | undefined;
  private readonly probe: boolean;
  private pending: Uint8Array = new Uint8Array(0);
  /** Input offset of pending[0]. */
  private base = 0;
  private rcStarted = false;
  /** Bytes decoded after the end are no longer passed on, which the end-marker probe relies on. */
  private sealed = false;
  /** Bytes after the end, the first PROBE_KEEP of them. */
  private after: Uint8Array = new Uint8Array(0);
  /** Set once the data has ended. */
  done = false;
  /** An end marker ended the data. */
  endMarker = false;
  /** Input bytes the data took, once done. */
  consumed = 0;
  /** Input bytes after the end of the data. */
  trailing = 0;

  /**
   * @param size Decoded size, or undefined when an end marker ends the data
   * @param sink Receives decoded bytes. The chunk is only valid during the call.
   * @param probe Look past a known size for an end marker or more data, as for an .lzma file
   */
  constructor(props: Lzma1Props, size: number | undefined, sink: (chunk: Uint8Array) => void, probe: boolean) {
    this.size = size;
    this.probe = probe;
    this.lz = new LzDecoder(effectiveDictSize(props.dictSize, size), chunk => {
      if (!this.sealed) sink(chunk);
    });
    this.lzma = new LzmaDecoder(this.lz, this.rc, props.lc, props.lp, props.pb);
  }

  /** Bytes decoded so far. */
  get decoded(): number {
    return this.lzma.outPos;
  }

  /** Decodes as much of `chunk` as possible. */
  write(chunk: Uint8Array): void {
    if (this.done) {
      this.keepAfter(chunk);
      return;
    }
    this.decode(concat(this.pending, chunk), false);
  }

  /** Decodes the rest. Throws when the data is incomplete or goes on past its declared size. */
  end(): void {
    if (!this.done) this.decode(this.pending, true);
    if (!this.done) throw new DataError('the data ends before its end', true);
    if (this.needsProbe) this.runProbe();
  }

  private needsProbe = false;

  private keepAfter(chunk: Uint8Array): void {
    this.trailing += chunk.length;
    if (this.after.length < PROBE_KEEP) this.after = concat(this.after, chunk.subarray(0, PROBE_KEEP - this.after.length));
  }

  private decode(input: Uint8Array, isLast: boolean): void {
    const rc = this.rc;
    if (!this.rcStarted) {
      if (input.length < RANGE_DECODER_INIT_SIZE) {
        // An empty stream of known size 0 may hold nothing at all.
        if (isLast && this.size === 0 && input.length === 0) {
          this.finish(input, 0, false);
          return;
        }
        if (isLast) throw new DataError('the data ends before its end', true);
        this.pending = input.slice();
        return;
      }
      try {
        rc.init(input, 0);
      } catch (e) {
        throw new DataError(String((e as Error).message).replace(/^Corrupted input: /, ''));
      }
      this.rcStarted = true;
    } else rc.setInput(input, 0);
    const outLimit = this.size ?? Number.POSITIVE_INFINITY;
    const inLimit = isLast ? Number.POSITIVE_INFINITY : input.length - INPUT_MARGIN;
    let endMarker: boolean;
    try {
      endMarker = this.size === 0 ? false : this.lzma.decode(outLimit, inLimit);
    } catch (e) {
      throw asDataError(e);
    }
    this.lz.flush();
    if (endMarker) {
      if (!rc.isFinished()) throw new DataError('invalid end marker');
      this.finish(input, rc.pos, true);
    } else if (this.lzma.outPos === this.size) {
      this.finish(input, rc.pos, false);
    } else {
      this.base += rc.pos;
      this.pending = input.slice(rc.pos);
    }
  }

  private finish(input: Uint8Array, pos: number, endMarker: boolean): void {
    this.done = true;
    this.sealed = true;
    this.endMarker = endMarker;
    this.consumed = this.base + pos;
    this.pending = new Uint8Array(0);
    this.keepAfter(input.subarray(pos));
    // The data ended at its size. A finished range coder ends it cleanly; otherwise an end marker or more data follows.
    this.needsProbe = !endMarker && this.probe && this.rcStarted && !this.rc.isFinished();
  }

  /** Decodes one more symbol, which must be the end marker. */
  private runProbe(): void {
    this.needsProbe = false;
    const rc = this.rc;
    const after = this.after;
    rc.setInput(after, 0);
    let marker = false;
    try {
      marker = this.lzma.decode((this.size ?? 0) + 1, Number.POSITIVE_INFINITY);
    } catch {
      marker = false;
    }
    if (!marker || !rc.isFinished()) throw new DataError('the data goes on past its declared size');
    this.endMarker = true;
    this.consumed += rc.pos;
    this.trailing -= rc.pos;
  }
}

/** The decoder's errors as data errors, with lzma1's prefix taken off. */
function asDataError(e: unknown): DataError {
  if (e instanceof DataError) return e;
  const message = String((e as Error)?.message ?? e);
  if (message === 'Truncated input') return new DataError('the data ends before its end', true);
  if (/declared size/.test(message)) return new DataError('the data goes on past its declared size');
  // An error from the sink, such as a limit, is not about the data.
  if (!/^Corrupted input/.test(message)) throw e;
  return new DataError(message.replace(/^Corrupted input: /, ''));
}

export function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  if (a.length === 0) return b;
  if (b.length === 0) return a;
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
