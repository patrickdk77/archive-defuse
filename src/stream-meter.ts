// Copied from lzma-defuse src/meter.ts when it merged into this package. Changed: the limits come from the engine, and
// StreamCounter is the shape the xz, lzma and 7z readers count through, so the engine's own meter can stand in.
import { checkTime, StopError } from './errors';
import { ArchiveCategory as C, ArchiveDetail as D } from './types';

/** The limits the xz, lzma and 7z readers check, with their defaults filled in. */
export interface Limits {
  entries: number;
  decompressedBytes: number;
  totalDecompressedBytes: number;
  compressionRatio: number;
  dictionaryBytes: number;
}

/** The ratio limit applies once a stream has decoded this much, so small files with long runs pass. */
const RATIO_FLOOR = 1024 * 1024;

/** What one decode has produced and the compressed bytes it took, shared by its meters. */
export interface Totals {
  decoded: number;
  compressed: number;
}

/** What a reader counts a stream through: the deadline, the compressed bytes it takes and the bytes it decodes. */
export interface StreamCounter {
  readonly decoded: number;
  readonly compressed: number;
  /** Checks the deadline. */
  tick(): void;
  packed(n: number): void;
  add(n: number): void;
}

/** Counts what one stream decodes against the limits, and checks the deadline. */
export class Meter implements StreamCounter {
  decoded = 0;
  compressed = 0;
  constructor(
    private readonly limits: Limits,
    private readonly totals: Totals,
    private readonly deadline: number | undefined,
    /** Set for a stream whose size counts against `decompressedBytes`, such as an entry; unset for a solid 7z folder. */
    private readonly single: boolean,
    private readonly location?: string,
  ) {}

  tick(): void {
    checkTime(this.deadline);
  }

  packed(n: number): void {
    this.compressed += n;
    this.totals.compressed += n;
  }

  add(n: number): void {
    this.decoded += n;
    this.totals.decoded += n;
    const loc = this.location;
    if (this.single && this.decoded > this.limits.decompressedBytes) {
      throw new StopError(C.Limit, D.DecompressedSize, 'Decompressed size limit exceeded', { limit: this.limits.decompressedBytes }, loc);
    }
    if (this.totals.decoded > this.limits.totalDecompressedBytes) {
      throw new StopError(C.Limit, D.TotalDecompressedSize, 'Total decompressed size limit exceeded', { limit: this.limits.totalDecompressedBytes }, loc);
    }
    // The ratio of the whole decode, so one long run of zeros among other files is judged with them, as a solid
    // folder is.
    const t = this.totals;
    if (t.decoded > RATIO_FLOOR && t.decoded > this.limits.compressionRatio * Math.max(1, t.compressed)) {
      throw new StopError(C.Limit, D.Ratio, 'Compression ratio limit exceeded', { limit: this.limits.compressionRatio }, loc);
    }
    checkTime(this.deadline);
  }
}
