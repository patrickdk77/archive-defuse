// The formats that compress one file: gzip, bzip2, zstd and Brotli. Each is an archive with one entry, whose content
// the engine hands to the file plugins like any other entry's. A gzip file can name its content, the others cannot.
import { type Bzip2Info, bunzip2, bzip2 } from './bzip2';
import { brotliDecode, brotliEncode, type Consumed, deflateRaw, inflateRaw, through, zstdDecompressor } from './codecs';
import { crc32 } from './crc32';
import { checkTime, DataError, StopError, UnsupportedError } from './errors';
import { Reader, SpillSink } from './io';
import { type Archive, contentOf, type Entry, type Kept, type Meter, type Note, nothing, sizeOf, type WriteContext, type WritePlan } from './model';
import { sniffType } from './sniff';
import { type ArchiveFormat, type ByteSink, type ByteSource, ArchiveCategory as C, ArchiveDetail as D } from './types';
import { type ZstdLayout, zstdEncode, zstdLayout } from './zstd';

/** The one entry of a compressed file. Its size is known once it has been read. */
export interface SingleEntry extends Entry {
  /** The decoded size, set when the engine has read the entry. */
  decoded?: number;
}

/** What the writer copies when the content stays as it was: the one compressed stream, header included. */
interface RawStream {
  start: number;
  length: number;
}

abstract class Single implements Archive<SingleEntry> {
  abstract readonly format: ArchiveFormat;
  readonly single = true;
  readonly lateNotes: Note[] = [];
  readonly entries: SingleEntry[];
  comment?: string;
  /** Set once the entry has been read and the stream turned out to be one stream with nothing after it. */
  protected raw?: RawStream;

  constructor(
    readonly reader: Reader,
    readonly notes: Note[],
    name = '',
  ) {
    this.entries = [{ index: 0, name, kind: 'file', size: 0, compressedSize: reader.size, notes: [] }];
  }

  async unlock(): Promise<boolean> {
    return false;
  }

  hasMetadata(): boolean {
    return false;
  }

  abstract read(e: SingleEntry, meter: Meter): AsyncGenerator<Uint8Array>;

  /** Compresses the content as one stream of the format. With `store`, a format that can store data uncompressed does. */
  protected abstract encode(chunks: AsyncIterable<Uint8Array>, plan: WritePlan<SingleEntry>, store: boolean): AsyncIterable<Uint8Array>;

  /** True when encode() can store data uncompressed. */
  protected readonly canStore: boolean = false;

  /** Notes what follows the last stream, and what it reads as. */
  protected async trailing(at: number): Promise<void> {
    const size = this.reader.size;
    if (at >= size) return;
    this.lateNotes.push({ category: C.Structure, detail: D.TrailingBytes, data: { bytes: size - at } });
    const type = sniffType(await this.reader.read(at, Math.min(1024, size - at)));
    if (type !== undefined) this.lateNotes.push({ category: C.Structure, detail: D.Polyglot, data: { type, where: 'after the compressed data' } });
  }

  /**
   * Writes the stream: the compressed bytes as they were when the content stayed as it was and was one stream, or the
   * content compressed again. Compressed data that would pass the run's ratio limit is stored instead where the
   * format can store, so the output reads under the same limit.
   */
  protected async writeStream(plan: WritePlan<SingleEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    const k = plan.kept[0];
    if (k && !k.replacement && !k.recompress && this.raw) {
      for await (const c of this.reader.chunks(this.raw.start, this.raw.length)) {
        context.meter().time();
        await sink.write(c);
      }
      return;
    }
    const size = k ? this.sizeOf(k) : 0;
    const content = () => (k ? contentOf(this, k, context) : nothing());
    const spill = new SpillSink(context.temp, context.threshold);
    try {
      for await (const c of this.encode(content(), plan, false)) await spill.write(c);
      await spill.close();
      if (this.canStore && size > 1024 * 1024 && size > spill.length * plan.ratioLimit) {
        await spill.dispose();
        for await (const c of this.encode(content(), plan, true)) await sink.write(c);
        return;
      }
      const source = spill.source();
      try {
        const length = await this.encodedLength(source, spill.length);
        for (let at = 0; at < length; at += 262144) {
          context.meter().time();
          await sink.write(await source.read(at, Math.min(262144, length - at)));
        }
      } finally {
        await source.close?.();
      }
    } finally {
      await spill.dispose();
    }
  }

  /** How much of what encode() wrote to keep. */
  protected async encodedLength(_source: ByteSource, length: number): Promise<number> {
    return length;
  }

  protected sizeOf(k: Kept<SingleEntry>): number {
    return k.replacement ? k.replacement.length : (k.entry.decoded ?? sizeOf(k));
  }

  async write(plan: WritePlan<SingleEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    await this.writeStream(plan, sink, context);
    if (plan.keepTrailing && this.trailingStart !== undefined) for await (const c of this.reader.chunks(this.trailingStart, this.reader.size - this.trailingStart)) await sink.write(c);
  }

  /** Where the data after the last stream starts, once the entry has been read. */
  protected trailingStart?: number;
}

// ---------------------------------------------------------------------------------------------------------------
// gzip

interface GzipHeader {
  flags: number;
  mtime: number;
  os: number;
  name?: string;
  comment?: string;
  /** Offset of the deflate data. */
  dataStart: number;
}

/** Reads a gzip member header at `at`. */
async function gzipHeader(reader: Reader, at: number, notes: Note[] | undefined): Promise<GzipHeader> {
  const h = await reader.read(at, 10);
  if (h.length < 10) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a gzip header', { what: 'gzip header' });
  if (h[0] !== 0x1f || h[1] !== 0x8b) throw new StopError(C.Corrupted, D.Unparseable, 'Not a gzip member', { reason: 'no gzip signature' });
  if (h[2] !== 8) throw new StopError(C.Compression, D.UnsupportedMethod, 'A gzip method other than deflate', { method: `gzip method ${h[2]}` });
  const flags = h[3];
  const view = new DataView(h.buffer, h.byteOffset, h.byteLength);
  const header: GzipHeader = { flags, mtime: view.getUint32(4, true), os: h[9], dataStart: 0 };
  if (flags & 0xe0) notes?.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'the gzip header sets reserved flags, which gzip refuses' } });
  let p = at + 10;
  const field = async (): Promise<Uint8Array> => {
    // A NUL ends the name and the comment. Neither may run past 64 KiB.
    const parts: Uint8Array[] = [];
    for (let len = 0; ; ) {
      const b = await reader.read(p, 4096);
      if (b.length === 0) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a gzip header', { what: 'gzip header' });
      const z = b.indexOf(0);
      const piece = z < 0 ? b : b.subarray(0, z);
      parts.push(piece);
      len += piece.length;
      p += piece.length;
      if (z >= 0) {
        p++;
        return Buffer.concat(parts);
      }
      if (len > 65536) throw new StopError(C.Corrupted, D.Unparseable, 'A gzip header field without an end', { reason: 'a gzip name or comment without an end' });
    }
  };
  if (flags & 0x04) {
    const x = await reader.read(p, 2);
    if (x.length < 2) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a gzip header', { what: 'gzip header' });
    const xlen = x[0] | (x[1] << 8);
    notes?.push({ category: C.Structure, detail: D.ExtraField, data: { field: 'a gzip extra field' } });
    p += 2 + xlen;
  }
  if (flags & 0x08) header.name = Buffer.from(await field()).toString('latin1');
  if (flags & 0x10) header.comment = Buffer.from(await field()).toString('latin1');
  if (flags & 0x02) {
    const stored = await reader.read(p, 2);
    if (stored.length < 2) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a gzip header', { what: 'gzip header' });
    const crc = crc32(await reader.read(at, p - at)) & 0xffff;
    if ((stored[0] | (stored[1] << 8)) !== crc) notes?.push({ category: C.Structure, detail: D.MalformedHeader, data: { reason: 'the gzip header CRC is wrong, which gzip refuses' } });
    p += 2;
  }
  if (p > reader.size) throw new StopError(C.Corrupted, D.Truncated, 'The file ends inside a gzip header', { what: 'gzip header' });
  header.dataStart = p;
  return header;
}

export class GzipArchive extends Single {
  readonly format = 'gzip';
  private constructor(
    reader: Reader,
    notes: Note[],
    readonly header: GzipHeader,
  ) {
    super(reader, notes, header.name ?? '');
    if (header.comment !== undefined) this.comment = header.comment;
  }

  override hasMetadata(): boolean {
    return this.header.mtime !== 0 || this.header.os !== 255 || this.comment !== undefined;
  }

  static async open(source: ByteSource): Promise<GzipArchive> {
    const reader = new Reader(source, await source.size());
    const notes: Note[] = [];
    const header = await gzipHeader(reader, 0, notes);
    return new GzipArchive(reader, notes, header);
  }

  async *read(e: SingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    const size = this.reader.size;
    let at = 0;
    let members = 0;
    let total = 0;
    let used = 0;
    this.lateNotes.length = 0;
    for (;;) {
      members++;
      const h = members === 1 ? this.header : await gzipHeader(this.reader, at, undefined);
      const consumed: Consumed = { bytes: 0 };
      let crc = 0;
      let length = 0;
      for await (const c of inflateRaw(this.reader.chunks(h.dataStart, size - h.dataStart), consumed)) {
        length += c.length;
        total += c.length;
        meter.add(total, used + consumed.bytes);
        crc = crc32(c, crc);
        yield c;
      }
      used += consumed.bytes;
      const trailerAt = h.dataStart + consumed.bytes;
      const t = await this.reader.read(trailerAt, 8);
      if (t.length < 8) throw new DataError('the file ends inside a gzip trailer', true);
      const view = new DataView(t.buffer, t.byteOffset, 8);
      if (view.getUint32(0, true) !== crc) throw new DataError('a gzip member does not match its CRC');
      if (view.getUint32(4, true) !== length % 2 ** 32) throw new DataError('a gzip member does not match its size');
      at = trailerAt + 8;
      if (members === 1) this.raw = { start: 0, length: at };
      const next = await this.reader.read(at, 2);
      if (next.length < 2 || next[0] !== 0x1f || next[1] !== 0x8b) break;
    }
    if (members > 1) {
      this.raw = undefined;
      this.lateNotes.push({ category: C.Structure, detail: D.MultipleStreams, data: { count: members } });
    }
    this.trailingStart = at;
    await this.trailing(at);
    e.decoded = total;
    e.size = total;
  }

  /** A member header with the name a rule fixed, and the metadata unless it is stripped. */
  private headerBytes(plan: WritePlan<SingleEntry>): Buffer {
    const k = plan.kept[0];
    const keepMeta = !plan.stripMetadata;
    const name = k?.name || undefined;
    const comment = keepMeta ? this.comment : undefined;
    const out = Buffer.alloc(10);
    out.set([0x1f, 0x8b, 8, (name !== undefined ? 0x08 : 0) | (comment !== undefined ? 0x10 : 0)]);
    out.writeUInt32LE(keepMeta ? this.header.mtime : 0, 4);
    out[8] = 0;
    out[9] = keepMeta ? this.header.os : 255;
    const field = (v: string) => Buffer.concat([Buffer.from(v.replace(/\0/g, '_'), 'latin1'), Buffer.alloc(1)]);
    return Buffer.concat([out, ...(name !== undefined ? [field(name)] : []), ...(comment !== undefined ? [field(comment)] : [])]);
  }

  protected override readonly canStore = true;

  protected async *encode(chunks: AsyncIterable<Uint8Array>, plan: WritePlan<SingleEntry>, store: boolean): AsyncGenerator<Uint8Array> {
    yield this.headerBytes(plan);
    let crc = 0;
    let length = 0;
    async function* tally(): AsyncGenerator<Uint8Array> {
      for await (const c of chunks) {
        crc = crc32(c, crc);
        length += c.length;
        yield c;
      }
    }
    yield* deflateRaw(tally(), store ? 0 : 6);
    const trailer = Buffer.alloc(8);
    trailer.writeUInt32LE(crc >>> 0, 0);
    trailer.writeUInt32LE(length % 2 ** 32, 4);
    yield trailer;
  }

  /** The header is written again, so the name a rule fixed and the metadata stripped apply also when the data is copied. */
  protected override async writeStream(plan: WritePlan<SingleEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
    const k = plan.kept[0];
    const raw = this.raw;
    if (!k || k.replacement || k.recompress || !raw) return super.writeStream(plan, sink, context);
    await sink.write(this.headerBytes(plan));
    for await (const c of this.reader.chunks(this.header.dataStart, raw.length - this.header.dataStart)) {
      context.meter().time();
      await sink.write(c);
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------
// bzip2

export class Bzip2Archive extends Single {
  readonly format = 'bzip2';
  private readonly level: number;

  private constructor(reader: Reader, level: number) {
    super(reader, []);
    this.level = level;
  }

  static async open(source: ByteSource): Promise<Bzip2Archive> {
    const reader = new Reader(source, await source.size());
    const h = await reader.read(0, 4);
    if (h.length < 4 || h[0] !== 0x42 || h[1] !== 0x5a || h[2] !== 0x68 || h[3] < 0x31 || h[3] > 0x39)
      throw new StopError(C.Corrupted, D.Unparseable, 'Not a bzip2 stream', { reason: 'no bzip2 signature' });
    return new Bzip2Archive(reader, h[3] - 0x30);
  }

  async *read(e: SingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    const info: Bzip2Info = { streams: [], trailing: 0, trailingZeros: true };
    const consumed: Consumed = { bytes: 0 };
    let total = 0;
    this.lateNotes.length = 0;
    for await (const c of bunzip2(this.reader.chunks(0, this.reader.size), info, true, consumed)) {
      total += c.length;
      meter.add(total, consumed.bytes);
      yield c;
    }
    const end = info.streams[info.streams.length - 1]?.end ?? 0;
    this.raw = info.streams.length === 1 ? { start: 0, length: end } : undefined;
    if (info.streams.length > 1) this.lateNotes.push({ category: C.Structure, detail: D.MultipleStreams, data: { count: info.streams.length } });
    this.trailingStart = end;
    await this.trailing(end);
    e.decoded = total;
    e.size = total;
  }

  protected encode(chunks: AsyncIterable<Uint8Array>): AsyncIterable<Uint8Array> {
    return bzip2(chunks, this.level);
  }
}

// ---------------------------------------------------------------------------------------------------------------
// zstd

export class ZstdArchive extends Single {
  readonly format = 'zstd';
  private constructor(
    reader: Reader,
    notes: Note[],
    readonly layout: ZstdLayout,
  ) {
    super(reader, notes);
  }

  static async open(source: ByteSource, deadline?: number): Promise<ZstdArchive> {
    const reader = new Reader(source, await source.size());
    let layout: ZstdLayout;
    try {
      layout = await zstdLayout(
        (o, n) => reader.read(o, n),
        0,
        reader.size,
        false,
        () => checkTime(deadline),
      );
    } catch (err) {
      if (err instanceof UnsupportedError) throw new StopError(C.Compression, D.UnsupportedMethod, err.message, { method: 'zstd', reason: err.message });
      if (err instanceof DataError) throw new StopError(C.Corrupted, err.truncated ? D.Truncated : D.Unparseable, err.message, err.truncated ? { what: 'zstd frame' } : { reason: err.message });
      throw err;
    }
    if (!zstdDecompressor) throw new StopError(C.Compression, D.Unavailable, 'This Node has no zstd', { method: 'zstd' });
    const notes: Note[] = [];
    const frames = layout.frames.filter(f => !f.skippable);
    const skipped = layout.frames.filter(f => f.skippable);
    if (skipped.length) notes.push({ category: C.Structure, detail: D.HiddenData, data: { bytes: skipped.reduce((s, f) => s + f.end - f.start, 0), reason: 'skippable zstd frames' } });
    if (frames.length > 1) notes.push({ category: C.Structure, detail: D.MultipleStreams, data: { count: frames.length } });
    const a = new ZstdArchive(reader, notes, layout);
    const last = layout.frames[layout.frames.length - 1];
    a.trailingStart = last?.end ?? 0;
    if (frames.length === 1 && !skipped.length) a.raw = { start: frames[0].start, length: frames[0].end - frames[0].start };
    const declared = frames.every(f => f.contentSize !== undefined) ? frames.reduce((s, f) => s + (f.contentSize ?? 0), 0) : undefined;
    if (declared !== undefined) a.entries[0].size = declared;
    return a;
  }

  async *read(e: SingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    const make = zstdDecompressor;
    if (!make) throw new StopError(C.Compression, D.Unavailable, 'This Node has no zstd', { method: 'zstd' });
    this.lateNotes.length = 0;
    let total = 0;
    let base = 0;
    for (const f of this.layout.frames) {
      if (f.skippable) continue;
      const consumed: Consumed = { bytes: 0 };
      let out = 0;
      for await (const c of through(make(), this.reader.chunks(f.start, f.end - f.start), consumed)) {
        out += c.length;
        total += c.length;
        if (f.contentSize !== undefined && out > f.contentSize) throw new DataError('a zstd frame decodes past its declared size');
        meter.add(total, base + consumed.bytes);
        yield c;
      }
      if (consumed.bytes !== f.end - f.start) throw new DataError('a zstd frame ends before its blocks do', true);
      if (f.contentSize !== undefined && out !== f.contentSize) throw new DataError('a zstd frame decodes to less than its declared size', true);
      base += f.end - f.start;
    }
    await this.trailing(this.trailingStart ?? this.reader.size);
    e.decoded = total;
    e.size = total;
  }

  protected encode(chunks: AsyncIterable<Uint8Array>): AsyncIterable<Uint8Array> {
    return zstdEncode(chunks);
  }

  /** Node's zstd stream can end with a second, empty frame after the one that holds the data, which is left out. */
  protected override async encodedLength(source: ByteSource, length: number): Promise<number> {
    const layout = await zstdLayout(
      (o, n) => source.read(o, n),
      0,
      length,
      false,
      () => undefined,
    );
    const last = layout.frames[layout.frames.length - 1];
    return layout.frames.length > 1 && last.contentSize === 0 ? last.start : length;
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Brotli

export class BrotliArchive extends Single {
  readonly format = 'brotli';

  static async open(source: ByteSource): Promise<BrotliArchive> {
    return new BrotliArchive(new Reader(source, await source.size()), []);
  }

  async *read(e: SingleEntry, meter: Meter): AsyncGenerator<Uint8Array> {
    this.lateNotes.length = 0;
    const consumed: Consumed = { bytes: 0 };
    let total = 0;
    for await (const c of brotliDecode(this.reader.chunks(0, this.reader.size), consumed)) {
      total += c.length;
      meter.add(total, consumed.bytes);
      yield c;
    }
    this.raw = { start: 0, length: consumed.bytes };
    this.trailingStart = consumed.bytes;
    await this.trailing(consumed.bytes);
    e.decoded = total;
    e.size = total;
  }

  protected encode(chunks: AsyncIterable<Uint8Array>): AsyncIterable<Uint8Array> {
    return brotliEncode(chunks);
  }
}

/**
 * True when the content decodes as one Brotli stream, which has no signature: the stream must end where the file
 * does, or decode to more than 32 MiB without an error. A prefix that merely decodes is not enough, since an
 * uncompressed meta-block can take megabytes of any bytes before the next header shows whether they are Brotli.
 */
export async function looksLikeBrotli(source: ByteSource): Promise<boolean> {
  const size = await source.size();
  if (size === 0) return false;
  const consumed: Consumed = { bytes: 0 };
  let out = 0;
  try {
    for await (const c of brotliDecode(new Reader(source, size).chunks(0, size), consumed)) {
      out += c.length;
      if (out > 32 * 1024 * 1024) return true;
    }
  } catch {
    return false;
  }
  return consumed.bytes === size;
}

export const isGzip = (b: Uint8Array) => b.length >= 3 && b[0] === 0x1f && b[1] === 0x8b && b[2] === 8;
export const isBzip2 = (b: Uint8Array) => b.length >= 4 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68 && b[3] >= 0x31 && b[3] <= 0x39;
