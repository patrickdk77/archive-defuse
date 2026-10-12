// Copied from office-defuse src/zip-writer.ts. Changed: an entry keeps its method, times, permissions, comment and the
// extra fields the plan keeps, and either copies its compressed bytes without their encryption or is compressed again
// from the content the plan gives. Data the plan keeps before and after the archive is written around it.
import { deflateRaw } from './codecs';
import { crc32 } from './crc32';
import { SpillSink } from './io';
import { contentOf, type Kept, nothing, sizeOf, type WriteContext, type WritePlan } from './model';
import type { ByteSink } from './types';
import type { ZipArchive, ZipEntry } from './zip';

/** Extra field records that hold only times and owners. The rewrite keeps them unless metadata is stripped. */
export const METADATA_EXTRAS = new Set([0x5455, 0x000a, 0x7875, 0x5855, 0x7855]);

const MAX16 = 0xffff;
const MAX32 = 0xffffffff;
/** 1980-01-01 00:00, the earliest date a ZIP header holds, for entries whose times are stripped. */
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
/** Unix file type bits, for the attributes of an entry that has permissions. */
const TYPE_BITS: Record<string, number> = { file: 0o100000, directory: 0o040000, symlink: 0o120000 };

class Builder {
  private readonly parts: number[] = [];
  u16(v: number): this {
    this.parts.push(v & 0xff, (v >>> 8) & 0xff);
    return this;
  }
  u32(v: number): this {
    return this.u16(v & 0xffff).u16(Math.floor(v / 0x10000) & 0xffff);
  }
  u64(v: number): this {
    return this.u32(v % 0x100000000).u32(Math.floor(v / 0x100000000));
  }
  bytes(b: Uint8Array): this {
    for (const x of b) this.parts.push(x);
    return this;
  }
  build(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

/** What the headers of one written entry say. */
export interface Written {
  name: Uint8Array;
  flags: number;
  method: number;
  versionNeeded: number;
  versionMadeBy: number;
  externalAttr: number;
  internalAttr: number;
  time: number;
  date: number;
  crc: number;
  compressedSize: number;
  size: number;
  extras: Uint8Array;
  comment: Uint8Array;
}

const versionFor = (method: number) => (method === 93 || method === 14 || method === 95 ? 63 : method === 12 ? 46 : method === 9 ? 21 : 20);

/** The data of one entry and its headers, before it is written. */
interface Prepared {
  info: Written;
  chunks: () => AsyncIterable<Uint8Array>;
  /** A compressed copy to dispose of once written. */
  spill?: SpillSink;
}

/**
 * Writes the entries of a ZIP archive one after another, then its central directory. Local headers carry the CRC and
 * sizes, so no entry needs a data descriptor. ZIP64 records appear only where a size, an offset or the entry count
 * needs them.
 */
export class ZipOutput {
  private offset = 0;
  private readonly central: Uint8Array[] = [];
  constructor(private readonly sink: ByteSink) {}

  /** Writes bytes as they are, such as data kept before the archive. */
  async put(b: Uint8Array): Promise<void> {
    await this.sink.write(b);
    this.offset += b.length;
  }

  /** Writes one entry: its local header, then `chunks`, which must hold exactly `info.compressedSize` bytes. */
  async entry(info: Written, chunks: () => AsyncIterable<Uint8Array>, label: string): Promise<void> {
    const big = info.size >= MAX32 || info.compressedSize >= MAX32;
    const localOffset = this.offset;
    const local = new Builder()
      .u32(0x04034b50)
      .u16(big ? Math.max(45, info.versionNeeded) : info.versionNeeded)
      .u16(info.flags)
      .u16(info.method)
      .u16(info.time)
      .u16(info.date)
      .u32(info.crc)
      .u32(big ? MAX32 : info.compressedSize)
      .u32(big ? MAX32 : info.size)
      .u16(info.name.length)
      .u16(info.extras.length + (big ? 20 : 0))
      .bytes(info.name);
    if (big) local.u16(0x0001).u16(16).u64(info.size).u64(info.compressedSize);
    local.bytes(info.extras);
    await this.put(local.build());
    let written = 0;
    for await (const c of chunks()) {
      written += c.length;
      await this.put(c);
    }
    if (written !== info.compressedSize) throw new Error(`Entry ${label} has ${written} compressed bytes, not ${info.compressedSize}`);
    this.central.push(centralRecord(info, localOffset));
  }

  /**
   * Writes one entry whose sizes are known only once its data has gone out: a local header with the data descriptor
   * flag and no CRC or sizes, then `chunks`, the compressed data, then a data descriptor with the CRC and the sizes.
   * `totals` gives the CRC and size of the uncompressed data once `chunks` has ended.
   *
   * With `zip64`, the local header has a ZIP64 field, which tells a reader the descriptor's sizes are eight bytes. Its
   * sizes are 0xFFFFFFFF and the field's are zero, as Python's zipfile writes a streamed entry. Without it, an entry of
   * 4 GiB or more still gets eight-byte sizes in its descriptor, as archiver writes one. Either way, the central
   * directory has a ZIP64 field only when a size or the offset needs one.
   */
  async streamEntry(info: Written, chunks: AsyncIterable<Uint8Array>, totals: () => { crc: number; size: number }, zip64 = false): Promise<void> {
    const flags = info.flags | 0x0008;
    const versionNeeded = zip64 ? Math.max(45, info.versionNeeded) : info.versionNeeded;
    const localOffset = this.offset;
    const local = new Builder()
      .u32(0x04034b50)
      .u16(versionNeeded)
      .u16(flags)
      .u16(info.method)
      .u16(info.time)
      .u16(info.date)
      .u32(0)
      .u32(zip64 ? MAX32 : 0)
      .u32(zip64 ? MAX32 : 0)
      .u16(info.name.length)
      .u16(info.extras.length + (zip64 ? 20 : 0))
      .bytes(info.name);
    if (zip64) local.u16(0x0001).u16(16).u64(0).u64(0);
    local.bytes(info.extras);
    await this.put(local.build());
    let compressedSize = 0;
    for await (const c of chunks) {
      compressedSize += c.length;
      await this.put(c);
    }
    const { crc, size } = totals();
    const descriptor = new Builder().u32(0x08074b50).u32(crc);
    if (zip64 || size >= MAX32 || compressedSize >= MAX32) descriptor.u64(compressedSize).u64(size);
    else descriptor.u32(compressedSize).u32(size);
    await this.put(descriptor.build());
    this.central.push(centralRecord({ ...info, versionNeeded, flags, crc, size, compressedSize }, localOffset));
  }

  /** Writes the central directory and the end records, with the archive's comment. */
  async end(comment: Uint8Array): Promise<void> {
    const dirOffset = this.offset;
    for (const c of this.central) await this.put(c);
    const dirSize = this.offset - dirOffset;
    const count = this.central.length;
    const big = count >= MAX16 || dirOffset >= MAX32 || dirSize >= MAX32;
    if (big) {
      const end64 = this.offset;
      await this.put(new Builder().u32(0x06064b50).u64(44).u16(45).u16(45).u32(0).u32(0).u64(count).u64(count).u64(dirSize).u64(dirOffset).build());
      await this.put(new Builder().u32(0x07064b50).u32(0).u64(end64).u32(1).build());
    }
    await this.put(
      new Builder()
        .u32(0x06054b50)
        .u16(0)
        .u16(0)
        .u16(big ? MAX16 : count)
        .u16(big ? MAX16 : count)
        .u32(big ? MAX32 : dirSize)
        .u32(big ? MAX32 : dirOffset)
        .u16(comment.length)
        .bytes(comment)
        .build(),
    );
  }
}

/** The central directory record of an entry whose local header starts at `localOffset`. */
function centralRecord(info: Written, localOffset: number): Uint8Array {
  const far = localOffset >= MAX32;
  const z64 = new Builder();
  if (info.size >= MAX32) z64.u64(info.size);
  if (info.compressedSize >= MAX32) z64.u64(info.compressedSize);
  if (far) z64.u64(localOffset);
  const z64Bytes = z64.build();
  const needed = z64Bytes.length ? Math.max(45, info.versionNeeded) : info.versionNeeded;
  const c = new Builder()
    .u32(0x02014b50)
    .u16(info.versionMadeBy)
    .u16(needed)
    .u16(info.flags)
    .u16(info.method)
    .u16(info.time)
    .u16(info.date)
    .u32(info.crc)
    .u32(info.compressedSize >= MAX32 ? MAX32 : info.compressedSize)
    .u32(info.size >= MAX32 ? MAX32 : info.size)
    .u16(info.name.length)
    .u16(info.extras.length + (z64Bytes.length ? z64Bytes.length + 4 : 0))
    .u16(info.comment.length)
    .u16(0)
    .u16(info.internalAttr)
    .u32(info.externalAttr)
    .u32(far ? MAX32 : localOffset)
    .bytes(info.name);
  if (z64Bytes.length) c.u16(0x0001).u16(z64Bytes.length).bytes(z64Bytes);
  c.bytes(info.extras).bytes(info.comment);
  return c.build();
}

/** Writes `zip` again with the entries `plan` keeps. */
export async function writeZip(zip: ZipArchive, plan: WritePlan<ZipEntry>, sink: ByteSink, context: WriteContext): Promise<void> {
  const out = new ZipOutput(sink);
  if (plan.keepLeading) for await (const c of zip.leading()) await out.put(c);
  for (const k of plan.kept) {
    context.meter().time();
    const p = await prepare(zip, k, plan, context);
    try {
      await out.entry(p.info, p.chunks, k.name);
    } finally {
      await p.spill?.dispose();
    }
  }
  await out.end(plan.stripMetadata ? new Uint8Array(0) : zip.commentBytes);
  if (plan.keepTrailing) for await (const c of zip.trailing()) await out.put(c);
}

/**
 * An extended timestamp record with its flags naming only the times it holds. The rewrite writes the central
 * directory's record, which may hold the modification time alone, into the local header too, where the flags have to
 * match the times that follow.
 */
function timestampFlags(data: Uint8Array): Uint8Array {
  let count = (data.length - 1) / 4;
  let flags = 0;
  for (let bit = 1; bit <= 4 && count > 0; bit <<= 1) {
    if (data[0] & bit) {
      flags |= bit;
      count--;
    }
  }
  if (flags === data[0]) return data;
  const out = Uint8Array.from(data);
  out[0] = flags;
  return out;
}

/** The headers and data of one kept entry: its own compressed bytes without their encryption, or its content compressed again. */
async function prepare(zip: ZipArchive, k: Kept<ZipEntry>, plan: WritePlan<ZipEntry>, context: WriteContext): Promise<Prepared> {
  const e = k.entry;
  const isDir = e.kind === 'directory';
  const name = Buffer.from(isDir && !k.name.endsWith('/') ? `${k.name}/` : k.name, 'utf8');
  const comment = plan.stripMetadata || !e.comment ? Buffer.alloc(0) : Buffer.from(e.comment, 'utf8');
  const flags = /^[\x20-\x7e]*$/.test(k.name) && /^[\x20-\x7e]*$/.test(e.comment && !plan.stripMetadata ? e.comment : '') ? 0 : 0x0800;
  const extras = Buffer.concat(
    e.extras
      .filter(r => (METADATA_EXTRAS.has(r.id) ? !plan.stripMetadata && (!r.malformed || plan.keepExtraFields) : plan.keepExtraFields))
      .map(r =>
        new Builder()
          .u16(r.id)
          .u16(r.data.length)
          .bytes(r.id === 0x5455 && !r.malformed ? timestampFlags(r.data) : r.data)
          .build(),
      ),
  );
  const unix = k.mode !== undefined;
  const typeBits = TYPE_BITS[e.kind] ?? 0;
  const info: Written = {
    name,
    flags,
    method: 0,
    versionNeeded: 20,
    versionMadeBy: unix ? (3 << 8) | 30 : 20,
    externalAttr: unix ? (((typeBits | (k.mode ?? 0)) << 16) >>> 0) | (isDir ? 0x10 : 0) : (e.externalAttr & 0xff & ~0x10) | (isDir ? 0x10 : 0),
    internalAttr: e.internalAttr,
    time: plan.stripMetadata ? 0 : e.dosTime,
    date: plan.stripMetadata ? DOS_DATE : e.dosDate,
    crc: 0,
    compressedSize: 0,
    size: 0,
    extras,
    comment,
  };
  if (isDir) return { info, chunks: nothing };
  if (!k.replacement && !k.recompress) {
    // The compressed bytes are copied, without any encryption they had.
    info.method = e.methodCode;
    info.versionNeeded = versionFor(e.methodCode);
    info.crc = k.crc ?? e.crc;
    info.size = e.size;
    info.compressedSize = zip.plainLength(e);
    return { info, chunks: () => zip.plain(e, k.password) };
  }
  // Compressed again: deflate, or stored when deflate gains nothing or would pass the run's ratio limit.
  const size = sizeOf(k);
  let crc = 0;
  async function* withCrc(chunks: AsyncIterable<Uint8Array>): AsyncGenerator<Uint8Array> {
    for await (const c of chunks) {
      context.meter().time();
      crc = crc32(c, crc);
      yield c;
    }
  }
  const spill = new SpillSink(context.temp, context.threshold);
  try {
    for await (const c of deflateRaw(withCrc(contentOf(zip, k, context)))) await spill.write(c);
    await spill.close();
  } catch (err) {
    await spill.dispose();
    throw err;
  }
  info.crc = crc;
  info.size = size;
  const passesRatio = size <= 1024 * 1024 || size <= spill.length * plan.ratioLimit;
  if (size > 0 && spill.length < size && passesRatio) {
    info.method = 8;
    info.compressedSize = spill.length;
    return { info, chunks: () => spill.read(), spill };
  }
  await spill.dispose();
  info.compressedSize = size;
  return { info, chunks: () => contentOf(zip, k, context) };
}
