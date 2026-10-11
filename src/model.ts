import type { SpillSink, TempDir } from './io';
import type { ArchiveCategory, ArchiveDetail, ArchiveFormat, ByteSink } from './types';

/** Something a reader saw, which the engine turns into a finding. */
export interface Note {
  category: ArchiveCategory;
  detail: ArchiveDetail;
  data?: Record<string, string | number>;
  location?: string;
  /** The rewrite keeps what the note reports when its rule is info, so an info override removes nothing. */
  keptOnInfo?: boolean;
}

export type EntryKind = 'file' | 'directory' | 'symlink' | 'hardlink' | 'device' | 'fifo' | 'socket' | 'other';

export type Encryption = { kind: 'zipcrypto' } | { kind: 'aes'; bits: 128 | 192 | 256 } | { kind: 'unsupported'; reason: string };

/** How an entry's bytes are compressed, as far as the engine needs to know. */
export interface Method {
  /** The format's own name or number for it, for findings. */
  name: string;
  /** False when this package has no decoder for it. */
  readable: boolean;
  /** Readable, but few readers handle it. */
  unusual: boolean;
  /** Readable by this package, but not on the running Node. */
  unavailable?: boolean;
}

/** One entry of an archive, as every format reader describes it. */
export interface Entry {
  /** Position in the archive's own order. */
  index: number;
  /** The name as the format gives it, decoded, before any rule fixes it. Folders end in "/". */
  name: string;
  kind: EntryKind;
  /** Permission bits, including setuid and setgid, when the format records them. */
  mode?: number;
  /** A link's target. A ZIP stores a symbolic link's target as its content, which the engine reads before the rules run. */
  linkTarget?: string;
  /** For an entry of a type no rule names, the format's code for it. */
  typeCode?: string;
  /** Decompressed size the headers declare. */
  size: number;
  /** Bytes the entry's data takes in the archive. */
  compressedSize: number;
  encryption?: Encryption;
  method?: Method;
  /** Why the entry's data cannot be read, when the headers already show it. The entry is removed. */
  broken?: string;
  /** Findings about this entry's headers. */
  notes: Note[];
  /** Extended attributes that grant capabilities, by name. */
  capabilities?: string[];
  /** The entry's comment, when the format has one. */
  comment?: string;
  /** A 7z anti-item, which tells an updater to delete the file of that name. */
  anti?: boolean;
}

/** What the engine decided about one entry, for the writer. */
export interface Kept<E extends Entry> {
  entry: E;
  /** The name to write, after the rules fixed it. */
  name: string;
  /** Permission bits to write. */
  mode?: number;
  /** A hard link's target as written, after the rules fixed the target's name. */
  linkTarget?: string;
  /** Bytes a plugin wrote in place of the entry's own. */
  replacement?: SpillSink;
  /** Compress the entry again with the format's common method instead of copying its compressed bytes. */
  recompress: boolean;
  /** The password that opened the entry. */
  password?: string;
  /** CRC-32 of the entry's decoded content, known once the engine has read it. */
  crc?: number;
  /** Drop the extended attributes that grant capabilities. */
  dropCapabilities: boolean;
}

export interface WritePlan<E extends Entry> {
  kept: Kept<E>[];
  stripMetadata: boolean;
  /** Write data found before the archive ahead of the rewritten one. */
  keepLeading: boolean;
  /** Write data found after the archive after the rewritten one. */
  keepTrailing: boolean;
  /** Keep header fields the rewrite would otherwise drop, such as unknown ZIP extra fields. */
  keepExtraFields: boolean;
  /** The ratio limit of the run. A writer stores data that compresses past it, so its output reads under the same limit. */
  ratioLimit: number;
}

/** Counts the bytes one entry decodes to against the limits, and checks the deadline. */
export interface Meter {
  /** Adds decoded bytes, with the compressed bytes read so far when the reader knows them. */
  add(decoded: number, compressedSoFar?: number): void;
  /** Throws once the deadline has passed. */
  time(): void;
}

/** What a writer needs from the run. */
export interface WriteContext {
  /** A meter that checks the deadline while the writer decodes entries again. */
  meter(): Meter;
  /** The run's temporary directory, for data a writer compresses before it knows the size. */
  temp: TempDir;
  /** Bytes a writer keeps in memory before it spills to a temporary file. */
  threshold: number;
}

/** An archive opened for reading, with what the engine needs to inspect it and write it again. */
export interface Archive<E extends Entry = Entry> {
  format: ArchiveFormat;
  entries: E[];
  /** True for gzip, bzip2, zstd and brotli, which hold one file. */
  single: boolean;
  /** True when the format stores no names for the entries, as a 7z archive without a names property can. */
  nameless?: boolean;
  /** Findings about the archive as a whole, known once it is open. */
  notes: Note[];
  /** Findings about the archive found while its single entry was read, such as the members of a gzip file. */
  lateNotes: Note[];
  /** The archive's own comment. */
  comment?: string;
  /** True when the archive holds metadata that stripMetadata removes: comments, owners, times or attributes. */
  hasMetadata(): boolean;
  /** True when `password` opens the encrypted entry. Only readers with encrypted entries are asked. */
  unlock(e: E, password: string): Promise<boolean>;
  /** A symbolic link's target, for a format that keeps it as the link's content. */
  linkTarget?(e: E, meter: Meter): Promise<string | undefined>;
  /** The entry's content, decrypted and decompressed, checked against its size and checksum as it goes. */
  read(e: E, meter: Meter, password?: string): AsyncGenerator<Uint8Array>;
  /** Writes the archive again with the entries in `plan`. The caller closes the sink. */
  write(plan: WritePlan<E>, sink: ByteSink, context: WriteContext): Promise<void>;
}

/** The content a writer puts in an entry: what a plugin wrote, or the entry's own bytes decoded again. */
export function contentOf<E extends Entry>(archive: Archive<E>, k: Kept<E>, context: WriteContext): AsyncIterable<Uint8Array> {
  return k.replacement ? k.replacement.read() : archive.read(k.entry, context.meter(), k.password);
}

/** No chunks, for an entry with no content. */
export async function* nothing(): AsyncGenerator<Uint8Array> {
  // An empty stream yields nothing.
}

/** The decoded size of what a writer puts in an entry. */
export const sizeOf = <E extends Entry>(k: Kept<E>) => (k.replacement ? k.replacement.length : k.entry.size);
