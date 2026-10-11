/** High-level kind of a finding. */
export enum ArchiveCategory {
  Corrupted = 'CORRUPTED',
  Structure = 'STRUCTURE',
  Name = 'NAME',
  Link = 'LINK',
  Special = 'SPECIAL',
  Permissions = 'PERMISSIONS',
  Encrypted = 'ENCRYPTED',
  Compression = 'COMPRESSION',
  Entry = 'ENTRY',
  Metadata = 'METADATA',
  Limit = 'LIMIT',
  Processing = 'PROCESSING',
}

/** Exact variant of a finding. */
export enum ArchiveDetail {
  // CORRUPTED
  Unparseable = 'UNPARSEABLE',
  Truncated = 'TRUNCATED',
  DataError = 'DATA_ERROR',
  EntryData = 'ENTRY_DATA',
  CheckFailed = 'CHECK_FAILED',
  // STRUCTURE
  LeadingBytes = 'LEADING_BYTES',
  TrailingBytes = 'TRAILING_BYTES',
  HiddenData = 'HIDDEN_DATA',
  Polyglot = 'POLYGLOT',
  SeveralEndRecords = 'SEVERAL_END_RECORDS',
  HeaderMismatch = 'HEADER_MISMATCH',
  OffsetShift = 'OFFSET_SHIFT',
  Overlap = 'OVERLAP',
  ExtraField = 'EXTRA_FIELD',
  NonFileData = 'NON_FILE_DATA',
  MultipleStreams = 'MULTIPLE_STREAMS',
  MalformedHeader = 'MALFORMED_HEADER',
  MultiVolume = 'MULTI_VOLUME',
  StreamPadding = 'STREAM_PADDING',
  BadPadding = 'BAD_PADDING',
  IndexMismatch = 'INDEX_MISMATCH',
  SizeMismatch = 'SIZE_MISMATCH',
  NoCheck = 'NO_CHECK',
  UnknownCheck = 'UNKNOWN_CHECK',
  UnknownProperty = 'UNKNOWN_PROPERTY',
  EmptyStartHeader = 'EMPTY_START_HEADER',
  // NAME
  Traversal = 'TRAVERSAL',
  Absolute = 'ABSOLUTE',
  DriveLetter = 'DRIVE_LETTER',
  Backslash = 'BACKSLASH',
  EmptySegment = 'EMPTY_SEGMENT',
  ControlCharacter = 'CONTROL_CHARACTER',
  WindowsReserved = 'WINDOWS_RESERVED',
  Encoding = 'ENCODING',
  UnicodePath = 'UNICODE_PATH',
  Empty = 'EMPTY',
  TooLong = 'TOO_LONG',
  Duplicate = 'DUPLICATE',
  CaseCollision = 'CASE_COLLISION',
  NormalizationCollision = 'NORMALIZATION_COLLISION',
  FileDirectoryClash = 'FILE_DIRECTORY_CLASH',
  ShortNameCollision = 'SHORT_NAME_COLLISION',
  // LINK
  Symlink = 'SYMLINK',
  Hardlink = 'HARDLINK',
  Outside = 'OUTSIDE',
  Dangling = 'DANGLING',
  ThroughLink = 'THROUGH_LINK',
  // SPECIAL
  Device = 'DEVICE',
  Fifo = 'FIFO',
  Socket = 'SOCKET',
  UnknownType = 'UNKNOWN_TYPE',
  AntiItem = 'ANTI_ITEM',
  // PERMISSIONS
  Setuid = 'SETUID',
  Setgid = 'SETGID',
  Sticky = 'STICKY',
  Capability = 'CAPABILITY',
  // ENCRYPTED
  ZipCrypto = 'ZIPCRYPTO',
  Aes128 = 'AES_128',
  Aes192 = 'AES_192',
  Aes256 = 'AES_256',
  Decrypted = 'DECRYPTED',
  EmptyPassword = 'EMPTY_PASSWORD',
  PasswordRequired = 'PASSWORD_REQUIRED',
  Unsupported = 'UNSUPPORTED',
  Header = 'HEADER',
  // COMPRESSION
  UnsupportedMethod = 'UNSUPPORTED_METHOD',
  UnsupportedFeature = 'UNSUPPORTED_FEATURE',
  UnusualMethod = 'UNUSUAL_METHOD',
  Unavailable = 'UNAVAILABLE',
  // ENTRY
  NoPlugin = 'NO_PLUGIN',
  TypeMismatch = 'TYPE_MISMATCH',
  PluginPassed = 'PLUGIN_PASSED',
  PluginScrubbed = 'PLUGIN_SCRUBBED',
  PluginFailed = 'PLUGIN_FAILED',
  PluginRemoved = 'PLUGIN_REMOVED',
  // METADATA
  Comment = 'COMMENT',
  Stripped = 'STRIPPED',
  // LIMIT
  FileSize = 'FILE_SIZE',
  EntryCount = 'ENTRY_COUNT',
  DecompressedSize = 'DECOMPRESSED_SIZE',
  TotalDecompressedSize = 'TOTAL_DECOMPRESSED_SIZE',
  Ratio = 'RATIO',
  DictionarySize = 'DICTIONARY_SIZE',
  NestingDepth = 'NESTING_DEPTH',
  Time = 'TIME',
  // PROCESSING
  MemoryFallback = 'MEMORY_FALLBACK',
  VerificationFailed = 'VERIFICATION_FAILED',
  ContentRemoved = 'CONTENT_REMOVED',
}

export type ArchiveFindingAction = 'reject' | 'strip' | 'info';

/**
 * A finding as any package of the defuse family reports it. Category and detail are plain strings, since the string
 * enums of two packages never match each other.
 */
export interface DefuseFinding {
  category: string;
  detail: string;
  /** Plain sentence, safe to show the uploader. */
  description: string;
  /** Default action after any caller override. */
  action: 'reject' | 'strip' | 'info';
  /** Where in the file, such as the name of an entry. */
  location?: string;
  /** Extra values: the entry name, sizes, counts, the plugin name. */
  data?: Record<string, string | number>;
  /**
   * Set when the finding comes from inside a contained file, such as a PDF inside the archive: the file's name, with
   * " > " between nesting levels. `location` then starts with where that file sits.
   */
  attachment?: string;
  /** How much the finding adds to a score, set by the package that made it. */
  weight?: number;
}

/** A finding archive-defuse makes itself. */
export interface ArchiveFinding extends DefuseFinding {
  category: ArchiveCategory;
  detail: ArchiveDetail;
}

export enum ArchiveRisk {
  None = 'NONE',
  Low = 'LOW',
  Medium = 'MEDIUM',
  High = 'HIGH',
  Critical = 'CRITICAL',
  /** The file could not be inspected: unparseable, an entry no password opens, or a limit stopped the run. */
  Unknown = 'UNKNOWN',
}

/** The formats archive-defuse reads and writes. */
export type ArchiveFormat = 'zip' | 'tar' | 'gzip' | 'bzip2' | 'zstd' | 'brotli' | 'cab' | '7z' | 'xz' | 'lzma';

export interface ArchiveInspection {
  status: 'clean' | 'strippable' | 'rejected';
  /** 0 to 100, null when risk is UNKNOWN. */
  score: number | null;
  risk: ArchiveRisk;
  findings: DefuseFinding[];
  /** The format the content was read as. Absent when it matched none. */
  format?: ArchiveFormat;
  /** Entries in the archive, or 1 for a compressed file. Absent when the archive could not be opened. */
  entries?: number;
}

export interface ArchiveDisarmResult {
  status: 'clean' | 'defused' | 'rejected';
  /** The uploaded file and its score. */
  before: ArchiveInspection;
  /** The output and its remaining score. Absent when rejected. */
  after?: ArchiveInspection;
  /** Findings whose content was removed. */
  removed: DefuseFinding[];
}

/** Random-access input. A buffer, a local file and an S3 ranged GetObject all fit. */
export interface ByteSource {
  size(): Promise<number>;
  read(offset: number, length: number): Promise<Uint8Array>;
  close?(): Promise<void>;
}

/** Append-only output. Never seeks. */
export interface ByteSink {
  write(chunk: Uint8Array): Promise<void>;
  close(): Promise<void>;
  /** Called instead of close() when copying to the sink fails, so a partial output is not taken for a whole one. */
  abort?(error: unknown): Promise<void>;
}

export interface ArchiveLimits {
  /** Bytes in the upload. Not enforced unless set. */
  fileSize?: number;
  /** Entries in the archive. Default 10,000. */
  entries?: number;
  /** Decompressed size of any one entry, declared or actual, in bytes. Default 512 MiB. */
  decompressedBytes?: number;
  /** Decompressed sizes of the entries read in one run added together, declared or actual, in bytes. Default 2 GiB. */
  totalDecompressedBytes?: number;
  /**
   * Decompressed bytes per compressed byte of one entry, checked once the entry passes 1 MiB decompressed. Default
   * 1,000.
   */
  compressionRatio?: number;
  /**
   * The deepest an archive may sit in the upload. The upload is at depth 0 and a file inside it at 1, and files of
   * every format in between count. Default 10, since an archive can hold itself.
   */
  nestingDepth?: number;
  /**
   * The dictionary memory LZMA decoding may need, in bytes: one LZMA or LZMA2 stream's dictionary, or those of all the
   * coders of one 7z folder together with their probability tables. A dictionary larger than the declared decoded size
   * counts at that size. Default 256 MiB.
   */
  dictionaryBytes?: number;
  /** Milliseconds for the whole run. Not enforced unless set. */
  timeMs?: number;
}

/** What a contained file plugin learns of the run, with nothing format-specific, so any package of the family can make one. */
export interface PluginContext {
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** When a time limit is set, the Date.now() value the whole run must finish by. Nested runs share it. */
  deadline?: number;
}

export interface ContainedFile {
  name?: string;
  /** The MIME type the container declares for the file. Archives declare none. */
  declaredType?: string;
  /** From the first bytes. */
  sniffedType?: string;
  /** Decoded size. */
  size: number;
  location: string;
  /** The depth of the file itself: 0 for the upload, 1 for a file inside it, and so on, whatever the formats. */
  depth: number;
  /** Decoded and decrypted bytes. */
  source: ByteSource;
}

/** What a file plugin did, plus anything it found inside the file. */
export interface ContainedFileResult {
  result: 'scrubbed' | 'passed' | 'removed';
  /** Findings inside the file as it arrived. They go into the report of the file that contains it. */
  findings?: DefuseFinding[];
  /** Findings inside the bytes the plugin kept. They go into the report of the output. */
  outputFindings?: DefuseFinding[];
}

export interface ContainedFilePlugin {
  kind: 'file';
  name: string;
  accepts(file: ContainedFile): boolean | Promise<boolean>;
  /** Writes the bytes to keep. Returning 'removed' drops the file after all. */
  process(file: ContainedFile, sink: ByteSink, context: PluginContext): Promise<'scrubbed' | 'passed' | 'removed' | ContainedFileResult>;
}

export interface ArchiveActionOverride {
  category: ArchiveCategory;
  detail?: ArchiveDetail;
  action: ArchiveFindingAction;
}

export interface ArchiveScoreWeight {
  category: ArchiveCategory;
  detail?: ArchiveDetail;
  weight: number;
}

/** Lower bound of each band. */
export interface ArchiveScoreBands {
  low: number;
  medium: number;
  high: number;
  critical: number;
}

export interface ArchiveOptions {
  /**
   * Passwords for encrypted entries. Each is tried in order on each encrypted entry, and the empty password after
   * them.
   */
  password?: string | string[];
  /** Limits left out take the defaults listed on ArchiveLimits. */
  limits?: ArchiveLimits;
  /** Default false. The rewrite drops comments, owner names and ids, timestamps and extended attributes. */
  stripMetadata?: boolean;
  actionOverrides?: ArchiveActionOverride[];
  scoreWeights?: ArchiveScoreWeight[];
  scoreBands?: ArchiveScoreBands;
  /** Every file entry goes to these in order. The first that accepts it decides. */
  filePlugins?: ContainedFilePlugin[];
  /** Directory for temporary files. Defaults to os.tmpdir(). */
  tempDir?: string;
  /**
   * Default 8 MiB. disarmArchiveSource keeps its copy of the upload in memory up to this size and in a temporary file
   * above it. Each entry handed to the plugins above it goes through a temporary file, and the copies plugins keep
   * share this much memory.
   */
  memoryThreshold?: number;
}
