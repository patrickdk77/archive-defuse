// The finding table and the factory, as pdf-defuse src/findings.ts has them, with archive-defuse's own kinds.
import { type ArchiveActionOverride, type ArchiveFinding, type ArchiveFindingAction, ArchiveCategory as C, ArchiveDetail as D } from './types';

interface Spec {
  action: ArchiveFindingAction;
  /**
   * May contain <key> placeholders filled from data, and <first|second> choices, which take the first alternative
   * whose {key} values are all set and not empty, or that names none. A filled value has control and format
   * characters replaced by "?", and one in a choice, such as an entry name, is cut to 60 characters.
   */
  description: string;
  weight: number;
}

const specs = new Map<string, Spec>();
function def(c: C, d: D, action: ArchiveFindingAction, weight: number, description: string): void {
  specs.set(`${c}/${d}`, { action, weight, description });
}

// CORRUPTED
def(C.Corrupted, D.Unparseable, 'reject', 0, 'Archive cannot be parsed<: {reason}|>');
def(C.Corrupted, D.Truncated, 'reject', 0, 'Archive ends before its last <{what}|entry>');
def(C.Corrupted, D.DataError, 'reject', 0, 'The compressed data does not decode<: {reason}|>');
def(C.Corrupted, D.EntryData, 'strip', 30, 'Entry removed because its data does not decode or does not match its size or checksum<: {reason}|>');
def(C.Corrupted, D.CheckFailed, 'reject', 0, 'An integrity check does not match<: {check}|>');
// STRUCTURE
def(C.Structure, D.LeadingBytes, 'strip', 10, 'Data before the start of the archive');
def(C.Structure, D.TrailingBytes, 'strip', 10, 'Data after the end of the archive');
def(C.Structure, D.HiddenData, 'strip', 20, 'Data inside the archive that belongs to no entry');
def(C.Structure, D.Polyglot, 'strip', 40, 'The file also reads as <{type}|another format>');
def(C.Structure, D.SeveralEndRecords, 'strip', 30, 'More than one end of central directory record, which readers can pick differently');
def(C.Structure, D.HeaderMismatch, 'strip', 40, 'Two headers of the archive disagree<: {what}|>');
def(C.Structure, D.OffsetShift, 'strip', 20, 'The offsets in the central directory are shifted, which some readers correct and others do not');
def(C.Structure, D.Overlap, 'strip', 50, 'Entries share bytes of the archive');
def(C.Structure, D.ExtraField, 'strip', 0, 'An entry carries <{field}|header data> that the rewrite does not keep');
def(C.Structure, D.NonFileData, 'strip', 10, 'An entry that is not a file carries data');
def(C.Structure, D.MultipleStreams, 'strip', 10, 'The file holds <count> compressed streams one after another, and some readers stop after the first');
def(C.Structure, D.MalformedHeader, 'strip', 10, 'A header is malformed<: {reason}|>');
def(C.Structure, D.MultiVolume, 'reject', 0, 'The archive is one part of a set split across several files');
def(C.Structure, D.StreamPadding, 'info', 0, 'Stream padding between or after xz streams');
def(C.Structure, D.BadPadding, 'strip', 20, 'Padding of a length or content the xz format does not allow');
def(C.Structure, D.IndexMismatch, 'strip', 30, 'The xz index disagrees with the blocks it lists<: {reason}|>');
def(C.Structure, D.SizeMismatch, 'strip', 20, 'A declared size disagrees with the data<: {reason}|>');
def(C.Structure, D.NoCheck, 'info', 0, 'The xz stream carries no integrity check, so the decoded data was not verified');
def(C.Structure, D.UnknownCheck, 'strip', 10, 'An xz integrity check of a type this package does not know, so the decoded data was not verified');
def(C.Structure, D.UnknownProperty, 'strip', 5, 'A 7z header property this package does not use<: {property}|>');
def(
  C.Structure,
  D.EmptyStartHeader,
  'strip',
  10,
  'The 7z start header is empty, as an archive whose writing did not finish leaves it. The header was found at the end of the file, where 7-Zip looks for it',
);
// NAME
def(C.Name, D.Traversal, 'strip', 70, 'An entry name climbs out of the folder it is extracted to');
def(C.Name, D.Absolute, 'strip', 60, 'An entry name is an absolute path');
def(C.Name, D.DriveLetter, 'strip', 60, 'An entry name starts with a drive letter');
def(C.Name, D.Backslash, 'strip', 20, 'An entry name holds a backslash, which Windows reads as a folder separator');
def(C.Name, D.EmptySegment, 'strip', 5, 'An entry name has empty or "." parts');
def(C.Name, D.ControlCharacter, 'strip', 40, 'An entry name holds control characters or characters that reorder text');
def(C.Name, D.WindowsReserved, 'strip', 20, 'An entry name is one Windows cannot create as written');
def(C.Name, D.Encoding, 'strip', 5, 'An entry name has no single reading in the encodings readers use');
def(C.Name, D.UnicodePath, 'strip', 30, 'The Unicode path field of an entry names a different file than its header');
def(C.Name, D.Empty, 'strip', 10, 'An entry has an empty name');
def(C.Name, D.TooLong, 'info', 10, 'An entry name is longer than file systems allow');
def(C.Name, D.Duplicate, 'strip', 40, 'Several entries have the same name, and readers keep different ones');
def(C.Name, D.CaseCollision, 'strip', 20, 'Entry names differ only in case, so they collide on file systems that ignore case');
def(C.Name, D.NormalizationCollision, 'strip', 30, 'Entry names differ only in Unicode normalization, so they collide on file systems that normalize names');
def(C.Name, D.FileDirectoryClash, 'strip', 30, 'An entry is a file or a link where other entries need a folder');
def(C.Name, D.ShortNameCollision, 'strip', 30, 'An entry name has the form of a Windows 8.3 short name that another name in its folder could get');
// LINK
def(C.Link, D.Symlink, 'info', 10, 'A symbolic link');
def(C.Link, D.Hardlink, 'info', 10, 'A hard link');
def(C.Link, D.Outside, 'strip', 70, 'A link points outside the folder the archive is extracted to');
def(C.Link, D.Dangling, 'strip', 40, 'A hard link names no entry before it, so extraction links to whatever file has that name');
def(C.Link, D.ThroughLink, 'strip', 70, 'An entry is written through a symbolic link of the archive');
// SPECIAL
def(C.Special, D.Device, 'strip', 60, 'A device file');
def(C.Special, D.Fifo, 'strip', 30, 'A named pipe');
def(C.Special, D.Socket, 'strip', 30, 'A socket');
def(C.Special, D.UnknownType, 'strip', 20, 'An entry of a type this package does not recognize');
def(C.Special, D.AntiItem, 'strip', 20, 'An entry is a 7z anti-item, which tells an updater to delete a file');
// PERMISSIONS
def(C.Permissions, D.Setuid, 'strip', 50, 'An entry has the setuid bit, which runs it as its owner');
def(C.Permissions, D.Setgid, 'strip', 40, "An entry has the setgid bit, which runs it as its group or gives a folder's group to new files");
def(C.Permissions, D.Sticky, 'strip', 10, 'An entry has the sticky bit');
def(C.Permissions, D.Capability, 'strip', 60, 'An entry carries file capabilities, which grant privileges when it runs');
// ENCRYPTED
def(C.Encrypted, D.ZipCrypto, 'info', 0, "Entry encrypted with PKWARE's traditional encryption");
def(C.Encrypted, D.Aes128, 'info', 0, 'Entry encrypted with AES and a 128-bit key');
def(C.Encrypted, D.Aes192, 'info', 0, 'Entry encrypted with AES and a 192-bit key');
def(C.Encrypted, D.Aes256, 'info', 0, 'Entry encrypted with AES and a 256-bit key');
def(C.Encrypted, D.Decrypted, 'strip', 0, 'Entry decrypted with a supplied password');
def(C.Encrypted, D.EmptyPassword, 'strip', 10, 'Entry encrypted with an empty password');
def(C.Encrypted, D.PasswordRequired, 'reject', 0, 'An entry requires a password, and none supplied opened it');
def(C.Encrypted, D.Unsupported, 'reject', 0, 'An entry uses encryption this package cannot open<: {reason}|>');
def(C.Encrypted, D.Header, 'strip', 0, 'The 7z header, which holds the names, was decrypted with a supplied password. The output does not encrypt it');
// COMPRESSION
def(C.Compression, D.UnsupportedMethod, 'reject', 0, 'An entry uses a compression method this package cannot decode<: {method}|>');
def(C.Compression, D.UnusualMethod, 'info', 10, 'An entry uses a compression method few readers handle<: {method}|>');
def(C.Compression, D.Unavailable, 'reject', 0, 'The data uses <{method}|a compression method> that this Node does not provide');
def(C.Compression, D.UnsupportedFeature, 'reject', 0, 'The file uses a feature this package cannot read<: {reason}|>');
// ENTRY
def(C.Entry, D.NoPlugin, 'strip', 30, '<Entry "{name}"|An entry> (<{sniffed}|unknown type>) removed. No plugin accepts this type');
def(
  C.Entry,
  D.TypeMismatch,
  'info',
  40,
  'The types of <entry "{name}"|an unnamed entry> disagree: <its name says {nameType}|its name has no known extension>, and <its content looks like {sniffed}|its content is not recognized>',
);
def(C.Entry, D.PluginPassed, 'info', 0, 'Entry kept by plugin <plugin> with nothing removed');
def(C.Entry, D.PluginScrubbed, 'info', 0, 'Entry cleaned and kept by plugin <plugin>');
def(C.Entry, D.PluginFailed, 'strip', 30, 'Plugin <plugin> failed, so the entry was removed');
def(C.Entry, D.PluginRemoved, 'strip', 0, 'Entry removed by plugin <plugin>');
// METADATA
def(C.Metadata, D.Comment, 'info', 0, 'The archive or an entry carries a comment');
def(C.Metadata, D.Stripped, 'info', 0, 'Metadata removed because the caller turned on metadata stripping');
// LIMIT
def(C.Limit, D.FileSize, 'reject', 0, 'Archive exceeds the file size limit');
def(C.Limit, D.EntryCount, 'reject', 0, 'Archive exceeds the entry count limit');
def(C.Limit, D.DecompressedSize, 'reject', 0, 'An entry exceeds the decompressed size limit');
def(C.Limit, D.TotalDecompressedSize, 'reject', 0, 'The entries together exceed the total decompressed size limit');
def(C.Limit, D.Ratio, 'reject', 0, 'An entry exceeds the compression ratio limit');
def(C.Limit, D.DictionarySize, 'reject', 0, 'Decoding needs more dictionary memory than the dictionary size limit allows');
def(C.Limit, D.NestingDepth, 'reject', 0, 'Archive exceeds the nesting depth limit');
def(C.Limit, D.Time, 'reject', 0, 'Archive exceeds the time limit');
// PROCESSING
def(C.Processing, D.MemoryFallback, 'info', 0, '<part> was too large for memory and went through a temporary file');
def(C.Processing, D.VerificationFailed, 'reject', 0, 'The defused output did not pass its own inspection, so nothing was written');
def(C.Processing, D.ContentRemoved, 'strip', 20, 'Content was removed that no other finding names');

/** The built-in spec for a kind of finding, or undefined for a kind archive-defuse does not make, such as one from another package. */
export function findingSpec(category: string, detail: string): Spec | undefined {
  return specs.get(`${category}/${detail}`);
}

/** The spec of a kind archive-defuse makes itself, which always has one. */
function ownSpec(category: C, detail: D): Spec {
  const s = findingSpec(category, detail);
  if (!s) throw new Error(`No finding spec for ${category}/${detail}`);
  return s;
}

export function allFindingSpecs(): Array<{ category: C; detail: D } & Spec> {
  return [...specs.entries()].map(([k, s]) => {
    const [category, detail] = k.split('/') as [C, D];
    return { category, detail, ...s };
  });
}

export class FindingFactory {
  constructor(private readonly overrides: ArchiveActionOverride[] = []) {}

  actionFor(category: C, detail: D): ArchiveFindingAction {
    const exact = this.overrides.find(o => o.category === category && o.detail === detail);
    if (exact) return exact.action;
    const byCategory = this.overrides.find(o => o.category === category && o.detail === undefined);
    if (byCategory) return byCategory.action;
    return ownSpec(category, detail).action;
  }

  /** True when findings of this kind remove what they report. */
  strips(category: C, detail: D): boolean {
    return this.actionFor(category, detail) === 'strip';
  }

  make(category: C, detail: D, location?: string, data?: Record<string, string | number>): ArchiveFinding {
    const spec = ownSpec(category, detail);
    // Values can come from the archive, so the description shows no control or direction characters from them.
    const shown = (v: string | number) => String(v).replace(/[\p{Cc}\p{Cf}]/gu, '?');
    const description = spec.description.replace(/<([^<>]*)>/g, (m, body: string) => {
      if (/^[a-z]+$/.test(body)) return data?.[body] !== undefined ? shown(data[body]) : m;
      for (const alt of body.split('|')) {
        let missing = false;
        const filled = alt.replace(/\{([a-zA-Z]+)\}/g, (_, key: string) => {
          const v = data?.[key];
          if (v === undefined || v === '') missing = true;
          const s = shown(v ?? '');
          return s.length > 60 ? `${s.slice(0, 57)}...` : s;
        });
        if (!missing) return filled;
      }
      return m;
    });
    const f: ArchiveFinding = { category, detail, description, action: this.actionFor(category, detail) };
    if (location !== undefined) f.location = location;
    if (data !== undefined && Object.keys(data).length) f.data = data;
    return f;
  }
}
