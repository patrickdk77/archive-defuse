# archive-defuse

Inspect and defuse ZIP, tar, gzip, bzip2, zstd, Brotli, cabinet, 7z, xz and .lzma files. archive-defuse reads the archive with its own parser, reports names that leave the extraction folder, links out of the tree, device files, colliding names, data hidden around or between entries, headers that two readers would read differently, encrypted entries and compression bombs, and scores the risk from 0 to 100. It hands every file inside the archive to file plugins, and writes a defused archive in the same format. It also makes and reads archives as a library, in place of archiver or adm-zip, as [Making and reading archives](#making-and-reading-archives) shows. It has no runtime dependencies.

```
npm install @patrickdk77/archive-defuse
```

Node 18 or later. zstd needs a Node that has it in zlib (22.15, 23.8 or later).

## Quick start

```js
const { inspectArchive, disarmArchive, passThrough } = require('@patrickdk77/archive-defuse');

const report = await inspectArchive(bytes, { filePlugins: [passThrough(['txt', 'csv'])] });
report.status;   // 'clean', 'strippable' or 'rejected'
report.risk;     // 'NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL' or 'UNKNOWN'
report.score;    // 0 to 100, null when the archive could not be inspected
report.format;   // 'zip', 'tar', 'gzip', 'bzip2', 'zstd', 'brotli', 'cab', '7z', 'xz' or 'lzma'
report.findings; // [{ category, detail, description, action, location, data, attachment }]

const result = await disarmArchive(bytes, { filePlugins: [passThrough(['txt', 'csv'])] });
if (result.status !== 'rejected') save(result.bytes);
```

Every file inside the archive goes to the file plugins. An entry no plugin accepts is removed, which is what pdf-defuse does with an attached file no plugin takes. With no plugins at all, the defused archive keeps its folders and links and drops every file. [The defuse family](#the-defuse-family) shows the router that hands each entry to the package for its format.

ES modules work too: `import { disarmArchive } from '@patrickdk77/archive-defuse'`.

### Files and S3

`inspectArchiveSource(source, options)` and `disarmArchiveSource(source, sink, options)` take a source with `size()` and `read(offset, length)` and a sink with `write(chunk)` and `close()`, the shapes pdf-defuse uses. `bufferSource`, `bufferSink`, `fileSource`, `fileSink` and `writableSink` are exported. pdf-defuse's README shows a source and sink over S3.

Both functions close the source when the run ends. `disarmArchiveSource` copies the upload once, to memory up to `memoryThreshold` and to a temporary file above it, and reads only that copy. Nothing reaches the sink unless the rewritten archive passes its own inspection. A rejected archive leaves the sink untouched, and a failed copy calls the sink's `abort()`.

## Formats

The first bytes decide the format, never the name.

| Format | Reads | Writes |
|---|---|---|
| ZIP and ZIPX | stored, deflate, Deflate64 (method 9), bzip2 (method 12), LZMA (method 14), zstd (method 93) and XZ (method 95) entries; ZIP64; data descriptors; ZipCrypto and WinZip AES entries | stored and deflate entries, and Deflate64, bzip2, LZMA, zstd and XZ entries copied as they are |
| tar | v7, ustar, star, GNU long names and links, GNU old sparse files, pax extended and global headers, pax sparse files 0.0, 0.1 and 1.0, base-256 numbers | ustar headers, with pax records for what they cannot hold |
| gzip | one or more members | one member |
| bzip2 | one or more streams, randomised blocks included | one stream |
| zstd | frames and skippable frames | one frame |
| Brotli | one stream | one stream |
| cabinet | stored and MSZIP folders | stored and MSZIP folders |
| 7z | Copy, LZMA, LZMA2, Deflate, Deflate64, BZip2, Delta and 7zAES coders, the BCJ, BCJ2, PPC, IA64, ARM, ARMT, SPARC, ARM64 and RISCV filters, solid folders, encoded and encrypted headers, empty files, directories, anti-items, attributes and times | one LZMA folder per file and a plain header |
| xz | every stream, LZMA2 with the delta and branch filters, CRC32, CRC64 and SHA-256 checks | one stream with one LZMA2 block |
| .lzma | known and unknown sizes, with or without an end marker | the size in the header and no end marker |

An .lzma file has no signature, so its 13-byte header must look the way liblzma's own format guess requires: valid properties with lc + lp at most 4, a dictionary of 2^n or 2^n + 2^(n-1) bytes, a size that is unknown or below 256 GiB, and a first data byte of 0.

A file that starts with no signature of these formats is still read as a ZIP archive when an end of central directory record near its end leads to a central directory. That covers a ZIP with data in front of it, such as a self-extracting executable. A 7z signature header in the first megabyte, with a start header whose CRC matches, is read the same way. Brotli has no signature. A file that matches nothing else is Brotli when it decodes as one Brotli stream that ends where the file does, or that decodes to more than 32 MiB without an error.

gzip, bzip2, zstd, Brotli, xz and .lzma hold one file. archive-defuse treats each as an archive with one entry and hands that entry to the file plugins like any other. The tar inside a `.tar.gz` reaches the tar reader through a plugin, such as `archivePlugin()` or file-defuse's router.

What archive-defuse cannot decode rejects the archive with the UNKNOWN risk:

- ZIP entries compressed with PPMd, implode, shrink, reduce or another method that is not in the table, with COMPRESSION/UNSUPPORTED_METHOD.
- 7z folders that use PPMd, Zstandard, LZ4, Brotli or another coder not in the table, and xz filters this package does not know, with COMPRESSION/UNSUPPORTED_METHOD. A 7z format version other than 0, or 7zAES key derivation over 2^24 rounds, with COMPRESSION/UNSUPPORTED_FEATURE.
- Cabinet folders compressed with LZX or Quantum, with COMPRESSION/UNSUPPORTED_METHOD.
- zstd data on a Node without zstd, with COMPRESSION/UNAVAILABLE. A zstd frame that needs a dictionary or a window over 128 MiB, with COMPRESSION/UNSUPPORTED_METHOD.
- Encrypted entries no password opens, with ENCRYPTED/PASSWORD_REQUIRED, and PKWARE strong encryption or an encrypted central directory, with ENCRYPTED/UNSUPPORTED.
- One part of an archive split across several files, a cabinet that continues in another file, and a GNU multi-volume tar, with STRUCTURE/MULTI_VOLUME.
- RAR, with CORRUPTED/UNPARSEABLE.

## What it checks

Each rule decides by itself. A rule whose action is `strip` makes its own change in the rewrite and no other. It fixes the name, clears the bit, drops the field or removes the entry. Setting one rule to `info` changes that rule alone.

**Names.** The name rules read the name as the archive gives it, and fix it in a fixed order.

- NAME/TRAVERSAL: a `..` part, also with the dots and spaces Windows drops from the end of a part, such as `.. `. The rewrite drops the `..` parts.
- NAME/ABSOLUTE: a name that starts with `/` or `\`, UNC paths included. The rewrite drops every leading separator.
- NAME/DRIVE_LETTER: a name that starts with a drive letter, such as `C:`, `C:..\x` or `\\?\C:\`. The rewrite drops the drive.
- NAME/BACKSLASH: a backslash in a name, which Windows reads as a separator. The rewrite turns it into `/`. Not reported for a cabinet, whose separator it is.
- NAME/EMPTY_SEGMENT: `.` parts and empty parts. The rewrite drops them.
- NAME/CONTROL_CHARACTER: control characters, NUL included, and the characters that reorder text. The rewrite puts `_` in their place.
- NAME/WINDOWS_RESERVED: a device name such as `CON`, a character Windows refuses such as `:`, or a trailing dot or space. The rewrite puts `_` in their place, after a device name too.
- NAME/ENCODING: a ZIP name with non-ASCII bytes and no UTF-8 flag, a name flagged UTF-8 that is not valid UTF-8, a tar name that is not UTF-8, or a 7z name with a lone UTF-16 surrogate, which reads as U+FFFD. The rewrite writes every name in UTF-8, or in UTF-16 for 7z.
- NAME/UNICODE_PATH: an Info-ZIP Unicode path field that names another file than an ASCII header, or that belongs to another name.
- NAME/EMPTY: an empty name. The entry goes.
- NAME/TOO_LONG: a name over 4,096 bytes or a part over 255 bytes. `info`; as `strip` the entry goes.

A name the rules leave empty goes with its entry. A folder keeps its trailing slash and nothing else does. A 7z archive can store no names at all, and then the name rules skip its entries, as they skip the one entry of a gzip file without a name.

**Collisions.** These read the names the output would have, after the name rules, so a fixed name cannot land on another. Readers that overwrite keep the last of several entries, and the rewrite keeps the last.

- NAME/DUPLICATE: entries with the same name.
- NAME/NORMALIZATION_COLLISION: names equal after Unicode compatibility normalization (NFKD), such as an accented letter written as one code point or two, or a ligature and its letters.
- NAME/CASE_COLLISION: names equal after case folding, with a sharp s folded to `ss`.
- NAME/FILE_DIRECTORY_CLASH: a file or a hard link where another entry needs a folder, or a link named like a folder the archive lists. The file goes.
- NAME/SHORT_NAME_COLLISION: a name in the form of a Windows 8.3 alias, such as `LONGFI~1.TXT`, that another name in the same folder could get. The check predicts only the `~1` to `~9` style aliases; Windows switches to hashed aliases after a few collisions, and those are not predicted.

**Links.** Symbolic link targets resolve inside the archive's own tree, from the folder the link sits in, through other links of the archive by their case-folded names, 40 links at most.

- LINK/SYMLINK and LINK/HARDLINK: `info`, one per link.
- LINK/OUTSIDE: a symbolic link whose target leaves the tree, is absolute, cannot be resolved or loops, and a hard link whose target is absolute or has a `..` part. The link goes. A 7z entry with the Windows reparse-point attribute and no Unix mode holds a reparse buffer, not a path, so its target cannot be resolved.
- LINK/DANGLING: a hard link that names no entry before it, so extraction would link to whatever file has that name. The link goes.
- LINK/THROUGH_LINK: an entry whose path runs through a symbolic link of the archive. The entry goes.

A tar hard link names its target from the top of the archive. When the rewrite renames the target, the link names the new name. When the target goes, the link goes with it.

**Special files.** SPECIAL/DEVICE, SPECIAL/FIFO, SPECIAL/SOCKET and SPECIAL/UNKNOWN_TYPE, for a tar type or Unix file type no rule names, and SPECIAL/ANTI_ITEM, a 7z anti-item, which tells an updater to delete a file. Each entry goes.

**Permissions.** PERMISSIONS/SETUID, PERMISSIONS/SETGID and PERMISSIONS/STICKY report the bit on any entry, folders included, and the rewrite clears it. PERMISSIONS/CAPABILITY reports a `security.capability` extended attribute in a pax record, and the rewrite drops it.

**Structure.** Each of these is a place where two readers can see different archives.

- STRUCTURE/LEADING_BYTES and STRUCTURE/TRAILING_BYTES: data before or after the archive. tar's zero padding after the end blocks is not reported.
- STRUCTURE/POLYGLOT: that data reads as another format, such as a PDF in front of a ZIP or an executable stub. For 7z, xz and .lzma it also reports a ZIP end record that a ZIP reader would find from the end of the file, and a PDF header in the first 1024 bytes.
- STRUCTURE/HIDDEN_DATA: bytes of a ZIP or cabinet no entry covers, with a count of the local headers among them; skippable zstd frames; tar headers after the end of the archive, which readers that go past a lone zero block read.
- STRUCTURE/SEVERAL_END_RECORDS: another ZIP end record whose comment reaches the end of the file and that leads to a directory. The archive is read from the last end record whose comment fits in the file. An entry whose compressed bytes hold the other record is compressed afresh, so the copy does not carry it.
- STRUCTURE/HEADER_MISMATCH: a local header that disagrees with the central directory on the name, flags, method, CRC or sizes; a data descriptor that disagrees; an end record that disagrees with the directory or with its ZIP64 records; a pax size that differs from the header's own; a header name, for readers without pax or GNU long names, that leaves the folder while the real name does not.
- STRUCTURE/OFFSET_SHIFT: a central directory whose offsets do not count data in front of the archive, which some readers correct.
- STRUCTURE/OVERLAP: entries that share bytes.
- STRUCTURE/MULTIPLE_STREAMS: several gzip members, bzip2 streams, zstd frames or xz streams, after the first of which some readers stop.
- STRUCTURE/EXTRA_FIELD: a ZIP extra field record that holds neither times nor owners, a times or owners record without the layout Info-ZIP documents for it, a gzip extra field, a cabinet's reserved areas.
- STRUCTURE/NON_FILE_DATA: a folder or link that carries data.
- STRUCTURE/MALFORMED_HEADER: a header field that does not read as written, such as a gzip header with reserved flags or a pax value with a NUL in it, which the reader cuts at as GNU tar does.

The xz and 7z formats have structures of their own, and the reader checks them against each other:

- STRUCTURE/STREAM_PADDING (`info`): padding between or after xz streams. STRUCTURE/BAD_PADDING: padding of a length or content xz does not allow.
- STRUCTURE/INDEX_MISMATCH: an xz index or a footer's index size that disagrees with the blocks. STRUCTURE/HEADER_MISMATCH covers an xz stream footer that disagrees with its stream header.
- STRUCTURE/SIZE_MISMATCH: a declared size that disagrees with the data, such as an .lzma end marker before the size in its header.
- STRUCTURE/NO_CHECK (`info`): an xz stream with no integrity check. STRUCTURE/UNKNOWN_CHECK: a check type this package does not know, so the data went unverified.
- STRUCTURE/UNKNOWN_PROPERTY: a 7z header property this package does not keep.
- STRUCTURE/EMPTY_START_HEADER: a 7z start header of zeros, as an interrupted write leaves it. The reader looks for the header at the end of the file, where 7-Zip's recovery looks.
- STRUCTURE/HIDDEN_DATA and STRUCTURE/OVERLAP also cover the bytes of a 7z archive that no structure refers to, and structures that share bytes.

The rewrite settles each one by writing one consistent archive from what the reader took.

**Data.** CORRUPTED/ENTRY_DATA removes an entry whose data does not decode, decodes past its declared size, or does not match its CRC or checksum. A compressed file whose one stream does not decode rejects with CORRUPTED/DATA_ERROR, and one whose xz check does not match with CORRUPTED/CHECK_FAILED, which a 7z header CRC that does not match also gives. A header or table that cannot be read rejects with CORRUPTED/UNPARSEABLE, and an archive cut off inside an entry with CORRUPTED/TRUNCATED.

**Encryption.** ENCRYPTED/ZIPCRYPTO and ENCRYPTED/AES_128, AES_192 or AES_256 name the cipher (`info`). An entry a supplied password opens gets ENCRYPTED/DECRYPTED, and one the empty password opens ENCRYPTED/EMPTY_PASSWORD. Both are `strip`, since the rewrite writes the entry without encryption, with its compressed bytes as they were. A 7z header a password opens gets ENCRYPTED/HEADER (`strip`), since the rewrite writes the names in a plain header.

**Compression.** COMPRESSION/UNUSUAL_METHOD reports a Deflate64, bzip2, LZMA, zstd or XZ ZIP entry. It is `info` and the bytes are copied; as `strip` the rewrite compresses the entry again with deflate.

**Metadata.** METADATA/COMMENT reports an archive or entry comment. The rewrite keeps comments unless `stripMetadata` is on, which adds METADATA/STRIPPED.

**Entries.** ENTRY/NO_PLUGIN, ENTRY/TYPE_MISMATCH and the ENTRY/PLUGIN_* findings come from the file plugins, under [File plugins](#file-plugins).

An override that makes a rule `info` keeps what the rule reports where the rewrite can keep it, which covers leading and trailing data and the extra fields of a ZIP's central directory. Bytes the rewrite cannot keep, such as hidden data, data in a folder entry, a ZIP's local extra fields, the bytes after a malformed extra field and the extra fields of other formats, add PROCESSING/CONTENT_REMOVED.

## The defused copy

The rewrite writes the format it read.

- ZIP: entries in their own order, with local headers that carry the CRC and sizes, so no data descriptors. An entry nothing changed keeps its compressed bytes, without any encryption they had. An entry a plugin rewrote is deflated, or stored when deflate gains nothing or when its ratio would pass `limits.compressionRatio`. Times, permissions, comments and the extra fields that hold times and owners stay. The local header gets the central directory's copy of each field, so the rewrite sets an extended timestamp's flags to name only the times it holds. ZIP64 records appear where a size or offset needs them.
- tar: ustar headers, with pax records for long or non-ASCII names, large values and the pax records the archive had, such as extended attributes. A sparse file is written out in full. The archive ends with two zero blocks and is padded to 10,240 bytes.
- gzip: one member, with the name a rule fixed, its time and its comment. A single member nothing changed keeps its deflate stream.
- bzip2, zstd and Brotli: one stream. A single stream nothing changed is copied as it is. Several streams, or content a plugin rewrote, are compressed again with archive-defuse's bzip2 encoder or Node's zstd and Brotli.
- cabinet: a folder whose files are all kept as they were keeps its data blocks. Any other folder is built again in 32 KiB blocks, stored or MSZIP as it was, with checksums.
- 7z: one folder per file with content, each with one LZMA coder at lzma1's preset 1, a plain header with the names, folders, empty files, attributes and times that remain, and a CRC for every file. A file LZMA would compress past `limits.compressionRatio` is stored with the Copy coder instead. An archive with nothing left is the 32-byte signature header alone.
- xz: one stream, with the input's check type when every stream had the same one this package can compute, CRC64 otherwise. One block with LZMA2 alone, in independent chunks of at most 64 KiB, each compressed by lzma1's encoder at its preset 1 or stored when that is no smaller. Chunks that would start in the first 1024 bytes stay compressed, so the content does not show where other readers look for their signatures. A single stream with nothing to report is copied as it is.
- .lzma: the header with the size and no end marker, then the content compressed by lzma1's encoder. A file with nothing to report is copied as it is. The format cannot store data, so content that compresses past the ratio limit fails the output's check, as it does for bzip2.

lzma1's encoder is plain JavaScript, so the same input gives the same 7z, xz and .lzma output on every Node.

A compressed file whose one entry goes leaves nothing to write, so it rejects instead, as file-defuse does with an upload it would have to strip whole.

The output then goes through the same inspection, with the plugins credited by the MD5 of what they kept. Anything left to strip or reject fails it with PROCESSING/VERIFICATION_FAILED, and nothing reaches the sink. Defusing the output again gives the same bytes.

## File plugins

Every file entry goes to `filePlugins` in order, with pdf-defuse's shapes. A plugin's `accepts(file)` sees the entry's name as the archive gives it, the type `sniffType` finds in its first bytes, its size, its location such as `entry "docs/a.pdf"`, its depth and a source over the decoded and decrypted content. `process(file, sink, context)` gets the depth and the deadline. The first plugin that accepts the entry decides it.

- `passed` keeps the entry, with the bytes the plugin wrote when it wrote any.
- `scrubbed` keeps the bytes the plugin wrote.
- `removed`, a thrown error or a scrub that wrote nothing removes the entry, with ENTRY/PLUGIN_REMOVED or ENTRY/PLUGIN_FAILED.

The plugin's findings come into the report with `attachment` set to the entry's name. A `reject` inside the entry becomes `strip`, since the entry goes and the archive stays. When no plugin accepts an entry, ENTRY/NO_PLUGIN removes it. As `info`, the entry stays.

Before the plugins, a type check reports ENTRY/TYPE_MISMATCH (`info`) when the name's extension and the content disagree, as pdf-defuse does for attached files. A plugin never checks types.

`passThrough(types)` keeps entries by MIME type or extension, such as `passThrough(['text/csv', '.txt'])`.

`archivePlugin(options)` defuses archives inside other files. It accepts a file by its content. Without `options`, it takes the options of the archive-defuse run that found the file, so `filePlugins: [archivePlugin(), passThrough(['txt'])]` reads a `.tar.gz` down to its text files.

## Passwords

`password` takes one password or a list. archive-defuse tries each in order on each encrypted entry, and the empty password after them. Each password is tried as UTF-8 and, when it differs, as Latin-1.

A 7z folder opens with one password, the first under which the folder decodes up to its first file with a CRC and that file matches it. A folder with no CRC at all opens with the first password under which its first file decodes. Every file of the folder is read with that password, so a file that fails its CRC is removed and the folder is not decoded again with another. An encrypted 7z header is tried with each password when the archive opens. The key derivation is 7-Zip's, SHA-256 over 2^n rounds, and a header that asks for more than 2^24 rounds rejects.

ZipCrypto is archive-defuse's own code. A header that passes the check byte can come from a wrong password, so an entry whose data then fails its CRC goes on to the next password that passes. WinZip AES uses AES in ECB mode, with counter mode built on it, HMAC-SHA1, and PBKDF2 built on HMAC-SHA1. The password verifier and the authentication code both have to match.

## Limits

| Limit | Default | Counts |
|---|---|---|
| `fileSize` | none | Bytes in the upload |
| `entries` | 10,000 | Entries in the archive |
| `decompressedBytes` | 512 MiB | Decoded bytes of any one entry, declared or actual |
| `totalDecompressedBytes` | 2 GiB | Decoded bytes of the entries one run reads, declared or actual |
| `compressionRatio` | 1,000 | Decoded bytes per compressed byte of an entry, checked once it passes 1 MiB |
| `dictionaryBytes` | 256 MiB | Dictionary memory LZMA decoding needs: one LZMA or LZMA2 stream's dictionary, or those of all the coders of a 7z folder with their probability tables. A dictionary larger than the declared size counts at that size |
| `nestingDepth` | 10 | The deepest an archive may sit, with the upload at depth 0 and every format in between counting |
| `timeMs` | none | Milliseconds for the run and every file inside it |

Declared sizes are checked when the archive opens, before any entry is decoded. Actual sizes are checked as each entry decodes, whatever its headers declare, so a stream that lies about its size stops at the same limit. The ratio counts the compressed bytes the decoder has used so far, so a zero-filled bomb stops after about 1 MiB. A 7z folder counts its ratio over the whole folder as it decodes, so bytes skipped on the way to a later file count too. Nothing is allocated from a declared size. The holes of a sparse tar file count as stored, since its size was declared and checked.

A limit rejects the archive with its LIMIT finding, a null score and the UNKNOWN risk. `timeMs` becomes one deadline when the run starts, and every nested run shares it. A time or nesting limit in a nested run throws an error with `code: 'DEFUSE_LIMIT'` and `limit` set to `'time'` or `'nesting'`, which every package of the family passes up to the upload. An I/O error inside a nested run comes up with `code: 'DEFUSE_IO'`.

## Findings

Each finding has `category` and `detail`, a `description` safe to show the uploader, an `action` (`reject`, `strip` or `info`), and where it applies `location` and `data`. Past 200 findings of one kind, further ones raise a count on one more finding, as in pdf-defuse.

`allFindingSpecs()` returns every kind with its default action and weight. `actionOverrides` changes the action of a category or of one detail:

```js
await disarmArchive(bytes, {
  actionOverrides: [
    { category: 'LINK', detail: 'SYMLINK', action: 'strip' },
    { category: 'NAME', action: 'reject' },
  ],
});
```

A run that stops early, or cannot read the archive, rejects it with a null score and the UNKNOWN risk, whatever the overrides say.

## Scoring

The score adds the highest weight in full and a quarter of each other kind's weight, plus weights for some combinations, capped at 100. Each kind counts once. `scoreWeights` replaces weights, and `scoreBands` the lower bounds of LOW, MEDIUM, HIGH and CRITICAL (1, 25, 50 and 80). `scoreFindings`, `COMBINATIONS` and `DEFAULT_BANDS` are exported.

A finding from another package scores at its `weight`. An archive's findings carry the weights its run used when `archivePlugin` returns them, so a container in another package can score them.

## Options

| Option | Default | Purpose |
|---|---|---|
| `password` | none | One password or a list |
| `limits` | see Limits | |
| `stripMetadata` | false | Drops comments, owners and ids, times, extended attributes and the gzip time and system |
| `actionOverrides` | none | Changes the action of a category or detail |
| `scoreWeights` | none | Replaces weights |
| `scoreBands` | 1, 25, 50, 80 | Lower bounds of the risk bands |
| `filePlugins` | none | Plugins for the files inside the archive |
| `tempDir` | `os.tmpdir()` | Folder for temporary files |
| `memoryThreshold` | 8 MiB | Bytes held in memory before a temporary file takes over, for the upload's copy, each entry handed to the plugins, and the copies plugins keep together |

## The defuse family

archive-defuse follows the contract of pdf-defuse. `ContainedFilePlugin`, `PluginContext`, `ContainedFile`, `ContainedFileResult` and `DefuseFinding` have pdf-defuse's shapes, and `context.depth` is the depth of the file itself, with the upload at 0. `archivePlugin(options)` is the plugin the router builds, and the router puts itself in `filePlugins`, so an entry of any format comes back to it. The same `password` list goes to every package.

### Detection

`detectArchive(bytes, options)` and `detectArchiveSource(source, options)` tell a router whether archive-defuse reads a file, and in which format. They return `{ mimeType, extension, offset }`, or undefined. The answer comes from the same format selection the inspection runs, so routing and reading cannot disagree. The content decides, apart from Brotli below. `options.name` and `options.declaredType` change nothing else, so a .docx comes back as a ZIP, and the router asks office-defuse before it takes that answer.

| Format | `mimeType` | `extension` |
|---|---|---|
| ZIP and ZIPX | application/zip | zip |
| tar | application/x-tar | tar |
| gzip | application/gzip | gz |
| bzip2 | application/x-bzip2 | bz2 |
| zstd | application/zstd | zst |
| Brotli | application/x-brotli | br |
| cabinet | application/vnd.ms-cab-compressed | cab |
| 7z | application/x-7z-compressed | 7z |
| xz | application/x-xz | xz |
| .lzma | application/x-lzma | lzma |

ZIPX has no format of its own here. The ZIP reader reads it, so it comes back as a ZIP.

`offset` is where the archive's data starts. It is 0 when a signature starts the file. For a ZIP found from its end record, it is where the ZIP reader finds the first entry, the same number STRUCTURE/LEADING_BYTES reports, or 0 when the reader cannot open the archive. For a 7z archive after a self-extracting program, it is the signature header's offset.

Three claims rest on no signature, and those answers carry `heuristic`, which says what the claim rests on. An .lzma file passes liblzma's header test. A Brotli file decodes as one stream that ends with the file, or past 32 MiB without an error. A file of zeros, at least 1024 bytes long and a multiple of 512, is an empty tar. Other runs of zeros, from 14 bytes, pass the .lzma test instead.

A file the selection picks and the reader then refuses, such as a truncated ZIP, still counts, and the inspection rejects it with its own finding. RAR is detected only to be rejected, so detection does not claim it.

Brotli has no signature, and a file of one or two bytes can decode as a Brotli stream. A file holding just `5` is an empty one. So detection claims Brotli only when `options.name` ends in `.br` or `options.declaredType` is application/x-brotli, and the whole file decodes. `archivePlugin` accepts exactly what detection claims, with the file's own name and declared type.

`detectArchiveSource` leaves the source open. It passes read errors on, and throws with the `DEFUSE_LIMIT` code once `options.deadline` passes. Detection uses no temporary files and ignores `tempDir` and `memoryThreshold`, which the family's options carry for other packages.

## Making and reading archives

archive-defuse also makes archives and reads them, with no defusing involved, for code that would otherwise use archiver, adm-zip or tar-stream.

```js
const { pipeline } = require('node:stream/promises');
const { createArchiveStream, openArchive } = require('@patrickdk77/archive-defuse');

// An xlsx is a ZIP. Entries go out in the order given, and each stream is read when its turn comes.
await pipeline(
  createArchiveStream('zip', [
    { name: '[Content_Types].xml', data: contentTypesXml },
    { name: 'xl/worksheets/sheet1.xml', data: sheetStream },
    { name: 'attachment.pdf', data: () => bucket.openDownloadStream(fileId) },
  ]),
  res,
);

// One file out of a ZIP an API sent back.
const zip = await openArchive(response.data);
const result = JSON.parse(await zip.text('result.json'));
```

**Making archives.** `createArchive(format, entries, sink, options)` writes to a sink and closes it. `createArchiveStream` returns a Node Readable instead, and `createArchiveBytes` a Uint8Array. The formats are `zip`, `tar`, `tar.gz`, `tar.bz2`, `tar.zst`, `tar.xz` and `7z`. `entries` is a list or an async iterable, and each entry has:

- `name`, with "/" between folders. A name that ends in "/" is a folder.
- `data`: bytes, text written as UTF-8, a stream such as a Node Readable, or a function that returns one of those. A function runs when the entry's turn comes, so a thousand downloads do not all open at once.
- `size`, a file's length in bytes, for a stream whose length you know, such as a GridFS file's. Content that comes to another size fails the archive.
- `linkTarget` for a symbolic link, `mode` for the permission bits, `mtime` for the time, and `store: true` to keep a ZIP entry uncompressed, which the `mimetype` entry of an ODF document needs.

ZIP and 7z need a file's CRC and sizes before its data, so a file given as a stream is read first, into memory up to `memoryThreshold` (8 MiB) and into a temporary file past it. tar needs only the size. Bytes, text and a stream with `size` go straight out, and only a stream without one is read first. ZIP entries are deflated at `level` 6. ZIP and 7z store an entry that compression gains nothing on, or that would compress past `ratioLimit`, 1,000 to 1 by default, so their archives read back under the default limits. A compressed tar and the output of `compress` have no stored form. Content that compresses past 1,000 to 1, such as a long run of zeros, stops `openArchive`, `decompress` and the inspection with LIMIT/RATIO. Raise `limits.compressionRatio` to read it.

`streaming: true` writes a ZIP archive the way archiver does, with no temporary file. Each file is deflated as its data arrives and goes straight to the sink, and a data descriptor after the data carries its CRC and sizes. Only zlib's buffers are held. A file with `store: true` and a link's target are held in memory, because a stored entry keeps its sizes in its header, and an empty file is stored. Two things of the default mode are lost. A file deflate cannot shrink is deflated anyway, and `ratioLimit` does not apply, since the entry is out before its ratio is known. A file whose size is known, from `size` or because it is bytes or text, gets ZIP64 fields in its local header when deflating it could pass 4 GiB, which tells a reader the descriptor's sizes are eight bytes. A stream without a size gets none, because some readers refuse ZIP64 fields an entry does not need. If such a stream reaches 4 GiB, its descriptor holds eight-byte sizes anyway, as archiver writes it. tar needs no option to stream, and 7z writes its header from every entry after the data, so `streaming` writes ZIP only. A 26 MB sheet given one row per chunk takes 0.75 seconds this way, and 1.2 in the default mode.

Small chunks of an entry are gathered into 64 KiB pieces before they are compressed, so data given one row at a time compresses as fast as data given in large pieces.

**Adding entries as you go.** `createArchiveWriter(format, options)` takes entries one at a time, the way archiver's `append` and `finalize` do, for code that finds them as it goes. `add(entry)` queues an entry and returns at once, so a synchronous callback can call it. Entries go out in the order added, and each waits in memory until its turn. `finish()` says no more entries come, and resolves once the end of the archive is written. `abort(reason)` stops the archive. `stream` is the archive as a Readable. Read it while you add entries, because the end of the archive is written only as the stream is read. A refused name, a failed stream or an abort fails the archive. The writer destroys `stream` with the error, `finish` rejects with it, and a later `add` throws a PackError whose `cause` is the error.

```js
const { createArchiveWriter } = require('@patrickdk77/archive-defuse');

const zip = createArchiveWriter('zip', { streaming: true });
const sent = pipeline(zip.stream, res);
try {
  zip.add({ name: 'mimetype', data: 'application/vnd.oasis.opendocument.text', store: true });
  // Each picture goes into the archive as layout finds it, before content.xml exists.
  const xml = render(doc, picture => zip.add({ name: `Pictures/${picture.name}`, data: picture.bytes }));
  zip.add({ name: 'content.xml', data: xml });
  zip.finish();
} catch (e) {
  zip.abort(e);
}
await sent;
```

`createArchive` throws a PackError, before it writes the entry, for a name the inspection would change. That covers an empty name, a NUL, an absolute path, a drive letter, a `..` part with or without dots and spaces after it, an empty or `.` part, a backslash, a control character or one that reorders text, and a part Windows cannot create, such as `con.txt`, `report:v2.txt` or a part that ends in a dot or a space. It also refuses a name that leaves its folder once NFKC normalization or Windows best fit changes it. NFKC turns two fullwidth full stops, U+FF0E, into `..`. Best fit turns a yen sign, U+00A5, into a backslash when a program on Japanese Windows converts the name to code page 932. A name with a yen sign is still written unless that conversion takes it out of its folder. Duplicate names are written as given.

When an entry's stream fails, the sink is aborted instead of closed, and the Readable is destroyed with the error, so an upload or an HTTP response never ends with a partial archive that looks whole.

`signal` takes an AbortSignal. When it aborts, the work stops at the next chunk, the sink is aborted, and the call throws the signal's reason. Destroying the Readable of `createArchiveStream` or `compressStream` stops the work the same way. Hand it to `stream.pipeline`, which destroys it when the response closes early. `pipe` does not, and the work then waits for a read that never comes, holding its source and temporary files.

`compress(format, data, options)` compresses one file to bytes, `compressTo` writes it to a sink, and `compressStream` returns a Readable. The formats are `gzip`, `bzip2`, `zstd`, `brotli`, `xz` and `lzma`. zstd needs a Node that has it.

**Reading archives.** `openArchive(input, options)` takes bytes or a source, finds the format from the content, and lists the entries. The reader has `format`, `entries`, `find(name)`, `stream(entry)`, `bytes(entry)`, `text(entry)` and `close()`, and each takes an entry or its name. It reads every format the inspection reads. `decompress(input)` decodes a compressed file, such as gzip or xz, to its content. A compressed tar opens as the compressed file, whose one entry is the tar. To list the tar, open that entry's bytes with `openArchive` again.

openArchive applies no rule. A name comes as the archive stores it, so it can climb out with `..`, be absolute or repeat another, and code that writes entries to disk has to check each name, or defuse the archive first. The limits are the inspection's, with the same defaults: declared sizes are checked when the archive opens, every read counts toward the total, and the ratio limit stops a bomb as it decodes. `password` takes one password or a list. The XZ entries of a ZIP decode from a copy, kept in memory up to `memoryThreshold` (8 MiB) and in a temporary file in `tempDir` past it. What stops a read throws an ArchiveReadError, whose `category` and `detail` name the finding `inspectArchive` would report, such as `LIMIT` and `RATIO`.

## Command line

```
archive-defuse inspect <file> [options]
archive-defuse defuse <in> <out> [options]

--password-file <path>    read passwords from a file, one per line; ARCHIVE_DEFUSE_PASSWORD holds one
--plugin <module>         load plugins from a file or an installed package, repeatable
--config <module>         load a whole options object, repeatable; the other options apply on top
--keep-type <type>        keep entries of this MIME type or file extension unchanged, repeatable
--defuse-inner-archives   defuse archives inside the archive, such as the tar inside a .tar.gz
--strip-metadata
--limit <name>=<value>    fileSize, entries, decompressedBytes, totalDecompressedBytes, compressionRatio,
                          nestingDepth, timeMs; sizes accept kb, mb, gb
--json                    print the result as JSON
```

Use `-` for stdin or stdout. stdin is copied to a temporary file first, and the copy stops one byte past `limits.fileSize` and at the time limit. `inspect` prints its report to stdout. `defuse` does too, unless the archive goes to stdout, and then the report goes to stderr. `defuse` refuses an output that is its input, since a failed write deletes the partial output.

`--password-file` reads one password per line. The tool drops a carriage return at the end of a line and skips blank lines, since the empty password is tried anyway. Spaces belong to the password. `ARCHIVE_DEFUSE_PASSWORD` holds one password, and a line break in it is part of that password. `--password-file` replaces it. There is no password flag, because other users can read command-line arguments from the process list. An unknown option shows in the error without the text after its `=`.

The text report shows each control character in an entry name as an escape such as `\u001b`. The JSON report escapes DEL and the C1 range as well.

Exit codes are 0 for clean, 1 for stripped or strippable, 2 for rejected and 3 for a usage or I/O error.

## What it does not check

- The content of the files inside the archive, which is the file plugins' business.
- Anything about the place an archive is extracted to, such as a symbolic link already there or Windows' Mark of the Web. archive-defuse writes no files of its own.
- Archives inside other bytes, apart from a ZIP that a reader finds from the end of the file. A cabinet that does not start the file is not read.

## Development

Development needs Node 22.12 or later, for mocha 12 and for chai 6 loaded with `require()`. The tests also read the rewritten archives with Python's `zipfile`, `tarfile`, `gzip` and `bz2`, so they need `python3`. Python reads each one in memory and writes no file.

```sh
npm install --ignore-scripts
npm run build
npm test
npm run lint
npm run format
```

`npm test` runs the lint, builds the package and the tests, then runs mocha.

`node scripts/make-fixtures.js` writes every file in `test/fixtures` from scratch with the builders in `scripts/builders.js`, on a Node with zstd and with no other tool. `manifest.json` in that folder gives each fixture's plugins, options, verdicts and findings, and `test/fixtures.test.ts` checks every case.

`node scripts/make-lzma-fixtures.js` writes `test/fixtures/lzma/cases` and its manifest, with Python's `lzma` and `bz2` modules. `node scripts/make-deflate64-fixtures.js` writes `test/fixtures/deflate64` with 7-Zip's Deflate64 encoder, and the Deflate64 tests check the hand-made streams against `7z` when it is installed. Both write the same bytes on every run. `test/fixtures/lzma/xz-utils` holds test files from XZ Utils under the BSD Zero Clause License, with their README and LICENSE. No fixture ships in the package.

`npx husky` turns on the pre-commit hook, which runs Biome on the staged files and then `npm audit`.

## License

MIT AND Apache-2.0. The package is MIT, in LICENSE. The LZMA and LZMA2 decoders and the LZMA encoder in `src/lzma1` come from lzma1 by Filip Seman, under the Apache License 2.0. Its text and a NOTICE that lists what changed sit next to them, and both ship in `dist/lzma1`. lzma1 ports that code from XZ for Java, which is 0BSD. The branch converters and the delta filter are ported from XZ for Java directly.
