# Changelog

## 0.1.0 - 2026-10-11

First release.

### Formats

- Reads and writes ZIP, tar, gzip, bzip2, zstd, Brotli, cabinet, 7z, xz and .lzma files, each in its own format. The first bytes decide the format. A ZIP with data in front of it is found from its end record, and a 7z archive by its signature header in the first megabyte.
- ZIP: stored, deflate, Deflate64, bzip2, LZMA, zstd and XZ entries, ZIP64, data descriptors, ZipCrypto and WinZip AES. PPMd and the legacy methods reject with COMPRESSION/UNSUPPORTED_METHOD. Deflate64 has its own decoder, and LZMA and XZ entries go through the package's LZMA code.
- tar: v7, ustar, star, GNU long names and old sparse files, pax headers and pax sparse files.
- gzip, bzip2, zstd and Brotli are read as an archive with one entry. bzip2 has its own decoder and encoder, randomised blocks included. zstd comes from Node's zlib, and a Node without it rejects zstd data with COMPRESSION/UNAVAILABLE.
- Cabinets with stored and MSZIP folders. LZX and Quantum reject with COMPRESSION/UNSUPPORTED_METHOD.
- 7z: Copy, LZMA, LZMA2, Deflate, Deflate64, BZip2, Delta and 7zAES coders, the BCJ, BCJ2 and other branch filters, solid folders, encoded and encrypted headers, and archives whose start header an interrupted write left empty. PPMd, Zstandard, LZ4 and Brotli folders reject with COMPRESSION/UNSUPPORTED_METHOD.
- xz with every stream, LZMA2, delta and branch filters, and CRC32, CRC64 and SHA-256 checks; .lzma with known or unknown sizes. The LZMA code comes from lzma1, under the Apache License 2.0, so the package license is `MIT AND Apache-2.0`.

### Checks

- Names that climb out, absolute paths, drive letters, backslashes, control characters and names Windows cannot create, each fixed by the rewrite.
- Duplicate names and names that collide by case, Unicode normalization or Windows 8.3 aliases. The rewrite keeps the last entry.
- Symbolic links resolved inside the archive's tree, hard links, entries written through a link, devices, named pipes, sockets, setuid, setgid and sticky bits, and file capabilities.
- Data before, between and after the entries, polyglots, several end records, local headers that disagree with the central directory, shifted offsets, overlapping entries and several compressed streams.
- xz padding, indexes and footers checked against the blocks, missing or unknown xz checks, unknown 7z header properties, 7z anti-items, and 7z entries that are Windows reparse points.
- ZIP times and owners extra fields without the layout Info-ZIP documents. The rewrite drops them.
- Limits on entries, decoded bytes per entry and in total, compression ratio, LZMA dictionary memory, nesting depth and time. The decoded size is checked as each entry decodes, whatever its headers declare.

### Making and reading archives

- `createArchive`, `createArchiveStream` and `createArchiveBytes` write ZIP, tar, tar.gz, tar.bz2, tar.zst, tar.xz and 7z from a list or stream of entries, each with bytes, text, a stream or a function that opens one. ZIP entries can be stored, as ODF's `mimetype` needs.
- `compress`, `compressTo` and `compressStream` write gzip, bzip2, zstd, Brotli, xz and .lzma.
- `createArchive` refuses a name the inspection would change, and a name that leaves its folder after NFKC normalization or Windows best fit.
- `signal` stops a write, and so does destroying the Readable that `createArchiveStream` or `compressStream` returns.
- `openArchive` lists and reads the entries of every format the inspection reads, under the same limits, and `decompress` decodes a compressed file.

### Plugins and tools

- Every file entry goes to `filePlugins`. An entry no plugin accepts is removed with ENTRY/NO_PLUGIN.
- `archivePlugin(options)` defuses archives inside other files, and `passThrough(types)` keeps entries by type or extension.
- `password` takes one password or a list.
- The `archive-defuse` command inspects and defuses, with `--password-file` and `ARCHIVE_DEFUSE_PASSWORD` for passwords.
