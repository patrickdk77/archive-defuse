// Copied from lzma1 0.6.1 (Apache-2.0, Copyright Filip Seman) and changed for archive-defuse. NOTICE in this folder lists the changes.
/**
 * CRC-32 (IEEE 802.3) lookup table. The match finders hash with a copy of
 * it, so changing this array does not affect compression.
 */
export const CRC32_TABLE: number[] = createCrc32Table();

function createCrc32Table(): number[] {
  const table: number[] = [];

  for (let i = 0; i < 256; ++i) {
    let r = i;
    for (let j = 0; j < 8; ++j) {
      r = (r & 1) !== 0 ? (r >>> 1) ^ 0xedb88320 : r >>> 1;
    }
    table.push(r >>> 0);
  }

  return table;
}
