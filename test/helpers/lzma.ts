// Helpers for the xz, lzma and 7z tests, which came from lzma-defuse when it merged into this package.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { crc32 } from '../../src/crc32';
import { DEFAULT_LIMITS } from '../../src/engine';
import { bufferSource, Reader } from '../../src/io';
import type { Content } from '../../src/lzma-writers';
import { openSevenZip, SevenReader } from '../../src/seven';
import type { ArchiveOptions, ContainedFile, ContainedFilePlugin } from '../../src/types';
import { fixtures } from './util';

/** The folder of the xz, lzma and 7z fixtures. */
export const lzmaFixtures = path.join(fixtures, 'lzma');

/** What the manifest says about one crafted fixture. */
export interface CaseExpect {
  status: 'clean' | 'strippable' | 'rejected';
  findings?: string[];
  entries?: number;
  /** CRC-32 of the decoded content of an xz or lzma file. */
  content?: number;
  /** Names of the entries the defused 7z archive keeps, in order. */
  names?: string[];
  /** CRC-32 of each kept file's content. */
  kept?: number[];
  attribs?: number[];
  password?: string | string[];
  limits?: ArchiveOptions['limits'];
  stripMetadata?: boolean;
  sniffed?: string;
  nested?: boolean;
}

export function manifest(): Record<string, CaseExpect> {
  return (JSON.parse(fs.readFileSync(path.join(lzmaFixtures, 'cases', 'manifest.json'), 'utf8')) as { cases: Record<string, CaseExpect> }).cases;
}

export const fixture = (name: string) => fs.readFileSync(path.join(lzmaFixtures, 'cases', name));

/** A plugin that keeps every file it is shown and records what it saw. */
export function keepAll(seen: ContainedFile[] = []): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'keep-all',
    accepts: () => true,
    process: async file => {
      seen.push(file);
      return 'passed';
    },
  };
}

/** The options a fixture's manifest entry asks for, with a plugin that keeps every file. */
export function optionsFor(e: CaseExpect, extra: ArchiveOptions = {}): ArchiveOptions {
  return { filePlugins: [keepAll()], password: e.password, limits: e.limits, stripMetadata: e.stripMetadata, ...extra };
}

/** One entry of a 7z archive as the package's own reader sees it. */
export interface Listed {
  name?: string;
  kind: string;
  attrib?: number;
  crc?: number;
  size: number;
}

/** Lists a 7z archive's entries with the package's reader, decoding each file's content. */
export async function list7z(bytes: Uint8Array, password = ''): Promise<Listed[]> {
  const source = bufferSource(bytes);
  const env = { source, reader: new Reader(source, bytes.length), size: bytes.length, limits: DEFAULT_LIMITS, totals: { decoded: 0, compressed: 0 }, passwords: [password] };
  const archive = await openSevenZip(env, 0);
  const reader = new SevenReader(env, archive);
  const out: Listed[] = [];
  for (const e of archive.entries) {
    let crc: number | undefined;
    if (e.folder !== undefined) {
      crc = 0;
      for await (const c of reader.content(e, password)) crc = crc32(c, crc);
    }
    out.push({ name: e.info.name, kind: e.kind, attrib: e.info.attrib, crc, size: e.size });
  }
  await reader.close();
  return out;
}

/** Bytes as the 7z writer takes them. */
export const contentOf = (b: Uint8Array): Content => ({
  size: b.length,
  async *chunks() {
    yield b;
  },
});
