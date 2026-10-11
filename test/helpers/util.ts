import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as zlib from 'node:zlib';
import { archivePlugin, type ContainedFilePlugin, type DefuseFinding, passThrough } from '../../src';

/** The package root. This file runs from build-test/test/helpers. */
export const root = path.join(__dirname, '..', '..', '..');
export const fixtures = path.join(root, 'test', 'fixtures');
export const fixture = (name: string) => fs.readFileSync(path.join(fixtures, name));

const cli = path.join(root, 'dist', 'cli.js');
/** Runs the built command-line tool. */
export const runCli = (args: string[], opts: { input?: Buffer; env?: NodeJS.ProcessEnv; cwd?: string } = {}) =>
  spawnSync(process.execPath, [cli, ...args], { input: opts.input, env: { ...process.env, ...opts.env }, cwd: opts.cwd, maxBuffer: 64 * 1024 * 1024 });

export const kind = (f: DefuseFinding) => `${f.category}/${f.detail}`;
export const kinds = (i: { findings: DefuseFinding[] }) => i.findings.map(kind);
/** The findings of one kind, such as 'NAME/TRAVERSAL'. */
export const of = (i: { findings: DefuseFinding[] }, k: string) => i.findings.filter(f => kind(f) === k);
export const has = (i: { findings: DefuseFinding[] }, k: string) => of(i, k).length > 0;
/** A finding as the manifest lists it: its action and kind, and the file it sits in when it comes from one. */
export const line = (f: DefuseFinding) => `${f.action} ${kind(f)}${f.attachment ? ` in ${f.attachment}` : ''}`;

/** Returns `value`, or fails the test when it is null or undefined. `what` names the value in the failure. */
export function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`${what} is missing`);
  return value;
}

/** The error a promise rejects with, or undefined when it resolves. */
export async function failure(p: Promise<unknown>): Promise<unknown> {
  try {
    await p;
  } catch (e) {
    return e;
  }
  return undefined;
}

/** A plugin that keeps every entry as it is. */
export const keepAll: ContainedFilePlugin = { kind: 'file', name: 'keep', accepts: () => true, process: async () => 'passed' };

/** Plugins by the names the fixture manifest uses. */
export function pluginsOf(names: string[] = []): ContainedFilePlugin[] {
  return names.map(n => (n === 'keep' ? keepAll : n === 'archive' ? archivePlugin() : passThrough([n.replace(/^keep:/, '')])));
}

/** True when the running Node has zstd. */
export const hasZstd = typeof (zlib as { createZstdDecompress?: unknown }).createZstdDecompress === 'function';

/** The builders the fixture script uses, for archives a test makes itself. */
export interface ZipEntrySpec {
  name: string | Buffer;
  data?: string | Buffer;
  method?: number;
  flags?: number;
  payload?: Buffer;
  mode?: number;
  crc?: number;
  usize?: number;
  local?: Record<string, number | Buffer>;
  central?: Record<string, number | Buffer>;
  localExtra?: Buffer;
  centralExtra?: Buffer;
  comment?: string;
  before?: Buffer;
  after?: Buffer;
}
export interface Builders {
  B(s: string, enc?: BufferEncoding): Buffer;
  u16(v: number): Buffer;
  u32(v: number): Buffer;
  u64(v: number | bigint): Buffer;
  crc32(b: Uint8Array): number;
  zipCrypto(data: Buffer, password: string, check: number): Buffer;
  winzipAes(data: Buffer, password: string, strength: number): Buffer;
  zip(entries: ZipEntrySpec[], o?: { prefix?: Buffer; shift?: boolean; comment?: Buffer; trailing?: Buffer; end?: Record<string, number> }): Buffer;
  extra(id: number, body: Buffer): Buffer;
  text(name: string, body?: string): ZipEntrySpec;
  octal(v: number, width: number): string;
  tarHeader(fields: Record<string, unknown>): Buffer;
  pad512(b: Buffer): Buffer;
  tarEntry(fields: Record<string, unknown>, data?: string | Buffer): Buffer;
  paxRecord(key: string, value: string | Buffer): Buffer;
  pax(records: Array<[string, string | Buffer]>, type?: string): Buffer;
  tarEnd(body: Buffer): Buffer;
  tar(...entries: Buffer[]): Buffer;
  gzipMember(data: Buffer, o?: { name?: string; comment?: string; extra?: Buffer; crc?: number }): Buffer;
  BZ: Record<'text' | 'zeros' | 'one' | 'two' | 'entry', Buffer>;
  ZS: Record<'text' | 'zeros' | 'one' | 'two' | 'entry', Buffer>;
  cabChecksum(b: Buffer, seed?: number): number;
  cab(folders: Array<{ type: number; files: Array<{ name: string; data: string | Buffer; folder?: number }> }>, o?: { flags?: number; badChecksum?: boolean; trailing?: Buffer }): Buffer;
}
// The builders are plain JavaScript shared with the fixture script, which runs without a build.
export const build: Builders = require(path.join(root, 'scripts', 'builders.js'));

/**
 * Reads an archive with Python's zipfile, tarfile, gzip or bz2, in memory, and prints each entry's name, kind and the
 * SHA-256 of its content. Python never writes a file, so nothing it reads can land outside its buffer.
 */
export function pythonList(format: 'zip' | 'tar' | 'gzip' | 'bzip2', bytes: Uint8Array): Array<[string, string, string]> {
  const script = [
    'import sys, io, hashlib, zipfile, tarfile, gzip, bz2, json',
    'fmt = sys.argv[1]; data = sys.stdin.buffer.read(); out = []',
    'h = lambda b: hashlib.sha256(b).hexdigest()[:16]',
    "if fmt == 'zip':",
    '  z = zipfile.ZipFile(io.BytesIO(data))',
    '  bad = z.testzip()',
    "  assert bad is None, 'bad entry ' + str(bad)",
    "  out = [[i.filename, 'dir' if i.is_dir() else 'file', '' if i.is_dir() else h(z.read(i))] for i in z.infolist()]",
    "elif fmt == 'tar':",
    "  t = tarfile.open(fileobj=io.BytesIO(data), mode='r:')",
    "  out = [[m.name + ('/' if m.isdir() else ''), 'dir' if m.isdir() else 'sym' if m.issym() else 'link' if m.islnk() else 'file', h(t.extractfile(m).read()) if m.isfile() else (m.linkname or '')] for m in t.getmembers()]",
    "elif fmt == 'gzip': out = [['', 'file', h(gzip.decompress(data))]]",
    "else: out = [['', 'file', h(bz2.decompress(data))]]",
    'print(json.dumps(out))',
  ].join('\n');
  const r = spawnSync('python3', ['-I', '-c', script, format], { input: Buffer.from(bytes), maxBuffer: 64 * 1024 * 1024 });
  if (r.status !== 0) throw new Error(`python3 could not read the ${format} output: ${r.stderr.toString().slice(-400)}`);
  return JSON.parse(r.stdout.toString()) as Array<[string, string, string]>;
}

export const sha16 = (b: Uint8Array) => crypto.createHash('sha256').update(b).digest('hex').slice(0, 16);
