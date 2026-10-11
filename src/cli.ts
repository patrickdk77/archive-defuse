#!/usr/bin/env node
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { pathToFileURL } from 'node:url';
import { disarmArchiveSource, inspectArchiveSource } from './engine';
import { TimeLimitError } from './errors';
import { fileSink, fileSource, TempDir, writableSink } from './io';
import { archivePlugin, passThrough } from './plugins';
import type { ArchiveInspection, ArchiveLimits, ArchiveOptions, ByteSource, ContainedFilePlugin } from './types';

const USAGE = `Usage:
  archive-defuse inspect <file> [options]
  archive-defuse defuse <in> <out> [options]

Options:
  --password-file <path>    read passwords from a file, one per line; ARCHIVE_DEFUSE_PASSWORD holds one
  --plugin <module>         load plugins from a file or an installed package, repeatable
  --config <module>         load a whole options object, repeatable; the other options apply on top
  --keep-type <type>        keep entries of this MIME type or file extension unchanged, repeatable
  --defuse-inner-archives   defuse archives inside the archive, such as the tar inside a .tar.gz
  --strip-metadata
  --limit <name>=<value>    fileSize, entries, decompressedBytes, totalDecompressedBytes, compressionRatio,
                            dictionaryBytes, nestingDepth, timeMs; sizes accept kb, mb, gb
  --json                    print the result as JSON

Use - for stdin or stdout.
Exit codes: 0 clean, 1 stripped or strippable, 2 rejected, 3 usage or I/O error.`;

class UsageError extends Error {}

function parseSize(v: string): number {
  const m = /^(\d+(?:\.\d+)?)\s*(b|kb|k|mb|m|gb|g)?$/i.exec(v.trim());
  if (!m) throw new UsageError(`Bad size "${v}"`);
  const mult: Record<string, number> = { b: 1, k: 1024, kb: 1024, m: 1024 ** 2, mb: 1024 ** 2, g: 1024 ** 3, gb: 1024 ** 3 };
  return Math.round(Number(m[1]) * mult[(m[2] ?? 'b').toLowerCase()]);
}

// A real dynamic import. TypeScript would compile import() to require() for CommonJS output,
// and require() cannot load ES modules or file URLs.
const dynamicImport = new Function('specifier', 'return import(specifier)') as (s: string) => Promise<unknown>;

/** Reads `key` from `v` the way `v?.[key]` does, for a value whose shape is not known. */
function prop(v: unknown, key: string): unknown {
  return (typeof v === 'object' && v !== null) || typeof v === 'function' ? (v as Record<string, unknown>)[key] : undefined;
}

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null;

async function loadModule(spec: string): Promise<unknown> {
  // A bare name ending in .js can be a file in the working directory or a package with that name. The file wins.
  const looksLikePath = spec.startsWith('.') || path.isAbsolute(spec) || (/\.(c|m)?js$/.test(spec) && fs.statSync(spec, { throwIfNoEntry: false })?.isFile() === true);
  let resolved: string | undefined;
  if (looksLikePath) resolved = path.resolve(process.cwd(), spec);
  else {
    try {
      resolved = require.resolve(spec, { paths: [process.cwd()] });
    } catch (e) {
      // require.resolve applies only the "require" condition, so a package that exports only "import" ends up here.
      if ((e as NodeJS.ErrnoException).code !== 'ERR_PACKAGE_PATH_NOT_EXPORTED') throw e;
      const name = spec
        .split('/')
        .slice(0, spec.startsWith('@') ? 2 : 1)
        .join('/');
      const subpath = `.${spec.slice(name.length)}`;
      for (let dir = process.cwd(); resolved === undefined; dir = path.dirname(dir)) {
        const pkg = path.join(dir, 'node_modules', name);
        if (fs.existsSync(path.join(pkg, 'package.json'))) {
          const exp = (JSON.parse(fs.readFileSync(path.join(pkg, 'package.json'), 'utf8')) as { exports?: unknown }).exports;
          const isMap = isObject(exp) && Object.keys(exp).some(k => k.startsWith('.'));
          let target: unknown;
          let match: string | undefined;
          if (!isMap) target = subpath === '.' ? exp : undefined;
          else if (Object.hasOwn(exp, subpath) && !subpath.includes('*')) target = exp[subpath];
          else {
            // A pattern key holds one "*". Node prefers the longest text before the "*", then the longest key, and puts
            // what the "*" matched into the target.
            let best = '';
            for (const k of Object.keys(exp)) {
              const star = k.indexOf('*');
              const trailer = k.slice(star + 1);
              if (star < 0 || trailer.includes('*') || !subpath.startsWith(k.slice(0, star)) || subpath.length === star) continue;
              if (trailer && (!subpath.endsWith(trailer) || subpath.length < k.length)) continue;
              if (!best || star > best.indexOf('*') || (star === best.indexOf('*') && k.length > best.length)) best = k;
            }
            if (best) {
              target = exp[best];
              match = subpath.slice(best.indexOf('*'), subpath.length - (best.length - best.indexOf('*') - 1));
              // Node refuses a match that would step outside the pattern's directory.
              if (match.split(/[/\\]/).some(s => s === '' || s === '.' || s === '..' || s.toLowerCase() === 'node_modules')) throw e;
            }
          }
          // Node takes the first condition it supports, in the order the package lists them.
          while (isObject(target) && !Array.isArray(target)) target = target[Object.keys(target).find(k => k === 'node' || k === 'import' || k === 'default') ?? ''];
          if (typeof target !== 'string') throw e;
          resolved = path.resolve(pkg, match === undefined ? target : target.replaceAll('*', match));
        } else if (path.dirname(dir) === dir) throw e;
      }
    }
  }
  return dynamicImport(pathToFileURL(resolved).href);
}

function pluginsFrom(mod: unknown): ContainedFilePlugin[] {
  // import() gives a CommonJS module a default export holding module.exports, so the named exports come first.
  const value = prop(mod, 'plugins') ?? prop(prop(mod, 'default'), 'plugins') ?? prop(mod, 'plugin') ?? prop(prop(mod, 'default'), 'plugin') ?? prop(mod, 'default');
  const list: unknown[] = Array.isArray(value) ? value : [value];
  for (const p of list) if (!p || prop(p, 'kind') !== 'file') throw new UsageError('A plugin module must export plugins with kind "file"');
  // The loop above checked each entry's kind, which is as far as a plugin's shape can be checked here.
  return list as ContainedFilePlugin[];
}

interface Parsed {
  command: string;
  positional: string[];
  options: ArchiveOptions;
  json: boolean;
}

async function parse(argv: string[]): Promise<Parsed> {
  const [command, ...rest] = argv;
  if (command !== 'inspect' && command !== 'defuse') throw new UsageError(command ? `Unknown command "${command}"` : 'No command');
  const positional: string[] = [];
  // Every --config module goes in first and the flags apply on top, wherever they sit on the command line.
  const options: ArchiveOptions = {};
  const ordered: ContainedFilePlugin[] = [];
  const limits: ArchiveLimits = {};
  let stripMetadata = false;
  let json = false;
  let password: string | string[] | undefined = process.env.ARCHIVE_DEFUSE_PASSWORD;
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const next = () => {
      const v = rest[++i];
      if (v === undefined) throw new UsageError(`${a} needs a value`);
      return v;
    };
    switch (a) {
      case '--password-file':
        // The empty password is always tried, so a blank line adds nothing.
        password = (await fsp.readFile(next(), 'utf8'))
          .split('\n')
          .map(line => line.replace(/\r$/, ''))
          .filter(line => line !== '');
        break;
      case '--plugin':
        ordered.push(...pluginsFrom(await loadModule(next())));
        break;
      case '--config': {
        const mod = await loadModule(next());
        // The module's shape is the caller's to get right, as ArchiveOptions documents it.
        const cfg = (prop(mod, 'default') ?? mod) as ArchiveOptions;
        // Modules combine: plugin lists join in order and limits merge. For any other option the later module wins.
        Object.assign(options, cfg, {
          filePlugins: [...(options.filePlugins ?? []), ...(cfg.filePlugins ?? [])],
          limits: { ...options.limits, ...cfg.limits },
        });
        break;
      }
      case '--keep-type':
        ordered.push(passThrough([next()]));
        break;
      case '--defuse-inner-archives':
        ordered.push(archivePlugin());
        break;
      case '--strip-metadata':
        stripMetadata = true;
        break;
      case '--limit': {
        const [name, value] = next().split('=');
        if (value === undefined) throw new UsageError('--limit expects name=value');
        if (name === 'fileSize' || name === 'decompressedBytes' || name === 'totalDecompressedBytes' || name === 'dictionaryBytes') limits[name] = parseSize(value);
        else if (name === 'entries' || name === 'compressionRatio' || name === 'nestingDepth' || name === 'timeMs') {
          // Number('abc') is NaN, and no comparison with NaN is true, so the limit would never apply.
          if (!/^\d+$/.test(value.trim())) throw new UsageError(`Bad value for ${name}: "${value}"`);
          limits[name] = Number(value);
        } else throw new UsageError(`Unknown limit "${name}"`);
        break;
      }
      case '--json':
        json = true;
        break;
      default:
        if (a === '--password' || a.startsWith('--password=')) throw new UsageError('Pass the password with --password-file or ARCHIVE_DEFUSE_PASSWORD, not on the command line');
        // What follows "=" can be a secret typed in the wrong place, and stderr often ends up in a log.
        if (a.startsWith('--')) throw new UsageError(`Unknown option ${a.replace(/=.*/s, '=...')}`);
        positional.push(a);
    }
  }
  if (stripMetadata) options.stripMetadata = true;
  if (ordered.length) options.filePlugins = [...(options.filePlugins ?? []), ...ordered];
  if (Object.keys(limits).length) options.limits = { ...(options.limits ?? {}), ...limits };
  if (password !== undefined) options.password = password;
  return { command, positional, options, json };
}

/**
 * The input as a source. stdin is copied to a temporary file first. The copy stops one byte past `fileSize`, so the
 * engine rejects the upload as too large without the rest being read, and at the deadline, where the source then
 * fails the run for time.
 */
async function inputSource(p: string, tempDir: string | undefined, fileSize: number | undefined, deadline: number | undefined): Promise<{ source: ByteSource; cleanup: () => Promise<void> }> {
  if (p !== '-') {
    return {
      source: fileSource(p),
      cleanup: async () => {
        // The caller's own file stays.
      },
    };
  }
  const temp = new TempDir(tempDir);
  try {
    const file = await temp.file('.bin');
    let room = (fileSize ?? Number.POSITIVE_INFINITY) + 1;
    try {
      await pipeline(
        process.stdin,
        async function* (chunks: AsyncIterable<Buffer>) {
          for await (const c of chunks) {
            yield c.subarray(0, room);
            room -= c.length;
            if (room <= 0) return;
          }
        },
        fs.createWriteStream(file),
        { signal: deadline === undefined ? undefined : AbortSignal.timeout(Math.max(0, deadline - Date.now())) },
      );
    } catch (e) {
      if ((e as Error).name !== 'AbortError') throw e;
      const late = () => Promise.reject(new TimeLimitError('Time limit exceeded'));
      return { source: { size: late, read: late }, cleanup: () => temp.cleanup() };
    }
    return { source: fileSource(file), cleanup: () => temp.cleanup() };
  } catch (e) {
    await temp.cleanup();
    throw e;
  }
}

/** Writes a control character as a JSON escape, since text from the archive could otherwise drive the terminal. */
const escaped = (c: string) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`;

function report(label: string, i: ArchiveInspection): string {
  const lines = [`${label}: ${i.status}, risk ${i.risk}${i.score === null ? '' : ` (score ${i.score})`}, ${i.format ?? 'unknown format'}, ${i.entries ?? 0} entries`];
  for (const f of i.findings) lines.push(`  ${f.action.padEnd(6)} ${f.category}/${f.detail}${f.location ? ` [${f.location}]` : ''}: ${f.description}`);
  // A location can hold an entry name from the archive. A line break in one would print a line of its own.
  return lines.map(l => l.replace(/\p{Cc}/gu, escaped)).join('\n');
}

export async function main(argv: string[]): Promise<number> {
  let parsed: Parsed;
  try {
    parsed = await parse(argv);
  } catch (e) {
    process.stderr.write(`${(e as Error).message}\n\n${USAGE}\n`);
    return 3;
  }
  const { command, positional, options, json } = parsed;
  try {
    if (command === 'inspect' && positional.length !== 1) throw new UsageError('inspect takes one file');
    if (command === 'defuse' && positional.length !== 2) throw new UsageError('defuse takes an input and an output');
    const toStdout = command === 'defuse' && positional[1] === '-';
    if (command === 'defuse' && positional[0] !== '-' && !toStdout) {
      // A failed write deletes the partial output, which here would be the only copy of the input.
      const [a, b] = await Promise.all([fsp.stat(positional[0]), fsp.stat(positional[1]).catch(() => undefined)]);
      if (b && a.dev === b.dev && a.ino === b.ino) throw new UsageError('The input and the output are the same file');
    }
    // Reading stdin counts toward the time limit, so the run gets what is left of it.
    const deadline = options.limits?.timeMs === undefined ? undefined : Date.now() + options.limits.timeMs;
    const input = await inputSource(positional[0], options.tempDir, options.limits?.fileSize, deadline);
    const runOptions = deadline === undefined ? options : { ...options, limits: { ...options.limits, timeMs: deadline - Date.now() } };
    let text: string;
    let code: number;
    try {
      if (command === 'inspect') {
        const r = await inspectArchiveSource(input.source, runOptions);
        text = json ? JSON.stringify(r, null, 2) : report('inspection', r);
        code = r.status === 'clean' ? 0 : r.status === 'strippable' ? 1 : 2;
      } else {
        const r = await disarmArchiveSource(input.source, toStdout ? writableSink(process.stdout) : fileSink(positional[1]), runOptions);
        text = json ? JSON.stringify(r, null, 2) : [`result: ${r.status}`, report('before', r.before), ...(r.after && r.status === 'defused' ? [report('after', r.after)] : [])].join('\n');
        code = r.status === 'clean' ? 0 : r.status === 'defused' ? 1 : 2;
      }
    } finally {
      await input.source.close?.();
      await input.cleanup();
    }
    // JSON.stringify escapes C0 controls but not DEL or the C1 range.
    if (json) text = text.replace(/[\u007f-\u009f]/g, escaped);
    // The report shares stdout only when the archive goes elsewhere. A report nobody can read is an I/O error.
    const out = toStdout ? process.stderr : process.stdout;
    await new Promise<void>((resolve, reject) => out.write(`${text}\n`, e => (e ? reject(e) : resolve())));
    return code;
  } catch (e) {
    process.stderr.write(`${e instanceof UsageError ? `${e.message}\n\n${USAGE}` : `Error: ${(e as Error).message}`}\n`);
    return 3;
  }
}

if (require.main === module) {
  // main() learns of a failed write from its callback. Node emits the failure as an 'error' event as well, which
  // with no listener would end the process with exit code 1.
  for (const stream of [process.stdout, process.stderr]) {
    stream.on('error', () => {
      process.exitCode = 3;
    });
  }
  main(process.argv.slice(2)).then(code => {
    process.exitCode = code;
  });
}
