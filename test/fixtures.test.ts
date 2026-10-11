import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { type ArchiveOptions, allFindingSpecs, disarmArchive, inspectArchive } from '../src';
import { fixture, fixtures, hasZstd, line, pluginsOf } from './helpers/util';

interface Case {
  file: string;
  about: string;
  plugins: string[];
  options: ArchiveOptions;
  inspect: string;
  disarm: string;
  findings: string[];
}

const manifest = JSON.parse(fs.readFileSync(path.join(fixtures, 'manifest.json'), 'utf8')) as { cases: Case[] };

/** A fixture with zstd in it, which a Node without zstd rejects as COMPRESSION/UNAVAILABLE. */
const needsZstd = (c: Case) => c.file.endsWith('.zst') || c.file === 'zip-bzip2-zstd.zip';

/** Kinds no fixture shows, which the test files named here assert. */
const ELSEWHERE: Record<string, string> = {
  'STRUCTURE/MALFORMED_HEADER': 'zip.test.ts',
  'NAME/SHORT_NAME_COLLISION': 'rules.test.ts',
  'ENCRYPTED/AES_192': 'engine.test.ts',
  'COMPRESSION/UNAVAILABLE': 'fixtures.test.ts, on a Node without zstd',
  'ENTRY/PLUGIN_SCRUBBED': 'plugin.test.ts',
  'ENTRY/PLUGIN_FAILED': 'plugin.test.ts',
  'ENTRY/PLUGIN_REMOVED': 'plugin.test.ts',
  'LIMIT/FILE_SIZE': 'limits.test.ts',
  'LIMIT/TIME': 'limits.test.ts',
  'PROCESSING/MEMORY_FALLBACK': 'engine.test.ts',
  'PROCESSING/VERIFICATION_FAILED': 'engine.test.ts',
};

describe('fixtures', () => {
  it('shows every kind of finding in a fixture, or names the test file that asserts it', () => {
    const shown = new Set(manifest.cases.flatMap(c => c.findings.map(f => f.split(' ')[1])));
    const lzma = JSON.parse(fs.readFileSync(path.join(fixtures, 'lzma', 'cases', 'manifest.json'), 'utf8')) as { cases: Record<string, { findings?: string[] }> };
    for (const e of Object.values(lzma.cases)) for (const f of e.findings ?? []) shown.add(f);
    const kinds = allFindingSpecs().map(s => `${s.category}/${s.detail}`);
    expect(kinds.filter(k => !shown.has(k) && !(k in ELSEWHERE))).to.deep.equal([]);
    expect(Object.keys(ELSEWHERE).filter(k => shown.has(k) || !kinds.includes(k))).to.deep.equal([]);
  });

  it('has a case for every fixture file', () => {
    // The xz, lzma and 7z fixtures sit in their own folder, with their own manifest.
    const files = fs.readdirSync(fixtures).filter(f => f !== 'manifest.json' && fs.statSync(path.join(fixtures, f)).isFile());
    expect(new Set(manifest.cases.map(c => c.file))).to.deep.equal(new Set(files));
  });

  for (const c of manifest.cases) {
    describe(`${c.file} ${JSON.stringify({ plugins: c.plugins, ...c.options })}`, () => {
      const options = (): ArchiveOptions => ({ ...c.options, filePlugins: pluginsOf(c.plugins) });

      it('inspects to the verdict and findings in the manifest', async () => {
        const r = await inspectArchive(fixture(c.file), options());
        if (needsZstd(c) && !hasZstd) {
          expect([r.status, r.findings.map(line).slice(-1)[0]]).to.deep.equal(['rejected', 'reject COMPRESSION/UNAVAILABLE']);
          return;
        }
        expect(r.status).to.equal(c.inspect);
        expect(r.findings.map(line)).to.deep.equal(c.findings);
        if (r.status === 'rejected' && r.findings.some(f => f.category === 'LIMIT' || f.category === 'CORRUPTED')) expect([r.score, r.risk]).to.deep.equal([null, 'UNKNOWN']);
      });

      it('disarms to the verdict in the manifest, with an output that inspects clean and disarms to the same bytes', async () => {
        if (needsZstd(c) && !hasZstd) return;
        const r = await disarmArchive(fixture(c.file), options());
        expect(r.status).to.equal(c.disarm);
        if (r.status === 'rejected') {
          expect(r.bytes).to.equal(undefined);
          return;
        }
        const bytes = r.bytes ?? Buffer.alloc(0);
        const again = await inspectArchive(bytes, options());
        expect(again.status).to.equal('clean');
        expect(again.findings.filter(f => f.action !== 'info')).to.deep.equal([]);
        const twice = await disarmArchive(bytes, options());
        expect(Buffer.from(twice.bytes ?? []).equals(Buffer.from(bytes))).to.equal(true);
      });
    });
  }
});
