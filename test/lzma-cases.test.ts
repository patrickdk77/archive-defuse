import { expect } from 'chai';
import { disarmArchive, inspectArchive } from '../src';
import { crc32 } from '../src/crc32';
import type { ContainedFile } from '../src/types';
import { fixture, keepAll, list7z, manifest, optionsFor } from './helpers/lzma';
import { kinds } from './helpers/util';

const cases = manifest();

describe('xz, lzma and 7z fixtures', () => {
  for (const [name, e] of Object.entries(cases)) {
    describe(name, () => {
      const bytes = fixture(name);

      it(`inspects as ${e.status}${e.findings ? ` with ${e.findings.join(', ')}` : ''}`, async () => {
        const r = await inspectArchive(bytes, optionsFor(e));
        expect(r.status, kinds(r).join(', ')).to.equal(e.status);
        for (const f of e.findings ?? []) expect(kinds(r)).to.include(f);
        if (e.entries !== undefined) expect(r.entries).to.equal(e.entries);
      });

      if (e.status === 'rejected') {
        it('writes nothing', async () => {
          const d = await disarmArchive(bytes, optionsFor(e));
          expect(d.status).to.equal('rejected');
          expect(d.bytes).to.equal(undefined);
        });
        return;
      }

      it('disarms to output that inspects clean and disarms again to the same bytes', async () => {
        const d = await disarmArchive(bytes, optionsFor(e));
        expect(d.status, kinds(d.before).join(', ')).to.equal(e.status === 'clean' ? 'clean' : 'defused');
        expect(d.bytes).to.be.instanceOf(Uint8Array);
        const out = d.bytes as Uint8Array;
        const again = await inspectArchive(out, optionsFor(e));
        expect(again.status, kinds(again).join(', ')).to.equal('clean');
        const d2 = await disarmArchive(out, optionsFor(e));
        expect(Buffer.compare(d2.bytes as Uint8Array, out)).to.equal(0);
      });

      if (e.content !== undefined) {
        it('hands the decoded content to the plugins', async () => {
          const seen: ContainedFile[] = [];
          await inspectArchive(bytes, { ...optionsFor(e), filePlugins: [keepAll(seen)] });
          expect(seen).to.have.length(1);
          const data = await seen[0].source.read(0, seen[0].size);
          expect(crc32(data)).to.equal(e.content);
        });
      }

      if (e.sniffed !== undefined) {
        it(`sniffs the content as ${e.sniffed}`, async () => {
          const seen: ContainedFile[] = [];
          await inspectArchive(bytes, { ...optionsFor(e), filePlugins: [keepAll(seen)] });
          expect(seen[0].sniffedType).to.equal(e.sniffed);
        });
      }

      if (e.names !== undefined || e.kept !== undefined || e.attribs !== undefined) {
        it('keeps the entries the rules allow, with fixed names', async () => {
          const d = await disarmArchive(bytes, optionsFor(e));
          const listed = await list7z(d.bytes as Uint8Array);
          if (e.names !== undefined) expect(listed.map(l => l.name)).to.deep.equal(e.names);
          if (e.kept !== undefined) expect(listed.filter(l => l.crc !== undefined).map(l => l.crc)).to.deep.equal(e.kept);
          if (e.attribs !== undefined) expect(listed.map(l => l.attrib)).to.deep.equal(e.attribs);
        });
      }
    });
  }
});
