import * as fs from 'node:fs';
import * as path from 'node:path';
import { expect } from 'chai';
import { disarmArchive, inspectArchive } from '../src';
import { keepAll, lzmaFixtures } from './helpers/lzma';
import { kinds } from './helpers/util';

// The .lzma files and the .xz files about LZMA2 from XZ Utils' tests/files, which lzma1's fork carries. Their README
// says what each tests. Good files must decode; bad files must not come out clean.
const dir = path.join(lzmaFixtures, 'xz-utils');
const files = fs.readdirSync(dir).filter(n => /\.(xz|lzma)$/.test(n));

describe('XZ Utils test files', () => {
  for (const name of files) {
    const bytes = fs.readFileSync(path.join(dir, name));
    if (name.startsWith('good-')) {
      it(`${name} is clean and disarms to output that inspects clean`, async () => {
        const options = { filePlugins: [keepAll()] };
        const r = await inspectArchive(bytes, options);
        expect(r.status, kinds(r).join(', ')).to.equal('clean');
        const d = await disarmArchive(bytes, options);
        expect(d.status).to.equal('clean');
        expect((await inspectArchive(d.bytes as Uint8Array, options)).status).to.equal('clean');
      });
    } else {
      it(`${name} does not come out clean`, async () => {
        const r = await inspectArchive(bytes, { filePlugins: [keepAll()] });
        expect(r.status).to.not.equal('clean');
      });
    }
  }

  it('reads an end marker before the declared size as a size mismatch, which the rewrite fixes', async () => {
    const r = await inspectArchive(fs.readFileSync(path.join(dir, 'bad-too_big_size-with_eopm.lzma')), { filePlugins: [keepAll()] });
    expect(kinds(r)).to.include('STRUCTURE/SIZE_MISMATCH');
    expect(r.status).to.equal('strippable');
  });

  it('rejects data that goes on past the declared size', async () => {
    for (const n of ['bad-too_small_size-without_eopm-1.lzma', 'bad-too_small_size-without_eopm-2.lzma', 'bad-too_small_size-without_eopm-3.lzma']) {
      const r = await inspectArchive(fs.readFileSync(path.join(dir, n)));
      expect(kinds(r), n).to.include('CORRUPTED/DATA_ERROR');
    }
  });
});
