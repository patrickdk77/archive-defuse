import * as crypto from 'node:crypto';
import * as zlib from 'node:zlib';
import { expect } from 'chai';
import { type ByteSink, bufferSink, bufferSource, disarmArchive, disarmArchiveSource, inspectArchive, inspectArchiveSource } from '../src';
import { build, failure, keepAll, kinds, line } from './helpers/util';

const { zip, text, extra, u16, u32, winzipAes, crc32 } = build;
const keep = { filePlugins: [keepAll] };

describe('engine', () => {
  it('opens AES-192 entries and names the key size', async () => {
    const data = Buffer.from('a 192-bit key\n'.repeat(8));
    const field = extra(0x9901, Buffer.concat([u16(1), Buffer.from('AE'), Buffer.from([2]), u16(8)]));
    const bytes = zip([{ name: 'a.txt', data, flags: 1, method: 99, payload: winzipAes(zlib.deflateRawSync(data), 'middle', 2), crc: crc32(data), centralExtra: field, localExtra: field }]);
    const r = await inspectArchive(bytes, { ...keep, password: 'middle' });
    expect(r.findings.map(line)).to.deep.equal(['info ENCRYPTED/AES_192', 'strip ENCRYPTED/DECRYPTED', 'info ENTRY/PLUGIN_PASSED']);
  });

  it('reports an entry that went through a temporary file because it was over the memory threshold', async () => {
    const r = await inspectArchive(zip([text('a.txt', 'x'.repeat(5000))]), { ...keep, memoryThreshold: 100 });
    expect(kinds(r)).to.deep.equal(['PROCESSING/MEMORY_FALLBACK', 'ENTRY/PLUGIN_PASSED']);
  });

  it('rejects with VERIFICATION_FAILED and writes nothing when the rewrite cannot remove what it reports', async () => {
    // Incompressible bytes, then a directory and an end record whose comment covers the rest of the file. Compressed
    // afresh the entry gains nothing, so it stays stored and the other end record stays in the copy.
    const random = crypto.createHash('sha512');
    const noise = Buffer.concat(Array.from({ length: 64 }, (_, i) => random.copy().update(String(i)).digest()));
    const make = (junk: Buffer) => zip([{ name: 'junk.bin', data: junk, method: 0 }, text('readme.txt')]);
    const probe = make(Buffer.alloc(noise.length + 200, 0x2e));
    const realEnd = probe.length - 22;
    const cdSize = probe.readUInt32LE(realEnd + 12);
    const cd = probe.subarray(probe.readUInt32LE(realEnd + 16), realEnd);
    const placeholder = Buffer.alloc(noise.length + cdSize + 22, 0x2e);
    const first = make(placeholder);
    const at = first.indexOf(placeholder) + noise.length;
    const fake = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(2), u16(2), u32(cdSize), u32(at), u16(first.length - (at + cdSize) - 22)]);
    const bytes = make(Buffer.concat([noise, cd, fake]));
    expect(kinds(await inspectArchive(bytes, keep))).to.include('STRUCTURE/SEVERAL_END_RECORDS');
    const sink = bufferSink();
    const r = await disarmArchiveSource(bufferSource(bytes), sink, keep);
    expect([r.status, line(r.before.findings.slice(-1)[0])]).to.deep.equal(['rejected', 'reject PROCESSING/VERIFICATION_FAILED']);
    expect(sink.size()).to.equal(0);
  });

  it('closes the source when a run ends, and leaves the sink untouched when it rejects', async () => {
    let closed = 0;
    const bytes = zip([{ name: 'x', data: 'x', flags: 0x41 }]);
    const source = { ...bufferSource(bytes), close: async () => void closed++ };
    await inspectArchiveSource(source);
    let written = 0;
    const sink: ByteSink = { write: async () => void written++, close: async () => undefined };
    expect((await disarmArchiveSource({ ...bufferSource(bytes), close: async () => void closed++ }, sink)).status).to.equal('rejected');
    expect([closed, written]).to.deep.equal([2, 0]);
  });

  it('aborts the sink when copying the output fails', async () => {
    let aborted: unknown;
    const sink: ByteSink = {
      write: async () => Promise.reject(Object.assign(new Error('disk full'), { code: 'ENOSPC' })),
      close: async () => undefined,
      abort: async reason => {
        aborted = reason;
      },
    };
    const e = await failure(disarmArchiveSource(bufferSource(zip([text('a.txt')])), sink, keep));
    expect((e as { code?: string }).code).to.equal('ENOSPC');
    expect(aborted).to.equal(e);
  });

  it('throws an I/O error from the source instead of a verdict', async () => {
    const failing = { size: async () => 1000, read: async () => Promise.reject(Object.assign(new Error('read failed'), { code: 'EIO' })) };
    expect(((await failure(inspectArchiveSource(failing))) as { code?: string }).code).to.equal('EIO');
  });

  it('caps findings of one kind at 200 and counts the rest', async () => {
    const r = await inspectArchive(zip(Array.from({ length: 250 }, (_, i) => text(`../f${i}.txt`))), keep);
    const traversal = r.findings.filter(f => f.detail === 'TRAVERSAL');
    expect(traversal.length).to.equal(201);
    expect([traversal[200].location, traversal[200].data?.count]).to.deep.equal(['additional occurrences', 50]);
  });

  it('gives the same verdict for bytes and for a source', async () => {
    const bytes = zip([text('../a.txt')]);
    const a = await inspectArchive(bytes, keep);
    const b = await inspectArchiveSource(bufferSource(bytes), keep);
    expect(b).to.deep.equal(a);
    const d = await disarmArchive(bytes, keep);
    expect(d.status).to.equal('defused');
  });
});
