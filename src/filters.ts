/**
 * The delta filter and the branch converters (BCJ filters) of xz and 7z, decoding only.
 *
 * The converters are ported from XZ for Java (0BSD) by Lasse Collin and Igor Pavlov, org.tukaani.xz.simple and
 * org.tukaani.xz.delta. Each `code` converts the instructions it can see whole and returns how many bytes it is done
 * with. SimpleFilterStream holds the rest back until more data comes, and passes it on unchanged at the end, as XZ for
 * Java's SimpleInputStream does.
 */

/** A branch converter: converts what it can of buf[off, off + len) in place and returns how many bytes it finished. */
interface SimpleFilter {
  code(buf: Uint8Array, off: number, len: number): number;
}

const getIntLE = (b: Uint8Array, i: number) => b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24);
const getIntBE = (b: Uint8Array, i: number) => (b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3];
function setIntLE(b: Uint8Array, i: number, v: number): void {
  b[i] = v;
  b[i + 1] = v >>> 8;
  b[i + 2] = v >>> 16;
  b[i + 3] = v >>> 24;
}
function setIntBE(b: Uint8Array, i: number, v: number): void {
  b[i] = v >>> 24;
  b[i + 1] = v >>> 16;
  b[i + 2] = v >>> 8;
  b[i + 3] = v;
}

const MASK_TO_ALLOWED_STATUS = [true, true, true, false, true, false, false, false];
const MASK_TO_BIT_NUMBER = [0, 1, 2, 2, 3, 3, 3, 3];
const test86MSByte = (b: number) => b === 0x00 || b === 0xff;

class X86 implements SimpleFilter {
  private pos: number;
  private prevMask = 0;
  constructor(startPos: number) {
    this.pos = startPos + 5;
  }
  code(buf: Uint8Array, off: number, len: number): number {
    let prevPos = off - 1;
    const end = off + len - 5;
    let i: number;
    for (i = off; i <= end; ++i) {
      if ((buf[i] & 0xfe) !== 0xe8) continue;
      prevPos = i - prevPos;
      if ((prevPos & ~3) !== 0) {
        this.prevMask = 0;
      } else {
        this.prevMask = (this.prevMask << (prevPos - 1)) & 7;
        if (this.prevMask !== 0 && (!MASK_TO_ALLOWED_STATUS[this.prevMask] || test86MSByte(buf[i + 4 - MASK_TO_BIT_NUMBER[this.prevMask]]))) {
          prevPos = i;
          this.prevMask = (this.prevMask << 1) | 1;
          continue;
        }
      }
      prevPos = i;
      if (test86MSByte(buf[i + 4])) {
        let src = getIntLE(buf, i + 1);
        let dest: number;
        for (;;) {
          dest = (src - (this.pos + i - off)) | 0;
          if (this.prevMask === 0) break;
          const index = MASK_TO_BIT_NUMBER[this.prevMask] * 8;
          if (!test86MSByte((dest >>> (24 - index)) & 0xff)) break;
          src = dest ^ ((1 << (32 - index)) - 1);
        }
        // Sign extend bit 24 to bits [31:24].
        dest = (dest << 7) >> 7;
        setIntLE(buf, i + 1, dest);
        i += 4;
      } else {
        this.prevMask = (this.prevMask << 1) | 1;
      }
    }
    prevPos = i - prevPos;
    this.prevMask = (prevPos & ~3) !== 0 ? 0 : this.prevMask << (prevPos - 1);
    i -= off;
    this.pos += i;
    return i;
  }
}

class PowerPC implements SimpleFilter {
  constructor(private pos: number) {}
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 4;
    let i: number;
    for (i = off; i <= end; i += 4) {
      if ((buf[i] & 0xfc) === 0x48 && (buf[i + 3] & 0x03) === 0x01) {
        const instr = getIntBE(buf, i);
        const pc = -(this.pos + i - off);
        setIntBE(buf, i, 0x48000001 | ((instr + pc) & 0x03fffffc));
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

const BRANCH_TABLE = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 6, 6, 0, 0, 7, 7, 4, 4, 0, 0, 4, 4, 0, 0];

class IA64 implements SimpleFilter {
  constructor(private pos: number) {}
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 16;
    let i: number;
    for (i = off; i <= end; i += 16) {
      const mask = BRANCH_TABLE[buf[i] & 0x1f];
      for (let slot = 0, bitPos = 5; slot < 3; ++slot, bitPos += 41) {
        if (((mask >>> slot) & 1) === 0) continue;
        const bytePos = bitPos >>> 3;
        const bitRes = BigInt(bitPos & 7);
        let instr = 0n;
        for (let j = 0; j < 6; ++j) instr |= BigInt(buf[i + bytePos + j]) << BigInt(8 * j);
        let instrNorm = instr >> bitRes;
        if (((instrNorm >> 37n) & 0x0fn) !== 0x05n || ((instrNorm >> 9n) & 0x07n) !== 0n) continue;
        let src = Number((instrNorm >> 13n) & 0x0fffffn);
        src |= Number((instrNorm >> 36n) & 1n) << 20;
        src <<= 4;
        let dest = (src - (this.pos + i - off)) | 0;
        dest >>>= 4;
        instrNorm &= ~(0x8fffffn << 13n);
        instrNorm |= BigInt(dest & 0x0fffff) << 13n;
        instrNorm |= BigInt(dest & 0x100000) << BigInt(36 - 20);
        instr &= (1n << bitRes) - 1n;
        instr |= instrNorm << bitRes;
        for (let j = 0; j < 6; ++j) buf[i + bytePos + j] = Number((instr >> BigInt(8 * j)) & 0xffn);
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

class ARM implements SimpleFilter {
  private pos: number;
  constructor(startPos: number) {
    this.pos = startPos + 8;
  }
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 4;
    let i: number;
    for (i = off; i <= end; i += 4) {
      if (buf[i + 3] === 0xeb) {
        const src = ((buf[i + 2] << 16) | (buf[i + 1] << 8) | buf[i]) << 2;
        const dest = ((src - (this.pos + i - off)) | 0) >>> 2;
        buf[i + 2] = dest >>> 16;
        buf[i + 1] = dest >>> 8;
        buf[i] = dest;
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

class ARMThumb implements SimpleFilter {
  private pos: number;
  constructor(startPos: number) {
    this.pos = startPos + 4;
  }
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 4;
    let i: number;
    for (i = off; i <= end; i += 2) {
      if ((buf[i + 1] & 0xf8) === 0xf0 && (buf[i + 3] & 0xf8) === 0xf8) {
        const src = (((buf[i + 1] & 0x07) << 19) | (buf[i] << 11) | ((buf[i + 3] & 0x07) << 8) | buf[i + 2]) << 1;
        const dest = ((src - (this.pos + i - off)) | 0) >>> 1;
        buf[i + 1] = 0xf0 | ((dest >>> 19) & 0x07);
        buf[i] = dest >>> 11;
        buf[i + 3] = 0xf8 | ((dest >>> 8) & 0x07);
        buf[i + 2] = dest;
        i += 2;
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

class SPARC implements SimpleFilter {
  constructor(private pos: number) {}
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 4;
    let i: number;
    for (i = off; i <= end; i += 4) {
      if ((buf[i] === 0x40 && (buf[i + 1] & 0xc0) === 0x00) || (buf[i] === 0x7f && (buf[i + 1] & 0xc0) === 0xc0)) {
        const src = getIntBE(buf, i);
        const pc = -((this.pos + i - off) >>> 2);
        let dest = (src + pc) | 0;
        dest = (dest << 9) >> 9;
        dest = 0x40000000 | (dest & 0x3fffffff);
        setIntBE(buf, i, dest);
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

class ARM64 implements SimpleFilter {
  constructor(private pos: number) {}
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 4;
    let i: number;
    for (i = off; i <= end; i += 4) {
      // Only the highest byte is needed to identify the BL and ADRP instructions.
      const top = buf[i + 3];
      if ((top & 0xfc) === 0x94) {
        // BL: the full 26-bit immediate.
        const instr = getIntLE(buf, i);
        const pc = -((this.pos + i - off) >>> 2);
        setIntLE(buf, i, 0x94000000 | ((instr + pc) & 0x03ffffff));
      } else if ((top & 0x9f) === 0x90) {
        // ADRP: only values in the range +/-512 MiB are converted.
        let instr = getIntLE(buf, i);
        const src = ((instr >>> 29) & 3) | ((instr >>> 3) & 0x001ffffc);
        if (((src + 0x00020000) & 0x001c0000) !== 0) continue;
        const pc = -((this.pos + i - off) >>> 12);
        const dest = (src + pc) | 0;
        instr &= 0x9000001f;
        instr |= (dest & 3) << 29;
        instr |= (dest & 0x0003fffc) << 3;
        instr |= -(dest & 0x00020000) & 0x00e00000;
        setIntLE(buf, i, instr);
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

class RISCV implements SimpleFilter {
  constructor(private pos: number) {}
  code(buf: Uint8Array, off: number, len: number): number {
    const end = off + len - 8;
    let i: number;
    for (i = off; i <= end; i += 2) {
      let inst = buf[i];
      if (inst === 0xef) {
        // JAL, only with rd = x1 (ra) or x5 (t0).
        const b1 = buf[i + 1];
        if ((b1 & 0x0d) !== 0) continue;
        const b2 = buf[i + 2];
        const b3 = buf[i + 3];
        const pc = this.pos + i - off;
        let addr = ((b1 & 0xf0) << 13) | (b2 << 9) | (b3 << 1);
        addr = (addr - pc) | 0;
        buf[i + 1] = (b1 & 0x0f) | ((addr >>> 8) & 0xf0);
        buf[i + 2] = ((addr >>> 16) & 0x0f) | ((addr >>> 7) & 0x10) | ((addr << 4) & 0xe0);
        buf[i + 3] = ((addr >>> 4) & 0x7f) | ((addr >>> 13) & 0x80);
        i += 4 - 2;
      } else if ((inst & 0x7f) === 0x17) {
        // AUIPC
        let inst2: number;
        inst |= buf[i + 1] << 8;
        inst |= buf[i + 2] << 16;
        inst |= buf[i + 3] << 24;
        if ((inst & 0xe80) !== 0) {
          // rd is neither x0 nor x2: a "fake" pair the encoder left alone, decoded the simple way.
          inst2 = getIntLE(buf, i + 4);
          if ((((inst << 8) ^ inst2) & 0xf8003) !== 3) {
            i += 6 - 2;
            continue;
          }
          const addr = (inst & 0xfffff000) + (inst2 >>> 20);
          inst = 0x17 | (2 << 7) | (inst2 << 12);
          inst2 = addr;
        } else {
          // rd is x0 or x2: the special format the encoder writes.
          const inst2Rs1 = inst >>> 27;
          if (((inst - 0x3100) & 0x3f80) >= (inst2Rs1 & 0x1d)) {
            i += 4 - 2;
            continue;
          }
          let addr = getIntBE(buf, i + 4);
          addr = (addr - (this.pos + i - off)) | 0;
          inst2 = (inst >>> 12) | (addr << 20);
          inst = 0x17 | (inst2Rs1 << 7) | ((addr + 0x800) & 0xfffff000);
        }
        setIntLE(buf, i, inst);
        setIntLE(buf, i + 4, inst2);
        i += 8 - 2;
      }
    }
    i -= off;
    this.pos += i;
    return i;
  }
}

/** The branch converters by name. */
export type BranchFilter = 'x86' | 'powerpc' | 'ia64' | 'arm' | 'armthumb' | 'sparc' | 'arm64' | 'riscv';

function makeSimple(kind: BranchFilter, start: number): SimpleFilter {
  switch (kind) {
    case 'x86':
      return new X86(start);
    case 'powerpc':
      return new PowerPC(start);
    case 'ia64':
      return new IA64(start);
    case 'arm':
      return new ARM(start);
    case 'armthumb':
      return new ARMThumb(start);
    case 'sparc':
      return new SPARC(start);
    case 'arm64':
      return new ARM64(start);
    default:
      return new RISCV(start);
  }
}

/** A filter that decodes data as it arrives and keeps its size. */
export interface Transform {
  /** Decodes `chunk`, which the transform may change in place, and returns what is ready. */
  push(chunk: Uint8Array): Uint8Array;
  /** Returns what was held back. */
  end(): Uint8Array;
}

/** Runs a branch converter over data that arrives in pieces, as XZ for Java's SimpleInputStream does. */
export class SimpleFilterStream implements Transform {
  private held: Uint8Array = new Uint8Array(0);
  private readonly filter: SimpleFilter;
  constructor(kind: BranchFilter, start: number) {
    this.filter = makeSimple(kind, start);
  }
  push(chunk: Uint8Array): Uint8Array {
    let buf: Uint8Array;
    if (this.held.length === 0) buf = chunk;
    else {
      buf = new Uint8Array(this.held.length + chunk.length);
      buf.set(this.held);
      buf.set(chunk, this.held.length);
    }
    const done = this.filter.code(buf, 0, buf.length);
    this.held = buf.slice(done);
    return buf.subarray(0, done);
  }
  end(): Uint8Array {
    const rest = this.held;
    this.held = new Uint8Array(0);
    return rest;
  }
}

/** The delta filter's decoder: each byte is added to the one `distance` bytes before it. */
export class DeltaStream implements Transform {
  private readonly history: Uint8Array;
  private pos = 0;
  constructor(private readonly distance: number) {
    this.history = new Uint8Array(256);
  }
  push(chunk: Uint8Array): Uint8Array {
    const h = this.history;
    const d = this.distance;
    for (let i = 0; i < chunk.length; i++) {
      const b = (chunk[i] + h[(this.pos - d) & 0xff]) & 0xff;
      chunk[i] = b;
      h[this.pos & 0xff] = b;
      this.pos++;
    }
    return chunk;
  }
  end(): Uint8Array {
    return new Uint8Array(0);
  }
}
