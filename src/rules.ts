// The rules on names, links, special files and permissions. Each rule looks at the archive as it is and reports with
// its own action. A rule whose action is strip makes its own change: it fixes the name, clears the bit, drops the
// attribute or removes the entry. No rule reads another rule's action. Paths are walked part by part through maps,
// so the work grows with the length of the names, never with its square, and no regular expression that can
// backtrack runs on a name.
import type { FindingFactory } from './findings';
import type { Entry } from './model';
import { CONTROL, trimEnd, windowsReserved, windowsSafe } from './names';
import { ArchiveCategory as C, ArchiveDetail as D } from './types';

/** What the rules decided about one entry. */
export interface Decision {
  remove: boolean;
  /** The name to write. */
  name: string;
  mode?: number;
  dropCapabilities: boolean;
  /** For a hard link: the index of the entry it links to, when that is an entry before it. */
  linkIndex?: number;
}

export type Emit = (category: C, detail: D, e: Entry, data?: Record<string, string | number>) => void;

const SEPARATOR = /[/\\]/;
/** A ".." part, also with the dots and spaces Windows drops from the end of a name. */
const DOTDOT = /^\.\.[. ]*$/;
const DRIVE = /^(?:[/\\]{2}[?.][/\\])?[A-Za-z]:/;
const ABSOLUTE = /^[/\\]/;
const CONTROL_TEST = new RegExp(CONTROL.source, 'u');
const utf8Length = (s: string) => Buffer.byteLength(s, 'utf8');
/** The most parts a link target may have and still be followed. */
const MAX_LINK_PARTS = 4096;

/** `s` without the characters in `chars` at its start. */
function trimStart(s: string, chars: string): string {
  let start = 0;
  while (start < s.length && chars.includes(s[start])) start++;
  return s.slice(start);
}

/** The parts of a name between separators. A folder's name ends in "/", which is not an empty part. */
const partsOf = (name: string) => (/[/\\]$/.test(name) ? name.slice(0, -1) : name).split(SEPARATOR);

/** A name without the slashes that end a folder's name. */
const exactKey = (n: string) => trimEnd(n, '/');
/** Equal for names a file system that normalizes Unicode, including compatibility forms such as ligatures, takes as one. */
const normalKey = (n: string) => exactKey(n).normalize('NFKD');
/** Equal for names a file system that ignores case takes as one. Upper-casing first turns a sharp s into "SS". */
const foldKey = (n: string) => normalKey(n).toUpperCase().toLowerCase();

/** Applies every name rule whose action is strip, in a fixed order, to `name`. Each one changes only what it reports. */
function fixName(name: string, dir: boolean, strips: (d: D) => boolean): string {
  // The drive letter is set aside, so the other rules fix the rest of the name, and comes back unless DRIVE_LETTER strips.
  const drive = DRIVE.exec(name)?.[0] ?? '';
  let n = name.slice(drive.length);
  if (strips(D.Absolute)) n = trimStart(n, '/\\');
  // Split into parts with the separator after each, so a rule that keeps backslashes keeps them where they were.
  const tokens = n.split(/([/\\])/);
  const parts: Array<{ part: string; sep: string }> = [];
  for (let i = 0; i < tokens.length; i += 2) parts.push({ part: tokens[i], sep: tokens[i + 1] ?? '' });
  const lead = Math.max(
    0,
    parts.findIndex(p => p.part !== ''),
  );
  let kept = parts.filter((p, i) => {
    if (strips(D.Traversal) && DOTDOT.test(p.part)) return false;
    // A leading empty part is the absolute path's, which ABSOLUTE decides, and a trailing one a folder's slash.
    if (strips(D.EmptySegment) && (p.part === '.' || (p.part === '' && i > lead && i < parts.length - 1))) return false;
    return true;
  });
  if (strips(D.ControlCharacter)) kept = kept.map(p => ({ ...p, part: p.part.replace(new RegExp(CONTROL.source, 'gu'), '_') }));
  if (strips(D.WindowsReserved)) kept = kept.map(p => (DOTDOT.test(p.part) ? p : { ...p, part: windowsSafe(p.part) }));
  n = kept.map((p, i) => p.part + (i < kept.length - 1 ? p.sep || '/' : '')).join('');
  if (!strips(D.DriveLetter)) n = drive + n;
  if (strips(D.Backslash)) n = n.replace(/\\/g, '/');
  // A name the rewrite ends in "/" is a folder to every reader, so only a folder keeps its slash.
  n = trimEnd(n, '/');
  if (n === '') return '';
  return dir ? `${n}/` : n;
}

/**
 * The name rules a name breaks, in the order they report. `applyRules` reports these, and `createArchive` refuses a
 * name that breaks any but TOO_LONG. A ".." part is TRAVERSAL's alone, and empty parts at the start belong to an
 * absolute or UNC path, which ABSOLUTE reports.
 */
export function nameDetails(name: string, backslashIsSeparator: boolean): D[] {
  const parts = partsOf(name.replace(DRIVE, ''));
  const found: D[] = [];
  if (name === '' || name === '/') found.push(D.Empty);
  if (DRIVE.test(name)) found.push(D.DriveLetter);
  if (ABSOLUTE.test(name) || ABSOLUTE.test(name.replace(DRIVE, ''))) found.push(D.Absolute);
  if (parts.some(p => DOTDOT.test(p))) found.push(D.Traversal);
  const lead = parts.findIndex(p => p !== '');
  if (parts.some((p, j) => p === '.' || (p === '' && j > lead && lead >= 0))) found.push(D.EmptySegment);
  if (backslashIsSeparator && name.includes('\\')) found.push(D.Backslash);
  if (CONTROL_TEST.test(name)) found.push(D.ControlCharacter);
  if (parts.some(p => windowsReserved(p) && !DOTDOT.test(p))) found.push(D.WindowsReserved);
  if (utf8Length(name) > 4096 || parts.some(p => utf8Length(p) > 255)) found.push(D.TooLong);
  return found;
}

/** A tree of path parts. Maps, not objects, so a part named "__proto__" is only a name. */
class PathTree {
  readonly children = new Map<string, PathTree>();
  /** A symbolic link's target, at the node the link names. */
  link?: string;
  explicitDir = false;
  /** The long names in this folder, by the 8.3 alias they could get. */
  aliases?: Map<string, Set<string>>;
  child(part: string, create: boolean): PathTree | undefined {
    let c = this.children.get(part);
    if (!c && create) {
      c = new PathTree();
      this.children.set(part, c);
    }
    return c;
  }
}

/** The node for `parts`, created when `create` is set. */
function walk(root: PathTree, parts: string[], create: boolean): PathTree | undefined {
  let node: PathTree | undefined = root;
  for (const p of parts) {
    node = node.child(p, create);
    if (!node) return undefined;
  }
  return node;
}

/**
 * Where a symbolic link's target leads, from the folder the link sits in, following the archive's other links by their
 * case-folded names. Undefined when it leaves the extraction folder, when it is too long to follow, or when links lead
 * to each other more than 40 times in all.
 */
function resolveLink(from: string[], target: string, links: PathTree, budget: { hops: number }): string[] | undefined {
  if (ABSOLUTE.test(target) || DRIVE.test(target)) return undefined;
  const parts = target.split(SEPARATOR);
  if (parts.length > MAX_LINK_PARTS) return undefined;
  // The path so far, and the tree node of each prefix of it, so a ".." steps back without walking from the root.
  const path = [...from];
  const nodesOf = (p: string[]) => {
    const nodes: Array<PathTree | undefined> = [links];
    for (const x of p) nodes.push(nodes[nodes.length - 1]?.child(x, false));
    return nodes;
  };
  let nodes = nodesOf(path);
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (DOTDOT.test(part)) {
      if (!path.length) return undefined;
      path.pop();
      nodes.pop();
      continue;
    }
    const key = foldKey(part);
    path.push(key);
    const node = nodes[nodes.length - 1]?.child(key, false);
    nodes.push(node);
    if (node?.link === undefined) continue;
    if (--budget.hops < 0) return undefined;
    const resolved = resolveLink(path.slice(0, -1), node.link, links, budget);
    if (resolved === undefined) return undefined;
    path.length = 0;
    path.push(...resolved);
    nodes = nodesOf(path);
  }
  return path;
}

/** The parts of the 8.3 alias Windows could give a long name: the first six characters of its base and three of its extension. */
function aliasKey(name: string): string | undefined {
  const dot = name.lastIndexOf('.');
  const rawBase = dot > 0 ? name.slice(0, dot) : name;
  const rawExt = dot > 0 ? name.slice(dot + 1) : '';
  // A name that already fits 8.3 is its own short name and gets no alias.
  if (rawBase.length <= 8 && rawExt.length <= 3 && /^[A-Za-z0-9_^$~!#%&{}@`'()-]*$/.test(rawBase + rawExt)) return undefined;
  const clean = (s: string) =>
    s
      .toUpperCase()
      .replace(/[ .]/g, '')
      .replace(/[+,;=[\]]/g, '_');
  return `${clean(rawBase).slice(0, 6)}|${clean(rawExt).slice(0, 3)}`;
}
/** The prefix and extension of a name in the form of an alias, such as PROGRA~1. */
const ALIAS = /^([^~.\\/]{1,6})~[1-9][0-9]{0,5}(?:\.([^.\\/]{0,3}))?$/;

/** Runs the rules over the entries of an archive. Single-file formats with no name skip the name rules. */
export function applyRules(entries: Entry[], factory: FindingFactory, emit: Emit, options: { names: boolean; backslashIsSeparator: boolean }): Decision[] {
  const strips = (d: D, c = C.Name) => factory.strips(c, d);
  const decisions: Decision[] = entries.map(e => ({ remove: false, name: e.name, mode: e.mode, dropCapabilities: false }));

  // Names, each rule on the name as the archive gives it.
  if (options.names) {
    for (const [i, e] of entries.entries()) {
      const name = e.name;
      const found = nameDetails(name, options.backslashIsSeparator);
      const tooLong = found.includes(D.TooLong);
      // A drive letter is DRIVE_LETTER's. The rest of the name, "..\\x" in "C:..\\x", is what the other rules read.
      for (const detail of found) {
        if (detail === D.Empty) emit(C.Name, detail, e);
        else if (detail === D.TooLong) emit(C.Name, detail, e, { name, bytes: utf8Length(name), parts: partsOf(name.replace(DRIVE, '')).length });
        else emit(C.Name, detail, e, { name });
      }
      const d = decisions[i];
      d.name = fixName(name, e.kind === 'directory', x => (x === D.Backslash && !options.backslashIsSeparator ? false : strips(x)));
      if (d.name === '' && (name !== '' || strips(D.Empty))) d.remove = true;
      if (tooLong && strips(D.TooLong)) d.remove = true;
    }
  }

  // Collisions, on the names the output would have.
  const groups = (key: (n: string) => string) => {
    const m = new Map<string, number[]>();
    for (const [i, d] of decisions.entries()) {
      if (d.name === '') continue;
      const k = key(d.name);
      const list = m.get(k);
      if (list) list.push(i);
      else m.set(k, [i]);
    }
    return m;
  };
  const notDir = (i: number) => entries[i].kind !== 'directory';
  for (const list of groups(exactKey).values()) {
    const files = list.filter(notDir);
    if (files.length < 2) continue;
    // Readers that overwrite keep the last copy, and that is the one the rewrite keeps.
    for (const i of files.slice(0, -1)) {
      emit(C.Name, D.Duplicate, entries[i], { name: entries[i].name });
      if (strips(D.Duplicate)) decisions[i].remove = true;
    }
  }
  const collide = (key: (n: string) => string, inner: (n: string) => string, detail: D) => {
    for (const list of groups(key).values()) {
      if (list.length < 2 || list.every(i => !notDir(i))) continue;
      const last = list[list.length - 1];
      for (const i of list) {
        if (inner(decisions[i].name) === inner(decisions[last].name)) continue;
        emit(C.Name, detail, entries[i], { name: entries[i].name, other: entries[last].name });
        if (strips(detail)) decisions[i].remove = true;
      }
    }
  };
  collide(normalKey, exactKey, D.NormalizationCollision);
  collide(foldKey, normalKey, D.CaseCollision);

  // The tree of the output's names, as written and case-folded: the folders the archive lists, every folder a name
  // needs, and the symbolic links.
  const tree = new PathTree();
  const folded = new PathTree();
  const finalParts = decisions.map(d => (d.name === '' ? [] : exactKey(d.name).split('/')));
  for (const [i, parts] of finalParts.entries()) {
    if (!parts.length) continue;
    const node = walk(tree, parts, true);
    if (node && entries[i].kind === 'directory') node.explicitDir = true;
    const f = walk(
      folded,
      parts.map(p => foldKey(p)),
      true,
    );
    if (f && entries[i].kind === 'symlink' && entries[i].linkTarget !== undefined) f.link = entries[i].linkTarget;
  }
  // A file where a folder is needed: a folder the archive lists under the same name, or a folder some other entry
  // sits in. A link counts when the archive lists a folder of its name; a link other entries sit under is THROUGH_LINK's.
  for (const [i, parts] of finalParts.entries()) {
    const e = entries[i];
    if (!parts.length || e.kind === 'directory') continue;
    const node = walk(tree, parts, false);
    if (!node || !(node.explicitDir || (node.children.size > 0 && e.kind !== 'symlink'))) continue;
    emit(C.Name, D.FileDirectoryClash, e, { name: e.name });
    if (strips(D.FileDirectoryClash)) decisions[i].remove = true;
  }
  // A name in the form of an 8.3 alias that Windows could give a long name in the same folder. Each folder node of the
  // case-folded tree keeps the long names in it by the alias they could get.
  for (const parts of finalParts) {
    let node: PathTree | undefined = folded;
    for (const part of parts) {
      if (!node) break;
      const k = aliasKey(part);
      if (k !== undefined) {
        node.aliases ??= new Map();
        const names = node.aliases.get(k) ?? new Set<string>();
        node.aliases.set(k, names);
        names.add(part.toUpperCase());
      }
      node = node.child(foldKey(part), false);
    }
  }
  for (const [i, parts] of finalParts.entries()) {
    let node: PathTree | undefined = folded;
    for (const part of parts) {
      if (!node) break;
      const m = ALIAS.exec(part);
      const longNames = m ? node.aliases?.get(`${m[1].toUpperCase()}|${(m[2] ?? '').toUpperCase()}`) : undefined;
      if (longNames && [...longNames].some(n => n !== part.toUpperCase())) {
        emit(C.Name, D.ShortNameCollision, entries[i], { name: entries[i].name, alias: part });
        if (strips(D.ShortNameCollision)) decisions[i].remove = true;
        break;
      }
      node = node.child(foldKey(part), false);
    }
  }

  // Links.
  const byName = new Map<string, number>();
  for (const [i, e] of entries.entries()) {
    const d = decisions[i];
    if (e.kind === 'symlink') {
      emit(C.Link, D.Symlink, e, { name: e.name, target: e.linkTarget ?? '' });
      if (strips(D.Symlink, C.Link)) d.remove = true;
      const from = finalParts[i].slice(0, -1).map(p => foldKey(p));
      if (e.linkTarget === undefined || resolveLink(from, e.linkTarget, folded, { hops: 40 }) === undefined) {
        emit(C.Link, D.Outside, e, { name: e.name, target: e.linkTarget ?? '' });
        if (strips(D.Outside, C.Link)) d.remove = true;
      }
    } else if (e.kind === 'hardlink') {
      // A tar hard link names its target from the top of the archive, not from the folder the link sits in.
      const target = e.linkTarget ?? '';
      emit(C.Link, D.Hardlink, e, { name: e.name, target });
      if (strips(D.Hardlink, C.Link)) d.remove = true;
      if (ABSOLUTE.test(target) || DRIVE.test(target) || target.split(SEPARATOR).some(p => DOTDOT.test(p))) {
        emit(C.Link, D.Outside, e, { name: e.name, target });
        if (strips(D.Outside, C.Link)) d.remove = true;
      }
      const to = byName.get(target);
      if (to === undefined || entries[to].kind === 'directory') {
        emit(C.Link, D.Dangling, e, { name: e.name, target });
        if (strips(D.Dangling, C.Link)) d.remove = true;
      } else d.linkIndex = to;
    }
    byName.set(e.name, i);
  }
  // An entry under a symbolic link is written wherever the link points.
  for (const [i, parts] of finalParts.entries()) {
    let node: PathTree | undefined = folded;
    for (let j = 0; j < parts.length - 1 && node; j++) {
      node = node.child(foldKey(parts[j]), false);
      if (node?.link === undefined) continue;
      emit(C.Link, D.ThroughLink, entries[i], { name: entries[i].name, link: parts.slice(0, j + 1).join('/') });
      if (strips(D.ThroughLink, C.Link)) decisions[i].remove = true;
      break;
    }
  }

  // Special files.
  for (const [i, e] of entries.entries()) {
    if (e.anti) {
      emit(C.Special, D.AntiItem, e, { name: e.name });
      if (strips(D.AntiItem, C.Special)) decisions[i].remove = true;
    }
    const detail = e.kind === 'device' ? D.Device : e.kind === 'fifo' ? D.Fifo : e.kind === 'socket' ? D.Socket : e.kind === 'other' ? D.UnknownType : undefined;
    if (detail === undefined) continue;
    emit(C.Special, detail, e, { name: e.name, ...(e.typeCode ? { type: e.typeCode } : {}) });
    if (strips(detail, C.Special)) decisions[i].remove = true;
  }

  // Permissions: setuid, setgid and sticky bits on any entry, folders included.
  const bits: Array<[number, D]> = [
    [0o4000, D.Setuid],
    [0o2000, D.Setgid],
    [0o1000, D.Sticky],
  ];
  for (const [i, e] of entries.entries()) {
    const d = decisions[i];
    for (const [bit, detail] of bits) {
      if (e.mode === undefined || !(e.mode & bit)) continue;
      emit(C.Permissions, detail, e, { name: e.name, mode: `0${e.mode.toString(8)}` });
      if (strips(detail, C.Permissions)) d.mode = (d.mode ?? 0) & ~bit;
    }
    if (e.capabilities?.length) {
      emit(C.Permissions, D.Capability, e, { name: e.name, attribute: e.capabilities.join(', ') });
      if (strips(D.Capability, C.Permissions)) d.dropCapabilities = true;
    }
  }
  return decisions;
}
