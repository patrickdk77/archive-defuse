import { detectArchiveSource } from './detect';
import { disarmAtDepth, RUN_OPTIONS, type RunContext } from './engine';
import { weightOf } from './score';
import { extensionOf, typeFromName } from './sniff';
import type { ArchiveOptions, ContainedFilePlugin } from './types';

/**
 * Keeps contained files unchanged by type or by name, as pdf-defuse's passThrough does. An entry with a "/" is a MIME
 * type. Any other entry, such as ".csv" or "csv", is a file name extension.
 */
export function passThrough(types: string[]): ContainedFilePlugin {
  const set = new Set(types.filter(t => t.includes('/')).map(t => t.toLowerCase()));
  const exts = new Set(types.filter(t => !t.includes('/')).map(t => t.trim().toLowerCase().replace(/^\./, '')));
  return {
    kind: 'file',
    name: `passThrough(${types.join(',')})`,
    // Matches on type alone. Whether the content, the declared type and the name agree is the type check's finding.
    accepts: f => {
      const ext = extensionOf(f.name);
      if (ext !== undefined && exts.has(ext)) return true;
      return [f.sniffedType, f.declaredType, typeFromName(f.name)].some(t => t !== undefined && set.has(t.toLowerCase().split(';')[0].trim()));
    },
    process: async () => 'passed',
  };
}

/**
 * Defuses archives inside other files, with `options` when given. Without them, it takes the options of the
 * archive-defuse run that found the file, or none when another package found it. It accepts a file by its content,
 * whatever its name says. `limits.nestingDepth` applies to the depth in the context. The archive's findings go into
 * the containing file's report, and its output's findings into the output's report, each with its `weight`.
 */
export function archivePlugin(options?: ArchiveOptions): ContainedFilePlugin {
  return {
    kind: 'file',
    name: 'archive',
    // It takes what detectArchive claims, which is what the inspection reads, Brotli included: the content decides.
    accepts: async f => (await detectArchiveSource(f.source, { name: f.name, declaredType: f.declaredType })) !== undefined,
    async process(file, sink, context) {
      const run = options ?? (context as RunContext)[RUN_OPTIONS] ?? {};
      const r = await disarmAtDepth(file.source, sink, run, context.depth, context.deadline);
      // A container in another package scores these by the weights this run used.
      for (const f of [...r.before.findings, ...(r.after?.findings ?? [])]) f.weight = weightOf(f, run);
      const findings = r.before.findings;
      // The sink holds the rewritten archive, also when nothing was removed.
      if (r.status === 'clean') return { result: 'passed', findings, outputFindings: r.after?.findings };
      if (r.status === 'defused') return { result: 'scrubbed', findings, outputFindings: r.after?.findings };
      return { result: 'removed', findings };
    },
  };
}
