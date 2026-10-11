// Scoring as pdf-defuse src/score.ts does it, with archive-defuse's own combinations.
import { findingSpec } from './findings';
import { type ArchiveOptions, ArchiveRisk, type ArchiveScoreBands, ArchiveCategory as C, ArchiveDetail as D, type DefuseFinding } from './types';

export const DEFAULT_BANDS: ArchiveScoreBands = { low: 1, medium: 25, high: 50, critical: 80 };

interface Combination {
  name: string;
  weight: number;
  test(has: (c: C, d?: D) => boolean): boolean;
}

export const COMBINATIONS: Combination[] = [
  {
    name: 'a name that leaves the folder with a link that leaves it',
    weight: 20,
    test: has => (has(C.Name, D.Traversal) || has(C.Name, D.Absolute) || has(C.Name, D.DriveLetter)) && (has(C.Link, D.Outside) || has(C.Link, D.ThroughLink)),
  },
  { name: 'setuid or setgid with a link out of the folder', weight: 15, test: has => (has(C.Permissions, D.Setuid) || has(C.Permissions, D.Setgid)) && has(C.Link, D.Outside) },
  { name: 'a polyglot with data hidden inside', weight: 10, test: has => has(C.Structure, D.Polyglot) && (has(C.Structure, D.HiddenData) || has(C.Structure, D.Overlap)) },
];

/** The caller's weights first, then the built-in table. A kind from another package scores at the weight it carries. */
export function weightOf(f: DefuseFinding, options: ArchiveOptions): number {
  const w = options.scoreWeights ?? [];
  const exact = w.find(x => x.category === f.category && x.detail === f.detail);
  if (exact) return exact.weight;
  const cat = w.find(x => x.category === f.category && x.detail === undefined);
  if (cat) return cat.weight;
  return findingSpec(f.category, f.detail)?.weight ?? f.weight ?? 0;
}

/** Highest weight in full, a quarter of each other kind's weight, plus combinations, capped at 100. */
export function scoreFindings(findings: DefuseFinding[], options: ArchiveOptions): { score: number; risk: ArchiveRisk } {
  // Each kind of finding counts once, so twenty copies of one minor finding do not add up to a critical file.
  const byKind = new Map<string, number>();
  for (const f of findings) {
    const k = `${f.category}/${f.detail}`;
    byKind.set(k, Math.max(byKind.get(k) ?? 0, weightOf(f, options)));
  }
  const weights = [...byKind.values()].sort((a, b) => b - a);
  let score = weights.length ? weights[0] + weights.slice(1).reduce((s, w) => s + w / 4, 0) : 0;
  const has = (c: C, d?: D) => findings.some(f => f.category === c && (d === undefined || f.detail === d) && weightOf(f, options) > 0);
  for (const combo of COMBINATIONS) if (combo.test(has)) score += combo.weight;
  score = Math.min(100, Math.round(score));
  return { score, risk: riskFor(score, options.scoreBands ?? DEFAULT_BANDS) };
}

export function riskFor(score: number, bands: ArchiveScoreBands): ArchiveRisk {
  if (score >= bands.critical) return ArchiveRisk.Critical;
  if (score >= bands.high) return ArchiveRisk.High;
  if (score >= bands.medium) return ArchiveRisk.Medium;
  if (score >= bands.low) return ArchiveRisk.Low;
  return ArchiveRisk.None;
}
