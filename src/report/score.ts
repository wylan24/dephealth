import type { Action, Category, Finding, PackageReport } from '../types.ts';

const isIgnored = (p: PackageReport, f: Finding) => !!p.ignored && (p.ignored.checks === 'all' || p.ignored.checks.includes(f.category));

export const activeFindings = (p: PackageReport) => p.findings.filter((f) => !isIgnored(p, f));

/** 0-100, starting at 100 and subtracting each non-ignored finding's penalty. */
export function score(p: PackageReport): number {
  const total = activeFindings(p).reduce((s, f) => s + f.penalty, 0);
  return Math.max(0, Math.min(100, 100 - total));
}

const LEVEL_WEIGHT = { critical: 100, high: 80, medium: 50, low: 25, info: 5 };
const CODE_BONUS: Record<string, number> = { vuln: 25, deprecated: 10, archived: 10, abandoned: 8, 'unsupported-major': 5, 'native-now': 10, 'major-behind': 0 };

/** One action per package and category, ranked; the report shows the top N. */
export function buildActions(packages: PackageReport[]): Action[] {
  const actions: Action[] = [];
  for (const p of packages) {
    const best = new Map<Category, Finding>();
    for (const f of activeFindings(p)) {
      if (f.level === 'info') continue;
      const cur = best.get(f.category);
      if (!cur || LEVEL_WEIGHT[f.level] + f.penalty > LEVEL_WEIGHT[cur.level] + cur.penalty) best.set(f.category, f);
    }
    for (const [category, f] of best) {
      const replacement = p.replacements[0];
      const fix =
        f.fix ??
        (replacement ? `Replace with ${replacement.name} (${replacement.effort}${replacement.source === 'search' ? ', candidate only' : ''})` : 'Review whether it is still needed');
      const drift = category === 'outdated' ? Math.min(10, Math.round((p.libyear ?? 0) * 2)) : 0;
      const priority = LEVEL_WEIGHT[f.level] + (CODE_BONUS[f.code] ?? 0) + (p.direct ? 10 : 0) - (p.dev ? 15 : 0) + drift;
      actions.push({ priority, package: `${p.name}@${p.version}`, category, title: fix, detail: f.message });
    }
  }
  return actions.sort((a, b) => b.priority - a.priority);
}
