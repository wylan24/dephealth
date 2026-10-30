import type { Finding, Hints, Level, Severity, Vulnerability } from '../types.ts';
import { sortVersions } from '../versions.ts';

const LEVEL: Record<Severity, Level> = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', unknown: 'medium' };
const PENALTY: Record<Severity, number> = { critical: 40, high: 25, moderate: 10, low: 3, unknown: 10 };
export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'moderate', 'low', 'unknown'];

export function analyzeInsecure(name: string, direct: boolean, via: string[], vulns: Vulnerability[], hints: Hints): Finding[] {
  const sorted = [...vulns].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  let budget = 60; // several advisories on one package shouldn't zero the score on their own
  // the lowest version that clears *every* advisory, when all of them have a fix
  const fixes = sortVersions(hints.scheme, vulns.map((v) => v.fixedIn).filter((f): f is string => !!f));
  const clearsAll = fixes.length === vulns.length && fixes.length ? fixes.at(-1) : undefined;
  const all = vulns.length > 1 && clearsAll ? ` (fixes ${vulns.length === 2 ? 'both' : `all ${vulns.length}`} advisories)` : '';
  return sorted.map((v) => {
    const target = clearsAll ?? v.fixedIn;
    const penalty = Math.min(PENALTY[v.severity], budget);
    budget -= penalty;
    const origin = direct ? 'direct dependency' : `pulled in by ${via.slice(0, 3).join(', ')}${via.length > 3 ? ` and ${via.length - 3} more` : ''}`;
    let fix: string;
    if (v.id.startsWith('MAL-')) fix = `Remove ${name} immediately and rotate any secrets on machines that installed it`;
    else if (!v.fixedIn) fix = `No fixed version published; replace ${name} or confirm the vulnerable code path is not used`;
    else if (direct) fix = `Upgrade to ${hints.pin(name, target!)} or later${all}`;
    else {
      const others = via.length - 1;
      const parents = others > 0 ? `${via[0]} (or the ${others} other ${others > 1 ? 'dependencies that pull' : 'dependency that pulls'} it in)` : (via[0] ?? 'the parent package');
      fix = `Upgrade ${parents} to a release that pulls ${name} >= ${target}, or ${hints.override(name, target!)}${all}`;
    }
    return {
      category: 'insecure' as const,
      level: LEVEL[v.severity],
      code: 'vuln',
      message: `${v.id} (${v.severity}): ${v.summary} — ${origin}; reachability: unknown`,
      penalty,
      fix,
      advisory: v.id,
      severity: v.severity,
    };
  });
}
