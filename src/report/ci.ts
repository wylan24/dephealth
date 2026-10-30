import { SEVERITY_ORDER } from '../analyzers/insecure.ts';
import type { PackageReport, Report, Severity } from '../types.ts';
import { activeFindings } from './score.ts';

export const RULE_HELP = `CI rules (comma-separated, any violation exits 1):
  vuln:<severity>         any vulnerability at or above critical|high|moderate|low
  vuln-direct:<severity>  same, direct dependencies only
  deprecated[:direct]     any deprecated package (or only direct ones)
  abandoned[:direct]      any package judged abandoned
  outdated:major          any direct dependency a major version behind
  score<N                 any direct dependency scoring below N
  avg<N                   average direct-dependency score below N
  libyear>N               total libyears of direct dependencies above N`;

export interface Violation {
  rule: string;
  packages: string[];
  message: string;
}

const atLeast = (s: Severity, min: Severity) => SEVERITY_ORDER.indexOf(s) <= SEVERITY_ORDER.indexOf(min);

export function parseRules(rules: string[]): string[] {
  const valid = /^(vuln(-direct)?:(critical|high|moderate|low)|deprecated(:direct)?|abandoned(:direct)?|outdated:major|score<\d+|avg<\d+|libyear>\d+(\.\d+)?)$/;
  const out = rules.flatMap((r) => r.split(',')).map((r) => r.trim()).filter(Boolean);
  for (const r of out) if (!valid.test(r)) throw new Error(`Unknown CI rule "${r}".\n${RULE_HELP}`);
  return out;
}

export function evaluate(report: Report, rules: string[]): Violation[] {
  const violations: Violation[] = [];
  const pkgs = report.packages.filter((p) => p.assessed);
  const hit = (rule: string, list: PackageReport[], message: string) => {
    if (list.length) violations.push({ rule, packages: list.map((p) => p.id), message });
  };
  const has = (p: PackageReport, code: string, category?: string) =>
    activeFindings(p).some((f) => f.code === code && (!category || f.category === category));

  for (const rule of rules) {
    let m: RegExpExecArray | null;
    if ((m = /^vuln(-direct)?:(\w+)$/.exec(rule))) {
      const min = m[2] as Severity;
      const list = pkgs.filter((p) => (!m![1] || p.direct) && activeFindings(p).some((f) => f.category === 'insecure') && p.vulnerabilities.some((v) => atLeast(v.severity, min)));
      hit(rule, list, `${list.length} package(s) with ${min}+ vulnerabilities`);
    } else if ((m = /^(deprecated|abandoned)(:direct)?$/.exec(rule))) {
      const code = m[1];
      const list = pkgs.filter((p) => (!m![2] || p.direct) && (has(p, code, 'abandoned') || (code === 'abandoned' && (has(p, 'archived') || has(p, 'deprecated')))));
      hit(rule, list, `${list.length} ${code} package(s)`);
    } else if (rule === 'outdated:major') {
      const list = pkgs.filter((p) => p.direct && has(p, 'major-behind'));
      hit(rule, list, `${list.length} direct dependencies are a major version behind`);
    } else if ((m = /^score<(\d+)$/.exec(rule))) {
      const n = Number(m[1]);
      const list = pkgs.filter((p) => p.direct && p.score < n);
      hit(rule, list, `${list.length} direct dependencies score below ${n}`);
    } else if ((m = /^avg<(\d+)$/.exec(rule))) {
      if (report.summary.averageScore < Number(m[1])) violations.push({ rule, packages: [], message: `average score ${report.summary.averageScore} is below ${m[1]}` });
    } else if ((m = /^libyear>([\d.]+)$/.exec(rule))) {
      if (report.summary.totalLibyear > Number(m[1])) violations.push({ rule, packages: [], message: `total libyear ${report.summary.totalLibyear} exceeds ${m[1]}` });
    }
  }
  return violations;
}
