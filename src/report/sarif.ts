import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { Ecosystem, Finding, Level, PackageReport, Report, Severity } from '../types.ts';
import { activeFindings } from './score.ts';

/**
 * SARIF 2.1.0 for GitHub code scanning. Each finding is anchored to the line of the manifest that
 * declares the dependency (or the lockfile, for transitive packages) and gets a fingerprint that
 * survives version bumps, so GitHub tracks one alert per problem rather than one per run.
 */

const LEVEL: Record<Level, 'error' | 'warning' | 'note' | 'none'> = { critical: 'error', high: 'error', medium: 'warning', low: 'note', info: 'none' };
// GitHub ranks code-scanning alerts by `security-severity` (CVSS-like 0-10)
const SECURITY_SEVERITY: Record<Severity, string> = { critical: '9.5', high: '8.0', moderate: '5.5', low: '2.0', unknown: '5.0' };

const RULES: Record<string, string> = {
  vuln: 'Dependency has a known vulnerability',
  deprecated: 'Dependency is deprecated by its author',
  archived: 'Dependency source repository is archived',
  'archived-recent': 'Dependency source repository was archived recently',
  abandoned: 'Dependency is likely abandoned',
  'at-risk': 'Dependency maintenance is at risk',
  legacy: 'Dependency is a legacy project in maintenance mode',
  'version-deprecated': 'Installed version is deprecated or yanked',
  'major-behind': 'Dependency is a major version behind',
  'unsupported-major': 'Installed major version no longer gets releases',
  'minor-behind': 'Dependency has a newer minor release',
  'native-now': 'Dependency is covered by a runtime built-in',
  'micro-utility': 'Dependency is replaceable by a line of code',
  'many-deps': 'Dependency pulls in many transitive packages',
  'install-size': 'Dependency has a large install size',
  'bundle-size': 'Dependency adds a lot to the browser bundle',
};

const MANIFESTS: Record<Ecosystem, string[]> = {
  npm: ['package.json'],
  PyPI: ['pyproject.toml', 'requirements.txt', 'requirements.in', 'requirements-dev.txt', 'requirements/base.txt'],
};

/** `name` written as a dependency on some line: `"name":`, `name = `, `name==`, `"name>=1"`… */
function lineOf(file: string, name: string, ecosystem: Ecosystem): number | undefined {
  const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  // PyPI names are case/punctuation-insensitive, so allow - _ . interchangeably
  const pattern = ecosystem === 'PyPI' ? name.split(/[-_.]+/).map(esc).join('[-_.]+') : esc(name);
  const re = new RegExp(`(^|["'\\s/])${pattern}(["'\\s=<>!~;@\\[:]|$)`, ecosystem === 'PyPI' ? 'i' : '');
  const lines = readFileSync(file, 'utf8').split(/\r?\n/);
  const i = lines.findIndex((l) => re.test(l));
  return i === -1 ? undefined : i + 1;
}

function locate(report: Report, p: PackageReport): { uri: string; line?: number } {
  const rel = (f: string) => path.relative(report.root, f).split(path.sep).join('/');
  if (p.direct) {
    for (const wsName of p.workspaces) {
      const ws = report.workspaces.find((w) => w.ecosystem === p.ecosystem && w.name === wsName);
      if (!ws) continue;
      for (const m of MANIFESTS[p.ecosystem]) {
        const file = path.join(report.root, ws.path, m);
        if (!existsSync(file)) continue;
        const line = lineOf(file, p.name, p.ecosystem);
        if (line) return { uri: rel(file), line };
      }
    }
  }
  const lock = report.lockfiles.find((l) => l.ecosystem === p.ecosystem);
  const lockFile = lock?.path?.split(',')[0].trim();
  if (lockFile && existsSync(path.join(report.root, lockFile))) {
    return { uri: lockFile, line: lineOf(path.join(report.root, lockFile), p.name, p.ecosystem) };
  }
  return { uri: MANIFESTS[p.ecosystem][0] };
}

const ruleId = (f: Finding) => (f.code === 'vuln' && f.advisory ? f.advisory : `dephealth/${f.code}`);

export function renderSarif(report: Report): string {
  const rules = new Map<string, Record<string, unknown>>();
  const results: Record<string, unknown>[] = [];

  for (const p of report.packages) {
    if (!p.assessed) continue;
    const loc = locate(report, p);
    for (const f of activeFindings(p)) {
      if (f.level === 'info') continue;
      const id = ruleId(f);
      if (!rules.has(id)) {
        const isVuln = f.code === 'vuln';
        rules.set(id, {
          id,
          name: isVuln ? 'KnownVulnerability' : f.code.replace(/(^|-)(\w)/g, (_, __, c: string) => c.toUpperCase()),
          shortDescription: { text: isVuln ? `${id}: ${f.message.replace(/^[^:]+:\s*/, '').split(' — ')[0]}` : (RULES[f.code] ?? f.code) },
          helpUri: isVuln ? `https://osv.dev/vulnerability/${id}` : 'https://github.com/wylan24/dephealth#the-checks',
          defaultConfiguration: { level: LEVEL[f.level] },
          properties: {
            tags: ['dependencies', f.category, ...(isVuln ? ['security'] : [])],
            ...(isVuln ? { 'security-severity': SECURITY_SEVERITY[f.severity ?? 'unknown'], precision: 'high' } : {}),
          },
        });
      }
      results.push({
        ruleId: id,
        level: LEVEL[f.level],
        message: { text: `${p.name}@${p.version} (${p.ecosystem}${p.direct ? '' : `, via ${p.via.slice(0, 3).join(', ')}`}): ${f.message}${f.fix ? `\nFix: ${f.fix}` : ''}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: loc.uri }, ...(loc.line ? { region: { startLine: loc.line } } : {}) } }],
        // version left out on purpose: bumping a still-broken package should update the alert, not open a new one
        partialFingerprints: { 'dephealth/v1': createHash('sha256').update(`${p.ecosystem}|${p.name}|${id}`).digest('hex').slice(0, 32) },
        properties: { ecosystem: p.ecosystem, package: p.name, version: p.version, direct: p.direct, score: p.score },
      });
    }
  }

  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'dephealth', version: report.tool.version, informationUri: 'https://github.com/wylan24/dephealth', rules: [...rules.values()] } },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2);
}
