import type { Finding, Hints, PackageReport, RegistryInfo } from '../types.ts';
import type { VersionScheme } from '../versions.ts';

const YEAR = 365.25 * 24 * 3600 * 1000;

export interface OutdatedResult {
  latest?: string;
  semverBehind?: PackageReport['semverBehind'];
  libyear?: number;
  findings: Finding[];
}

/** Latest release (by publish time) within the installed major line. */
function lastReleaseInLine(reg: RegistryInfo, major: number, scheme: VersionScheme): string | undefined {
  let best: string | undefined;
  for (const v of reg.versions) {
    if (!scheme.valid(v) || scheme.prerelease(v) || scheme.major(v) !== major || !reg.time[v]) continue;
    if (!best || reg.time[v] > reg.time[best]) best = v;
  }
  return best;
}

export function analyzeOutdated(name: string, version: string, reg: RegistryInfo, hints: Hints, now = new Date()): OutdatedResult {
  const findings: Finding[] = [];
  const { scheme } = hints;
  const latest = reg.latest;
  if (!latest || !scheme.valid(version) || !scheme.valid(latest)) return { latest, findings };

  if (reg.deprecated && !reg.latestDeprecated) {
    findings.push({
      category: 'outdated',
      level: 'medium',
      code: 'version-deprecated',
      message: `Installed version ${version} is deprecated: "${reg.deprecated}"`,
      penalty: 10,
      fix: hints.update(name, latest),
    });
  }

  const cmp = scheme.compare(version, latest);
  if (cmp >= 0) return { latest, semverBehind: cmp > 0 ? 'ahead' : 'none', libyear: 0, findings };

  let behind: PackageReport['semverBehind'] = scheme.diff(version, latest) ?? 'patch';
  // CalVer (2024.8 -> 2026.1, common on PyPI) bumps the "major" every year without breaking changes
  if (behind === 'major' && scheme.major(latest) >= 1990) behind = 'minor';
  const t0 = reg.time[version] ? Date.parse(reg.time[version]) : undefined;
  const t1 = reg.time[latest] ? Date.parse(reg.time[latest]) : undefined;
  const libyear = t0 && t1 ? Math.max(0, Math.round(((t1 - t0) / YEAR) * 100) / 100) : undefined;
  const drift = libyear ? Math.min(10, Math.floor(libyear * 2)) : 0;
  const ly = libyear !== undefined ? ` (${libyear} libyears)` : '';

  if (behind === 'major') {
    const majors = Math.max(1, scheme.major(latest) - scheme.major(version));
    findings.push({
      category: 'outdated',
      level: 'medium',
      code: 'major-behind',
      message: `${majors} major version${majors > 1 ? 's' : ''} behind: ${version} → ${latest}${ly}`,
      penalty: Math.min(20, 8 + 2 * majors) + drift,
      fix: `Upgrade to ${hints.pin(name, latest)} (check the changelog for breaking changes)`,
    });
    const line = scheme.major(version);
    const lastInLine = lastReleaseInLine(reg, line, scheme);
    const lastTime = lastInLine ? reg.time[lastInLine] : undefined;
    if (lastTime && now.getTime() - Date.parse(lastTime) > YEAR) {
      findings.push({
        category: 'outdated',
        level: 'medium',
        code: 'unsupported-major',
        message: `The ${line}.x line has had no release since ${lastTime.slice(0, 10)}; security fixes now ship only in newer majors`,
        penalty: 8,
        fix: `Move to ${scheme.major(latest)}.x`,
      });
    }
  } else if (behind === 'minor') {
    findings.push({ category: 'outdated', level: 'low', code: 'minor-behind', message: `Minor update available: ${version} → ${latest}${ly}`, penalty: 3 + drift, fix: hints.update(name, latest) });
  } else {
    findings.push({ category: 'outdated', level: 'info', code: 'patch-behind', message: `Patch update available: ${version} → ${latest}`, penalty: 1, fix: hints.update(name, latest) });
  }
  return { latest, semverBehind: behind, libyear, findings };
}
