import semver from 'semver';
import type { Finding, PackageReport, RegistryInfo } from '../types.ts';

const YEAR = 365.25 * 24 * 3600 * 1000;

export interface OutdatedResult {
  latest?: string;
  semverBehind?: PackageReport['semverBehind'];
  libyear?: number;
  findings: Finding[];
}

/** Latest release (by publish time) within the installed major line. */
function lastReleaseInLine(reg: RegistryInfo, major: number): string | undefined {
  let best: string | undefined;
  for (const v of reg.versions) {
    if (semver.prerelease(v) || semver.major(v) !== major || !reg.time[v]) continue;
    if (!best || reg.time[v] > reg.time[best]) best = v;
  }
  return best;
}

export function analyzeOutdated(name: string, version: string, reg: RegistryInfo, now = new Date()): OutdatedResult {
  const findings: Finding[] = [];
  const latest = reg.latest;
  if (!latest || !semver.valid(version) || !semver.valid(latest)) return { latest, findings };

  if (reg.deprecated && !reg.latestDeprecated) {
    findings.push({
      category: 'outdated',
      level: 'medium',
      code: 'version-deprecated',
      message: `Installed version ${version} is deprecated: "${reg.deprecated}"`,
      penalty: 10,
      fix: `npm install ${name}@${latest}`,
    });
  }

  if (semver.gte(version, latest)) return { latest, semverBehind: semver.gt(version, latest) ? 'ahead' : 'none', libyear: 0, findings };

  const diff = semver.diff(version, latest);
  const behind: PackageReport['semverBehind'] = diff === 'major' || diff === 'premajor' ? 'major' : diff === 'minor' || diff === 'preminor' ? 'minor' : 'patch';
  const t0 = reg.time[version] ? Date.parse(reg.time[version]) : undefined;
  const t1 = reg.time[latest] ? Date.parse(reg.time[latest]) : undefined;
  const libyear = t0 && t1 ? Math.max(0, Math.round(((t1 - t0) / YEAR) * 100) / 100) : undefined;
  const drift = libyear ? Math.min(10, Math.floor(libyear * 2)) : 0;
  const ly = libyear !== undefined ? ` (${libyear} libyears)` : '';

  if (behind === 'major') {
    const majors = semver.major(latest) - semver.major(version);
    findings.push({
      category: 'outdated',
      level: 'medium',
      code: 'major-behind',
      message: `${majors} major version${majors > 1 ? 's' : ''} behind: ${version} → ${latest}${ly}`,
      penalty: Math.min(20, 8 + 2 * majors) + drift,
      fix: `Upgrade to ${name}@${latest} (check the changelog for breaking changes)`,
    });
    const line = semver.major(version);
    const lastInLine = lastReleaseInLine(reg, line);
    const lastTime = lastInLine ? reg.time[lastInLine] : undefined;
    if (lastTime && now.getTime() - Date.parse(lastTime) > YEAR) {
      findings.push({
        category: 'outdated',
        level: 'medium',
        code: 'unsupported-major',
        message: `The ${line}.x line has had no release since ${lastTime.slice(0, 10)}; security fixes now ship only in newer majors`,
        penalty: 8,
        fix: `Move to ${semver.major(latest)}.x`,
      });
    }
  } else if (behind === 'minor') {
    findings.push({ category: 'outdated', level: 'low', code: 'minor-behind', message: `Minor update available: ${version} → ${latest}${ly}`, penalty: 3 + drift, fix: `npm install ${name}@^${latest}` });
  } else {
    findings.push({ category: 'outdated', level: 'info', code: 'patch-behind', message: `Patch update available: ${version} → ${latest}`, penalty: 1, fix: `npm update ${name}` });
  }
  return { latest, semverBehind: behind, libyear, findings };
}
