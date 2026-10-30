import type { Finding, PackageReport, RegistryInfo, RepoInfo } from '../types.ts';

const YEAR = 365.25 * 24 * 3600 * 1000;
/** Weekly downloads above which a quiet package is presumed "finished" rather than abandoned. */
export const FINISHED_DOWNLOADS = 1_000_000;

export interface AbandonedResult {
  status: NonNullable<PackageReport['abandonment']>['status'];
  failed: string[];
  passed: string[];
  findings: Finding[];
}

export function lastPublish(reg: RegistryInfo): string | undefined {
  let last: string | undefined;
  for (const [v, t] of Object.entries(reg.time)) {
    if (v === 'created' || v === 'modified') continue;
    if (!last || t > last) last = t;
  }
  return last;
}

/**
 * Never flag on a single signal: a tiny "finished" utility with no commits but millions of weekly
 * downloads and no known vulnerabilities is stable, not abandoned. Explicit deprecation or an
 * archived repository are the only hard signals.
 */
export function analyzeAbandoned(reg: RegistryInfo, repo: RepoInfo | undefined, vulnCount: number, staleYears = 2, now = new Date()): AbandonedResult {
  const failed: string[] = [];
  const passed: string[] = [];
  const check = (ok: boolean | undefined, fail: string, pass: string) => {
    if (ok === undefined) return;
    (ok ? passed : failed).push(ok ? pass : fail);
  };

  if (reg.latestDeprecated) {
    return {
      status: 'abandoned',
      failed: ['deprecated by its author'],
      passed,
      findings: [{ category: 'abandoned', level: 'high', code: 'deprecated', message: `Deprecated by its author: "${reg.latestDeprecated}"`, penalty: 35 }],
    };
  }
  if (repo?.archived) {
    return {
      status: 'abandoned',
      failed: ['repository archived'],
      passed,
      findings: [{ category: 'abandoned', level: 'high', code: 'archived', message: 'Source repository is archived (read-only)', penalty: 30 }],
    };
  }

  const last = lastPublish(reg);
  if (last) {
    const age = (now.getTime() - Date.parse(last)) / YEAR;
    check(age < staleYears, `no release in ${Math.floor(age * 10) / 10} years`, `last release ${last.slice(0, 10)}`);
  }
  if (repo?.commitsLastYear !== undefined) {
    check(repo.commitsLastYear > 0, 'no commits in the last 12 months', `${repo.commitsLastYear}${repo.commitsLastYear >= 100 ? '+' : ''} commits in the last 12 months`);
  } else if (repo?.scorecardMaintained !== undefined) {
    check(repo.scorecardMaintained > 0, 'no recent activity (Scorecard "Maintained" = 0)', `Scorecard "Maintained" ${repo.scorecardMaintained}/10`);
  }
  if (reg.maintainers !== undefined) {
    check(reg.maintainers > 1, `${reg.maintainers === 0 ? 'no' : 'a single'} registry maintainer`, `${reg.maintainers} registry maintainers`);
  }
  if (repo?.openIssues !== undefined) {
    // big projects always have big backlogs; only flag a backlog that is large for the project's size
    const backlog = repo.openIssues >= 50 && repo.openIssues * 100 > (repo.stars ?? 0);
    check(!backlog, `${repo.openIssues} open issues/PRs (large backlog for its size)`, `${repo.openIssues} open issues/PRs`);
  }
  if (!reg.repository) failed.push('no linked source repository');

  const finished = (reg.weeklyDownloads ?? 0) >= FINISHED_DOWNLOADS && vulnCount === 0;
  const need = finished ? 4 : 3;
  const status = failed.length >= need ? 'abandoned' : failed.length >= need - 1 ? 'at-risk' : 'healthy';
  const findings: Finding[] = [];
  if (status === 'abandoned') {
    findings.push({ category: 'abandoned', level: 'medium', code: 'abandoned', message: `Likely abandoned: ${failed.join('; ')}`, penalty: 25 });
  } else if (status === 'at-risk') {
    findings.push({
      category: 'abandoned',
      level: 'low',
      code: 'at-risk',
      message: `Maintenance at risk: ${failed.join('; ')}${finished ? ' (widely used and no known vulnerabilities, so probably stable)' : ''}`,
      penalty: finished ? 3 : 8,
    });
  }
  return { status, failed, passed, findings };
}
