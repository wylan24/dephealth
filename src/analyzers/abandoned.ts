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
 * downloads and no known vulnerabilities is stable, not abandoned. Explicit deprecation, or a repository
 * archived with no recent activity, are the only hard signals.
 */
export function analyzeAbandoned(reg: RegistryInfo, repo: RepoInfo | undefined, vulnCount: number, staleYears = 2, now = new Date()): AbandonedResult {
  const failed: string[] = [];
  const passed: string[] = [];
  if (reg.latestDeprecated) {
    return {
      status: 'abandoned',
      failed: ['deprecated by its author'],
      passed,
      findings: [{ category: 'abandoned', level: 'high', code: 'deprecated', message: `Deprecated by its author: "${reg.latestDeprecated}"`, penalty: 35 }],
    };
  }
  // @types/* (DefinitelyTyped) and PyPI types-* (typeshed) stubs share one monorepo each, so repo signals
  // describe that monorepo, not the package; a quiet stub package just means the typed library is stable.
  if (reg.name.startsWith('@types/') || reg.name.startsWith('types-')) {
    return { status: 'healthy', failed, passed: ['types package: judged by deprecation only'], findings: [] };
  }

  const last = lastPublish(reg);
  const age = last ? (now.getTime() - Date.parse(last)) / YEAR : undefined;

  if (repo?.archived) {
    // a repo archived after recent work usually means the package moved, not that it died
    const recentlyActive = (repo.commitsLastYear ?? 0) > 0 || (age !== undefined && age < 1);
    if (!recentlyActive) {
      return {
        status: 'abandoned',
        failed: ['repository archived'],
        passed,
        findings: [{ category: 'abandoned', level: 'high', code: 'archived', message: 'Source repository is archived (read-only)', penalty: 30 }],
      };
    }
    return {
      status: 'at-risk',
      failed: ['repository archived recently'],
      passed,
      findings: [
        {
          category: 'abandoned',
          level: 'low',
          code: 'archived-recent',
          message: 'Source repository was archived within a year of active development; check whether the package moved or is being wound down',
          penalty: 10,
        },
      ],
    };
  }

  // Activity signals decide; the secondary ones (bus factor, backlog, no repo link) only add weight
  // once activity has stopped, so an actively developed solo project is never "at risk".
  const activity: string[] = [];
  const secondary: string[] = [];
  if (age !== undefined) {
    if (age >= staleYears) activity.push(`no release in ${Math.floor(age * 10) / 10} years`);
    else passed.push(`last release ${last!.slice(0, 10)}`);
  }
  if (repo?.commitsLastYear !== undefined) {
    if (repo.commitsLastYear === 0) activity.push('no commits in the last 12 months');
    else passed.push(`${repo.commitsLastYear}${repo.commitsLastYear >= 100 ? '+' : ''} commits in the last 12 months`);
  } else if (repo?.scorecardMaintained !== undefined) {
    if (repo.scorecardMaintained === 0) activity.push('no recent activity (Scorecard "Maintained" = 0)');
    else passed.push(`Scorecard "Maintained" ${repo.scorecardMaintained}/10`);
  }
  if (reg.maintainers !== undefined) {
    if (reg.maintainers <= 1) secondary.push(`${reg.maintainers === 0 ? 'no' : 'a single'} registry maintainer`);
    else passed.push(`${reg.maintainers} registry maintainers`);
  }
  if (repo?.openIssues !== undefined) {
    // big projects always have big backlogs; only flag a backlog that is large for the project's size
    if (repo.openIssues >= 50 && repo.openIssues * 100 > (repo.stars ?? 0)) secondary.push(`${repo.openIssues} open issues/PRs (large backlog for its size)`);
    else passed.push(`${repo.openIssues} open issues/PRs`);
  }
  if (!reg.repository) secondary.push('no linked source repository');

  failed.push(...activity);
  if (activity.length) failed.push(...secondary);
  else passed.push(...secondary.map((x) => `${x} (not counted: still active)`));

  // a "finished" utility: very widely used, no known vulnerabilities, so quiet is expected
  const finished = (reg.weeklyDownloads ?? 0) >= FINISHED_DOWNLOADS && vulnCount === 0;
  const [abandonedAt, atRiskAt] = finished ? [5, 4] : [3, 2];
  const status = failed.length >= abandonedAt ? 'abandoned' : failed.length >= atRiskAt ? 'at-risk' : 'healthy';
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
