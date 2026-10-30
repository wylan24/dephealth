import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyzeAbandoned } from '../src/analyzers/abandoned.ts';
import { analyzeInsecure } from '../src/analyzers/insecure.ts';
import { analyzeOutdated } from '../src/analyzers/outdated.ts';
import { analyzeWeight, nativeAlternatives } from '../src/analyzers/weight.ts';
import { authorSuggestions, curatedSuggestions, fromDeprecation } from '../src/advisor/replacements.ts';
import { cvss3Score, fixedIn, severityOf } from '../src/fetchers/osv.ts';
import { parseRepository } from '../src/fetchers/npm.ts';
import type { RegistryInfo } from '../src/types.ts';

const NOW = new Date('2026-10-30T00:00:00Z');

function reg(over: Partial<RegistryInfo> = {}): RegistryInfo {
  return {
    name: 'pkg',
    assessed: true,
    latest: '3.0.0',
    time: { '1.0.0': '2019-01-01T00:00:00Z', '1.1.0': '2020-01-01T00:00:00Z', '2.0.0': '2023-01-01T00:00:00Z', '3.0.0': '2026-01-01T00:00:00Z' },
    versions: ['1.0.0', '1.1.0', '2.0.0', '3.0.0'],
    maintainers: 3,
    keywords: [],
    repository: { owner: 'o', repo: 'r', url: 'https://github.com/o/r' },
    ...over,
  };
}

test('outdated: major drift, libyear, unsupported major line', () => {
  const r = analyzeOutdated('pkg', '1.0.0', reg(), NOW);
  assert.equal(r.semverBehind, 'major');
  assert.equal(r.libyear, 7);
  const codes = r.findings.map((f) => f.code);
  assert.deepEqual(codes, ['major-behind', 'unsupported-major']);
  assert.match(r.findings[0].message, /2 major versions behind/);
});

test('outdated: up to date and ahead', () => {
  assert.equal(analyzeOutdated('pkg', '3.0.0', reg(), NOW).findings.length, 0);
  assert.equal(analyzeOutdated('pkg', '3.1.0-beta.1', reg(), NOW).semverBehind, 'ahead');
});

test('abandoned: never flags on a single signal', () => {
  const r = analyzeAbandoned(reg({ time: { '1.0.0': '2018-01-01T00:00:00Z' } }), { commitsLastYear: 4, source: [] }, 0, 2, NOW);
  assert.equal(r.status, 'healthy');
  assert.deepEqual(r.failed, ['no release in 8.8 years']);
});

test('abandoned: three failing signals => abandoned; "finished" popular package needs four', () => {
  const stale = reg({ time: { '1.0.0': '2018-01-01T00:00:00Z' }, maintainers: 1 });
  const repo = { commitsLastYear: 0, source: [] };
  assert.equal(analyzeAbandoned(stale, repo, 0, 2, NOW).status, 'abandoned');
  const popular = { ...stale, weeklyDownloads: 5_000_000 };
  assert.equal(analyzeAbandoned(popular, repo, 0, 2, NOW).status, 'at-risk');
  // ...unless it has known vulnerabilities
  assert.equal(analyzeAbandoned(popular, repo, 1, 2, NOW).status, 'abandoned');
});

test('abandoned: deprecation and archived repos are hard signals', () => {
  assert.equal(analyzeAbandoned(reg({ latestDeprecated: 'use x instead' }), undefined, 0, 2, NOW).findings[0].code, 'deprecated');
  assert.equal(analyzeAbandoned(reg(), { archived: true, source: [] }, 0, 2, NOW).findings[0].code, 'archived');
});

test('abandoned: open-issue backlog is judged relative to project size', () => {
  const big = analyzeAbandoned(reg(), { openIssues: 1500, stars: 200_000, commitsLastYear: 100, source: [] }, 0, 2, NOW);
  assert.ok(!big.failed.some((f) => f.includes('open issues')));
  const small = analyzeAbandoned(reg(), { openIssues: 80, stars: 300, commitsLastYear: 100, source: [] }, 0, 2, NOW);
  assert.ok(small.failed.some((f) => f.includes('open issues')));
});

test('insecure: one upgrade target that clears every advisory, transitive guidance', () => {
  const vulns = [
    { id: 'GHSA-1', aliases: [], summary: 'a', severity: 'high' as const, fixedIn: '1.2.0', url: '' },
    { id: 'GHSA-2', aliases: [], summary: 'b', severity: 'low' as const, fixedIn: '1.4.0', url: '' },
  ];
  const direct = analyzeInsecure('x', true, [], vulns);
  assert.equal(direct[0].fix, 'Upgrade to x@1.4.0 or later (fixes both advisories)');
  const transitive = analyzeInsecure('x', false, ['parent'], vulns);
  assert.match(transitive[0].fix!, /Upgrade parent .* x@>=1\.4\.0.*overrides/);
  assert.match(transitive[0].message, /pulled in by parent; reachability: unknown/);
});

test('osv: fixed-in range matching, severity labels, CVSS 3.1 scoring', () => {
  const rec = {
    id: 'GHSA-x',
    modified: '',
    affected: [
      {
        package: { name: 'x', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.2.3' }, { introduced: '2.0.0' }, { fixed: '2.0.5' }] }],
      },
    ],
  };
  assert.equal(fixedIn(rec, 'x', '1.0.0'), '1.2.3');
  assert.equal(fixedIn(rec, 'x', '2.0.1'), '2.0.5');
  assert.equal(fixedIn(rec, 'x', '1.5.0'), undefined);
  assert.equal(severityOf({ id: 'MAL-2024-1', modified: '' }), 'critical');
  assert.equal(severityOf({ id: 'G', modified: '', database_specific: { severity: 'MODERATE' } }), 'moderate');
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), 9.8);
  assert.equal(cvss3Score('CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N'), 6.1);
  assert.equal(severityOf({ id: 'C', modified: '', severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N' }] }), 'moderate');
});

test('weight: native-now respects runtime targets and primary-choice rule', () => {
  assert.equal(nativeAlternatives('node-fetch', { node: '22.0.0' })[0]?.id, 'fetch');
  assert.equal(nativeAlternatives('node-fetch', { node: '16.0.0' }).length, 0);
  // moment lists `Date` as an option, but it is not a like-for-like swap
  assert.equal(nativeAlternatives('moment', { node: '22.0.0' }).length, 0);
  const f = analyzeWeight({ name: 'object-assign', dev: false, transitive: 0, targets: { node: '22.0.0' } });
  assert.equal(f[0].code, 'native-now');
  const heavy = analyzeWeight({ name: 'big', dev: false, transitive: 200, unpackedSize: 30 * 1024 * 1024, bundle: { minified: 400_000, gzip: 120_000 }, targets: { node: '22.0.0' } });
  assert.deepEqual(heavy.map((x) => x.code), ['many-deps', 'install-size', 'bundle-size']);
});

test('advisor: deprecation messages, curated mapping, effort', () => {
  assert.deepEqual(fromDeprecation('babel-eslint', 'babel-eslint is now @babel/eslint-parser. This package will no longer receive updates.'), []);
  assert.deepEqual(fromDeprecation('x', 'Package no longer supported. Use `y-lib` instead.'), ['y-lib']);
  assert.deepEqual(fromDeprecation('core', 'This package has been moved to @scope/core'), ['@scope/core']);
  assert.deepEqual(fromDeprecation('x', 'Please upgrade to version 7 or higher'), []);
  assert.equal(authorSuggestions('core', 'renamed to @scope/core')[0].effort, 'drop-in');
  const moment = curatedSuggestions('moment');
  assert.equal(moment[0].name, 'dayjs');
  assert.equal(moment.find((r) => r.name === 'date-fns')?.effort, 'rewrite');
  assert.equal(curatedSuggestions('left-pad')[0].effort, 'drop-in');
});

test('repository URL parsing', () => {
  assert.equal(parseRepository('git+https://github.com/lodash/lodash.git')?.url, 'https://github.com/lodash/lodash');
  assert.equal(parseRepository('git@github.com:a/b.git')?.repo, 'b');
  assert.equal(parseRepository('github:x/y')?.owner, 'x');
  assert.equal(parseRepository('https://github.com/babel/babel/tree/main/packages/x')?.repo, 'babel');
  assert.equal(parseRepository('https://gitlab.com/a/b'), undefined);
});
