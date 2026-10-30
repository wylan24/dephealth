import assert from 'node:assert/strict';
import { test } from 'node:test';
import { analyzeAbandoned } from '../src/analyzers/abandoned.ts';
import { analyzeInsecure } from '../src/analyzers/insecure.ts';
import { analyzeOutdated } from '../src/analyzers/outdated.ts';
import { analyzeWeight, nativeAlternatives } from '../src/analyzers/weight.ts';
import { authorSuggestions, curatedSuggestions, fromDeprecation } from '../src/advisor/replacements.ts';
import { cvss3Score, fixedIn, severityOf } from '../src/fetchers/osv.ts';
import { parseRepository } from '../src/fetchers/npm.ts';
import { npmEcosystem, pypiEcosystem } from '../src/ecosystems.ts';
import type { DependencyGraph, RegistryInfo } from '../src/types.ts';

const graph = (kind: DependencyGraph['lockfile']['kind']) => ({ lockfile: { kind } }) as DependencyGraph;
const NPM = npmEcosystem.hints(graph('npm'));
const PNPM = npmEcosystem.hints(graph('pnpm'));
const UV = pypiEcosystem.hints(graph('uv'));

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
  const r = analyzeOutdated('pkg', '1.0.0', reg(), NPM, NOW);
  assert.equal(r.semverBehind, 'major');
  assert.equal(r.libyear, 7);
  const codes = r.findings.map((f) => f.code);
  assert.deepEqual(codes, ['major-behind', 'unsupported-major']);
  assert.match(r.findings[0].message, /2 major versions behind/);
});

test('outdated: up to date and ahead', () => {
  assert.equal(analyzeOutdated('pkg', '3.0.0', reg(), NPM, NOW).findings.length, 0);
  assert.equal(analyzeOutdated('pkg', '3.1.0-beta.1', reg(), NPM, NOW).semverBehind, 'ahead');
});

test('abandoned: never flags on a single signal', () => {
  const r = analyzeAbandoned(reg({ time: { '1.0.0': '2018-01-01T00:00:00Z' } }), { commitsLastYear: 4, source: [] }, 0, 2, NOW);
  assert.equal(r.status, 'healthy');
  assert.deepEqual(r.failed, ['no release in 8.8 years']);
});

test('abandoned: three failing signals => abandoned; a "finished" popular package needs five', () => {
  const stale = reg({ time: { '1.0.0': '2018-01-01T00:00:00Z' }, maintainers: 1 });
  const repo = { commitsLastYear: 0, source: [] };
  assert.equal(analyzeAbandoned(stale, repo, 0, 2, NOW).status, 'abandoned');
  // picocolors / escape-html shape: quiet, solo, but used everywhere with no known bugs
  const popular = { ...stale, weeklyDownloads: 5_000_000 };
  assert.equal(analyzeAbandoned(popular, repo, 0, 2, NOW).status, 'healthy');
  // ...unless it has known vulnerabilities
  assert.equal(analyzeAbandoned(popular, repo, 1, 2, NOW).status, 'abandoned');
});

test('abandoned: an actively developed solo project is not at risk (esbuild shape)', () => {
  const r = analyzeAbandoned(reg({ maintainers: 1 }), { commitsLastYear: 100, openIssues: 640, stars: 39_000, source: [] }, 0, 2, NOW);
  assert.equal(r.status, 'healthy');
  assert.deepEqual(r.failed, []);
  assert.ok(r.passed.some((x) => x.includes('single registry maintainer (not counted: still active)')));
});

test('abandoned: @types packages are judged by deprecation only', () => {
  const types = reg({ name: '@types/jsesc', time: { '1.0.0': '2018-01-01T00:00:00Z' }, maintainers: 1 });
  assert.equal(analyzeAbandoned(types, { commitsLastYear: 0, openIssues: 685, stars: 50_000, source: [] }, 0, 2, NOW).status, 'healthy');
  assert.equal(analyzeAbandoned({ ...types, latestDeprecated: 'stub types' }, undefined, 0, 2, NOW).findings[0].code, 'deprecated');
  assert.equal(analyzeAbandoned({ ...types, name: 'types-boto' }, { commitsLastYear: 0, openIssues: 410, stars: 4_000, source: [] }, 0, 2, NOW).status, 'healthy');
});

test('abandoned: deprecation and long-dead archived repos are hard signals; a recent archive is not', () => {
  assert.equal(analyzeAbandoned(reg({ latestDeprecated: 'use x instead' }), undefined, 0, 2, NOW).findings[0].code, 'deprecated');
  const old = reg({ latest: '1.0.0', time: { '1.0.0': '2020-01-01T00:00:00Z' }, versions: ['1.0.0'] });
  assert.equal(analyzeAbandoned(old, { archived: true, commitsLastYear: 0, source: [] }, 0, 2, NOW).findings[0].code, 'archived');
  // webpack-contrib loaders: archived this year right after releases and commits
  const r = analyzeAbandoned(reg(), { archived: true, commitsLastYear: 15, source: [] }, 0, 2, NOW);
  assert.equal(r.status, 'at-risk');
  assert.equal(r.findings[0].code, 'archived-recent');
});

test('abandoned: a backlog counts only once activity has stopped, and relative to project size', () => {
  const active = analyzeAbandoned(reg(), { openIssues: 80, stars: 300, commitsLastYear: 100, source: [] }, 0, 2, NOW);
  assert.ok(!active.failed.some((f) => f.includes('open issues')));
  const stale = reg({ time: { '1.0.0': '2018-01-01T00:00:00Z' } });
  const big = analyzeAbandoned(stale, { openIssues: 1500, stars: 200_000, commitsLastYear: 0, source: [] }, 0, 2, NOW);
  assert.ok(!big.failed.some((f) => f.includes('open issues')));
  const small = analyzeAbandoned(stale, { openIssues: 80, stars: 300, commitsLastYear: 0, source: [] }, 0, 2, NOW);
  assert.ok(small.failed.some((f) => f.includes('open issues')));
});

test('insecure: one upgrade target that clears every advisory, transitive guidance', () => {
  const vulns = [
    { id: 'GHSA-1', aliases: [], summary: 'a', severity: 'high' as const, fixedIn: '1.2.0', url: '' },
    { id: 'GHSA-2', aliases: [], summary: 'b', severity: 'low' as const, fixedIn: '1.4.0', url: '' },
  ];
  const direct = analyzeInsecure('x', true, [], vulns, NPM);
  assert.equal(direct[0].fix, 'Upgrade to x@1.4.0 or later (fixes both advisories)');
  const transitive = analyzeInsecure('x', false, ['parent'], vulns, NPM);
  assert.match(transitive[0].fix!, /Upgrade parent .* x >= 1\.4\.0.*"overrides" entry/);
  assert.match(analyzeInsecure('x', false, ['a', 'b', 'c'], vulns, NPM)[0].fix!, /^Upgrade a \(or the 2 other dependencies that pull it in\)/);
  assert.match(analyzeInsecure('x', false, ['parent'], vulns, PNPM)[0].fix!, /pnpm\.overrides/);
  assert.match(analyzeInsecure('x', false, ['parent'], vulns, UV)[0].fix!, /constraint-dependencies/);
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
  const f = analyzeWeight({ name: 'object-assign', dev: false, transitive: 0, natives: nativeAlternatives('object-assign', { node: '22.0.0' }) });
  assert.equal(f[0].code, 'native-now');
  const heavy = analyzeWeight({ name: 'big', dev: false, transitive: 200, unpackedSize: 30 * 1024 * 1024, bundle: { minified: 400_000, gzip: 120_000 }, natives: [] });
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
