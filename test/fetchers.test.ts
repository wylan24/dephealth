import assert from 'node:assert/strict';
import { mkdtempSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, test } from 'node:test';
import { DiskCache } from '../src/fetchers/http.ts';
import { NpmFetcher } from '../src/fetchers/npm.ts';
import { OsvFetcher } from '../src/fetchers/osv.ts';
import { PypiFetcher } from '../src/fetchers/pypi.ts';
import { RepoFetcher } from '../src/fetchers/repo.ts';
import { pep440Scheme } from '../src/versions.ts';
import { mockFetch, status } from './mock-fetch.ts';

const tempCache = () => new DiskCache(mkdtempSync(path.join(os.tmpdir(), 'dephealth-cache-')));
let restore: (() => void) | undefined;
afterEach(() => restore?.());

const packument = (over: Record<string, unknown> = {}) => ({
  'dist-tags': { latest: '2.0.0' },
  time: { created: '2019-01-01T00:00:00Z', modified: '2025-01-01T00:00:00Z', '1.0.0': '2019-01-01T00:00:00Z', '2.0.0': '2025-01-01T00:00:00Z' },
  versions: { '1.0.0': { deprecated: 'old line, use 2.x', dist: { unpackedSize: 1234 } }, '2.0.0': { dist: { unpackedSize: 2048 } } },
  maintainers: [{ name: 'a' }, { name: 'b' }],
  repository: { type: 'git', url: 'git+https://github.com/owner/pkg.git' },
  keywords: ['x'],
  description: 'a package',
  ...over,
});

test('npm: packument is trimmed to the fields analyzers use', async () => {
  const m = mockFetch([['https://registry.npmjs.org/pkg', () => packument()]]);
  restore = m.restore;
  const info = await new NpmFetcher(new DiskCache(null)).info('pkg', '1.0.0', false);
  assert.equal(info.latest, '2.0.0');
  assert.equal(info.deprecated, 'old line, use 2.x');
  assert.equal(info.latestDeprecated, undefined);
  assert.equal(info.maintainers, 2);
  assert.equal(info.unpackedSize, 1234);
  assert.deepEqual(info.repository, { owner: 'owner', repo: 'pkg', url: 'https://github.com/owner/pkg' });
  assert.deepEqual(info.versions, ['1.0.0', '2.0.0']);
});

test('npm: a 404 means "not assessed", scoped names are URL-encoded', async () => {
  const m = mockFetch([]);
  restore = m.restore;
  const info = await new NpmFetcher(new DiskCache(null)).info('@corp/private', '1.0.0', false);
  assert.equal(info.assessed, false);
  assert.match(info.notAssessedReason!, /private package/);
  assert.equal(m.calls[0].url, 'https://registry.npmjs.org/@corp/private'); // %2f decoded by the mock
});

test('npm: unscoped downloads are batched through the bulk endpoint; scoped go one by one', async () => {
  const m = mockFetch([
    ['https://registry.npmjs.org/', () => packument()],
    [/api\.npmjs\.org\/downloads\/point\/last-week\/[^@]+,/, (url) => Object.fromEntries(url.pathname.split('/').pop()!.split(',').map((n) => [n, { downloads: n.length * 1000 }]))],
    ['https://api.npmjs.org/downloads/point/last-week/@scope/one', () => ({ downloads: 42 })],
  ]);
  restore = m.restore;
  const npm = new NpmFetcher(new DiskCache(null));
  const infos = await Promise.all(['aa', 'bbb', 'cccc', '@scope/one'].map((n) => npm.info(n, '2.0.0', true)));
  assert.deepEqual(infos.map((i) => i.weeklyDownloads), [2000, 3000, 4000, 42]);
  assert.equal(m.count('https://api.npmjs.org/downloads'), 2); // one bulk request + one scoped
});

test('npm: a failed downloads lookup is not cached', async () => {
  const cache = tempCache();
  let broken = true;
  const m = mockFetch([
    ['https://registry.npmjs.org/', () => packument()],
    ['https://api.npmjs.org/downloads', () => (broken ? new Response('not json', { status: 200 }) : { downloads: 7 })],
  ]);
  restore = m.restore;
  assert.equal((await new NpmFetcher(cache).info('solo', '2.0.0', true)).weeklyDownloads, undefined);
  broken = false;
  assert.equal((await new NpmFetcher(cache).info('solo', '2.0.0', true)).weeklyDownloads, 7);
  // ...and a success is
  broken = true;
  assert.equal((await new NpmFetcher(cache).info('solo', '2.0.0', true)).weeklyDownloads, 7);
});

test('PyPI: yanked installed version, Inactive classifier, repo from project_urls', async () => {
  const m = mockFetch([
    [
      'https://pypi.org/pypi/oldlib/json',
      () => ({
        info: {
          version: '2.0',
          summary: 'old',
          keywords: 'a, b',
          classifiers: ['Development Status :: 7 - Inactive'],
          project_urls: { Homepage: 'https://example.com', Source: 'https://github.com/org/oldlib' },
        },
        releases: {
          '1.0': [{ upload_time_iso_8601: '2015-01-01T00:00:00Z', yanked: true, yanked_reason: 'broken wheel' }],
          '2.0': [{ upload_time_iso_8601: '2016-06-01T00:00:00Z' }, { upload_time_iso_8601: '2016-05-01T00:00:00Z' }],
          '3.0': [],
        },
      }),
    ],
    ['https://pypistats.org/api/packages/oldlib/recent', () => ({ data: { last_week: 99 } })],
  ]);
  restore = m.restore;
  const info = await new PypiFetcher(new DiskCache(null)).info('oldlib', '1.0', true);
  assert.equal(info.deprecated, 'version 1.0 was yanked from PyPI: broken wheel');
  assert.equal(info.latestDeprecated, 'Development Status :: 7 - Inactive');
  assert.equal(info.repository?.url, 'https://github.com/org/oldlib');
  assert.equal(info.time['2.0'], '2016-05-01T00:00:00Z'); // earliest file upload
  assert.deepEqual(info.versions.sort(), ['1.0', '2.0']); // releases without files are skipped
  assert.equal(info.maintainers, undefined);
  assert.equal(info.weeklyDownloads, 99);
  assert.deepEqual(info.keywords, ['a', 'b']);
});

test('OSV: one batch query, records fetched once, aliases merged, PyPI ranges with PEP 440', async () => {
  const records: Record<string, unknown> = {
    'GHSA-aaaa': {
      id: 'GHSA-aaaa', modified: '1', aliases: ['CVE-1', 'PYSEC-1'], summary: 'bad thing', database_specific: { severity: 'HIGH' },
      affected: [{ package: { name: 'Django', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.2.5' }] }] }],
    },
    'PYSEC-1': {
      id: 'PYSEC-1', modified: '1', aliases: ['CVE-1'], details: 'same bad thing',
      affected: [{ package: { name: 'django', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '3.2.5' }] }] }],
    },
  };
  const m = mockFetch([
    ['https://api.osv.dev/v1/querybatch', (_u, init) => {
      const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string; ecosystem: string } }[] };
      assert.ok(queries.every((q) => q.package.ecosystem === 'PyPI'));
      return { results: queries.map((q) => (q.package.name === 'django' ? { vulns: [{ id: 'GHSA-aaaa', modified: '1' }, { id: 'PYSEC-1', modified: '1' }] } : {})) };
    }],
    [/api\.osv\.dev\/v1\/vulns\//, (url) => records[url.pathname.split('/').pop()!]],
  ]);
  restore = m.restore;
  const out = await new OsvFetcher(new DiskCache(null)).scan([{ name: 'django', version: '3.2' }, { name: 'requests', version: '2.31.0' }], 'PyPI', pep440Scheme);
  assert.deepEqual([...out.keys()], ['django@3.2']);
  const [v] = out.get('django@3.2')!;
  assert.equal(v.id, 'GHSA-aaaa');
  assert.equal(v.severity, 'high');
  assert.equal(v.fixedIn, '3.2.5');
  assert.equal(out.get('django@3.2')!.length, 1);
  assert.equal(m.count('https://api.osv.dev/v1/querybatch'), 1);
  assert.equal(m.count('https://api.osv.dev/v1/vulns/'), 2);
});

test('repo: deps.dev + GitHub combined, token sent, commits counted', async () => {
  const m = mockFetch([
    ['https://api.deps.dev/v3/projects/github.com/o/r', () => ({ openIssuesCount: 3, starsCount: 500, scorecard: { overallScore: 6.5, checks: [{ name: 'Maintained', score: 10 }] } })],
    ['https://api.github.com/repos/o/r/commits', () => [{}, {}, {}]],
    ['https://api.github.com/repos/o/r', () => ({ archived: false, pushed_at: '2026-10-01T00:00:00Z', open_issues_count: 9, stargazers_count: 400 })],
  ]);
  restore = m.restore;
  const info = await new RepoFetcher(new DiskCache(null), 'tok', () => {}).info('o', 'r');
  assert.deepEqual(info, { source: ['deps.dev', 'github'], openIssues: 3, stars: 500, scorecard: 6.5, scorecardMaintained: 10, archived: false, pushedAt: '2026-10-01T00:00:00Z', commitsLastYear: 3 });
  assert.equal(m.calls.find((c) => c.url.startsWith('https://api.github.com'))!.headers.authorization, 'Bearer tok');
});

test('repo: GitHub rate limit warns once and falls back to deps.dev', async () => {
  const warnings: string[] = [];
  const m = mockFetch([
    [/api\.deps\.dev/, () => ({ openIssuesCount: 1, starsCount: 10 })],
    [/api\.github\.com/, () => status(403, { 'x-ratelimit-remaining': '0' })],
  ]);
  restore = m.restore;
  const repos = new RepoFetcher(new DiskCache(null), undefined, (w) => warnings.push(w));
  const [a, b] = await Promise.all([repos.info('o', 'a'), repos.info('o', 'b')]);
  assert.deepEqual(a.source, ['deps.dev']);
  assert.deepEqual(b.source, ['deps.dev']);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /60 requests\/hour without a token/);
});
