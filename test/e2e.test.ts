import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { analyze } from '../src/analyze.ts';
import { loadConfig } from '../src/config.ts';
import { evaluate, parseRules } from '../src/report/ci.ts';
import { renderHtml } from '../src/report/html.ts';
import { renderSarif } from '../src/report/sarif.ts';
import type { Report } from '../src/types.ts';
import { mockFetch } from './mock-fetch.ts';

// A mixed npm + Python project, analysed end to end with every external service simulated.

function project(): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'dephealth-e2e-'));
  const files: Record<string, unknown> = {
    'package.json': { name: 'shop', dependencies: { 'left-pad': '^1.3.0', vulnlib: '^1.0.0', healthy: '^3.0.0' }, devDependencies: { 'node-fetch': '^2.6.0', '@types/node': '^20.0.0' }, engines: { node: '>=20' } },
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'shop' },
        'node_modules/left-pad': { version: '1.3.0' },
        'node_modules/vulnlib': { version: '1.0.0', dependencies: { 'deep-dep': '^0.1.0' } },
        'node_modules/deep-dep': { version: '0.1.0' },
        'node_modules/healthy': { version: '3.1.0' },
        'node_modules/node-fetch': { version: '2.6.0', dev: true },
        'node_modules/@types/node': { version: '20.19.0', dev: true },
      },
    },
    'requirements.txt': 'mock==4.0.3\n',
  };
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    writeFileSync(path.join(dir, name), typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}

const t = (y: number) => `${y}-01-01T00:00:00Z`;
const packuments: Record<string, unknown> = {
  'left-pad': { 'dist-tags': { latest: '1.3.0' }, time: { '1.3.0': t(2018) }, versions: { '1.3.0': { deprecated: 'use String.prototype.padStart()' } }, maintainers: [{}], repository: 'github:stevemao/left-pad' },
  vulnlib: { 'dist-tags': { latest: '1.2.0' }, time: { '1.0.0': t(2024), '1.2.0': t(2026) }, versions: { '1.0.0': {}, '1.2.0': {} }, maintainers: [{}, {}], repository: 'github:acme/vulnlib' },
  healthy: { 'dist-tags': { latest: '3.1.0' }, time: { '3.1.0': '2026-09-01T00:00:00Z' }, versions: { '3.1.0': {} }, maintainers: [{}, {}], repository: 'github:acme/healthy' },
  '@types/node': { 'dist-tags': { latest: '26.6.6' }, time: { '20.19.0': t(2026), '26.6.6': t(2026) }, versions: { '20.19.0': {}, '26.6.6': {} }, maintainers: [{}, {}], repository: 'github:DefinitelyTyped/DefinitelyTyped' },
  'node-fetch': { 'dist-tags': { latest: '3.3.2' }, time: { '2.6.0': t(2019), '3.3.2': t(2023) }, versions: { '2.6.0': {}, '3.3.2': {} }, maintainers: [{}, {}], repository: 'github:node-fetch/node-fetch' },
};

let report: Report;
let mock: ReturnType<typeof mockFetch>;

before(async () => {
  mock = mockFetch([
    ['https://registry.npmjs.org/', (url) => packuments[decodeURIComponent(url.pathname.slice(1))] ?? new Response('', { status: 404 })],
    ['https://api.npmjs.org/downloads/', (url) => Object.fromEntries(url.pathname.split('/').pop()!.split(',').map((n) => [n, { downloads: 5000 }]))],
    ['https://pypi.org/pypi/mock/json', () => ({ info: { version: '5.2.0', project_urls: { Source: 'https://github.com/testing-cabal/mock' } }, releases: { '4.0.3': [{ upload_time_iso_8601: t(2020) }], '5.2.0': [{ upload_time_iso_8601: t(2025) }] } })],
    ['https://pypistats.org/', () => ({ data: { last_week: 5_000_000 } })],
    ['https://api.osv.dev/v1/querybatch', (_u, init) => {
      const { queries } = JSON.parse(String(init!.body)) as { queries: { package: { name: string }; version: string }[] };
      return { results: queries.map((q) => (q.package.name === 'deep-dep' ? { vulns: [{ id: 'GHSA-deep', modified: '1' }] } : q.package.name === 'vulnlib' ? { vulns: [{ id: 'GHSA-vuln', modified: '1' }] } : {})) };
    }],
    ['https://api.osv.dev/v1/vulns/GHSA-deep', () => ({ id: 'GHSA-deep', modified: '1', summary: 'Prototype pollution', database_specific: { severity: 'CRITICAL' }, affected: [{ package: { name: 'deep-dep', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '0.1.5' }] }] }] })],
    ['https://api.osv.dev/v1/vulns/GHSA-vuln', () => ({ id: 'GHSA-vuln', modified: '1', summary: 'ReDoS', database_specific: { severity: 'MODERATE' }, affected: [{ package: { name: 'vulnlib', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.1.0' }] }] }] })],
    ['https://api.deps.dev/', () => ({ openIssuesCount: 2, starsCount: 1000 })],
    [/api\.github\.com\/repos\/stevemao\/left-pad$/, () => ({ archived: true, pushed_at: t(2019), open_issues_count: 2, stargazers_count: 1000 })],
    [/api\.github\.com\/repos\/[^/]+\/[^/]+\/commits/, (url) => (url.pathname.includes('left-pad') ? [] : [{}, {}])],
    [/api\.github\.com\/repos\//, () => ({ archived: false, pushed_at: '2026-10-01T00:00:00Z', open_issues_count: 2, stargazers_count: 1000 })],
  ]);
  const root = project();
  report = await analyze({ root, config: loadConfig(root).config, cacheDir: null, deep: false, bundle: false, prodOnly: false, noSearch: true, githubToken: 't', version: 'test', log: () => {} });
});
after(() => mock.restore());

const pkg = (id: string) => report.packages.find((p) => p.id === id)!;

test('e2e: both ecosystems detected and the graph is right', () => {
  assert.deepEqual(report.ecosystems, ['npm', 'PyPI']);
  assert.deepEqual(report.lockfiles.map((l) => l.kind), ['npm', 'requirements']);
  assert.equal(report.summary.packages, 7);
  assert.equal(report.summary.direct, 6);
  assert.deepEqual(pkg('deep-dep@0.1.0').via, ['vulnlib']);
  assert.equal(pkg('node-fetch@2.6.0').dev, true);
  assert.deepEqual(report.warnings, []);
});

test('e2e: insecure, abandoned, outdated and weight findings', () => {
  const codes = (id: string) => pkg(id).findings.map((f) => f.code).sort();
  assert.deepEqual(codes('deep-dep@0.1.0'), ['vuln']);
  assert.match(pkg('deep-dep@0.1.0').findings[0].fix!, /Upgrade vulnlib .* deep-dep >= 0\.1\.5, or add an "overrides" entry/);
  assert.deepEqual(codes('vulnlib@1.0.0'), ['minor-behind', 'vuln']);
  assert.deepEqual(codes('left-pad@1.3.0'), ['deprecated', 'native-now']);
  assert.equal(pkg('left-pad@1.3.0').replacements[0].name, 'String.prototype.padStart');
  assert.deepEqual(codes('node-fetch@2.6.0'), ['major-behind', 'native-now', 'unsupported-major']);
  assert.deepEqual(codes('mock@4.0.3'), ['major-behind', 'native-now', 'unsupported-major']);
  assert.equal(pkg('healthy@3.1.0').score, 100);
  // @types/node pinned to the oldest supported Node major (engines >=20) is deliberate, not outdated
  assert.deepEqual(codes('@types/node@20.19.0'), []);
});

test('e2e: actions ranked, CI rules evaluated, HTML renders', () => {
  assert.equal(report.actions[0].package, 'deep-dep@0.1.0');
  assert.equal(report.summary.vulnerabilities.critical, 1);
  const violations = evaluate(report, parseRules(['vuln:high', 'deprecated:direct', 'vuln-direct:high']));
  assert.deepEqual(violations.map((v) => [v.rule, v.packages]), [['vuln:high', ['deep-dep@0.1.0']], ['deprecated:direct', ['left-pad@1.3.0']]]);
  const html = renderHtml(report);
  assert.ok(html.includes('"deep-dep@0.1.0"'));
});

test('e2e: SARIF anchors findings to the declaring line, with stable fingerprints', () => {
  const sarif = JSON.parse(renderSarif(report));
  const run = sarif.runs[0];
  assert.equal(sarif.version, '2.1.0');
  const rule = run.tool.driver.rules.find((r: { id: string }) => r.id === 'GHSA-deep');
  assert.equal(rule.properties['security-severity'], '9.5');
  assert.ok(rule.properties.tags.includes('security'));
  const result = (pkgName: string, ruleId: string) =>
    run.results.find((r: { ruleId: string; properties: { package: string } }) => r.ruleId === ruleId && r.properties.package === pkgName);
  const lp = result('left-pad', 'dephealth/deprecated');
  assert.deepEqual(lp.locations[0].physicalLocation, { artifactLocation: { uri: 'package.json' }, region: { startLine: 4 } });
  assert.equal(lp.level, 'error');
  const deep = result('deep-dep', 'GHSA-deep');
  assert.equal(deep.locations[0].physicalLocation.artifactLocation.uri, 'package-lock.json');
  assert.match(deep.message.text, /via vulnlib/);
  const mock = result('mock', 'dephealth/native-now');
  assert.deepEqual(mock.locations[0].physicalLocation, { artifactLocation: { uri: 'requirements.txt' }, region: { startLine: 1 } });
  // the fingerprint ignores the version, so upgrading a still-broken package updates the same alert
  assert.equal(JSON.parse(renderSarif(report)).runs[0].results[0].partialFingerprints['dephealth/v1'], run.results[0].partialFingerprints['dephealth/v1']);
  assert.ok(!run.results.some((r: { level: string }) => r.level === 'none'));
});
