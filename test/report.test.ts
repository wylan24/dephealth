import assert from 'node:assert/strict';
import { test } from 'node:test';
import { findIgnore, type Config } from '../src/config.ts';
import { evaluate, parseRules } from '../src/report/ci.ts';
import { renderHtml } from '../src/report/html.ts';
import { buildActions, score } from '../src/report/score.ts';
import type { PackageReport, Report } from '../src/types.ts';

function pkg(over: Partial<PackageReport>): PackageReport {
  return { ecosystem: 'npm', id: 'p@1.0.0', name: 'p', version: '1.0.0', direct: true, depTypes: ['prod'], dev: false, workspaces: ['app'], via: [], assessed: true, vulnerabilities: [], findings: [], replacements: [], score: 100, ...over };
}

function report(packages: PackageReport[]): Report {
  for (const p of packages) p.score = score(p);
  return {
    tool: { name: 'dephealth', version: '0.0.0' },
    generatedAt: new Date().toISOString(),
    root: '/x',
    ecosystems: ['npm'],
    lockfiles: [{ ecosystem: 'npm', kind: 'npm' }],
    workspaces: [{ ecosystem: 'npm', path: '.', name: 'app', direct: packages.length }],
    summary: { packages: packages.length, direct: packages.length, assessed: packages.length, averageScore: 50, totalLibyear: 12, byCategory: { abandoned: 0, outdated: 0, insecure: 0, weight: 0 }, vulnerabilities: { critical: 0, high: 0, moderate: 0, low: 0, unknown: 0 }, duplicates: [] },
    actions: buildActions(packages),
    packages,
    warnings: [],
  };
}

const deprecated = pkg({ id: 'old@1.0.0', name: 'old', findings: [{ category: 'abandoned', level: 'high', code: 'deprecated', message: 'Deprecated', penalty: 35 }] });
const vulnerable = pkg({
  id: 'v@1.0.0',
  name: 'v',
  direct: false,
  via: ['parent'],
  vulnerabilities: [{ id: 'GHSA-1', aliases: [], summary: 's', severity: 'high', url: '', fixedIn: '1.0.1' }],
  findings: [{ category: 'insecure', level: 'high', code: 'vuln', message: 'm', penalty: 25, fix: 'upgrade' }],
});

test('score subtracts penalties and honours the ignore list', () => {
  assert.equal(score(deprecated), 65);
  const ignored = { ...deprecated, ignored: { reason: 'internal fork', checks: ['abandoned' as const] } };
  assert.equal(score(ignored), 100);
});

test('CI rules', () => {
  const r = report([deprecated, vulnerable]);
  assert.deepEqual(evaluate(r, parseRules(['vuln:high,deprecated:direct'])).map((v) => v.rule), ['vuln:high', 'deprecated:direct']);
  assert.deepEqual(evaluate(r, parseRules(['vuln-direct:high'])), []);
  assert.deepEqual(evaluate(r, parseRules(['vuln:critical'])), []);
  assert.deepEqual(evaluate(r, parseRules(['score<70'])).map((v) => v.packages), [['old@1.0.0']]);
  assert.equal(evaluate(r, parseRules(['libyear>10'])).length, 1);
  assert.throws(() => parseRules(['vuln:bogus']), /Unknown CI rule/);
});

test('actions are ranked with the most severe first', () => {
  const actions = buildActions([deprecated, vulnerable]);
  assert.equal(actions[0].package, 'v@1.0.0');
  assert.equal(actions[1].package, 'old@1.0.0');
});

test('ignore entries support wildcards and expiry', () => {
  const config = { ignore: [{ package: '@types/*', reason: 'types only' }, { package: 'x', reason: 'r', until: '2000-01-01' }] } as unknown as Config;
  assert.ok(findIgnore(config, '@types/node'));
  assert.equal(findIgnore(config, 'x'), undefined);
});

test('HTML report escapes untrusted text against script breakout', () => {
  const evil = pkg({ name: '</script><img src=x onerror=alert(1)>', findings: [{ category: 'abandoned', level: 'high', code: 'deprecated', message: '</script><script>alert(1)</script>', penalty: 35 }] });
  const html = renderHtml(report([evil]));
  assert.equal(html.match(/<\/script>/g)?.length, 2); // only the two real closing tags
  assert.ok(!html.includes('<img src=x'));
});
