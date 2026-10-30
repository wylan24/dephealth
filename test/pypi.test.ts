import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { analyzeOutdated } from '../src/analyzers/outdated.ts';
import { pythonNative } from '../src/advisor/replacements.ts';
import { pypiEcosystem, pythonTarget } from '../src/ecosystems.ts';
import { dedupeAliases, fixedIn } from '../src/fetchers/osv.ts';
import { loadPythonProject, normalizeName, parseRequirement } from '../src/parsers/pypi.ts';
import type { Config } from '../src/config.ts';
import type { DependencyGraph, RegistryInfo, Vulnerability } from '../src/types.ts';
import { pep440Scheme as pep } from '../src/versions.ts';

function project(files: Record<string, string>): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'dephealth-py-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

const directs = (g: DependencyGraph) => Object.fromEntries(g.workspaces.flatMap((w) => w.direct.map((d) => [d.name, `${d.id ?? '-'} ${d.type}`])));

test('PEP 440 ordering, diff and validity', () => {
  const order = ['1.0.dev1', '1.0a1.dev1', '1.0a1', '1.0b2', '1.0rc1', '1.0', '1.0.post1.dev1', '1.0.post1', '1.1', '2!0.1'];
  for (let i = 0; i < order.length - 1; i++) assert.ok(pep.compare(order[i], order[i + 1]) < 0, `${order[i]} < ${order[i + 1]}`);
  assert.equal(pep.compare('1.0', '1.0.0'), 0);
  assert.equal(pep.diff('1.4.2', '2.0'), 'major');
  assert.equal(pep.diff('1.4.2', '1.5'), 'minor');
  assert.equal(pep.diff('1.4.2', '1.4.3'), 'patch');
  assert.ok(pep.prerelease('2.0rc1'));
  assert.ok(!pep.valid('not-a-version'));
});

test('PEP 508 requirements and PEP 503 names', () => {
  assert.equal(normalizeName('Foo_Bar.baz'), 'foo-bar-baz');
  assert.deepEqual(parseRequirement('Requests[socks,security] >=2.31 ; python_version >= "3.8"'), {
    name: 'requests', extras: ['socks', 'security'], specifier: '>=2.31', url: undefined, marker: 'python_version >= "3.8"',
  });
  assert.equal(parseRequirement('pkg @ https://example.com/pkg.whl')?.url, 'https://example.com/pkg.whl');
  assert.equal(parseRequirement('django (>=3.2,<4)')?.specifier, '>=3.2,<4');
});

test('uv.lock: forks, extras, dev groups, workspace members are internal', () => {
  const root = project({
    'pyproject.toml': `[project]
name = "app"
requires-python = ">=3.11"
dependencies = ["requests[socks]>=2", "lib"]
[dependency-groups]
dev = ["pytest"]
[tool.uv.workspace]
members = ["packages/*"]
[tool.uv.sources]
lib = { workspace = true }
`,
    'packages/lib/pyproject.toml': `[project]
name = "lib"
dependencies = ["Six==1.16"]
`,
    'uv.lock': `version = 1
requires-python = ">=3.11"

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }
dependencies = [{ name = "requests", extra = ["socks"] }, { name = "lib" }]

[[package]]
name = "lib"
version = "0.1.0"
source = { editable = "packages/lib" }
dependencies = [{ name = "six" }]

[[package]]
name = "requests"
version = "2.25.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "urllib3" }]

[package.optional-dependencies]
socks = [{ name = "pysocks" }]

[[package]]
name = "urllib3"
version = "1.26.4"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pysocks"
version = "1.7.1"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "six"
version = "1.16.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "6.2.4"
source = { git = "https://github.com/pytest-dev/pytest?rev=abc#abc" }
`,
  });
  const g = loadPythonProject(root);
  assert.equal(g.lockfile.kind, 'uv');
  assert.deepEqual(g.workspaces.map((w) => w.name), ['app', 'lib']);
  assert.deepEqual(directs(g), { requests: 'requests@2.25.1 prod', pytest: 'pytest@6.2.4 dev', six: 'six@1.16.0 prod' });
  assert.deepEqual(g.nodes.get('requests@2.25.1')!.deps.sort(), ['pysocks@1.7.1', 'urllib3@1.26.4']);
  assert.equal(g.nodes.get('pytest@6.2.4')!.resolved, 'git+https://github.com/pytest-dev/pytest?rev=abc#abc');
  assert.equal(pypiEcosystem.privateReason(root)('pytest', g.nodes.get('pytest@6.2.4')!.resolved), 'installed from git or a local path, not a registry');
});

test('poetry.lock with groups and optional deps', () => {
  const root = project({
    'pyproject.toml': `[tool.poetry]
name = "poetic"
[tool.poetry.dependencies]
python = "^3.9"
Django = "^3.2"
local-lib = { path = "../lib" }
[tool.poetry.group.test.dependencies]
pytest = "^7"
`,
    'poetry.lock': `[[package]]
name = "django"
version = "3.2.25"
[package.dependencies]
asgiref = ">=3.3.2,<4"
argon2-cffi = { version = ">=19.1.0", optional = true }

[[package]]
name = "asgiref"
version = "3.8.1"

[[package]]
name = "pytest"
version = "7.4.0"
`,
  });
  const g = loadPythonProject(root);
  assert.equal(g.lockfile.kind, 'poetry');
  assert.equal(g.workspaces[0].pythonRequires, '^3.9');
  assert.deepEqual(directs(g), { django: 'django@3.2.25 prod', 'local-lib': '- prod', pytest: 'pytest@7.4.0 dev' });
  assert.deepEqual(g.nodes.get('django@3.2.25')!.deps, ['asgiref@3.8.1']);
});

test('pip-compile requirements: `# via` gives edges and direct/transitive split', () => {
  const root = project({
    'requirements.txt': `certifi==2026.1.1
    # via requests
flask==2.0.1 \\
    --hash=sha256:abc
    # via -r requirements.in
markupsafe==3.0.0
    # via
    #   jinja2
    #   werkzeug
jinja2==3.1.0
    # via flask
requests==2.26.0
    # via -r requirements.in
werkzeug==3.0.0
    # via flask
`,
    'requirements-dev.txt': 'nose==1.3.7\nblack\n',
  });
  const warnings: string[] = [];
  const g = loadPythonProject(root, warnings);
  assert.equal(g.lockfile.kind, 'requirements');
  assert.deepEqual(directs(g), { nose: 'nose@1.3.7 dev', flask: 'flask@2.0.1 prod', requests: 'requests@2.26.0 prod' });
  assert.deepEqual(g.nodes.get('requests@2.26.0')!.deps, ['certifi@2026.1.1']);
  assert.deepEqual(g.nodes.get('jinja2@3.1.0')!.deps, ['markupsafe@3.0.0']);
  assert.equal(g.nodes.get('markupsafe@3.0.0')!.dev, false);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /aren't pinned.*black/);
});

test('virtualenv fallback reads dist-info metadata', () => {
  const root = project({
    'pyproject.toml': '[project]\nname = "v"\ndependencies = ["requests"]\n',
    '.venv/Lib/site-packages/requests-2.31.0.dist-info/METADATA': 'Metadata-Version: 2.1\nName: requests\nVersion: 2.31.0\nRequires-Dist: idna (<4,>=2.5)\nRequires-Dist: PySocks (!=1.5.7,>=1.5.6) ; extra == "socks"\n\nlong description\n',
    '.venv/Lib/site-packages/idna-3.6.dist-info/METADATA': 'Metadata-Version: 2.1\nName: idna\nVersion: 3.6\n',
  });
  const g = loadPythonProject(root);
  assert.equal(g.lockfile.kind, 'virtualenv');
  assert.deepEqual(directs(g), { requests: 'requests@2.31.0 prod' });
  assert.deepEqual(g.nodes.get('requests@2.31.0')!.deps, ['idna@3.6']);
});

test('PyPI outdated: CalVer bumps are not "major", hints use uv', () => {
  const hints = pypiEcosystem.hints({ lockfile: { kind: 'uv' } } as DependencyGraph);
  const reg: RegistryInfo = { name: 'certifi', assessed: true, latest: '2026.10.23', time: { '2020.12.5': '2020-12-05T00:00:00Z', '2026.10.23': '2026-10-23T00:00:00Z' }, versions: ['2020.12.5', '2026.10.23'], keywords: [] };
  const r = analyzeOutdated('certifi', '2020.12.5', reg, hints, new Date('2026-10-30'));
  assert.equal(r.semverBehind, 'minor');
  assert.equal(r.findings[0].fix, 'uv add "certifi>=2026.10.23"');
});

test('OSV: PyPI names match case-insensitively; GHSA/PYSEC aliases are merged', () => {
  const rec = { id: 'PYSEC-1', modified: '', affected: [{ package: { name: 'Django', ecosystem: 'PyPI' }, ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '3.2' }, { fixed: '3.2.4' }] }] }] };
  assert.equal(fixedIn(rec, 'django', '3.2', 'PyPI', pep), '3.2.4');
  assert.equal(fixedIn(rec, 'django', '3.2.4', 'PyPI', pep), undefined);
  const v = (id: string, aliases: string[], severity: Vulnerability['severity']): Vulnerability => ({ id, aliases, summary: id, severity, url: '' });
  const merged = dedupeAliases([v('PYSEC-1', ['CVE-1', 'GHSA-1'], 'unknown'), v('GHSA-1', ['CVE-1'], 'high'), v('GHSA-2', [], 'low')]);
  assert.deepEqual(merged.map((m) => [m.id, m.severity]), [['GHSA-1', 'high'], ['GHSA-2', 'low']]);
});

test('Python native-now honours requires-python', () => {
  const ws = (pythonRequires?: string) => [{ path: '.', name: 'x', direct: [], frontend: false, pythonRequires }];
  const config = {} as Config;
  assert.equal(pythonTarget(config, ws('>=3.9')), '3.9');
  assert.equal(pythonTarget(config, ws()), '3.10');
  assert.equal(pythonNative('toml', '3.10'), undefined);
  assert.equal(pythonNative('toml', '3.11')?.id, 'tomllib');
  assert.equal(pypiEcosystem.natives('pytz', ws('>=3.9'), false, config)[0]?.id, 'zoneinfo');
});
