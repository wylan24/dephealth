import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { loadProject } from '../src/parsers/index.ts';
import { parsePnpmKey } from '../src/parsers/pnpm.ts';

function project(files: Record<string, unknown>): string {
  const dir = mkdtempSync(path.join(os.tmpdir(), 'dephealth-test-'));
  for (const [name, content] of Object.entries(files)) {
    mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    writeFileSync(path.join(dir, name), typeof content === 'string' ? content : JSON.stringify(content, null, 2));
  }
  return dir;
}

const directIds = (root: string) => Object.fromEntries(loadProject(root).workspaces.flatMap((w) => w.direct.map((d) => [d.name, d.id])));

test('npm lockfile v3: nested resolution, dev marking, transitive edges', () => {
  const root = project({
    'package.json': { name: 'app', dependencies: { a: '^1.0.0' }, devDependencies: { b: '^2.0.0' } },
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'app' },
        'node_modules/a': { version: '1.2.0', dependencies: { c: '^1.0.0' } },
        'node_modules/b': { version: '2.0.0', dev: true, dependencies: { c: '^2.0.0' } },
        'node_modules/b/node_modules/c': { version: '2.1.0', dev: true },
        'node_modules/c': { version: '1.5.0' },
      },
    },
  });
  const g = loadProject(root);
  assert.equal(g.lockfile.kind, 'npm');
  assert.deepEqual(directIds(root), { a: 'a@1.2.0', b: 'b@2.0.0' });
  assert.deepEqual(g.nodes.get('a@1.2.0')!.deps, ['c@1.5.0']);
  assert.deepEqual(g.nodes.get('b@2.0.0')!.deps, ['c@2.1.0']);
  assert.equal(g.nodes.get('c@1.5.0')!.dev, false);
  assert.equal(g.nodes.get('c@2.1.0')!.dev, true);
});

test('npm workspaces: workspace packages are internal, not dependencies', () => {
  const root = project({
    'package.json': { name: 'mono', workspaces: ['packages/*'], devDependencies: { x: '1.0.0' } },
    'packages/web/package.json': { name: '@mono/web', dependencies: { '@mono/lib': '*', y: '^3.0.0' } },
    'packages/lib/package.json': { name: '@mono/lib', dependencies: { y: '^2.0.0' } },
    'package-lock.json': {
      lockfileVersion: 3,
      packages: {
        '': { name: 'mono' },
        'packages/web': { name: '@mono/web' },
        'packages/lib': { name: '@mono/lib' },
        'node_modules/@mono/lib': { resolved: 'packages/lib', link: true },
        'node_modules/x': { version: '1.0.0', dev: true },
        'node_modules/y': { version: '2.0.0' },
        'packages/web/node_modules/y': { version: '3.1.0' },
      },
    },
  });
  const g = loadProject(root);
  assert.deepEqual(g.workspaces.map((w) => w.path), ['.', 'packages/lib', 'packages/web']);
  const web = g.workspaces.find((w) => w.name === '@mono/web')!;
  assert.deepEqual(web.direct.map((d) => [d.name, d.id]), [['y', 'y@3.1.0']]);
  const lib = g.workspaces.find((w) => w.name === '@mono/lib')!;
  assert.equal(lib.direct[0].id, 'y@2.0.0');
});

test('npm lockfile v1 (nested dependencies) and aliases', () => {
  const root = project({
    'package.json': { name: 'old', dependencies: { a: '^1.0.0', b: 'npm:real-b@^1.0.0' } },
    'package-lock.json': {
      lockfileVersion: 1,
      dependencies: {
        a: { version: '1.0.0', requires: { c: '^1.0.0' }, dependencies: { c: { version: '1.0.1' } } },
        b: { version: 'npm:real-b@1.4.0' },
      },
    },
  });
  const g = loadProject(root);
  assert.deepEqual(directIds(root), { a: 'a@1.0.0', b: 'real-b@1.4.0' });
  assert.deepEqual(g.nodes.get('a@1.0.0')!.deps, ['c@1.0.1']);
});

test('pnpm key parsing across lockfile versions', () => {
  assert.deepEqual(parsePnpmKey('/@babel/core/7.1.0_react@17.0.0', true), { name: '@babel/core', version: '7.1.0' });
  assert.deepEqual(parsePnpmKey('/lodash.get@4.4.2', false), { name: 'lodash.get', version: '4.4.2' });
  assert.deepEqual(parsePnpmKey('@types/react@18.2.0(@types/node@20.0.0)', false), { name: '@types/react', version: '18.2.0' });
  assert.deepEqual(parsePnpmKey('registry.npmjs.org/ms/2.1.3', true), { name: 'ms', version: '2.1.3' });
});

test('pnpm v9 lockfile with importers and snapshots', () => {
  const root = project({
    'package.json': { name: 'p', dependencies: { react: '^18.0.0' }, devDependencies: { vitest: '^1.0.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      react:
        specifier: ^18.0.0
        version: 18.2.0
    devDependencies:
      vitest:
        specifier: ^1.0.0
        version: 1.6.0(@types/node@20.1.0)
packages:
  react@18.2.0:
    resolution: {integrity: sha512-x}
  loose-envify@1.4.0:
    resolution: {integrity: sha512-y}
  vitest@1.6.0:
    resolution: {integrity: sha512-z}
  '@types/node@20.1.0':
    resolution: {integrity: sha512-w}
snapshots:
  react@18.2.0:
    dependencies:
      loose-envify: 1.4.0
  loose-envify@1.4.0: {}
  vitest@1.6.0(@types/node@20.1.0):
    dependencies:
      '@types/node': 20.1.0
  '@types/node@20.1.0': {}
`,
  });
  const g = loadProject(root);
  assert.equal(g.lockfile.kind, 'pnpm');
  assert.deepEqual(directIds(root), { react: 'react@18.2.0', vitest: 'vitest@1.6.0' });
  assert.deepEqual(g.nodes.get('react@18.2.0')!.deps, ['loose-envify@1.4.0']);
  assert.equal(g.nodes.get('loose-envify@1.4.0')!.dev, false);
  assert.equal(g.nodes.get('@types/node@20.1.0')!.dev, true);
});

test('pnpm v6 lockfile', () => {
  const root = project({
    'package.json': { name: 'p6', dependencies: { debug: '^4.0.0' } },
    'pnpm-lock.yaml': `lockfileVersion: '6.0'
dependencies:
  debug:
    specifier: ^4.0.0
    version: 4.3.4
packages:
  /debug@4.3.4:
    resolution: {integrity: sha512-a}
    dependencies:
      ms: 2.1.2
  /ms@2.1.2:
    resolution: {integrity: sha512-b}
`,
  });
  const g = loadProject(root);
  assert.deepEqual(directIds(root), { debug: 'debug@4.3.4' });
  assert.deepEqual(g.nodes.get('debug@4.3.4')!.deps, ['ms@2.1.2']);
});

test('yarn classic lockfile', () => {
  const root = project({
    'package.json': { name: 'y1', dependencies: { debug: '^4.1.0' } },
    'yarn.lock': `# yarn lockfile v1


debug@^4.1.0, debug@^4.3.1:
  version "4.3.4"
  resolved "https://registry.yarnpkg.com/debug/-/debug-4.3.4.tgz"
  dependencies:
    ms "2.1.2"

ms@2.1.2:
  version "2.1.2"
  resolved "https://registry.yarnpkg.com/ms/-/ms-2.1.2.tgz"
`,
  });
  const g = loadProject(root);
  assert.equal(g.lockfile.kind, 'yarn-classic');
  assert.deepEqual(directIds(root), { debug: 'debug@4.3.4' });
  assert.deepEqual(g.nodes.get('debug@4.3.4')!.deps, ['ms@2.1.2']);
});

test('yarn berry lockfile', () => {
  const root = project({
    'package.json': { name: 'y2', dependencies: { debug: '^4.1.0' } },
    'yarn.lock': `__metadata:
  version: 8
  cacheKey: 10

"debug@npm:^4.1.0":
  version: 4.3.4
  resolution: "debug@npm:4.3.4"
  dependencies:
    ms: "npm:2.1.2"
  languageName: node
  linkType: hard

"ms@npm:2.1.2":
  version: 2.1.2
  resolution: "ms@npm:2.1.2"
  languageName: node
  linkType: hard

"y2@workspace:.":
  version: 0.0.0-use.local
  resolution: "y2@workspace:."
  dependencies:
    debug: "npm:^4.1.0"
  languageName: unknown
  linkType: soft
`,
  });
  const g = loadProject(root);
  assert.equal(g.lockfile.kind, 'yarn-berry');
  assert.deepEqual(directIds(root), { debug: 'debug@4.3.4' });
  assert.deepEqual(g.nodes.get('debug@4.3.4')!.deps, ['ms@2.1.2']);
  assert.equal(g.nodes.size, 2);
});
