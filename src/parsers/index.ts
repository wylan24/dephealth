import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { DependencyGraph } from '../types.ts';
import { GraphBuilder, markDev } from './graph.ts';
import { isLocalRange, loadWorkspace, readJson, workspaceDirs, type Manifest } from './manifest.ts';
import { parseNpmLock } from './npm.ts';
import { parsePnpmLock } from './pnpm.ts';
import { parseYarnBerry, parseYarnClassic } from './yarn.ts';
import YAML from 'yaml';

/** Read every manifest in the project (including workspaces) and its lockfile into one graph. */
export function loadProject(rootDir: string, warnings: string[] = []): DependencyGraph {
  const root = path.resolve(rootDir);
  if (!existsSync(path.join(root, 'package.json'))) throw new Error(`No package.json found in ${root}`);
  const rootManifest = readJson<Manifest>(path.join(root, 'package.json'));
  const workspaces = workspaceDirs(root, rootManifest).map((dir) => loadWorkspace(root, dir).ws);

  // workspace packages depending on each other are internal, not registry dependencies
  if (workspaces.length > 1) {
    const internal = new Set(workspaces.map((w) => w.name));
    for (const ws of workspaces) ws.direct = ws.direct.filter((d) => !internal.has(d.name));
  }

  const b = new GraphBuilder();
  const at = (f: string) => path.join(root, f);
  let lockfile: DependencyGraph['lockfile'];

  if (existsSync(at('package-lock.json')) || existsSync(at('npm-shrinkwrap.json'))) {
    const file = existsSync(at('npm-shrinkwrap.json')) ? 'npm-shrinkwrap.json' : 'package-lock.json';
    parseNpmLock(readJson(at(file)), workspaces, b);
    lockfile = { kind: 'npm', path: file };
  } else if (existsSync(at('pnpm-lock.yaml'))) {
    parsePnpmLock(YAML.parse(readFileSync(at('pnpm-lock.yaml'), 'utf8')), workspaces, b);
    lockfile = { kind: 'pnpm', path: 'pnpm-lock.yaml' };
  } else if (existsSync(at('yarn.lock'))) {
    const text = readFileSync(at('yarn.lock'), 'utf8');
    const berry = /^__metadata:/m.test(text);
    (berry ? parseYarnBerry : parseYarnClassic)(text, workspaces, b);
    lockfile = { kind: berry ? 'yarn-berry' : 'yarn-classic', path: 'yarn.lock' };
  } else {
    lockfile = { kind: 'none' };
    warnings.push('No lockfile found: only direct dependencies installed in node_modules are checked, and transitive dependencies are skipped.');
    for (const ws of workspaces) {
      for (const d of ws.direct) {
        for (const dir of [path.join(root, ws.path, 'node_modules', d.name), at(path.join('node_modules', d.name))]) {
          const pj = path.join(dir, 'package.json');
          if (!existsSync(pj)) continue;
          d.id = b.add(d.name, readJson<Manifest>(pj).version ?? '0.0.0');
          break;
        }
        if (!d.id && !isLocalRange(d.range)) warnings.push(`${ws.name}: ${d.name} is not installed; skipped.`);
      }
    }
  }

  for (const ws of workspaces) {
    for (const d of ws.direct) {
      if (!d.id && !isLocalRange(d.range) && lockfile.kind !== 'none') {
        warnings.push(`${ws.name}: ${d.name}@${d.range} is not in the lockfile (run your package manager's install).`);
      }
    }
  }
  markDev(b.nodes, workspaces);
  return { ecosystem: 'npm', root, lockfile, workspaces, nodes: b.nodes };
}
