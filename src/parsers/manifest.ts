import { existsSync, globSync, readFileSync } from 'node:fs';
import path from 'node:path';
import YAML from 'yaml';
import type { DepType, DirectDep, Workspace } from '../types.ts';

export interface Manifest {
  name?: string;
  version?: string;
  private?: boolean;
  workspaces?: string[] | { packages?: string[] };
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  engines?: Record<string, string>;
  browser?: unknown;
  browserslist?: unknown;
}

const FRONTEND_MARKERS = [
  'react', 'react-dom', 'vue', 'svelte', 'preact', '@angular/core', 'solid-js', 'lit',
  'next', 'nuxt', '@sveltejs/kit', 'astro', 'vite', 'webpack', 'parcel', '@remix-run/react',
];

export function readJson<T>(file: string): T {
  return JSON.parse(readFileSync(file, 'utf8').replace(/^﻿/, '')) as T;
}

export const toPosix = (p: string) => p.split(path.sep).join('/');

/** Expand workspace globs from package.json `workspaces` or pnpm-workspace.yaml. */
export function workspaceDirs(root: string, rootManifest: Manifest): string[] {
  let patterns: string[] = [];
  const ws = rootManifest.workspaces;
  if (Array.isArray(ws)) patterns = ws;
  else if (ws?.packages) patterns = ws.packages;
  const pnpmWs = path.join(root, 'pnpm-workspace.yaml');
  if (existsSync(pnpmWs)) {
    const doc = YAML.parse(readFileSync(pnpmWs, 'utf8')) as { packages?: string[] } | null;
    patterns = patterns.concat(doc?.packages ?? []);
  }
  const include = patterns.filter((p) => !p.startsWith('!'));
  const exclude = patterns.filter((p) => p.startsWith('!')).map((p) => p.slice(1));
  const found = new Set<string>(['.']);
  for (const pattern of include) {
    const matches = globSync(`${pattern.replace(/\/$/, '')}/package.json`, {
      cwd: root,
      exclude: (f) => toPosix(String(f)).includes('node_modules'),
    });
    for (const m of matches) {
      const dir = toPosix(path.dirname(String(m)));
      if (exclude.some((ex) => path.matchesGlob(dir, ex))) continue;
      found.add(dir);
    }
  }
  return [...found].sort();
}

const DEP_FIELDS: [keyof Manifest, DepType][] = [
  ['dependencies', 'prod'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
  ['devDependencies', 'dev'],
];

export function loadWorkspace(root: string, dir: string): { ws: Workspace; manifest: Manifest } {
  const manifest = readJson<Manifest>(path.join(root, dir, 'package.json'));
  const seen = new Set<string>();
  const direct: DirectDep[] = [];
  for (const [field, type] of DEP_FIELDS) {
    const deps = manifest[field] as Record<string, string> | undefined;
    for (const [name, range] of Object.entries(deps ?? {})) {
      // a package listed as both peer and dev is installed as dev; keep the first (strongest) type
      if (seen.has(name)) continue;
      seen.add(name);
      direct.push({ name, range, type });
    }
  }
  const allNames = direct.map((d) => d.name);
  const frontend =
    manifest.browser !== undefined ||
    manifest.browserslist !== undefined ||
    existsSync(path.join(root, dir, '.browserslistrc')) ||
    allNames.some((n) => FRONTEND_MARKERS.includes(n));
  return {
    manifest,
    ws: {
      path: dir,
      name: manifest.name ?? (dir === '.' ? path.basename(root) : dir),
      direct,
      nodeEngine: manifest.engines?.node,
      frontend,
    },
  };
}

/** Ranges that point at local/workspace code rather than a registry package. */
export function isLocalRange(range: string): boolean {
  return /^(workspace:|link:|file:|portal:|\.{0,2}\/)/.test(range);
}
