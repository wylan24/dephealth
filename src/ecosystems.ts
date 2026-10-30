import { existsSync } from 'node:fs';
import path from 'node:path';
import semver from 'semver';
import { nativeAlternatives, type NativeMatch } from './analyzers/weight.ts';
import { authorSuggestions, curatedSuggestions, legacyNote, pythonLegacyNote, pythonNative, pythonSuggestions } from './advisor/replacements.ts';
import type { Config } from './config.ts';
import type { DiskCache } from './fetchers/http.ts';
import { NpmFetcher } from './fetchers/npm.ts';
import { NpmRc } from './fetchers/npmrc.ts';
import { PypiFetcher } from './fetchers/pypi.ts';
import { loadProject } from './parsers/index.ts';
import { hasPythonProject, loadPythonProject } from './parsers/pypi.ts';
import type { DependencyGraph, Ecosystem, Hints, RegistryInfo, Replacement, Workspace } from './types.ts';
import { pep440Scheme, semverScheme, type VersionScheme } from './versions.ts';

export type SearchHit = { package: { name: string; description?: string }; score: { final: number; detail: { maintenance: number } } };

/** Everything that differs between package ecosystems; analyzers only see this interface. */
export interface EcosystemAdapter {
  id: Ecosystem;
  scheme: VersionScheme;
  detect(root: string): boolean;
  load(root: string, warnings: string[]): DependencyGraph;
  hints(graph: DependencyGraph): Hints;
  registry(cache: DiskCache): { info(name: string, version: string, withDownloads: boolean): Promise<RegistryInfo>; search?(text: string): Promise<SearchHit[]> };
  /** packages that can't be checked against public data (git, local paths, private scopes) */
  privateReason(root: string): (name: string, resolved?: string) => string | undefined;
  natives(name: string, workspaces: Workspace[], prodFrontend: boolean, config: Config): NativeMatch[];
  suggestions(name: string, deprecation?: string): Replacement[];
  legacy(name: string): string | undefined;
  /** browser bundle sizes make sense for this ecosystem */
  bundles: boolean;
}

/** Lowest Node.js version the project must support. */
export function nodeTarget(config: Config, workspaces: Workspace[]): string {
  if (config.nodeTarget) return config.nodeTarget;
  const mins = workspaces.map((w) => w.nodeEngine && semver.minVersion(w.nodeEngine)?.version).filter(Boolean) as string[];
  return mins.length ? semver.sort(mins)[0] : '22.0.0';
}

/** Lowest Python version from `requires-python` (">=3.9", "~=3.10", "^3.11"), default 3.10. */
export function pythonTarget(config: Config, workspaces: Workspace[]): string {
  if (config.pythonTarget) return config.pythonTarget;
  const mins = workspaces
    .map((w) => w.pythonRequires && /(?:>=|~=|==|\^|>|~)\s*(\d+(?:\.\d+)?)/.exec(w.pythonRequires)?.[1])
    .filter(Boolean) as string[];
  return mins.sort((a, b) => Number(a.split('.')[1] ?? 0) - Number(b.split('.')[1] ?? 0))[0] ?? '3.10';
}

export const npmEcosystem: EcosystemAdapter = {
  id: 'npm',
  scheme: semverScheme,
  bundles: true,
  detect: (root) => existsSync(path.join(root, 'package.json')),
  load: loadProject,
  hints(graph) {
    const kind = graph.lockfile.kind;
    const pm = kind === 'pnpm' ? 'pnpm add' : kind.startsWith('yarn') ? 'yarn add' : 'npm install';
    const override =
      kind === 'pnpm' ? 'add a "pnpm.overrides" entry for' : kind.startsWith('yarn') ? 'add a "resolutions" entry for' : 'add an "overrides" entry for';
    return {
      scheme: semverScheme,
      pin: (n, v) => `${n}@${v}`,
      update: (n, v) => `${pm} ${n}@${v}`,
      override: (n) => `${override} ${n}`,
    };
  },
  registry(cache) {
    const npm = new NpmFetcher(cache);
    return { info: (n, v, d) => npm.info(n, v, d), search: (t) => npm.search(t) };
  },
  privateReason(root) {
    const rc = new NpmRc(root);
    return (n, r) => rc.privateReason(n, r);
  },
  natives(name, workspaces, prodFrontend, config) {
    return nativeAlternatives(name, { node: nodeTarget(config, workspaces), browsers: prodFrontend ? config.browserTargets : undefined });
  },
  suggestions: (name, deprecation) => [...authorSuggestions(name, deprecation), ...curatedSuggestions(name)],
  legacy: legacyNote,
};

export const pypiEcosystem: EcosystemAdapter = {
  id: 'PyPI',
  scheme: pep440Scheme,
  bundles: false,
  detect: hasPythonProject,
  load: loadPythonProject,
  hints(graph) {
    const kind = graph.lockfile.kind;
    return {
      scheme: pep440Scheme,
      pin: (n, v) => `${n}==${v}`,
      update: (n, v) =>
        kind === 'uv' ? `uv add "${n}>=${v}"` : kind === 'poetry' ? `poetry add "${n}>=${v}"` : `pin ${n}==${v} in your requirements and reinstall`,
      override: (n, v) =>
        kind === 'uv'
          ? `add "${n}>=${v}" to [tool.uv] constraint-dependencies`
          : kind === 'poetry'
            ? `declare "${n}>=${v}" as a direct dependency`
            : `pin ${n}>=${v} in your requirements or constraints file`,
    };
  },
  registry(cache) {
    const pypi = new PypiFetcher(cache);
    return { info: (n, v, d) => pypi.info(n, v, d) }; // PyPI has no search API
  },
  privateReason: () => (_name, resolved) =>
    resolved && /^(git\+|file:)/.test(resolved) ? 'installed from git or a local path, not a registry' : undefined,
  natives(name, workspaces, _frontend, config) {
    const n = pythonNative(name, pythonTarget(config, workspaces));
    return n ? [{ kind: 'native', id: n.id, description: n.description }] : [];
  },
  suggestions: (name) => pythonSuggestions(name),
  legacy: pythonLegacyNote,
};

export const ECOSYSTEMS: EcosystemAdapter[] = [npmEcosystem, pypiEcosystem];
