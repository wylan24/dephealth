import type { Workspace } from '../types.ts';
import { GraphBuilder } from './graph.ts';
import { isLocalRange } from './manifest.ts';

type DepMap = Record<string, string | { specifier?: string; version: string }>;
interface PnpmEntry {
  resolution?: { tarball?: string };
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}
interface PnpmImporter {
  dependencies?: DepMap;
  devDependencies?: DepMap;
  optionalDependencies?: DepMap;
}
interface PnpmLock extends PnpmImporter {
  lockfileVersion: string | number;
  importers?: Record<string, PnpmImporter>;
  packages?: Record<string, PnpmEntry>;
  snapshots?: Record<string, PnpmEntry>;
}

/**
 * Lockfile keys across versions:
 *   v5  `/name/1.2.3_peer@1.0.0`   v6 `/name@1.2.3(peer@1.0.0)`   v9 `name@1.2.3(peer@1.0.0)`
 */
export function parsePnpmKey(key: string, v5: boolean): { name: string; version: string } | undefined {
  let k = key.replace(/^[a-z0-9-]+(?:\.[a-z0-9-]+)+\//, '').replace(/^\//, ''); // drop "registry.host/" or "/"
  if (v5) {
    const i = k.lastIndexOf('/');
    if (i <= 0) return undefined;
    return { name: k.slice(0, i), version: k.slice(i + 1).split('_')[0] };
  }
  k = k.split('(')[0];
  const i = k.indexOf('@', 1);
  if (i === -1) return undefined;
  return { name: k.slice(0, i), version: k.slice(i + 1) };
}

/** Turn a dependency reference (`1.2.3(peer)`, or an alias `real@1.2.3`) into a node id. */
function refToId(name: string, ref: string, v5: boolean): string | undefined {
  if (isLocalRange(ref)) return undefined;
  let parsed;
  if (v5) parsed = parsePnpmKey(ref.startsWith('/') ? ref : `/${name}/${ref}`, true);
  else {
    const bare = ref.replace(/^\//, '').split('(')[0];
    parsed = parsePnpmKey(bare.indexOf('@', 1) > 0 ? bare : `${name}@${bare}`, false);
  }
  return parsed && `${parsed.name}@${parsed.version}`;
}

export function parsePnpmLock(lock: PnpmLock, workspaces: Workspace[], b = new GraphBuilder()) {
  const v5 = Number.parseFloat(String(lock.lockfileVersion)) < 6;
  const sections = [lock.packages ?? {}, lock.snapshots ?? {}];

  for (const section of sections) {
    for (const [key, e] of Object.entries(section)) {
      const p = parsePnpmKey(key, v5);
      if (p) b.add(p.name, p.version, e.resolution?.tarball);
    }
  }
  for (const section of sections) {
    for (const [key, e] of Object.entries(section)) {
      const p = parsePnpmKey(key, v5);
      if (!p) continue;
      const from = `${p.name}@${p.version}`;
      for (const [dep, ref] of Object.entries({ ...e.dependencies, ...e.optionalDependencies })) {
        b.edge(from, refToId(dep, ref, v5));
      }
    }
  }

  const importers = lock.importers ?? { '.': lock };
  for (const ws of workspaces) {
    const imp = importers[ws.path] ?? {};
    const locked: DepMap = { ...imp.devDependencies, ...imp.optionalDependencies, ...imp.dependencies };
    for (const d of ws.direct) {
      if (isLocalRange(d.range)) continue;
      const entry = locked[d.name];
      const ref = typeof entry === 'string' ? entry : entry?.version;
      const id = ref ? refToId(d.name, ref, v5) : undefined;
      d.id = id && b.nodes.has(id) ? id : b.bestMatch(d.name, d.range);
    }
  }
  return b;
}
