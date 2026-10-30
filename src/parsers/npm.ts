import type { Workspace } from '../types.ts';
import { GraphBuilder } from './graph.ts';
import { isLocalRange } from './manifest.ts';

interface LockEntry {
  name?: string;
  version?: string;
  resolved?: string;
  link?: boolean;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
}
interface V1Entry {
  version: string;
  resolved?: string;
  requires?: Record<string, string>;
  dependencies?: Record<string, V1Entry>;
}
interface NpmLock {
  lockfileVersion?: number;
  packages?: Record<string, LockEntry>;
  dependencies?: Record<string, V1Entry>;
}

const nameFromLocation = (loc: string) => {
  const i = loc.lastIndexOf('node_modules/');
  return i === -1 ? loc : loc.slice(i + 'node_modules/'.length);
};

/** Convert a lockfile v1 nested tree into the flat v2 `packages` shape. */
function flattenV1(deps: Record<string, V1Entry>, prefix = '', out: Record<string, LockEntry> = {}) {
  for (const [name, e] of Object.entries(deps)) {
    const loc = `${prefix}node_modules/${name}`;
    let version = e.version;
    let realName: string | undefined;
    const alias = /^npm:(.+)@([^@]+)$/.exec(version);
    if (alias) [, realName, version] = alias;
    out[loc] = { name: realName, version, resolved: e.resolved, dependencies: e.requires };
    if (e.dependencies) flattenV1(e.dependencies, `${loc}/`, out);
  }
  return out;
}

export function parseNpmLock(lock: NpmLock, workspaces: Workspace[], b = new GraphBuilder()) {
  const pkgs = lock.packages ?? flattenV1(lock.dependencies ?? {});
  const locToId = new Map<string, string>();

  for (const [loc, e] of Object.entries(pkgs)) {
    // skip the root, workspace folders and symlinks to workspace packages
    if (!loc.includes('node_modules/') || !e.version || e.link) continue;
    const name = e.name ?? nameFromLocation(loc);
    locToId.set(loc, b.add(name, e.version, e.resolved));
  }

  // Node's resolution algorithm: look in <from>/node_modules, then each ancestor's node_modules.
  const resolveFrom = (from: string, dep: string): string | undefined => {
    let dir = from;
    for (;;) {
      const candidate = dir ? `${dir}/node_modules/${dep}` : `node_modules/${dep}`;
      if (locToId.has(candidate)) return locToId.get(candidate);
      if (pkgs[candidate]?.link) return undefined; // workspace link — internal
      if (!dir) return undefined;
      const idx = dir.lastIndexOf('/node_modules/');
      // "a/node_modules/b" -> "a"; "node_modules/a" or a workspace folder -> project root
      dir = idx === -1 ? '' : dir.slice(0, idx);
    }
  };

  for (const [loc, e] of Object.entries(pkgs)) {
    const id = locToId.get(loc);
    if (!id) continue;
    const all = { ...e.dependencies, ...e.optionalDependencies, ...e.peerDependencies };
    for (const dep of Object.keys(all)) b.edge(id, resolveFrom(loc, dep));
  }

  for (const ws of workspaces) {
    const from = ws.path === '.' ? '' : ws.path;
    for (const d of ws.direct) {
      if (isLocalRange(d.range)) continue;
      d.id = resolveFrom(from, d.name) ?? resolveFrom('', d.name);
    }
  }
  return b;
}
