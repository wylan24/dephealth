import semver from 'semver';
import type { PackageNode, Workspace } from '../types.ts';
import { sortVersions, type VersionScheme } from '../versions.ts';

/** Accumulates nodes from any lockfile format; merges duplicate install locations. */
export class GraphBuilder {
  nodes = new Map<string, PackageNode>();
  private byName = new Map<string, Set<string>>();

  add(name: string, version: string, resolved?: string): string {
    const id = `${name}@${version}`;
    if (!this.nodes.has(id)) {
      this.nodes.set(id, { id, name, version, deps: [], dev: true, resolved });
      if (!this.byName.has(name)) this.byName.set(name, new Set());
      this.byName.get(name)!.add(id);
    }
    return id;
  }

  edge(from: string, to: string | undefined) {
    if (!to || from === to) return;
    const node = this.nodes.get(from);
    if (node && !node.deps.includes(to)) node.deps.push(to);
  }

  /** Highest locked version of `name` (PEP 440 order when given a scheme; npm ranges otherwise). */
  highest(name: string, scheme: VersionScheme): string | undefined {
    const versions = [...(this.byName.get(name) ?? [])].map((id) => this.nodes.get(id)!.version);
    const version = sortVersions(scheme, versions).at(-1) ?? versions[0];
    return version === undefined ? undefined : `${name}@${version}`;
  }

  /** Fallback resolution: highest locked version of `name` that satisfies `range`. */
  bestMatch(name: string, range?: string): string | undefined {
    const ids = [...(this.byName.get(name) ?? [])];
    if (!ids.length) return undefined;
    const versions = ids.map((id) => this.nodes.get(id)!.version);
    const valid = range ? semver.validRange(range.replace(/^npm:/, '')) : null;
    const pick = valid ? semver.maxSatisfying(versions, valid) : null;
    const version = pick ?? semver.rsort(versions.filter((v) => semver.valid(v)))[0] ?? versions[0];
    return `${name}@${version}`;
  }
}

/** A package is `dev` unless it is reachable from a non-dev direct dependency. */
export function markDev(nodes: Map<string, PackageNode>, workspaces: Workspace[]) {
  for (const n of nodes.values()) n.dev = true;
  const stack: string[] = [];
  for (const ws of workspaces) for (const d of ws.direct) if (d.type !== 'dev' && d.id) stack.push(d.id);
  while (stack.length) {
    const node = nodes.get(stack.pop()!);
    if (!node || !node.dev) continue;
    node.dev = false;
    stack.push(...node.deps);
  }
}
