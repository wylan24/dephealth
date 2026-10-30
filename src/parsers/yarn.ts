import yarnLockfile from '@yarnpkg/lockfile';
import YAML from 'yaml';
import type { Workspace } from '../types.ts';
import { GraphBuilder } from './graph.ts';
import { isLocalRange } from './manifest.ts';

interface YarnEntry {
  version: string;
  resolved?: string;
  resolution?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
}

/** `name@range` -> [name, range]; the first "@" after position 0 separates them. */
const splitDescriptor = (d: string): [string, string] => {
  const i = d.indexOf('@', 1);
  return [d.slice(0, i), d.slice(i + 1)];
};

function build(
  entries: Map<string, YarnEntry>,
  realName: (descriptor: string, e: YarnEntry) => string | undefined,
  descriptor: (name: string, range: string) => string,
  workspaces: Workspace[],
  b: GraphBuilder,
) {
  const descToId = new Map<string, string>();
  for (const [desc, e] of entries) {
    const name = realName(desc, e);
    if (name) descToId.set(desc, b.add(name, e.version, e.resolved));
  }
  const lookup = (name: string, range: string) =>
    descToId.get(descriptor(name, range)) ?? (isLocalRange(range) ? undefined : b.bestMatch(name, range));
  for (const [desc, e] of entries) {
    const from = descToId.get(desc);
    if (!from) continue;
    for (const [dep, range] of Object.entries({ ...e.dependencies, ...e.optionalDependencies })) {
      b.edge(from, lookup(dep, range));
    }
  }
  for (const ws of workspaces) {
    for (const d of ws.direct) if (!isLocalRange(d.range)) d.id = lookup(d.name, d.range);
  }
  return b;
}

export function parseYarnClassic(text: string, workspaces: Workspace[], b = new GraphBuilder()) {
  const parsed = yarnLockfile.parse(text);
  if (parsed.type !== 'success') throw new Error(`yarn.lock could not be parsed (${parsed.type})`);
  const entries = new Map(Object.entries(parsed.object as Record<string, YarnEntry>));
  return build(
    entries,
    (desc) => {
      const [name, range] = splitDescriptor(desc);
      return range.startsWith('npm:') ? splitDescriptor(range.slice(4))[0] : name;
    },
    (name, range) => `${name}@${range}`,
    workspaces,
    b,
  );
}

export function parseYarnBerry(text: string, workspaces: Workspace[], b = new GraphBuilder()) {
  const doc = YAML.parse(text) as Record<string, YarnEntry>;
  const entries = new Map<string, YarnEntry>();
  for (const [key, e] of Object.entries(doc)) {
    if (key === '__metadata') continue;
    for (const desc of key.split(/,\s*/)) entries.set(desc.trim(), e);
  }
  return build(
    entries,
    (_desc, e) => {
      if (!e.resolution) return undefined;
      const [name, ref] = splitDescriptor(e.resolution);
      return /^(workspace|link|portal|file):/.test(ref) ? undefined : name;
    },
    (name, range) => `${name}@${/^[a-z]+:/.test(range) ? range : `npm:${range}`}`,
    workspaces,
    b,
  );
}
