import { gzipSync } from 'node:zlib';
import { all as replacements, nativeReplacements, type ModuleReplacement } from 'module-replacements';
import semver from 'semver';
import type { Finding, PackageNode } from '../types.ts';

const MB = 1024 * 1024;

export const formatBytes = (n: number) => (n >= MB ? `${(n / MB).toFixed(1)} MB` : `${Math.round(n / 1024)} kB`);

/** Number of distinct packages reachable from `id` (excluding itself). */
export function transitiveCount(nodes: Map<string, PackageNode>, id: string): number {
  const seen = new Set<string>([id]);
  const stack = [...(nodes.get(id)?.deps ?? [])];
  while (stack.length) {
    const next = stack.pop()!;
    if (seen.has(next)) continue;
    seen.add(next);
    stack.push(...(nodes.get(next)?.deps ?? []));
  }
  return seen.size - 1;
}

/** Package names locked at more than one version. */
export function duplicates(nodes: Map<string, PackageNode>): { name: string; versions: string[] }[] {
  const byName = new Map<string, string[]>();
  for (const n of nodes.values()) byName.set(n.name, [...(byName.get(n.name) ?? []), n.version]);
  return [...byName]
    .filter(([, v]) => v.length > 1)
    .map(([name, versions]) => ({ name, versions: semver.sort(versions.filter((v) => semver.valid(v))).concat(versions.filter((v) => !semver.valid(v))) }))
    .sort((a, b) => b.versions.length - a.versions.length || a.name.localeCompare(b.name));
}

export interface Targets {
  node: string;
  browsers?: Record<string, string>;
}

function engineSupports(rep: ModuleReplacement, targets: Targets): boolean {
  if (!rep.engines?.length) return true; // language features documented without engine data
  const supports = (engine: string, min: string) => {
    const c = rep.engines!.find((e) => e.engine === engine);
    const need = c?.minVersion && semver.coerce(c.minVersion);
    const have = semver.coerce(min);
    return !!(need && have && semver.gte(have, need));
  };
  if (!supports('nodejs', targets.node)) return false;
  return Object.entries(targets.browsers ?? {}).every(([engine, min]) => supports(engine, min));
}

export interface NativeMatch {
  kind: 'native' | 'snippet';
  id: string;
  description?: string;
  url?: string;
}

/** Built-in APIs or one-line snippets that cover what this package does, for the given targets. */
export function nativeAlternatives(name: string, targets: Targets): NativeMatch[] {
  const mapping = replacements.mappings[name];
  if (!mapping) return [];
  const out: NativeMatch[] = [];
  // "moment -> Date" is listed as an option but isn't a like-for-like swap; only polyfill-style
  // mappings, or ones where a built-in is the first choice, count as "native now".
  const polyfill = !!nativeReplacements.mappings[name];
  for (const [i, id] of mapping.replacements.entries()) {
    const rep = replacements.replacements[id];
    if (!rep) continue;
    if (rep.type === 'native' && (polyfill || i === 0) && engineSupports(rep, targets)) out.push({ kind: 'native', id, description: rep.description });
    if (rep.type === 'simple') out.push({ kind: 'snippet', id, description: rep.description });
  }
  return out;
}

export interface WeightInput {
  name: string;
  dev: boolean;
  unpackedSize?: number;
  transitive: number;
  bundle?: { minified: number; gzip: number };
  targets: Targets;
}

export function analyzeWeight(w: WeightInput): Finding[] {
  const findings: Finding[] = [];
  const scale = w.dev ? 0.5 : 1; // dev tooling weight matters less than what ships
  const natives = nativeAlternatives(w.name, w.targets);
  const native = natives.find((n) => n.kind === 'native');
  const snippet = natives.find((n) => n.kind === 'snippet');
  if (native) {
    findings.push({
      category: 'weight',
      level: 'low',
      code: 'native-now',
      message: `Your runtime already provides this: ${native.id}${native.description ? ` — ${native.description.replace(/\.$/, '')}` : ''}`,
      penalty: 6,
      fix: `Replace with ${native.id} and remove ${w.name}`,
    });
  } else if (snippet) {
    findings.push({
      category: 'weight',
      level: 'low',
      code: 'micro-utility',
      message: `Micro-utility replaceable by a line of code: ${snippet.description ?? snippet.id}`,
      penalty: 4,
      fix: `Inline the snippet and remove ${w.name}`,
    });
  }
  if (w.transitive >= 50) {
    findings.push({ category: 'weight', level: 'low', code: 'many-deps', message: `Pulls in ${w.transitive} transitive packages`, penalty: Math.round((w.transitive >= 150 ? 6 : 3) * scale) });
  }
  if (w.unpackedSize && w.unpackedSize >= 5 * MB) {
    findings.push({ category: 'weight', level: w.dev ? 'info' : 'low', code: 'install-size', message: `Large install: ${formatBytes(w.unpackedSize)} unpacked`, penalty: Math.round((w.unpackedSize >= 20 * MB ? 5 : 3) * scale) });
  }
  if (w.bundle && !w.dev && w.bundle.gzip >= 30 * 1024) {
    findings.push({
      category: 'weight',
      level: w.bundle.gzip >= 100 * 1024 ? 'medium' : 'low',
      code: 'bundle-size',
      message: `Adds ${formatBytes(w.bundle.gzip)} gzipped (${formatBytes(w.bundle.minified)} minified) to a browser bundle if fully imported`,
      penalty: w.bundle.gzip >= 100 * 1024 ? 8 : 4,
      fix: 'Import only the parts you use, or pick a lighter alternative',
    });
  }
  return findings;
}

/** Minified + gzipped size of `export * from "<name>"`, bundled from the project's node_modules. */
export async function measureBundle(name: string, resolveDir: string): Promise<{ minified: number; gzip: number } | undefined> {
  try {
    const esbuild = await import('esbuild');
    const result = await esbuild.build({
      stdin: { contents: `export * from ${JSON.stringify(name)};`, resolveDir, loader: 'js' },
      bundle: true,
      minify: true,
      write: false,
      format: 'esm',
      platform: 'browser',
      logLevel: 'silent',
      treeShaking: true,
      define: { 'process.env.NODE_ENV': '"production"' },
      loader: { '.node': 'empty', '.css': 'empty', '.svg': 'empty', '.png': 'empty' },
    });
    const code = result.outputFiles[0].contents;
    return { minified: code.byteLength, gzip: gzipSync(code).byteLength };
  } catch {
    return undefined; // not installed, Node-only, or needs a framework compiler
  }
}
