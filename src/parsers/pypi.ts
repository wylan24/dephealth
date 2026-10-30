import { existsSync, globSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { DependencyGraph, DepType, DirectDep, Workspace } from '../types.ts';
import { pep440Scheme } from '../versions.ts';
import { GraphBuilder, markDev } from './graph.ts';
import { toPosix } from './manifest.ts';

/** PEP 503 normalisation: `Foo_Bar.baz` -> `foo-bar-baz`. Used for every PyPI name we store. */
export const normalizeName = (name: string) => name.toLowerCase().replace(/[-_.]+/g, '-');

export interface Requirement {
  name: string;
  extras: string[];
  specifier: string;
  marker?: string;
  url?: string;
}

/** Parse a PEP 508 requirement string such as `requests[socks]>=2.31; python_version >= "3.8"`. */
export function parseRequirement(text: string): Requirement | undefined {
  const m = /^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[([^\]]*)\])?\s*(?:@\s*([^\s;]+)|\(?([^;]*?)\)?)\s*(?:;\s*(.*))?$/.exec(text);
  if (!m) return undefined;
  return {
    name: normalizeName(m[1]),
    extras: (m[2] ?? '').split(',').map((e) => e.trim()).filter(Boolean),
    specifier: (m[4] ?? '').trim(),
    url: m[3],
    marker: m[5]?.trim(),
  };
}

/** Markers that only apply when an optional extra is requested. */
const extraOnly = (marker?: string) => !!marker && /\bextra\s*==/.test(marker);

type Toml = Record<string, any>; // eslint-disable-line @typescript-eslint/no-explicit-any

function readToml(file: string): Toml {
  return parseToml(readFileSync(file, 'utf8')) as Toml;
}

// ---------------------------------------------------------------- pyproject.toml

const DEV_GROUP = /^(dev|test|tests|testing|lint|linting|docs?|typing|types|ci|bench)/i;

function pyprojectDirects(doc: Toml): DirectDep[] {
  const out: DirectDep[] = [];
  const add = (name: string, range: string, type: DepType) => {
    const n = normalizeName(name);
    if (n === 'python' || out.some((d) => d.name === n)) return;
    out.push({ name: n, range, type });
  };
  const addReq = (spec: unknown, type: DepType) => {
    if (typeof spec !== 'string') return; // {include-group = "..."} entries
    const r = parseRequirement(spec);
    if (r) add(r.name, r.url ? `file:${r.url}` : r.specifier || '*', type);
  };
  const project = doc.project ?? {};
  for (const s of project.dependencies ?? []) addReq(s, 'prod');
  for (const list of Object.values<string[]>(project['optional-dependencies'] ?? {})) for (const s of list) addReq(s, 'optional');
  for (const [group, list] of Object.entries<unknown[]>(doc['dependency-groups'] ?? {})) for (const s of list) addReq(s, DEV_GROUP.test(group) ? 'dev' : 'optional');
  for (const s of doc.tool?.uv?.['dev-dependencies'] ?? []) addReq(s, 'dev');

  // Poetry: `name = "^1.2"` or `name = { version = "^1.2", optional = true }`; path/git sources are local
  const poetryDeps = (deps: Record<string, unknown> | undefined, type: DepType) => {
    for (const [name, spec] of Object.entries(deps ?? {})) {
      if (typeof spec === 'string') add(name, spec, type);
      else if (spec && typeof spec === 'object' && !Array.isArray(spec)) {
        const s = spec as Record<string, unknown>;
        if (s.path || s.git || s.url) add(name, `file:${String(s.path ?? s.git ?? s.url)}`, type);
        else add(name, String(s.version ?? '*'), s.optional ? 'optional' : type);
      } else if (Array.isArray(spec)) add(name, '*', type);
    }
  };
  const poetry = doc.tool?.poetry ?? {};
  poetryDeps(poetry.dependencies, 'prod');
  poetryDeps(poetry['dev-dependencies'], 'dev');
  for (const [group, g] of Object.entries<{ dependencies?: Record<string, unknown> }>(poetry.group ?? {})) {
    poetryDeps(g.dependencies, group === 'main' ? 'prod' : 'dev');
  }

  // uv workspace members referenced as `{ workspace = true }` are internal
  for (const [name, src] of Object.entries<Record<string, unknown>>(doc.tool?.uv?.sources ?? {})) {
    const d = out.find((x) => x.name === normalizeName(name));
    if (d && (src.workspace || src.path)) d.range = `file:${String(src.path ?? 'workspace')}`;
  }
  return out;
}

function loadPyWorkspace(root: string, dir: string): { ws: Workspace; doc: Toml } {
  const doc = readToml(path.join(root, dir, 'pyproject.toml'));
  const name = doc.project?.name ?? doc.tool?.poetry?.name ?? (dir === '.' ? path.basename(root) : dir);
  const poetryPython = doc.tool?.poetry?.dependencies?.python;
  return {
    doc,
    ws: {
      path: dir,
      name,
      direct: pyprojectDirects(doc),
      pythonRequires: doc.project?.['requires-python'] ?? (typeof poetryPython === 'string' ? poetryPython : undefined),
      frontend: false,
    },
  };
}

// ---------------------------------------------------------------- requirements*.txt

const DEV_FILE = /(dev|test|lint|doc|ci|typing)/i;

export function requirementFiles(root: string): string[] {
  const files = globSync(['requirements*.txt', '*-requirements.txt', '*_requirements.txt', 'requirements/*.txt'], { cwd: root }).map((f) => toPosix(String(f)));
  return [...new Set(files)].sort();
}

/**
 * Parse pinned requirements. pip-compile/uv `# via` annotations give us the dependency edges and tell
 * direct dependencies (`via -r requirements.in`) apart from transitive ones.
 */
export function parseRequirementsFile(root: string, file: string, b: GraphBuilder, seen = new Set<string>()) {
  const directs: DirectDep[] = [];
  const unpinned: string[] = [];
  if (seen.has(file)) return { directs, unpinned };
  seen.add(file);
  const full = path.join(root, file);
  if (!existsSync(full)) return { directs, unpinned };
  const type: DepType = DEV_FILE.test(path.basename(file)) ? 'dev' : 'prod';
  const lines = readFileSync(full, 'utf8').replace(/\\\r?\n/g, ' ').split(/\r?\n/);
  const annotated = lines.some((l) => /^\s*#\s+via\b/.test(l));
  const parents = new Map<string, string[]>(); // node id -> via entries
  let current: string | undefined;
  let inVia = false;

  for (const raw of lines) {
    const viaInline = /^\s*#\s+via\s+(.+)$/.exec(raw);
    const viaHeader = /^\s*#\s+via\s*$/.test(raw);
    const viaItem = /^\s*#\s{2,}(\S.*)$/.exec(raw);
    if (current && viaInline) {
      parents.get(current)!.push(viaInline[1].trim());
      inVia = false;
      continue;
    }
    if (current && viaHeader) {
      inVia = true;
      continue;
    }
    if (current && inVia && viaItem) {
      parents.get(current)!.push(viaItem[1].trim());
      continue;
    }
    inVia = false;
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    const include = /^(?:-r|--requirement)\s*(\S+)/.exec(line);
    if (include) {
      const nested = toPosix(path.join(path.dirname(file), include[1]));
      const r = parseRequirementsFile(root, nested, b, seen);
      directs.push(...r.directs);
      unpinned.push(...r.unpinned);
      continue;
    }
    if (line.startsWith('-')) continue; // -c, -e, --index-url, --hash continuation, etc.
    const spec = line.split(/\s--hash/)[0];
    const req = parseRequirement(spec);
    if (!req) continue;
    const pin = /^===?\s*([^\s,;]+)$/.exec(req.specifier);
    if (!pin) {
      unpinned.push(req.name);
      current = undefined;
      continue;
    }
    current = b.add(req.name, pin[1], req.url ? `file:${req.url}` : undefined);
    parents.set(current, []);
  }

  for (const [id, via] of parents) {
    const node = b.nodes.get(id)!;
    const fromRequirementsIn = via.some((v) => v.startsWith('-r') || v.startsWith('-c'));
    if (!annotated || fromRequirementsIn) directs.push({ name: node.name, range: `==${node.version}`, type, id });
    for (const v of via) {
      if (v.startsWith('-')) continue;
      const parent = b.highest(normalizeName(v.split(/[\s[]/)[0]), pep440Scheme);
      if (parent) b.edge(parent, id);
    }
  }
  return { directs, unpinned };
}

// ---------------------------------------------------------------- lockfiles

function parseUvLock(doc: Toml, b: GraphBuilder) {
  interface UvDep { name: string; version?: string; extra?: string[] }
  interface UvPkg { name: string; version?: string; source?: Record<string, string>; dependencies?: UvDep[]; 'optional-dependencies'?: Record<string, UvDep[]> }
  const pkgs: UvPkg[] = doc.package ?? [];
  const isMember = (p: UvPkg) => !!(p.source?.editable || p.source?.virtual || p.source?.workspace);
  for (const p of pkgs) {
    if (isMember(p) || !p.version) continue;
    const src = p.source ?? {};
    const resolved = src.registry ?? (src.git ? `git+${src.git}` : src.path || src.directory ? `file:${src.path ?? src.directory}` : src.url);
    b.add(normalizeName(p.name), p.version, resolved);
  }
  const target = (d: UvDep) => (d.version ? `${normalizeName(d.name)}@${d.version}` : b.highest(normalizeName(d.name), pep440Scheme));
  for (const p of pkgs) {
    if (!p.version) continue;
    // workspace members aren't nodes, but extras they request (`requests[socks]`) still add edges
    const from = isMember(p) ? undefined : `${normalizeName(p.name)}@${p.version}`;
    for (const d of p.dependencies ?? []) {
      const to = target(d);
      if (from) b.edge(from, to);
      // `foo[bar]` also pulls in foo's `bar` extra
      const t = to ? pkgs.find((x) => `${normalizeName(x.name)}@${x.version}` === to) : undefined;
      for (const extra of d.extra ?? []) for (const e of t?.['optional-dependencies']?.[extra] ?? []) b.edge(to!, target(e));
    }
  }
}

function parsePoetryLock(doc: Toml, b: GraphBuilder) {
  interface PoetryPkg { name: string; version: string; source?: { type?: string; url?: string }; dependencies?: Record<string, unknown> }
  const pkgs: PoetryPkg[] = doc.package ?? [];
  for (const p of pkgs) {
    const t = p.source?.type;
    const resolved = t === 'git' ? `git+${p.source!.url}` : t === 'directory' || t === 'file' ? `file:${p.source!.url}` : t === 'legacy' ? p.source!.url : undefined;
    b.add(normalizeName(p.name), p.version, resolved);
  }
  for (const p of pkgs) {
    const from = `${normalizeName(p.name)}@${p.version}`;
    for (const [dep, spec] of Object.entries(p.dependencies ?? {})) {
      if (spec && typeof spec === 'object' && !Array.isArray(spec) && (spec as { optional?: boolean }).optional) continue;
      b.edge(from, b.highest(normalizeName(dep), pep440Scheme));
    }
  }
}

/** Read `*.dist-info/METADATA` from a local virtualenv: the installed versions and their Requires-Dist. */
function parseVirtualenv(root: string, b: GraphBuilder): string | undefined {
  for (const venv of ['.venv', 'venv', 'env']) {
    const sites = [
      ...globSync(`${venv}/lib/python*/site-packages`, { cwd: root }),
      ...globSync(`${venv}/Lib/site-packages`, { cwd: root }),
    ].map((s) => path.join(root, String(s)));
    const site = sites.find((s) => existsSync(s));
    if (!site) continue;
    const requires = new Map<string, string[]>();
    for (const entry of readdirSync(site)) {
      if (!entry.endsWith('.dist-info')) continue;
      const meta = path.join(site, entry, 'METADATA');
      if (!existsSync(meta)) continue;
      const text = readFileSync(meta, 'utf8').split(/\r?\n\r?\n/)[0];
      const name = /^Name:\s*(.+)$/m.exec(text)?.[1].trim();
      const version = /^Version:\s*(.+)$/m.exec(text)?.[1].trim();
      if (!name || !version) continue;
      const id = b.add(normalizeName(name), version);
      requires.set(id, [...text.matchAll(/^Requires-Dist:\s*(.+)$/gm)].map((m) => m[1]));
    }
    for (const [id, reqs] of requires) {
      for (const r of reqs) {
        const req = parseRequirement(r);
        if (req && !extraOnly(req.marker)) b.edge(id, b.highest(req.name, pep440Scheme));
      }
    }
    return toPosix(path.relative(root, site));
  }
  return undefined;
}

// ---------------------------------------------------------------- entry point

export function hasPythonProject(root: string): boolean {
  return existsSync(path.join(root, 'pyproject.toml')) || requirementFiles(root).length > 0;
}

export function loadPythonProject(rootDir: string, warnings: string[] = []): DependencyGraph {
  const root = path.resolve(rootDir);
  const b = new GraphBuilder();
  const workspaces: Workspace[] = [];

  if (existsSync(path.join(root, 'pyproject.toml'))) {
    const { ws, doc } = loadPyWorkspace(root, '.');
    workspaces.push(ws);
    const uvWs = doc.tool?.uv?.workspace;
    for (const pattern of uvWs?.members ?? []) {
      for (const m of globSync(`${pattern}/pyproject.toml`, { cwd: root })) {
        const dir = toPosix(path.dirname(String(m)));
        if (dir === '.' || (uvWs.exclude ?? []).some((ex: string) => path.matchesGlob(dir, ex))) continue;
        workspaces.push(loadPyWorkspace(root, dir).ws);
      }
    }
    // workspace members depending on each other are internal
    const internal = new Set(workspaces.map((w) => normalizeName(w.name)));
    for (const ws of workspaces) ws.direct = ws.direct.filter((d) => !internal.has(d.name));
  }

  let lockfile: DependencyGraph['lockfile'];
  const reqFiles = requirementFiles(root);
  if (existsSync(path.join(root, 'uv.lock'))) {
    parseUvLock(readToml(path.join(root, 'uv.lock')), b);
    lockfile = { kind: 'uv', path: 'uv.lock' };
  } else if (existsSync(path.join(root, 'poetry.lock'))) {
    parsePoetryLock(readToml(path.join(root, 'poetry.lock')), b);
    lockfile = { kind: 'poetry', path: 'poetry.lock' };
  } else {
    // requirements files: pinned versions, and the direct list when there's no pyproject
    const reqDirects: DirectDep[] = [];
    const unpinned = new Set<string>();
    const seen = new Set<string>();
    for (const f of reqFiles) {
      const r = parseRequirementsFile(root, f, b, seen);
      reqDirects.push(...r.directs);
      r.unpinned.forEach((u) => unpinned.add(u));
    }
    const venv = parseVirtualenv(root, b);
    if (!workspaces.length || !workspaces.some((w) => w.direct.length)) {
      const seenNames = new Set<string>();
      const direct = reqDirects.filter((d) => !seenNames.has(d.name) && seenNames.add(d.name));
      if (workspaces.length) workspaces[0].direct = direct;
      else workspaces.push({ path: '.', name: path.basename(root), direct, frontend: false });
    }
    lockfile = venv ? { kind: 'virtualenv', path: venv } : reqFiles.length ? { kind: 'requirements', path: reqFiles.join(', ') } : { kind: 'none' };
    if (unpinned.size && !venv) {
      warnings.push(`Python: ${unpinned.size} requirement(s) aren't pinned with == (${[...unpinned].slice(0, 5).join(', ')}${unpinned.size > 5 ? ', …' : ''}). Pin them, use a lockfile (uv.lock, poetry.lock), or create a .venv so installed versions can be read.`);
    }
    if (lockfile.kind === 'none') warnings.push('Python: no uv.lock, poetry.lock, pinned requirements or .venv found, so versions are unknown and nothing could be checked.');
  }

  for (const ws of workspaces) {
    for (const d of ws.direct) {
      if (d.id || d.range.startsWith('file:')) continue;
      d.id = b.highest(d.name, pep440Scheme);
      if (!d.id && lockfile.kind !== 'none') warnings.push(`${ws.name}: ${d.name} is not in ${lockfile.path ?? 'the lockfile'}.`);
    }
  }
  markDev(b.nodes, workspaces);
  return { ecosystem: 'PyPI', root, lockfile, workspaces, nodes: b.nodes };
}
