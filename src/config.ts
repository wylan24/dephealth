import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { parse as parseToml } from 'smol-toml';
import type { Category } from './types.ts';
import { readJson } from './parsers/manifest.ts';

export interface IgnoreEntry {
  /** package name; `*` wildcards allowed, e.g. `@types/*` */
  package: string;
  /** limit to some checks; omitted = all */
  checks?: Category[];
  /** required: why this is safe to ignore (shown in the report) */
  reason: string;
  /** optional ISO date after which the entry stops applying */
  until?: string;
}

export interface Config {
  ignore: IgnoreEntry[];
  /** CI rules, e.g. ["vuln:high", "deprecated:direct", "score<40"] */
  failOn: string[];
  /** minimum Node.js version the project supports (defaults to engines.node, then 22) */
  nodeTarget?: string;
  /** minimum Python version (defaults to requires-python, then 3.10) */
  pythonTarget?: string;
  /** minimum browser versions for frontend "native now" checks */
  browserTargets: Record<string, string>;
  /** years without a publish before that abandonment signal fails */
  staleYears: number;
}

export const DEFAULT_FAIL_ON = ['vuln:high', 'deprecated:direct'];

// Roughly Baseline "widely available" as of 2026.
const DEFAULT_BROWSERS = { chrome: '111', edge: '111', firefox: '114', safari: '16.4' };

export function loadConfig(root: string, explicit?: string): { config: Config; file?: string } {
  const candidates = explicit ? [path.resolve(explicit)] : [path.join(root, '.dephealthrc.json'), path.join(root, 'dephealth.config.json')];
  let raw: Partial<Config> = {};
  let file: string | undefined;
  for (const c of candidates) {
    if (existsSync(c)) {
      raw = readJson<Partial<Config>>(c);
      file = c;
      break;
    }
  }
  if (explicit && !file) throw new Error(`Config file not found: ${explicit}`);
  if (!file && existsSync(path.join(root, 'package.json'))) {
    const pkg = readJson<{ dephealth?: Partial<Config> }>(path.join(root, 'package.json'));
    if (pkg.dephealth) {
      raw = pkg.dephealth;
      file = 'package.json#dephealth';
    }
  }
  if (!file && existsSync(path.join(root, 'pyproject.toml'))) {
    const doc = parseToml(readFileSync(path.join(root, 'pyproject.toml'), 'utf8')) as { tool?: { dephealth?: Record<string, unknown> } };
    const t = doc.tool?.dephealth;
    if (t) {
      // TOML style keys (fail-on, node-target) map onto the JSON names
      const camel = Object.fromEntries(Object.entries(t).map(([k, v]) => [k.replace(/-(\w)/g, (_, c: string) => c.toUpperCase()), v]));
      raw = camel as Partial<Config>;
      file = 'pyproject.toml [tool.dephealth]';
    }
  }
  for (const entry of raw.ignore ?? []) {
    if (!entry.package || !entry.reason?.trim()) {
      throw new Error(`Every ignore entry needs "package" and a non-empty "reason" (in ${file}): ${JSON.stringify(entry)}`);
    }
  }
  return {
    file,
    config: {
      ignore: raw.ignore ?? [],
      failOn: raw.failOn ?? DEFAULT_FAIL_ON,
      nodeTarget: raw.nodeTarget,
      pythonTarget: raw.pythonTarget,
      browserTargets: { ...DEFAULT_BROWSERS, ...raw.browserTargets },
      staleYears: raw.staleYears ?? 2,
    },
  };
}

export function findIgnore(config: Config, name: string, now = new Date()): IgnoreEntry | undefined {
  return config.ignore.find((e) => {
    if (e.until && new Date(e.until) < now) return false;
    const re = new RegExp('^' + e.package.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
    return re.test(name);
  });
}
