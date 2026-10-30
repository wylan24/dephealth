import type { Ecosystem, Severity, Vulnerability } from '../types.ts';
import { semverScheme, type VersionScheme } from '../versions.ts';
import { type DiskCache, fetchJson, limiter } from './http.ts';

const API = 'https://api.osv.dev/v1';
const BATCH = 1000; // OSV querybatch limit

interface OsvRecord {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  modified: string;
  database_specific?: { severity?: string };
  severity?: { type: string; score: string }[];
  affected?: {
    package?: { name: string; ecosystem: string };
    ranges?: { type: string; events: Record<string, string>[] }[];
    database_specific?: { severity?: string };
  }[];
}

const SEVERITIES: Record<string, Severity> = { CRITICAL: 'critical', HIGH: 'high', MODERATE: 'moderate', MEDIUM: 'moderate', LOW: 'low' };

const fromScore = (s: number): Severity => (s >= 9 ? 'critical' : s >= 7 ? 'high' : s >= 4 ? 'moderate' : s > 0 ? 'low' : 'unknown');

/** CVSS 3.x base score from a vector string such as `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`. */
export function cvss3Score(vector: string): number | undefined {
  if (!/^CVSS:3\.[01]\//.test(vector)) return undefined;
  const m = Object.fromEntries(vector.split('/').slice(1).map((p) => p.split(':') as [string, string]));
  const changed = m.S === 'C';
  const W: Record<string, Record<string, number>> = {
    AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.2 },
    AC: { L: 0.77, H: 0.44 },
    PR: changed ? { N: 0.85, L: 0.68, H: 0.5 } : { N: 0.85, L: 0.62, H: 0.27 },
    UI: { N: 0.85, R: 0.62 },
    CIA: { H: 0.56, L: 0.22, N: 0 },
  };
  const [av, ac, pr, ui, c, i, a] = [W.AV[m.AV], W.AC[m.AC], W.PR[m.PR], W.UI[m.UI], W.CIA[m.C], W.CIA[m.I], W.CIA[m.A]];
  if ([av, ac, pr, ui, c, i, a].some((x) => x === undefined)) return undefined;
  const iss = 1 - (1 - c) * (1 - i) * (1 - a);
  const impact = changed ? 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 : 6.42 * iss;
  if (impact <= 0) return 0;
  const exploitability = 8.22 * av * ac * pr * ui;
  const raw = Math.min((changed ? 1.08 : 1) * (impact + exploitability), 10);
  return Math.ceil(raw * 10 - 1e-9) / 10;
}

export function severityOf(rec: OsvRecord): Severity {
  // malicious-package records (MAL-*) never carry a severity but are always worst-case
  if (rec.id.startsWith('MAL-')) return 'critical';
  const label = rec.database_specific?.severity ?? rec.affected?.find((a) => a.database_specific?.severity)?.database_specific?.severity;
  if (label && SEVERITIES[label.toUpperCase()]) return SEVERITIES[label.toUpperCase()];
  for (const s of rec.severity ?? []) {
    const n = s.type === 'CVSS_V3' ? cvss3Score(s.score) : undefined;
    if (n !== undefined) return fromScore(n);
  }
  return 'unknown';
}

/** PyPI names are case/punctuation-insensitive (PEP 503); npm names are exact. */
const sameName = (ecosystem: Ecosystem, a: string, b: string) =>
  ecosystem === 'PyPI' ? a.toLowerCase().replace(/[-_.]+/g, '-') === b.toLowerCase().replace(/[-_.]+/g, '-') : a === b;

/** Lowest `fixed` event of a range that contains the installed version. */
export function fixedIn(rec: OsvRecord, name: string, version: string, ecosystem: Ecosystem = 'npm', scheme: VersionScheme = semverScheme): string | undefined {
  if (!scheme.valid(version)) return undefined;
  const fixes: string[] = [];
  for (const a of rec.affected ?? []) {
    if (a.package?.ecosystem !== ecosystem || !sameName(ecosystem, a.package.name, name)) continue;
    for (const r of a.ranges ?? []) {
      if (r.type !== 'SEMVER' && r.type !== 'ECOSYSTEM') continue;
      let introduced: string | undefined;
      for (const ev of r.events) {
        if (ev.introduced !== undefined) introduced = ev.introduced === '0' ? scheme.zero : ev.introduced;
        if (ev.fixed && introduced && scheme.valid(ev.fixed) && scheme.valid(introduced)) {
          if (scheme.compare(version, introduced) >= 0 && scheme.compare(version, ev.fixed) < 0) fixes.push(ev.fixed);
          introduced = undefined;
        }
      }
    }
  }
  return fixes.sort((x, y) => scheme.compare(x, y))[0];
}

const shorten = (s: string, max = 160) => (s.length > max ? `${s.slice(0, max - 1).replace(/\s+\S*$/, '')}…` : s);

const SOURCE_RANK = (id: string) => (id.startsWith('MAL-') ? 0 : id.startsWith('GHSA-') ? 1 : id.startsWith('PYSEC-') ? 2 : 3);

/**
 * OSV returns the same issue once per database (GHSA-…, PYSEC-…, CVE aliases). Keep one record per
 * alias group, preferring GHSA (which carries a severity label), and keep the best severity/fix seen.
 */
export function dedupeAliases(vulns: Vulnerability[]): Vulnerability[] {
  const sorted = [...vulns].sort((a, b) => SOURCE_RANK(a.id) - SOURCE_RANK(b.id));
  const kept: { v: Vulnerability; keys: Set<string> }[] = [];
  for (const v of sorted) {
    const keys = new Set([v.id, ...v.aliases]);
    const twin = kept.find((k) => [...keys].some((x) => k.keys.has(x)));
    if (!twin) {
      kept.push({ v: { ...v }, keys });
      continue;
    }
    keys.forEach((x) => twin.keys.add(x));
    if (twin.v.severity === 'unknown') twin.v.severity = v.severity;
    twin.v.fixedIn ??= v.fixedIn;
    if (!twin.v.aliases.includes(v.id)) twin.v.aliases.push(v.id);
  }
  return kept.map((k) => k.v);
}

export class OsvFetcher {
  private limit = limiter(8);
  private cache: DiskCache;
  constructor(cache: DiskCache) {
    this.cache = cache;
  }

  /** Returns `name@version` -> vulnerabilities for every package that has any. */
  async scan(pkgs: { name: string; version: string }[], ecosystem: Ecosystem = 'npm', scheme: VersionScheme = semverScheme): Promise<Map<string, Vulnerability[]>> {
    const out = new Map<string, Vulnerability[]>();
    const idsByPkg = new Map<string, { id: string; modified: string }[]>();
    const uncached: { name: string; version: string }[] = [];

    for (const p of pkgs) {
      const hit = this.cache.get<{ id: string; modified: string }[]>(`osv:q:${ecosystem}:${p.name}@${p.version}`);
      if (hit) idsByPkg.set(`${p.name}@${p.version}`, hit);
      else uncached.push(p);
    }

    for (let i = 0; i < uncached.length; i += BATCH) {
      const chunk = uncached.slice(i, i + BATCH);
      const { data } = await fetchJson<{ results: { vulns?: { id: string; modified: string }[] }[] }>(`${API}/querybatch`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ queries: chunk.map((p) => ({ package: { name: p.name, ecosystem }, version: p.version })) }),
      });
      data?.results.forEach((r, j) => {
        const key = `${chunk[j].name}@${chunk[j].version}`;
        const vulns = r.vulns ?? [];
        idsByPkg.set(key, vulns);
        this.cache.set(`osv:q:${ecosystem}:${key}`, vulns);
      });
    }

    const records = new Map<string, OsvRecord | null>();
    const wanted = new Map<string, string>();
    for (const list of idsByPkg.values()) for (const v of list) wanted.set(v.id, v.modified);
    await Promise.all(
      [...wanted].map(([id, modified]) =>
        this.cache
          .wrap(`osv:vuln:${id}:${modified}`, () => this.limit(async () => (await fetchJson<OsvRecord>(`${API}/vulns/${id}`)).data))
          .then((rec) => records.set(id, rec)),
      ),
    );

    for (const [key, list] of idsByPkg) {
      if (!list.length) continue;
      const at = key.lastIndexOf('@');
      const name = key.slice(0, at);
      const version = key.slice(at + 1);
      const vulns: Vulnerability[] = [];
      for (const { id } of list) {
        const rec = records.get(id);
        if (!rec) continue;
        vulns.push({
          id: rec.id,
          aliases: rec.aliases ?? [],
          summary: shorten(rec.summary ?? rec.details?.split('\n')[0] ?? rec.id),
          severity: severityOf(rec),
          fixedIn: fixedIn(rec, name, version, ecosystem, scheme),
          url: `https://osv.dev/vulnerability/${rec.id}`,
        });
      }
      const unique = dedupeAliases(vulns);
      if (unique.length) out.set(key, unique);
    }
    return out;
  }
}
