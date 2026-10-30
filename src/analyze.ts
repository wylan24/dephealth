import path from 'node:path';
import semver from 'semver';
import { analyzeAbandoned, lastPublish } from './analyzers/abandoned.ts';
import { analyzeInsecure, SEVERITY_ORDER } from './analyzers/insecure.ts';
import { analyzeOutdated } from './analyzers/outdated.ts';
import { analyzeWeight, duplicates, measureBundle, transitiveCount, type Targets } from './analyzers/weight.ts';
import { authorSuggestions, curatedSuggestions, legacyNote, searchCandidates } from './advisor/replacements.ts';
import { type Config, findIgnore } from './config.ts';
import { DiskCache, limiter } from './fetchers/http.ts';
import { NpmFetcher } from './fetchers/npm.ts';
import { NpmRc } from './fetchers/npmrc.ts';
import { OsvFetcher } from './fetchers/osv.ts';
import { RepoFetcher } from './fetchers/repo.ts';
import { loadProject } from './parsers/index.ts';
import { buildActions, score } from './report/score.ts';
import type { Category, DepType, PackageReport, RegistryInfo, Report, RepoInfo, Severity, Vulnerability } from './types.ts';

export interface AnalyzeOptions {
  root: string;
  config: Config;
  githubToken?: string;
  cacheDir: string | null;
  /** fetch registry metadata (outdated/abandoned/deprecated) for transitive packages too */
  deep: boolean;
  /** compute browser bundle sizes with esbuild for frontend workspaces */
  bundle: boolean;
  /** skip devDependencies entirely */
  prodOnly: boolean;
  /** skip npm search for replacement candidates */
  noSearch: boolean;
  version: string;
  log: (msg: string) => void;
}

/** Lowest Node.js major the project must support. */
function nodeTarget(config: Config, engines: (string | undefined)[]): string {
  if (config.nodeTarget) return config.nodeTarget;
  const mins = engines.filter(Boolean).map((r) => semver.minVersion(r!)?.version).filter(Boolean) as string[];
  return mins.length ? semver.sort(mins)[0] : '22.0.0';
}

export async function analyze(opts: AnalyzeOptions): Promise<Report> {
  const warnings: string[] = [];
  const warn = (m: string) => {
    if (!warnings.includes(m)) warnings.push(m);
  };
  const graph = loadProject(opts.root, warnings);
  const cache = new DiskCache(opts.cacheDir);
  const npmrc = new NpmRc(graph.root);
  const npm = new NpmFetcher(cache);
  const osv = new OsvFetcher(cache);
  const repos = new RepoFetcher(cache, opts.githubToken, warn);

  // ------------------------------------------------------------ who depends on what
  const directInfo = new Map<string, { types: Set<DepType>; workspaces: Set<string> }>();
  for (const ws of graph.workspaces) {
    for (const d of ws.direct) {
      if (!d.id || (opts.prodOnly && d.type === 'dev')) continue;
      const info = directInfo.get(d.id) ?? { types: new Set(), workspaces: new Set() };
      info.types.add(d.type);
      info.workspaces.add(ws.name);
      directInfo.set(d.id, info);
    }
  }
  const via = new Map<string, Set<string>>();
  for (const directId of directInfo.keys()) {
    const directName = graph.nodes.get(directId)!.name;
    const stack = [...graph.nodes.get(directId)!.deps];
    const seen = new Set<string>([directId]);
    while (stack.length) {
      const id = stack.pop()!;
      if (seen.has(id)) continue;
      seen.add(id);
      if (!via.has(id)) via.set(id, new Set());
      via.get(id)!.add(directName);
      stack.push(...(graph.nodes.get(id)?.deps ?? []));
    }
  }
  const included = [...graph.nodes.values()].filter((n) => directInfo.has(n.id) || (via.has(n.id) && !(opts.prodOnly && n.dev)));
  opts.log(`Found ${included.length} packages (${directInfo.size} direct) across ${graph.workspaces.length} workspace(s), lockfile: ${graph.lockfile.kind}`);

  // ------------------------------------------------------------ fetch
  const privateReason = new Map<string, string>();
  for (const n of included) {
    const r = npmrc.privateReason(n.name, n.resolved);
    if (r) privateReason.set(n.id, r);
  }
  const publicPkgs = included.filter((n) => !privateReason.has(n.id));

  opts.log(`Querying OSV.dev for ${publicPkgs.length} package versions…`);
  let vulns = new Map<string, Vulnerability[]>();
  try {
    vulns = await osv.scan(publicPkgs.map((n) => ({ name: n.name, version: n.version })));
  } catch (err) {
    warn(`OSV.dev query failed, security results are missing: ${(err as Error).message}`);
  }

  const wantRegistry = publicPkgs.filter((n) => opts.deep || directInfo.has(n.id));
  opts.log(`Fetching npm registry metadata for ${wantRegistry.length} packages…`);
  const registry = new Map<string, RegistryInfo>();
  const regLimit = limiter(24);
  await Promise.all(
    wantRegistry.map((n) =>
      regLimit(() => npm.info(n.name, n.version, directInfo.has(n.id)))
        .then((info) => registry.set(n.id, info))
        .catch((err) => warn(`npm registry lookup failed for ${n.name}: ${(err as Error).message}`)),
    ),
  );

  const repoFor = new Map<string, RepoInfo>();
  const repoTargets = wantRegistry.filter((n) => directInfo.has(n.id) && registry.get(n.id)?.repository);
  opts.log(`Checking ${repoTargets.length} source repositories (GitHub${opts.githubToken ? '' : ', no token'} + deps.dev)…`);
  await Promise.all(
    repoTargets.map(async (n) => {
      const r = registry.get(n.id)!.repository!;
      try {
        repoFor.set(n.id, await repos.info(r.owner, r.repo));
      } catch (err) {
        warn(`Repository lookup failed for ${r.url}: ${(err as Error).message}`);
      }
    }),
  );
  if (!opts.githubToken && repoTargets.length > 25) warn('No GITHUB_TOKEN set: GitHub allows ~60 requests/hour without one, which may not cover this project.');

  // ------------------------------------------------------------ analyze
  const wsByName = new Map(graph.workspaces.map((w) => [w.name, w]));
  const allEngines = graph.workspaces.map((w) => w.nodeEngine);
  const anyFrontend = graph.workspaces.some((w) => w.frontend);
  const now = new Date();
  const bundleLimit = limiter(4);

  const packages: PackageReport[] = await Promise.all(
    included.map(async (n) => {
      const d = directInfo.get(n.id);
      const viaList = [...(via.get(n.id) ?? [])].sort();
      const reg = registry.get(n.id);
      const repo = repoFor.get(n.id);
      const v = vulns.get(n.id) ?? [];
      const wsNames = d ? [...d.workspaces] : [];
      const assessed = !privateReason.has(n.id) && (reg ? reg.assessed : true);
      const report: PackageReport = {
        id: n.id,
        name: n.name,
        version: n.version,
        direct: !!d,
        depTypes: d ? [...d.types] : [],
        dev: n.dev,
        workspaces: wsNames,
        via: d ? [] : viaList,
        assessed,
        notAssessedReason: privateReason.get(n.id) ?? (reg && !reg.assessed ? reg.notAssessedReason : undefined),
        vulnerabilities: v,
        findings: [],
        replacements: [],
        score: 100,
        repo,
      };
      if (!assessed) return report;

      report.findings.push(...analyzeInsecure(n.name, !!d, viaList, v));

      if (reg?.assessed) {
        report.registry = { maintainers: reg.maintainers, weeklyDownloads: reg.weeklyDownloads, deprecated: reg.deprecated, latestDeprecated: reg.latestDeprecated, lastPublish: lastPublish(reg) };
        const o = analyzeOutdated(n.name, n.version, reg, now);
        Object.assign(report, { latest: o.latest, libyear: o.libyear, semverBehind: o.semverBehind });
        // minor/patch drift on transitive packages is the parent's business, not actionable here
        report.findings.push(...o.findings.filter((f) => d || f.code === 'version-deprecated' || f.code === 'unsupported-major'));

        if (d) {
          const a = analyzeAbandoned(reg, repo, v.length, opts.config.staleYears, now);
          report.abandonment = { status: a.status, failed: a.failed, passed: a.passed };
          report.findings.push(...a.findings);
          const legacy = legacyNote(n.name);
          if (legacy && !reg.latestDeprecated) {
            report.findings.push({ category: 'abandoned', level: 'low', code: 'legacy', message: `Legacy project: ${legacy}`, penalty: 8 });
          }
        } else if (reg.latestDeprecated) {
          report.findings.push({ category: 'abandoned', level: 'low', code: 'deprecated', message: `Deprecated by its author: "${reg.latestDeprecated}" (pulled in by ${viaList.slice(0, 3).join(', ')})`, penalty: 15, fix: `Upgrade or replace ${viaList[0]}` });
        }
      }

      if (d) {
        const wsList = wsNames.map((w) => wsByName.get(w)!).filter(Boolean);
        const frontend = wsList.some((w) => w.frontend) && !d.types.has('dev');
        const targets: Targets = {
          node: nodeTarget(opts.config, wsList.length ? wsList.map((w) => w.nodeEngine) : allEngines),
          browsers: frontend ? opts.config.browserTargets : undefined,
        };
        const transitive = transitiveCount(graph.nodes, n.id);
        const ws0 = wsList[0];
        const bundle = opts.bundle && frontend && anyFrontend ? await bundleLimit(() => measureBundle(n.name, path.join(graph.root, ws0?.path ?? '.'))) : undefined;
        report.weight = { unpackedSize: reg?.unpackedSize, transitiveCount: transitive, bundle };
        report.findings.push(...analyzeWeight({ name: n.name, dev: !d.types.has('prod') && !d.types.has('optional') && !d.types.has('peer'), unpackedSize: reg?.unpackedSize, transitive, bundle, targets }));
      }
      return report;
    }),
  );

  // ------------------------------------------------------------ replacements
  const needsAdvice = (p: PackageReport) => p.findings.some((f) => ['deprecated', 'archived', 'abandoned', 'at-risk', 'legacy', 'native-now', 'micro-utility'].includes(f.code) || (f.code === 'vuln' && f.fix?.startsWith('No fixed')));
  const searchLimit = limiter(4);
  await Promise.all(
    packages.filter(needsAdvice).map(async (p) => {
      const reg = registry.get(p.id);
      const list = [...authorSuggestions(p.name, reg?.latestDeprecated ?? reg?.deprecated), ...curatedSuggestions(p.name)];
      const seen = new Set<string>();
      p.replacements = list.filter((r) => !seen.has(r.name) && seen.add(r.name));
      const hardProblem = p.findings.some((f) => ['deprecated', 'archived', 'abandoned'].includes(f.code));
      if (!p.replacements.length && hardProblem && p.direct && !opts.noSearch && reg) {
        p.replacements = await searchLimit(() => searchCandidates(p.name, reg.keywords, reg.description, (t) => npm.search(t)));
      }
    }),
  );

  // ------------------------------------------------------------ ignore list, scoring, summary
  for (const p of packages) {
    const ig = findIgnore(opts.config, p.name, now);
    if (ig) p.ignored = { reason: ig.reason, checks: ig.checks ?? 'all' };
    p.score = score(p);
  }
  packages.sort((a, b) => a.score - b.score || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name));

  const byCategory: Record<Category, number> = { abandoned: 0, outdated: 0, insecure: 0, weight: 0 };
  const sevCount = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, 0])) as Record<Severity, number>;
  for (const p of packages) {
    const cats = new Set(p.findings.filter((f) => f.level !== 'info').map((f) => f.category));
    for (const c of cats) byCategory[c]++;
    for (const vv of p.vulnerabilities) sevCount[vv.severity]++;
  }
  const directs = packages.filter((p) => p.direct);
  const assessed = packages.filter((p) => p.assessed);
  const scored = directs.filter((p) => p.assessed);

  if (cache.dir) opts.log(`Cache: ${cache.hits} hits, ${cache.misses} misses (${cache.dir})`);
  return {
    tool: { name: 'dephealth', version: opts.version },
    generatedAt: now.toISOString(),
    root: graph.root,
    lockfile: graph.lockfile,
    workspaces: graph.workspaces.map((w) => ({ path: w.path, name: w.name, direct: w.direct.length })),
    summary: {
      packages: packages.length,
      direct: directs.length,
      assessed: assessed.length,
      averageScore: scored.length ? Math.round(scored.reduce((s, p) => s + p.score, 0) / scored.length) : 100,
      totalLibyear: Math.round(directs.reduce((s, p) => s + (p.libyear ?? 0), 0) * 100) / 100,
      byCategory,
      vulnerabilities: sevCount,
      duplicates: duplicates(new Map(included.map((n) => [n.id, n]))),
    },
    actions: buildActions(packages),
    packages,
    warnings,
  };
}
