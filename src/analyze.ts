import path from 'node:path';
import { analyzeAbandoned, lastPublish } from './analyzers/abandoned.ts';
import { analyzeInsecure, SEVERITY_ORDER } from './analyzers/insecure.ts';
import { analyzeOutdated } from './analyzers/outdated.ts';
import { analyzeWeight, duplicates, measureBundle, transitiveCount } from './analyzers/weight.ts';
import { searchCandidates } from './advisor/replacements.ts';
import { type Config, findIgnore } from './config.ts';
import { ECOSYSTEMS, type EcosystemAdapter } from './ecosystems.ts';
import { DiskCache, limiter } from './fetchers/http.ts';
import { OsvFetcher } from './fetchers/osv.ts';
import { RepoFetcher } from './fetchers/repo.ts';
import { buildActions, score } from './report/score.ts';
import type { Category, DependencyGraph, DepType, Ecosystem, PackageReport, RegistryInfo, Report, RepoInfo, Severity, Vulnerability } from './types.ts';

export interface AnalyzeOptions {
  root: string;
  config: Config;
  githubToken?: string;
  gitlabToken?: string;
  cacheDir: string | null;
  /** fetch registry metadata (outdated/abandoned/deprecated) for transitive packages too */
  deep: boolean;
  /** compute browser bundle sizes with esbuild for frontend workspaces */
  bundle: boolean;
  /** skip devDependencies entirely */
  prodOnly: boolean;
  /** skip npm search for replacement candidates */
  noSearch: boolean;
  /** limit to these ecosystems; default: every one detected in the project */
  ecosystems?: Ecosystem[];
  version: string;
  log: (msg: string) => void;
}

interface Shared {
  opts: AnalyzeOptions;
  osv: OsvFetcher;
  repos: RepoFetcher;
  cache: DiskCache;
  warn: (msg: string) => void;
  log: (msg: string) => void;
  now: Date;
}

interface EcosystemResult {
  graph: DependencyGraph;
  packages: PackageReport[];
  registry: Map<string, RegistryInfo>;
}

/** Run every check for one ecosystem's dependency graph. */
async function analyzeEcosystem(eco: EcosystemAdapter, graph: DependencyGraph, s: Shared): Promise<EcosystemResult> {
  const { opts, osv, repos, warn, log, now } = s;
  const hints = eco.hints(graph);
  const reg = eco.registry(s.cache);
  const privateReasonFor = eco.privateReason(graph.root);

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
  log(`Found ${included.length} packages (${directInfo.size} direct) across ${graph.workspaces.length} workspace(s), lockfile: ${graph.lockfile.kind}`);

  // ------------------------------------------------------------ fetch
  const privateReason = new Map<string, string>();
  for (const n of included) {
    const r = privateReasonFor(n.name, n.resolved);
    if (r) privateReason.set(n.id, r);
  }
  const publicPkgs = included.filter((n) => !privateReason.has(n.id));

  log(`Querying OSV.dev for ${publicPkgs.length} package versions…`);
  let vulns = new Map<string, Vulnerability[]>();
  try {
    vulns = await osv.scan(publicPkgs.map((n) => ({ name: n.name, version: n.version })), eco.id, eco.scheme);
  } catch (err) {
    warn(`OSV.dev query failed, ${eco.id} security results are missing: ${(err as Error).message}`);
  }

  const wantRegistry = publicPkgs.filter((n) => opts.deep || directInfo.has(n.id));
  log(`Fetching ${eco.id} registry metadata for ${wantRegistry.length} packages…`);
  const registry = new Map<string, RegistryInfo>();
  const regLimit = limiter(24);
  await Promise.all(
    wantRegistry.map((n) =>
      regLimit(() => reg.info(n.name, n.version, directInfo.has(n.id)))
        .then((info) => registry.set(n.id, info))
        .catch((err) => warn(`${eco.id} registry lookup failed for ${n.name}: ${(err as Error).message}`)),
    ),
  );

  const repoFor = new Map<string, RepoInfo>();
  const repoTargets = wantRegistry.filter((n) => directInfo.has(n.id) && registry.get(n.id)?.repository);
  log(`Checking ${repoTargets.length} source repositories (GitHub${opts.githubToken ? '' : ', no token'}, GitLab, deps.dev)…`);
  await Promise.all(
    repoTargets.map(async (n) => {
      const r = registry.get(n.id)!.repository!;
      try {
        repoFor.set(n.id, await repos.info(r));
      } catch (err) {
        warn(`Repository lookup failed for ${r.url}: ${(err as Error).message}`);
      }
    }),
  );
  if (!opts.githubToken && repoTargets.length > 25) warn('No GITHUB_TOKEN set: GitHub allows ~60 requests/hour without one, which may not cover this project.');

  // ------------------------------------------------------------ analyze
  const wsByName = new Map(graph.workspaces.map((w) => [w.name, w]));
  const anyFrontend = graph.workspaces.some((w) => w.frontend);
  const bundleLimit = limiter(4);

  const packages: PackageReport[] = await Promise.all(
    included.map(async (n) => {
      const d = directInfo.get(n.id);
      const viaList = [...(via.get(n.id) ?? [])].sort();
      const info = registry.get(n.id);
      const repo = repoFor.get(n.id);
      const v = vulns.get(n.id) ?? [];
      const wsNames = d ? [...d.workspaces] : [];
      const assessed = !privateReason.has(n.id) && (info ? info.assessed : true);
      const report: PackageReport = {
        ecosystem: eco.id,
        id: n.id,
        name: n.name,
        version: n.version,
        direct: !!d,
        depTypes: d ? [...d.types] : [],
        dev: n.dev,
        workspaces: wsNames,
        via: d ? [] : viaList,
        assessed,
        notAssessedReason: privateReason.get(n.id) ?? (info && !info.assessed ? info.notAssessedReason : undefined),
        vulnerabilities: v,
        findings: [],
        replacements: [],
        score: 100,
        repo,
      };
      if (!assessed) return report;

      report.findings.push(...analyzeInsecure(n.name, !!d, viaList, v, hints));

      if (info?.assessed) {
        report.registry = { maintainers: info.maintainers, weeklyDownloads: info.weeklyDownloads, deprecated: info.deprecated, latestDeprecated: info.latestDeprecated, lastPublish: lastPublish(info) };
        const o = analyzeOutdated(n.name, n.version, info, hints, now);
        Object.assign(report, { latest: o.latest, libyear: o.libyear, semverBehind: o.semverBehind });
        // minor/patch drift on transitive packages is the parent's business, not actionable here
        report.findings.push(...o.findings.filter((f) => d || f.code === 'version-deprecated' || f.code === 'unsupported-major'));

        if (d) {
          const a = analyzeAbandoned(info, repo, v.length, opts.config.staleYears, now);
          report.abandonment = { status: a.status, failed: a.failed, passed: a.passed };
          report.findings.push(...a.findings);
          const legacy = eco.legacy(n.name);
          if (legacy && !info.latestDeprecated) {
            report.findings.push({ category: 'abandoned', level: 'low', code: 'legacy', message: `Legacy project: ${legacy}`, penalty: 8 });
          }
        } else if (info.latestDeprecated) {
          report.findings.push({ category: 'abandoned', level: 'low', code: 'deprecated', message: `Deprecated by its author: "${info.latestDeprecated}" (pulled in by ${viaList.slice(0, 3).join(', ')})`, penalty: 15, fix: `Upgrade or replace ${viaList[0]}` });
        }
      }

      if (d) {
        const wsList = wsNames.map((w) => wsByName.get(w)!).filter(Boolean);
        const frontend = wsList.some((w) => w.frontend) && !d.types.has('dev');
        const transitive = transitiveCount(graph.nodes, n.id);
        const ws0 = wsList[0];
        const bundle = eco.bundles && opts.bundle && frontend && anyFrontend ? await bundleLimit(() => measureBundle(n.name, path.join(graph.root, ws0?.path ?? '.'))) : undefined;
        report.weight = { unpackedSize: info?.unpackedSize, transitiveCount: transitive, bundle };
        report.findings.push(
          ...analyzeWeight({
            name: n.name,
            dev: !d.types.has('prod') && !d.types.has('optional') && !d.types.has('peer'),
            unpackedSize: info?.unpackedSize,
            transitive,
            bundle,
            natives: eco.natives(n.name, wsList.length ? wsList : graph.workspaces, frontend, opts.config),
          }),
        );
      }
      return report;
    }),
  );

  // ------------------------------------------------------------ replacements
  const needsAdvice = (p: PackageReport) =>
    p.findings.some((f) => ['deprecated', 'archived', 'archived-recent', 'abandoned', 'at-risk', 'legacy', 'native-now', 'micro-utility'].includes(f.code) || (f.code === 'vuln' && f.fix?.startsWith('No fixed')));
  const searchLimit = limiter(4);
  await Promise.all(
    packages.filter(needsAdvice).map(async (p) => {
      const info = registry.get(p.id);
      const seen = new Set<string>();
      p.replacements = eco.suggestions(p.name, info?.latestDeprecated ?? info?.deprecated).filter((r) => !seen.has(r.name) && seen.add(r.name));
      const hardProblem = p.findings.some((f) => ['deprecated', 'archived', 'abandoned'].includes(f.code));
      if (!p.replacements.length && hardProblem && p.direct && !opts.noSearch && info && reg.search) {
        p.replacements = await searchLimit(() => searchCandidates(p.name, info.keywords, info.description, (t) => reg.search!(t)));
      }
    }),
  );
  return { graph, packages, registry };
}

export async function analyze(opts: AnalyzeOptions): Promise<Report> {
  const root = path.resolve(opts.root);
  const warnings: string[] = [];
  const warn = (m: string) => {
    if (!warnings.includes(m)) warnings.push(m);
  };
  const adapters = ECOSYSTEMS.filter((e) => (!opts.ecosystems || opts.ecosystems.includes(e.id)) && e.detect(root));
  if (!adapters.length) {
    throw new Error(
      opts.ecosystems
        ? `No ${opts.ecosystems.join('/')} project found in ${root}`
        : `No package.json, pyproject.toml or requirements*.txt found in ${root}`,
    );
  }
  const cache = new DiskCache(opts.cacheDir);
  const shared: Omit<Shared, 'log'> = { opts, osv: new OsvFetcher(cache), repos: new RepoFetcher(cache, opts.githubToken, warn, opts.gitlabToken), cache, warn, now: new Date() };

  const results: EcosystemResult[] = [];
  for (const eco of adapters) {
    const log = (m: string) => opts.log(adapters.length > 1 ? `[${eco.id}] ${m}` : m);
    const graph = eco.load(root, warnings);
    results.push(await analyzeEcosystem(eco, graph, { ...shared, log }));
  }

  // ------------------------------------------------------------ ignore list, scoring, summary
  const now = shared.now;
  const packages = results.flatMap((r) => r.packages);
  for (const p of packages) {
    const ig = findIgnore(opts.config, p.name, now);
    if (ig) p.ignored = { reason: ig.reason, checks: ig.checks ?? 'all' };
    p.score = score(p);
  }
  packages.sort((a, b) => a.score - b.score || Number(b.direct) - Number(a.direct) || a.name.localeCompare(b.name));

  const byCategory: Record<Category, number> = { abandoned: 0, outdated: 0, insecure: 0, weight: 0 };
  const sevCount = Object.fromEntries(SEVERITY_ORDER.map((sv) => [sv, 0])) as Record<Severity, number>;
  for (const p of packages) {
    const cats = new Set(p.findings.filter((f) => f.level !== 'info').map((f) => f.category));
    for (const c of cats) byCategory[c]++;
    for (const vv of p.vulnerabilities) sevCount[vv.severity]++;
  }
  const directs = packages.filter((p) => p.direct);
  const scored = directs.filter((p) => p.assessed);

  if (cache.dir) opts.log(`Cache: ${cache.hits} hits, ${cache.misses} misses (${cache.dir})`);
  return {
    tool: { name: 'dephealth', version: opts.version },
    generatedAt: now.toISOString(),
    root,
    ecosystems: results.map((r) => r.graph.ecosystem),
    lockfiles: results.map((r) => ({ ecosystem: r.graph.ecosystem, ...r.graph.lockfile })),
    workspaces: results.flatMap((r) => r.graph.workspaces.map((w) => ({ ecosystem: r.graph.ecosystem, path: w.path, name: w.name, direct: w.direct.length }))),
    summary: {
      packages: packages.length,
      direct: directs.length,
      assessed: packages.filter((p) => p.assessed).length,
      averageScore: scored.length ? Math.round(scored.reduce((sum, p) => sum + p.score, 0) / scored.length) : 100,
      totalLibyear: Math.round(directs.reduce((sum, p) => sum + (p.libyear ?? 0), 0) * 100) / 100,
      byCategory,
      vulnerabilities: sevCount,
      duplicates: results.flatMap((r) => {
        const ids = new Set(r.packages.map((p) => p.id));
        const nodes = new Map([...r.graph.nodes].filter(([id]) => ids.has(id)));
        const eco = adapters.find((a) => a.id === r.graph.ecosystem)!;
        return duplicates(nodes, eco.scheme).map((d) => ({ ecosystem: r.graph.ecosystem, ...d }));
      }),
    },
    actions: buildActions(packages),
    packages,
    warnings,
  };
}
