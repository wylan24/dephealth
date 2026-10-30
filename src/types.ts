import type { VersionScheme } from './versions.ts';

// Shared data model. Everything an analyzer needs flows through these types so that a
// second ecosystem (PyPI) only has to produce a DependencyGraph and its own fetchers.

export type Ecosystem = 'npm' | 'PyPI';
export type DepType = 'prod' | 'dev' | 'optional' | 'peer';

/** One resolved package@version in the lockfile. */
export interface PackageNode {
  /** `name@version` */
  id: string;
  name: string;
  version: string;
  /** ids of packages this one depends on */
  deps: string[];
  /** true when only reachable through devDependencies */
  dev: boolean;
  /** resolved tarball URL, when the lockfile records one */
  resolved?: string;
}

/** A dependency declared in a workspace's package.json. */
export interface DirectDep {
  name: string;
  range: string;
  type: DepType;
  /** id of the resolved node, if the lockfile has it */
  id?: string;
}

export interface Workspace {
  /** path relative to the project root ('.' for the root) */
  path: string;
  name: string;
  direct: DirectDep[];
  /** `engines.node` from this manifest, if any */
  nodeEngine?: string;
  /** `requires-python` from pyproject.toml, if any */
  pythonRequires?: string;
  /** looks like a browser/frontend project */
  frontend: boolean;
}

export type LockfileKind = 'npm' | 'pnpm' | 'yarn-classic' | 'yarn-berry' | 'uv' | 'poetry' | 'requirements' | 'virtualenv' | 'none';

export interface DependencyGraph {
  ecosystem: Ecosystem;
  root: string;
  lockfile: { kind: LockfileKind; path?: string };
  workspaces: Workspace[];
  nodes: Map<string, PackageNode>;
}

// ---------------------------------------------------------------- fetched metadata

export interface RegistryInfo {
  name: string;
  /** false for private/scoped-registry packages and 404s */
  assessed: boolean;
  notAssessedReason?: string;
  latest?: string;
  /** version -> ISO publish time */
  time: Record<string, string>;
  versions: string[];
  /** deprecation message for the installed version */
  deprecated?: string;
  /** deprecation message for the latest version (whole package deprecated) */
  latestDeprecated?: string;
  /** undefined where the registry doesn't expose it (PyPI) */
  maintainers?: number;
  repository?: Repository;
  /** unpackedSize (bytes) for the installed version */
  unpackedSize?: number;
  weeklyDownloads?: number;
  keywords: string[];
  description?: string;
}

/** A source repository; `owner` may contain GitLab subgroups (`group/sub`). */
export interface Repository {
  host: 'github' | 'gitlab';
  owner: string;
  repo: string;
  url: string;
}

export interface RepoInfo {
  archived?: boolean;
  pushedAt?: string;
  /** commits on the default branch in the last 12 months (capped at 100) */
  commitsLastYear?: number;
  openIssues?: number;
  stars?: number;
  /** OpenSSF Scorecard overall score 0-10 */
  scorecard?: number;
  /** Scorecard "Maintained" check 0-10 */
  scorecardMaintained?: number;
  source: string[];
}

export type Severity = 'critical' | 'high' | 'moderate' | 'low' | 'unknown';

export interface Vulnerability {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  /** lowest version that fixes it, newer than the installed one */
  fixedIn?: string;
  url: string;
}

// ---------------------------------------------------------------- findings

export type Category = 'abandoned' | 'outdated' | 'insecure' | 'weight';
export type Level = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface Finding {
  category: Category;
  level: Level;
  /** short machine-friendly code, e.g. `deprecated`, `major-behind`, `vuln` */
  code: string;
  message: string;
  /** points subtracted from the 0-100 health score */
  penalty: number;
  fix?: string;
  /** advisory id for `vuln` findings (GHSA-…, PYSEC-…) */
  advisory?: string;
  /** advisory severity for `vuln` findings */
  severity?: Severity;
}

/** Ecosystem-specific wording and version ordering that the analyzers need. */
export interface Hints {
  scheme: VersionScheme;
  /** `lodash@4.17.21` / `requests==2.32.3` */
  pin(name: string, version: string): string;
  /** command or instruction to move a direct dependency to `version` */
  update(name: string, version: string): string;
  /** how to force a transitive dependency to at least `version` */
  override(name: string, version: string): string;
}

export type Effort = 'drop-in' | 'small API changes' | 'rewrite' | 'unknown';

export interface Replacement {
  /** package name, or a native API such as `fetch` */
  name: string;
  kind: 'native' | 'package' | 'snippet' | 'removal';
  source: 'author' | 'curated' | 'search';
  effort: Effort;
  note?: string;
  url?: string;
}

export interface PackageReport {
  ecosystem: Ecosystem;
  id: string;
  name: string;
  version: string;
  direct: boolean;
  depTypes: DepType[];
  dev: boolean;
  workspaces: string[];
  /** direct dependencies that pull this package in (for transitive packages) */
  via: string[];
  assessed: boolean;
  notAssessedReason?: string;
  latest?: string;
  libyear?: number;
  semverBehind?: 'major' | 'minor' | 'patch' | 'none' | 'ahead';
  vulnerabilities: Vulnerability[];
  abandonment?: { status: 'abandoned' | 'at-risk' | 'healthy'; failed: string[]; passed: string[] };
  weight?: { unpackedSize?: number; transitiveCount: number; bundle?: { minified: number; gzip: number } };
  findings: Finding[];
  replacements: Replacement[];
  score: number;
  ignored?: { reason: string; checks: Category[] | 'all' };
  repo?: RepoInfo;
  registry?: Pick<RegistryInfo, 'maintainers' | 'weeklyDownloads' | 'deprecated' | 'latestDeprecated'> & { lastPublish?: string };
}

export interface Action {
  ecosystem: Ecosystem;
  priority: number;
  package: string;
  title: string;
  detail: string;
  category: Category;
}

export interface Report {
  tool: { name: 'dephealth'; version: string };
  generatedAt: string;
  root: string;
  ecosystems: Ecosystem[];
  lockfiles: (DependencyGraph['lockfile'] & { ecosystem: Ecosystem })[];
  workspaces: { ecosystem: Ecosystem; path: string; name: string; direct: number }[];
  summary: {
    packages: number;
    direct: number;
    assessed: number;
    averageScore: number;
    totalLibyear: number;
    byCategory: Record<Category, number>;
    vulnerabilities: Record<Severity, number>;
    duplicates: { ecosystem: Ecosystem; name: string; versions: string[] }[];
  };
  actions: Action[];
  packages: PackageReport[];
  warnings: string[];
  /**
   * Reasons the results can't be trusted as complete (a service was unreachable, nothing could be
   * resolved…). Non-empty means "unknown", never "all clear": CI mode exits 2.
   */
  incomplete: string[];
}
