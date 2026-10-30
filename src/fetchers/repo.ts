import type { RepoInfo } from '../types.ts';
import { type DiskCache, HttpError, fetchJson, limiter } from './http.ts';

interface DepsDevProject {
  openIssuesCount?: number;
  starsCount?: number;
  scorecard?: { overallScore?: number; checks?: { name: string; score: number }[] };
}
interface GhRepo {
  archived: boolean;
  pushed_at: string;
  open_issues_count: number;
  stargazers_count: number;
  default_branch: string;
}

/**
 * Repository health from deps.dev (includes OpenSSF Scorecard, no auth, generous limits) and the
 * GitHub API (archived flag, commit activity). GitHub without a token allows ~60 requests/hour,
 * so once the budget runs out we keep going on deps.dev data alone.
 */
export class RepoFetcher {
  private ghLimit = limiter(6);
  private ddLimit = limiter(8);
  private ghExhausted = false;
  ghCalls = 0;

  private cache: DiskCache;
  private token: string | undefined;
  private warn: (msg: string) => void;
  constructor(cache: DiskCache, token: string | undefined, warn: (msg: string) => void) {
    this.cache = cache;
    this.token = token;
    this.warn = warn;
  }

  private depsDev(owner: string, repo: string) {
    const key = encodeURIComponent(`github.com/${owner}/${repo}`.toLowerCase());
    return this.cache.wrap(`depsdev:project:${key}`, () =>
      this.ddLimit(async () => {
        try {
          return (await fetchJson<DepsDevProject>(`https://api.deps.dev/v3/projects/${key}`)).data;
        } catch {
          return null;
        }
      }),
    );
  }

  private async gh<T>(url: string): Promise<{ data: T | null; headers?: Headers } | undefined> {
    if (this.ghExhausted) return undefined;
    const headers: Record<string, string> = { accept: 'application/vnd.github+json', 'x-github-api-version': '2022-11-28' };
    if (this.token) headers.authorization = `Bearer ${this.token}`;
    try {
      this.ghCalls++;
      const res = await fetchJson<T>(`https://api.github.com${url}`, { headers }, 1);
      if (res.headers.get('x-ratelimit-remaining') === '0') this.exhaust();
      return res;
    } catch (err) {
      if (err instanceof HttpError && (err.status === 403 || err.status === 429)) {
        this.exhaust();
        return undefined;
      }
      if (err instanceof HttpError && err.status === 409) return { data: null }; // empty repository
      throw err;
    }
  }

  private exhaust() {
    if (this.ghExhausted) return;
    this.ghExhausted = true;
    this.warn(
      this.token
        ? 'GitHub API rate limit reached; remaining packages use deps.dev/Scorecard data only.'
        : 'GitHub API rate limit reached (60 requests/hour without a token). Set GITHUB_TOKEN for archived/commit-activity signals on every package.',
    );
  }

  private github(owner: string, repo: string) {
    type Gh = { archived: boolean; pushedAt: string; openIssues: number; stars: number; commitsLastYear?: number } | null;
    const key = `github:repo:${owner}/${repo}`.toLowerCase();
    const cached = this.cache.get<Gh>(key);
    if (cached !== undefined) return Promise.resolve(cached);
    return this.ghLimit(async (): Promise<Gh | undefined> => {
      const r = await this.gh<GhRepo>(`/repos/${owner}/${repo}`);
      if (!r) return undefined; // rate limited: don't cache
      if (!r.data) {
        this.cache.set(key, null);
        return null;
      }
      const since = new Date(Date.now() - 365 * 24 * 3600 * 1000).toISOString();
      const c = await this.gh<unknown[]>(`/repos/${owner}/${repo}/commits?since=${since}&per_page=100`);
      const result = {
        archived: r.data.archived,
        pushedAt: r.data.pushed_at,
        openIssues: r.data.open_issues_count,
        stars: r.data.stargazers_count,
        commitsLastYear: c?.data ? c.data.length : undefined,
      };
      if (c) this.cache.set(key, result);
      return result;
    });
  }

  async info(owner: string, repo: string): Promise<RepoInfo> {
    const [dd, gh] = await Promise.all([this.depsDev(owner, repo), this.github(owner, repo).catch(() => undefined)]);
    const info: RepoInfo = { source: [] };
    if (dd) {
      info.source.push('deps.dev');
      info.openIssues = dd.openIssuesCount;
      info.stars = dd.starsCount;
      info.scorecard = dd.scorecard?.overallScore;
      const maintained = dd.scorecard?.checks?.find((c) => c.name === 'Maintained');
      if (maintained && maintained.score >= 0) info.scorecardMaintained = maintained.score;
    }
    if (gh) {
      info.source.push('github');
      info.archived = gh.archived;
      info.pushedAt = gh.pushedAt;
      info.commitsLastYear = gh.commitsLastYear;
      info.openIssues ??= gh.openIssues;
      info.stars ??= gh.stars;
    }
    return info;
  }
}
