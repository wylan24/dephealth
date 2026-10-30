import type { RepoInfo, Repository } from '../types.ts';
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
interface GlProject {
  archived: boolean;
  last_activity_at: string;
  open_issues_count?: number; // absent when the issue tracker is disabled
  star_count: number;
}
type Activity = { archived: boolean; pushedAt: string; openIssues?: number; stars: number; commitsLastYear?: number } | null;

const yearAgo = () => new Date(Date.now() - 365 * 24 * 3600 * 1000).toISOString();

/**
 * Repository health from deps.dev (includes OpenSSF Scorecard, no auth, generous limits) and the
 * GitHub or GitLab API (archived flag, commit activity). GitHub without a token allows ~60
 * requests/hour, so once a host's budget runs out we keep going on deps.dev data alone.
 */
export class RepoFetcher {
  private ghLimit = limiter(6);
  private glLimit = limiter(4);
  private ddLimit = limiter(8);
  private ghExhausted = false;
  private glExhausted = false;
  ghCalls = 0;

  private cache: DiskCache;
  private token: string | undefined;
  private gitlabToken: string | undefined;
  private warn: (msg: string) => void;
  constructor(cache: DiskCache, token: string | undefined, warn: (msg: string) => void, gitlabToken?: string) {
    this.cache = cache;
    this.token = token;
    this.gitlabToken = gitlabToken;
    this.warn = warn;
  }

  private depsDev(r: Repository) {
    const key = encodeURIComponent(`${r.host}.com/${r.owner}/${r.repo}`.toLowerCase());
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
    const key = `github:repo:${owner}/${repo}`.toLowerCase();
    const cached = this.cache.get<Activity>(key);
    if (cached !== undefined) return Promise.resolve(cached);
    return this.ghLimit(async (): Promise<Activity | undefined> => {
      const r = await this.gh<GhRepo>(`/repos/${owner}/${repo}`);
      if (!r) return undefined; // rate limited: don't cache
      if (!r.data) {
        this.cache.set(key, null);
        return null;
      }
      const c = await this.gh<unknown[]>(`/repos/${owner}/${repo}/commits?since=${yearAgo()}&per_page=100`);
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

  /** GitLab REST API; public projects need no token (GITLAB_TOKEN raises the limits and reaches private ones). */
  private gitlab(path: string) {
    const key = `gitlab:repo:${path}`.toLowerCase();
    const cached = this.cache.get<Activity>(key);
    if (cached !== undefined) return Promise.resolve(cached);
    const api = (url: string) => {
      const headers: Record<string, string> = this.gitlabToken ? { 'private-token': this.gitlabToken } : {};
      return fetchJson<unknown>(`https://gitlab.com/api/v4/projects/${encodeURIComponent(path)}${url}`, { headers }, 1);
    };
    return this.glLimit(async (): Promise<Activity | undefined> => {
      if (this.glExhausted) return undefined;
      try {
        const p = (await api('')).data as GlProject | null;
        if (!p) {
          this.cache.set(key, null);
          return null;
        }
        const commits = (await api(`/repository/commits?since=${yearAgo()}&per_page=100`)).data as unknown[] | null;
        const result: Activity = { archived: p.archived, pushedAt: p.last_activity_at, openIssues: p.open_issues_count, stars: p.star_count, commitsLastYear: commits?.length };
        this.cache.set(key, result);
        return result;
      } catch (err) {
        if (err instanceof HttpError && (err.status === 401 || err.status === 403 || err.status === 429)) {
          if (!this.glExhausted) this.warn('GitLab API refused further requests (rate limit or access); remaining GitLab packages use deps.dev data only. Set GITLAB_TOKEN to raise the limit.');
          this.glExhausted = true;
          return undefined;
        }
        throw err;
      }
    });
  }

  async info(r: Repository): Promise<RepoInfo> {
    const live = r.host === 'github' ? this.github(r.owner, r.repo) : this.gitlab(`${r.owner}/${r.repo}`);
    const [dd, gh] = await Promise.all([this.depsDev(r), live.catch(() => undefined)]);
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
      info.source.push(r.host);
      info.archived = gh.archived;
      info.pushedAt = gh.pushedAt;
      info.commitsLastYear = gh.commitsLastYear;
      info.openIssues ??= gh.openIssues;
      info.stars ??= gh.stars;
    }
    return info;
  }
}
