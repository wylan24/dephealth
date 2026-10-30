import type { RegistryInfo } from '../types.ts';
import { type DiskCache, fetchJson, limiter } from './http.ts';
import { parseRepository } from './npm.ts';

interface PypiFile {
  upload_time_iso_8601?: string;
  yanked?: boolean;
  yanked_reason?: string | null;
}
interface PypiProject {
  info: {
    version: string;
    summary?: string;
    keywords?: string | null;
    classifiers?: string[];
    project_urls?: Record<string, string> | null;
    home_page?: string | null;
  };
  releases: Record<string, PypiFile[]>;
}

/** What we keep of a PyPI project document. */
interface TrimmedProject {
  latest: string;
  time: Record<string, string>;
  /** version -> yank reason ("" when yanked without one) */
  yanked: Record<string, string>;
  inactive: boolean;
  repository?: string;
  keywords: string[];
  description?: string;
}

const INACTIVE = 'Development Status :: 7 - Inactive';

/** First URL that looks like the source repository, falling back to the homepage. */
function repoUrl(info: PypiProject['info']): string | undefined {
  const urls = Object.entries(info.project_urls ?? {});
  const pick = urls.find(([k, v]) => /source|repo|code|github/i.test(k) && /(github|gitlab)\.com/i.test(v)) ?? urls.find(([, v]) => /(github|gitlab)\.com/i.test(v));
  return pick?.[1] ?? (info.home_page && /(github|gitlab)\.com/i.test(info.home_page) ? info.home_page : undefined);
}

export class PypiFetcher {
  private limit = limiter(16);
  private dlLimit = limiter(2); // pypistats.org is strict about rate limits
  private cache: DiskCache;
  private index: string;
  constructor(cache: DiskCache, index = 'https://pypi.org/pypi') {
    this.cache = cache;
    this.index = index;
  }

  private project(name: string): Promise<TrimmedProject | null> {
    return this.cache.wrap(`pypi:project:${name}`, () =>
      this.limit(async () => {
        const { data } = await fetchJson<PypiProject>(`${this.index}/${encodeURIComponent(name)}/json`);
        if (!data) return null;
        const time: Record<string, string> = {};
        const yanked: Record<string, string> = {};
        for (const [v, files] of Object.entries(data.releases ?? {})) {
          const times = files.map((f) => f.upload_time_iso_8601).filter(Boolean).sort() as string[];
          if (times.length) time[v] = times[0];
          if (files.length && files.every((f) => f.yanked)) yanked[v] = files[0].yanked_reason ?? '';
        }
        return {
          latest: data.info.version,
          time,
          yanked,
          inactive: (data.info.classifiers ?? []).includes(INACTIVE),
          repository: repoUrl(data.info),
          keywords: (data.info.keywords ?? '').split(/[,\s]+/).filter(Boolean).slice(0, 10),
          description: data.info.summary,
        };
      }),
    );
  }

  /** Weekly downloads from pypistats.org; failures aren't cached (see NpmFetcher.downloads). */
  private async downloads(name: string): Promise<number | undefined> {
    const key = `pypi:downloads:${name}`;
    const hit = this.cache.get<number | null>(key);
    if (typeof hit === 'number') return hit;
    return this.dlLimit(async () => {
      try {
        const { data } = await fetchJson<{ data?: { last_week?: number } }>(`https://pypistats.org/api/packages/${encodeURIComponent(name)}/recent`, {}, 3);
        const n = data?.data?.last_week;
        if (n !== undefined) this.cache.set(key, n);
        return n;
      } catch {
        return undefined; // non-essential
      }
    });
  }

  async info(name: string, version: string, withDownloads: boolean): Promise<RegistryInfo> {
    const p = await this.project(name);
    if (!p) {
      return { name, assessed: false, notAssessedReason: 'not found on PyPI (private package?)', time: {}, versions: [], keywords: [] };
    }
    const yank = p.yanked[version];
    return {
      name,
      assessed: true,
      latest: p.latest,
      time: p.time,
      versions: Object.keys(p.time),
      deprecated: yank !== undefined ? `version ${version} was yanked from PyPI${yank ? `: ${yank}` : ''}` : undefined,
      latestDeprecated: p.inactive ? INACTIVE : undefined,
      maintainers: undefined, // not exposed by the PyPI JSON API
      repository: parseRepository(p.repository),
      weeklyDownloads: withDownloads ? await this.downloads(name) : undefined,
      keywords: p.keywords,
      description: p.description,
    };
  }
}
