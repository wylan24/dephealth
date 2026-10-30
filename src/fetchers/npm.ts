import type { RegistryInfo } from '../types.ts';
import { type DiskCache, fetchJson, limiter } from './http.ts';

interface Packument {
  'dist-tags'?: Record<string, string>;
  time?: Record<string, string>;
  versions?: Record<string, { deprecated?: string; dist?: { unpackedSize?: number } }>;
  maintainers?: unknown[];
  repository?: string | { url?: string };
  keywords?: string[];
  description?: string;
}

/** The parts of a packument we keep (full packuments can be tens of MB). */
interface TrimmedPackument {
  latest?: string;
  time: Record<string, string>;
  versions: Record<string, { d?: string; s?: number }>;
  maintainers: number;
  repository?: string;
  keywords: string[];
  description?: string;
}

export function parseRepository(repo: string | undefined): RegistryInfo['repository'] {
  if (!repo) return undefined;
  const m =
    /github\.com[/:]([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i.exec(repo) ??
    /^(?:github:)?([\w.-]+)\/([\w.-]+?)(?:\.git)?$/.exec(repo);
  if (!m) return undefined;
  return { owner: m[1], repo: m[2], url: `https://github.com/${m[1]}/${m[2]}` };
}

const encodeName = (name: string) => name.replace('/', '%2f');
const DOWNLOADS = 'https://api.npmjs.org/downloads/point/last-week';

export class NpmFetcher {
  private limit = limiter(16);
  private dlLimit = limiter(4);
  private cache: DiskCache;
  private registry: string;
  constructor(cache: DiskCache, registry = 'https://registry.npmjs.org') {
    this.cache = cache;
    this.registry = registry;
  }

  private packument(name: string): Promise<TrimmedPackument | null> {
    return this.cache.wrap(`npm:packument:${name}`, () =>
      this.limit(async () => {
        // packuments of packages with thousands of versions (playwright, @types/node) run to tens of MB
        const { data } = await fetchJson<Packument>(`${this.registry}/${encodeName(name)}`, {}, 3, 120_000);
        if (!data) return null;
        const versions: TrimmedPackument['versions'] = {};
        for (const [v, meta] of Object.entries(data.versions ?? {})) {
          versions[v] = { d: meta.deprecated || undefined, s: meta.dist?.unpackedSize };
        }
        const repo = typeof data.repository === 'string' ? data.repository : data.repository?.url;
        return {
          latest: data['dist-tags']?.latest,
          time: data.time ?? {},
          versions,
          maintainers: data.maintainers?.length ?? 0,
          repository: repo,
          keywords: (data.keywords ?? []).slice(0, 10),
          description: data.description,
        };
      }),
    );
  }

  /**
   * Weekly downloads. The downloads API rate-limits hard, so unscoped names are batched through its
   * bulk endpoint (up to 128 per request); scoped names have no bulk form. Failures are not cached,
   * because a missing count disables the "finished utility" exemption in the abandonment check.
   */
  private downloads(name: string): Promise<number | undefined> {
    const key = `npm:downloads:${name}`;
    const hit = this.cache.get<number | null>(key);
    if (typeof hit === 'number') return Promise.resolve(hit); // older versions cached failures as null
    const store = (n: number | undefined) => {
      if (n !== undefined) this.cache.set(key, n);
      return n;
    };
    if (name.startsWith('@')) {
      return this.dlLimit(async () => {
        try {
          const { data } = await fetchJson<{ downloads?: number }>(`${DOWNLOADS}/${name}`, {}, 5);
          return store(data?.downloads);
        } catch {
          return undefined;
        }
      });
    }
    return new Promise((resolve) => {
      this.dlQueue.set(name, [...(this.dlQueue.get(name) ?? []), resolve]);
      this.dlTimer ??= setTimeout(() => this.flushDownloads(), 25);
    }).then((n) => store(n as number | undefined));
  }

  private dlQueue = new Map<string, ((n: number | undefined) => void)[]>();
  private dlTimer: ReturnType<typeof setTimeout> | undefined;

  private flushDownloads() {
    const queue = this.dlQueue;
    this.dlQueue = new Map();
    this.dlTimer = undefined;
    const names = [...queue.keys()];
    for (let i = 0; i < names.length; i += 128) {
      const chunk = names.slice(i, i + 128);
      void this.dlLimit(async () => {
        let data: Record<string, { downloads?: number } | null> | null = null;
        try {
          // a single name returns `{downloads}` rather than a map
          const res = await fetchJson<Record<string, { downloads?: number } | null> & { downloads?: number }>(`${DOWNLOADS}/${chunk.join(',')}`, {}, 5);
          data = chunk.length === 1 ? { [chunk[0]]: res.data } : res.data;
        } catch {
          // leave counts unknown
        }
        for (const n of chunk) for (const resolve of queue.get(n)!) resolve(data?.[n]?.downloads);
      });
    }
  }

  async info(name: string, version: string, withDownloads: boolean): Promise<RegistryInfo> {
    const p = await this.packument(name);
    if (!p) {
      return { name, assessed: false, notAssessedReason: 'not found on the public npm registry (private package?)', time: {}, versions: [], maintainers: 0, keywords: [] };
    }
    const latest = p.latest;
    return {
      name,
      assessed: true,
      latest,
      time: p.time,
      versions: Object.keys(p.versions),
      deprecated: p.versions[version]?.d,
      latestDeprecated: latest ? p.versions[latest]?.d : undefined,
      maintainers: p.maintainers,
      repository: parseRepository(p.repository),
      unpackedSize: p.versions[version]?.s,
      weeklyDownloads: withDownloads ? await this.downloads(name) : undefined,
      keywords: p.keywords,
      description: p.description,
    };
  }

  /** npm search, used for "candidates, not recommendations". */
  async search(text: string, size = 10) {
    type Hit = { package: { name: string; description?: string; date?: string; links?: { repository?: string } }; score: { final: number; detail: { quality: number; popularity: number; maintenance: number } }; downloads?: { weekly?: number } };
    return this.cache.wrap(`npm:search:${text}:${size}`, async () => {
      const { data } = await fetchJson<{ objects: Hit[] }>(`${this.registry}/-/v1/search?text=${encodeURIComponent(text)}&size=${size}`);
      return data?.objects ?? [];
    });
  }
}
