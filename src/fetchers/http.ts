import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const DAY = 24 * 60 * 60 * 1000;

/** On-disk JSON cache. Entries expire after `ttl` (24h by default) so re-runs are near-instant. */
export class DiskCache {
  hits = 0;
  misses = 0;
  readonly dir: string | null;
  readonly ttl: number;
  /** `dir` null disables caching */
  constructor(dir: string | null, ttl = DAY) {
    this.dir = dir;
    this.ttl = ttl;
    if (dir) mkdirSync(dir, { recursive: true });
  }

  static defaultDir() {
    const base = process.env.XDG_CACHE_HOME ?? (process.platform === 'win32' ? process.env.LOCALAPPDATA : undefined) ?? path.join(os.homedir(), '.cache');
    return path.join(base ?? os.tmpdir(), 'dephealth');
  }

  private file(key: string) {
    return path.join(this.dir!, createHash('sha1').update(key).digest('hex') + '.json');
  }

  get<T>(key: string): T | undefined {
    if (!this.dir) return undefined;
    try {
      const { t, v } = JSON.parse(readFileSync(this.file(key), 'utf8')) as { t: number; v: T };
      if (Date.now() - t < this.ttl) {
        this.hits++;
        return v;
      }
    } catch {
      // missing or corrupt entry: treat as a miss
    }
    this.misses++;
    return undefined;
  }

  set(key: string, v: unknown) {
    if (!this.dir) return;
    try {
      writeFileSync(this.file(key), JSON.stringify({ t: Date.now(), v }));
    } catch {
      // cache is best-effort
    }
  }

  async wrap<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const hit = this.get<T>(key);
    if (hit !== undefined) return hit;
    const v = await fn();
    this.set(key, v);
    return v;
  }
}

/** Minimal concurrency limiter: at most `n` tasks in flight. */
export function limiter(n: number) {
  let active = 0;
  const queue: (() => void)[] = [];
  const next = () => {
    if (active >= n || !queue.length) return;
    active++;
    queue.shift()!();
  };
  return <T>(fn: () => Promise<T>): Promise<T> =>
    new Promise<T>((resolve, reject) => {
      queue.push(() =>
        fn()
          .then(resolve, reject)
          .finally(() => {
            active--;
            next();
          }),
      );
      next();
    });
}

export class HttpError extends Error {
  readonly status: number;
  readonly url: string;
  readonly headers?: Headers;
  constructor(status: number, url: string, headers?: Headers) {
    super(`HTTP ${status} for ${url}`);
    this.status = status;
    this.url = url;
    this.headers = headers;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** fetch() + JSON with retries on 429/5xx and network errors. Returns null on 404. */
export async function fetchJson<T>(url: string, init: RequestInit = {}, retries = 3): Promise<{ data: T | null; headers: Headers }> {
  for (let attempt = 0; ; attempt++) {
    let res: Response;
    try {
      res = await fetch(url, {
        ...init,
        headers: { 'user-agent': 'dephealth (+https://github.com/wylan24/dephealth)', accept: 'application/json', ...init.headers },
        signal: AbortSignal.timeout(30_000),
      });
    } catch (err) {
      if (attempt >= retries) throw err;
      await sleep(500 * 2 ** attempt);
      continue;
    }
    if (res.status === 404) return { data: null, headers: res.headers };
    if (res.ok) return { data: (await res.json()) as T, headers: res.headers };
    const retryable = res.status === 429 || res.status >= 500;
    if (!retryable || attempt >= retries) throw new HttpError(res.status, url, res.headers);
    const retryAfter = Number(res.headers.get('retry-after'));
    await sleep(retryAfter > 0 && retryAfter < 60 ? retryAfter * 1000 : 500 * 2 ** attempt);
  }
}
