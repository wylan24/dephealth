// Replaces globalThis.fetch with a router so fetchers can be tested without the network.

export type Handler = (url: URL, init?: RequestInit) => unknown | Response | Promise<unknown | Response>;
export interface Call {
  url: string;
  method: string;
  body?: string;
  headers: Record<string, string>;
}

/** Routes match on URL prefix (string) or regex, first match wins; anything else is a 404. */
export function mockFetch(routes: [string | RegExp, Handler][]) {
  const calls: Call[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    const href = decodeURIComponent(url.toString());
    calls.push({ url: href, method: init?.method ?? 'GET', body: init?.body as string | undefined, headers: Object.fromEntries(Object.entries(init?.headers ?? {})) });
    for (const [match, handler] of routes) {
      if (typeof match === 'string' ? href.startsWith(match) : match.test(href)) {
        const out = await handler(url, init);
        return out instanceof Response ? out : Response.json(out);
      }
    }
    return new Response('not found', { status: 404 });
  }) as typeof fetch;
  return {
    calls,
    restore: () => {
      globalThis.fetch = original;
    },
    count: (prefix: string | RegExp) => calls.filter((c) => (typeof prefix === 'string' ? c.url.startsWith(prefix) : prefix.test(c.url))).length,
  };
}

export const status = (code: number, headers: Record<string, string> = {}) => new Response('', { status: code, headers });
