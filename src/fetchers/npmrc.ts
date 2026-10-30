import { existsSync, readFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const PUBLIC_HOSTS = ['registry.npmjs.org', 'registry.npmjs.com', 'registry.yarnpkg.com'];

/**
 * Reads `registry` and `@scope:registry` from the project's and the user's .npmrc so that
 * packages served by a private registry are reported as "not assessed" instead of failing.
 */
export class NpmRc {
  readonly defaultRegistry: string;
  private scoped = new Map<string, string>();

  constructor(projectRoot: string) {
    let registry = process.env.npm_config_registry ?? process.env.NPM_CONFIG_REGISTRY;
    // later files override earlier ones: user config first, then project
    for (const file of [path.join(os.homedir(), '.npmrc'), path.join(projectRoot, '.npmrc')]) {
      if (!existsSync(file)) continue;
      for (const raw of readFileSync(file, 'utf8').split(/\r?\n/)) {
        const line = raw.trim();
        if (!line || line.startsWith('#') || line.startsWith(';')) continue;
        const m = /^(@[^:]+:)?registry\s*=\s*(.+)$/.exec(line);
        if (!m) continue;
        const url = m[2].trim().replace(/^["']|["']$/g, '');
        if (m[1]) this.scoped.set(m[1].slice(0, -1), url);
        else registry = url;
      }
    }
    this.defaultRegistry = registry ?? 'https://registry.npmjs.org/';
  }

  registryFor(name: string): string {
    const scope = name.startsWith('@') ? name.split('/')[0] : undefined;
    return (scope && this.scoped.get(scope)) ?? this.defaultRegistry;
  }

  static isPublic(url: string): boolean {
    try {
      return PUBLIC_HOSTS.includes(new URL(url).hostname);
    } catch {
      return false;
    }
  }

  /**
   * Why a package can't be assessed against public data, or undefined if it can.
   * A non-public *default* registry is usually a mirror of npm (Artifactory, Verdaccio), so those
   * packages are still looked up publicly and only marked private if the public registry 404s.
   */
  privateReason(name: string, resolved?: string): string | undefined {
    if (resolved && /^(git|github:|git\+|file:)/.test(resolved)) return 'installed from git or a local path, not a registry';
    const scope = name.startsWith('@') ? name.split('/')[0] : undefined;
    const scoped = scope && this.scoped.get(scope);
    if (scoped && !NpmRc.isPublic(scoped)) return `scope ${scope} is served by a private registry`;
    return undefined;
  }
}
