import { readFileSync } from 'node:fs';
import { all as e18e, nativeReplacements, resolveDocUrl } from 'module-replacements';
import type { Effort, Replacement } from '../types.ts';

interface Overlay {
  aliases: Record<string, string>;
  legacy: Record<string, string>;
  effort: Record<string, Effort>;
  extra: Record<string, (Omit<Replacement, 'source'> & { kind: Replacement['kind'] })[]>;
}

const overlay = JSON.parse(readFileSync(new URL('../../data/replacements.json', import.meta.url), 'utf8')) as Overlay;

const PKG_NAME = /^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/;
const STOP_WORDS = new Set(['the', 'a', 'an', 'it', 'this', 'that', 'version', 'latest', 'native', 'built-in', 'builtin', 'instead', 'new', 'newer', 'v2', 'v3', 'npm', 'node', 'nodejs', 'something', 'another', 'alternative', 'alternatives', 'package', 'packages', 'module', 'modules', 'at', 'an', 'other', 'our', 'your']);

/**
 * Pull "use X instead" style suggestions out of an author's deprecation message.
 * Returns package names only; prose that names no package yields nothing.
 */
export function fromDeprecation(name: string, message: string): string[] {
  const patterns = [
    /\buse\s+[`'"]?(@?[a-z0-9][\w./-]*)[`'"]?\s+instead\b/gi,
    /\b(?:moved|renamed|migrated|has moved)\s+to\s+[`'"]?(@?[a-z0-9][\w./-]*)/gi,
    /\b(?:replaced|superseded)\s+by\s+[`'"]?(@?[a-z0-9][\w./-]*)/gi,
    /\b(?:please\s+)?(?:use|switch to|migrate to|upgrade to|install)\s+[`'"]?(@[a-z0-9][\w.-]*\/[\w.-]+|[a-z0-9][\w.-]*(?:-[\w.-]+)+)[`'"]?/gi,
    /\bnow\s+(?:available\s+)?(?:at|as)\s+[`'"]?(@?[a-z0-9][\w./-]*)/gi,
  ];
  const out: string[] = [];
  for (const re of patterns) {
    for (const m of message.matchAll(re)) {
      let candidate = m[1].replace(/[.,;:)]+$/, '').toLowerCase();
      candidate = candidate.replace(/^(@?[^@]+)@.*$/, '$1'); // drop a trailing @version
      if (candidate.startsWith('http') || candidate.includes('github.com')) continue;
      if (!PKG_NAME.test(candidate) || STOP_WORDS.has(candidate) || candidate === name || /^v?\d/.test(candidate)) continue;
      if (!out.includes(candidate)) out.push(candidate);
    }
  }
  return out;
}

/** A rename (same base name, new scope or prefix) is usually a drop-in swap. */
function renameEffort(from: string, to: string): Effort {
  const base = (n: string) => n.replace(/^@[^/]+\//, '').replace(/^(node-|js-)/, '');
  return base(from) === base(to) || to.endsWith(`/${base(from)}`) ? 'drop-in' : 'small API changes';
}

export function authorSuggestions(name: string, message: string | undefined): Replacement[] {
  if (!message) return [];
  return fromDeprecation(name, message).map((r) => ({ name: r, kind: 'package' as const, source: 'author' as const, effort: renameEffort(name, r), note: 'from the deprecation notice' }));
}

/** Packages their own maintainers describe as legacy / maintenance-only, with the source of that statement. */
export const legacyNote = (name: string): string | undefined => overlay.legacy[name];

export function curatedSuggestions(name: string): Replacement[] {
  const out: Replacement[] = [];
  const mapping = e18e.mappings[name];
  for (const id of mapping?.replacements ?? []) {
    const rep = e18e.replacements[id];
    if (!rep) continue;
    const display = overlay.aliases[id] ?? (rep.type === 'documented' ? (overlay.aliases[rep.replacementModule] ?? rep.replacementModule) : id);
    const kind: Replacement['kind'] = rep.type === 'documented' ? 'package' : rep.type === 'simple' ? 'snippet' : rep.type;
    const polyfill = kind === 'native' && !!nativeReplacements.mappings[name];
    const effort = overlay.effort[`${name} > ${id}`] ?? (kind === 'snippet' || polyfill ? 'drop-in' : 'small API changes');
    const note = rep.type === 'documented' ? undefined : rep.description;
    out.push({ name: kind === 'snippet' ? 'inline snippet' : display, kind, source: 'curated', effort, note, url: resolveDocUrl(rep.url ?? mapping?.url) ?? undefined });
  }
  for (const extra of overlay.extra[name] ?? []) {
    if (!out.some((r) => r.name === extra.name)) out.push({ ...extra, source: 'curated' });
  }
  return out;
}

/**
 * Fallback: similar packages from npm search, ranked by npm's own health score.
 * These are clearly labelled candidates, never recommendations.
 */
export async function searchCandidates(
  name: string,
  keywords: string[],
  description: string | undefined,
  search: (text: string) => Promise<{ package: { name: string; description?: string }; score: { final: number; detail: { maintenance: number } } }[]>,
): Promise<Replacement[]> {
  const terms = keywords.filter((k) => k.length > 2 && !STOP_WORDS.has(k.toLowerCase())).slice(0, 3);
  const query = terms.length ? terms.map((k) => `keywords:${k}`).join(' ') : description?.split(/\s+/).slice(0, 6).join(' ');
  if (!query) return [];
  let hits;
  try {
    hits = await search(`${query} not:deprecated`);
  } catch {
    return [];
  }
  return hits
    .filter((h) => h.package.name !== name && h.score.detail.maintenance > 0.5)
    .sort((a, b) => b.score.final - a.score.final)
    .slice(0, 3)
    .map((h) => ({
      name: h.package.name,
      kind: 'package' as const,
      source: 'search' as const,
      effort: 'unknown' as const,
      note: `candidate, not a recommendation${h.package.description ? ` — ${h.package.description.slice(0, 100)}` : ''}`,
      url: `https://www.npmjs.com/package/${h.package.name}`,
    }));
}
