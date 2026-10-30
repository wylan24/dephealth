import semver from 'semver';

export type Bump = 'major' | 'minor' | 'patch';

/** The version operations analyzers need, so they work for both semver (npm) and PEP 440 (PyPI). */
export interface VersionScheme {
  valid(v: string): boolean;
  /** negative / zero / positive like Array.prototype.sort; only call with valid versions */
  compare(a: string, b: string): number;
  prerelease(v: string): boolean;
  major(v: string): number;
  /** largest component that differs between a and b */
  diff(a: string, b: string): Bump | undefined;
  /** smallest version, used for OSV `introduced: "0"` */
  zero: string;
}

export const semverScheme: VersionScheme = {
  valid: (v) => !!semver.valid(v, true),
  compare: (a, b) => semver.compare(a, b, true),
  prerelease: (v) => !!semver.prerelease(v, true),
  major: (v) => semver.major(v, true),
  diff: (a, b) => {
    const d = semver.diff(a, b);
    if (!d) return undefined;
    return d === 'major' || d === 'premajor' ? 'major' : d === 'minor' || d === 'preminor' ? 'minor' : 'patch';
  },
  zero: '0.0.0-0',
};

// ---------------------------------------------------------------- PEP 440

const PEP440 =
  /^v?(?:(\d+)!)?(\d+(?:\.\d+)*)(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d+)?)?(?:-(\d+)|[-_.]?(post|rev|r)[-_.]?(\d+)?)?(?:[-_.]?(dev)[-_.]?(\d+)?)?(?:\+([a-z0-9]+(?:[-_.][a-z0-9]+)*))?$/i;

interface Pep440 {
  epoch: number;
  release: number[];
  pre?: [number, number]; // a=0, b=1, rc=2
  post?: number;
  dev?: number;
}

const PRE_RANK: Record<string, number> = { a: 0, alpha: 0, b: 1, beta: 1, c: 2, rc: 2, pre: 2, preview: 2 };

export function parsePep440(v: string): Pep440 | undefined {
  const m = PEP440.exec(v.trim());
  if (!m) return undefined;
  const [, epoch, release, preL, preN, postImplicit, postL, postN, devL, devN] = m;
  return {
    epoch: epoch ? Number(epoch) : 0,
    release: release.split('.').map(Number),
    pre: preL ? [PRE_RANK[preL.toLowerCase()], Number(preN ?? 0)] : undefined,
    post: postImplicit !== undefined ? Number(postImplicit) : postL ? Number(postN ?? 0) : undefined,
    dev: devL ? Number(devN ?? 0) : undefined,
  };
}

/**
 * Mirrors `packaging.version`'s ordering: dev < pre-release < final < post; local versions ignored.
 * Releases are zero-padded to a common length so 1.0 == 1.0.0.
 */
function pepKey(p: Pep440, len: number): number[] {
  const release = [...p.release];
  while (release.length < len) release.push(0);
  // a bare dev release (1.0.dev1) sorts before any pre-release of 1.0
  const pre = p.pre ?? (p.post === undefined && p.dev !== undefined ? [-Infinity, 0] : [Infinity, 0]);
  return [p.epoch, ...release, ...pre, p.post ?? -Infinity, p.dev ?? Infinity];
}

function cmpPep(a: Pep440, b: Pep440): number {
  const len = Math.max(a.release.length, b.release.length);
  const ka = pepKey(a, len);
  const kb = pepKey(b, len);
  for (let i = 0; i < ka.length; i++) if (ka[i] !== kb[i]) return ka[i] < kb[i] ? -1 : 1;
  return 0;
}

export const pep440Scheme: VersionScheme = {
  valid: (v) => !!parsePep440(v),
  compare: (a, b) => cmpPep(parsePep440(a)!, parsePep440(b)!),
  prerelease: (v) => {
    const p = parsePep440(v);
    return !!p && (p.pre !== undefined || p.dev !== undefined);
  },
  major: (v) => parsePep440(v)?.release[0] ?? 0,
  diff: (a, b) => {
    const pa = parsePep440(a);
    const pb = parsePep440(b);
    if (!pa || !pb || cmpPep(pa, pb) === 0) return undefined;
    if (pa.epoch !== pb.epoch || (pa.release[0] ?? 0) !== (pb.release[0] ?? 0)) return 'major';
    if ((pa.release[1] ?? 0) !== (pb.release[1] ?? 0)) return 'minor';
    return 'patch';
  },
  zero: '0.dev0',
};

export const sortVersions = (scheme: VersionScheme, versions: string[]) =>
  versions.filter((v) => scheme.valid(v)).sort((a, b) => scheme.compare(a, b));
