# dephealth

[![npm](https://img.shields.io/npm/v/@wylan24/dephealth)](https://www.npmjs.com/package/@wylan24/dephealth)
[![CI](https://github.com/wylan24/dephealth/actions/workflows/ci.yml/badge.svg)](https://github.com/wylan24/dephealth/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@wylan24/dephealth)](LICENSE)

## Quick start

You need [Node.js](https://nodejs.org) 22.18 or newer. In your project folder (the one with `package.json`, `pyproject.toml` or `requirements.txt`), run:

```bash
npx @wylan24/dephealth
```

You get a short summary with the top actions in the terminal, and a full interactive report in `dephealth-report.html`; open it in your browser. Nothing in your project is changed.

* **On GitHub?** Add the [GitHub Action](#github-action) to check every pull request.
* **Checking a different folder?** `npx @wylan24/dephealth path/to/project`
* **Something odd?** See [Troubleshooting](#troubleshooting).

## What it does

A dependency health report for **npm** and **Python (PyPI)** projects. Point it at a project folder and it reads the manifests and lockfiles, checks every package, and groups the problems into four categories, each with a suggested fix:

| Category | What it means |
| --- | --- |
| **Insecure** | Known vulnerabilities from [OSV.dev](https://osv.dev), for every package in the lockfile, including transitive ones |
| **Abandoned** | Deprecated, archived, or failing several maintenance signals at once |
| **Outdated** | Versions behind latest, measured in [libyears](https://libyear.com), plus major lines that no longer get fixes |
| **Heavier than needed** | Built-ins that now cover the package ("native now"), micro-utilities, big installs, deep trees, bundle size |

Every package gets a 0–100 health score **with the reasons behind it**, so the score is never a black box.

```
dephealth — sample-app (163 packages, 12 direct, 1 workspace)
  Average score  53/100     Libyears 45.18
  Insecure 16 (2 critical, 13 high, 13 moderate, 7 low)   Abandoned 6   Outdated 8   Heavy 8

Top 10 actions
   1. form-data@2.3.3 [insecure] Upgrade request to a release that pulls form-data >= 2.5.6, or add an "overrides" entry for form-data (fixes both advisories)
   2. node-fetch@2.6.0 [insecure] Upgrade to node-fetch@2.6.7 or later (fixes both advisories)
   3. lodash@4.17.15 [insecure] Upgrade to lodash@4.18.0 or later (fixes all 6 advisories)
   ...
   9. request@2.88.2 [abandoned] Replace with fetch (rewrite)
  10. left-pad@1.3.0 [abandoned] Replace with String.prototype.padStart (drop-in)
```

## Usage

Requires Node.js 22.18 or newer. For CI on GitHub, use the [GitHub Action](#github-action).

```bash
npx @wylan24/dephealth [path/to/project] [options]
```

Or install it once and run `dephealth`:

```bash
npm install -g @wylan24/dephealth
dephealth path/to/project
```

The latest unreleased version runs straight from GitHub with `npx github:wylan24/dephealth path/to/project` (slower: it builds on install). Or from a clone:

```bash
git clone https://github.com/wylan24/dephealth && cd dephealth
npm ci && npm run build
node dist/cli.js path/to/project
```

dephealth detects which ecosystems the folder contains (`package.json`, `pyproject.toml`, `requirements*.txt`) and checks all of them in one report. This prints a summary with the top actions and writes `dephealth-report.html`, an interactive report with a summary, the top 10 actions, and a sortable, filterable table. Click a row to see why it scored what it did, the fixes, replacement suggestions and the raw maintenance signals.

| Option | |
| --- | --- |
| `--json <file>` | Also write the full report as JSON (`-` for stdout) |
| `--sarif <file>` | Also write SARIF 2.1.0 for GitHub code scanning (see [GitHub Action](#github-action)) |
| `--html <file>` / `--no-html` | HTML report location, or skip it |
| `--ci` | Exit 1 when a `--fail-on` rule is violated, 2 when results are incomplete |
| `--allow-incomplete` | In CI, accept partial results (e.g. a service was unreachable) instead of exiting 2 |
| `--fail-on <rules>` | e.g. `vuln:high,deprecated:direct,score<40` |
| `--deep` | Registry metadata for transitive packages too (deprecations, outdated major lines). Slower on first run |
| `--bundle` | Measure minified + gzipped browser bundle size (frontend workspaces; needs `node_modules` and [esbuild](https://esbuild.github.io), which is optional: `npm install -D esbuild`) |
| `--prod` | Ignore dev dependencies (devDependencies, dev dependency groups, dev requirement files) |
| `--ecosystem <list>` | `npm`, `pypi` or `npm,pypi` (default: every one detected) |
| `--no-search` | Don't search npm for replacement candidates (PyPI has no search API) |
| `--github-token <t>` | Defaults to `$GITHUB_TOKEN` / `$GH_TOKEN` |
| `--no-cache` / `--cache-dir <dir>` | API responses are cached on disk for 24 hours |

### Tokens

**GitHub**: optional but recommended (`GITHUB_TOKEN` or `--github-token`). Without one GitHub allows about 60 requests per hour, which won't cover a mid-sized project. When the budget runs out dephealth keeps going on [deps.dev](https://deps.dev) and [OpenSSF Scorecard](https://securityscorecards.dev) data alone and says so in the report. A token with no scopes is enough.

**GitLab**: packages whose source lives on gitlab.com (including nested groups) are checked through GitLab's API. Without a token GitLab hides the archived flag and the issue count, so set `GITLAB_TOKEN` (a read-only personal access token) to get those too. A GitHub token is never sent to GitLab.

## The checks

### Insecure

All `name@version` pairs in the lockfile go to OSV.dev's batch API. Each advisory reports severity (GHSA label, else computed from the CVSS 3.x vector), the fixed-in version, and whether the package is a direct dependency or which direct dependencies pull it in. The fix is a single version that clears *every* advisory on that package. For transitive packages it's "upgrade the parent, or force the version", phrased for your tool: npm `overrides`, `pnpm.overrides`, yarn `resolutions`, uv `constraint-dependencies`, or a pin in your requirements. Advisories that appear under several ids (GHSA, PYSEC, CVE) are merged into one. Malicious-package records (`MAL-*`) are always critical.

v1 doesn't do reachability analysis (whether your code actually calls the vulnerable path). Every finding says `reachability: unknown`.

### Abandoned

Signals (from GitHub or GitLab, plus deps.dev): author deprecation (npm `deprecated`; on PyPI the `Development Status :: 7 - Inactive` classifier), archived repository, time since last publish, commits in the last 12 months, number of npm maintainers (PyPI doesn't publish this), an open-issue backlog that's large *for the project's size*, Scorecard's "Maintained" check, and whether it links a source repo at all.

**It never flags on a single signal.** The only hard signals are deprecation and a repository archived with no recent activity. A repo archived right after a year of commits or releases usually means the package moved, so it's reported as *at risk* instead.

Otherwise a package needs to fail three signals to be called *abandoned* (two makes it *at risk*). Activity decides: a single maintainer, an issue backlog or a missing repo link only count once releases or commits have stopped, so an actively developed one-person project is never flagged for being one-person. A "finished" utility with more than 1M weekly downloads and no known vulnerabilities needs five (four for *at risk*): a tiny package nobody has needed to touch for years is stable, not abandoned.

Type stub packages (`@types/*` on npm, `types-*` on PyPI) live in shared monorepos (DefinitelyTyped, typeshed), so only their deprecation is checked.

### Outdated

Installed version (from the lockfile) against `latest`: patch, minor or major versions behind, and **libyears** (how much older the installed release is than the latest one), so drift can be tracked over time. A major line that is behind and has had no release for over a year is flagged as no longer receiving fixes. Minor and patch drift on transitive packages is left out because you can't act on it directly. Python versions are compared with PEP 440 rules, and CalVer packages (`certifi 2020.12.5 → 2026.10.23`) count as updates, not major jumps. A yanked PyPI release is reported like a deprecated npm version.

### Heavier than needed

* **Native now**: built-ins that cover the package for *your* targets, from the [e18e module-replacements](https://github.com/e18e/module-replacements) data and its engine-version metadata. The Node target comes from `engines.node` (default 22). Frontend workspaces also check browser targets. So `node-fetch` → `fetch` is flagged on Node 18+ but not on Node 16.
* **Python**: standard-library replacements for your minimum Python (from `requires-python`, default 3.10), e.g. `mock` → `unittest.mock`, `pytz` → `zoneinfo` (3.9+), `toml` → `tomllib` (3.11+), `six` → Python 3 built-ins. The list is in [`data/pypi-replacements.json`](data/pypi-replacements.json).
* **Micro-utilities** that are one line of code (`is-number` → `typeof x === "number"`).
* Install size (unpacked), transitive package count, and versions duplicated in the lockfile.
* Bundle size with `--bundle`, computed locally with esbuild rather than a rate-limited service.

## Replacement suggestions

Pulled from three places, in order of trust:

1. **The author**: "use X instead" / "moved to X" in the deprecation message.
2. **Curated**: for npm, the e18e `module-replacements` dataset plus a small overlay in [`data/replacements.json`](data/replacements.json) with effort ratings and packages e18e doesn't cover. For Python, [`data/pypi-replacements.json`](data/pypi-replacements.json) (e.g. `nose` → `pytest`, `pycrypto` → `pycryptodome`).
3. **Search** (npm only): a fallback only for abandoned direct dependencies with no other suggestion. It shows similar npm packages ranked by npm's own score, labelled **"candidate, not a recommendation"**.

Each suggestion has an effort level: **drop-in**, **small API changes**, or **rewrite**.

## Scoring

Scores start at 100 and lose points per finding, e.g. critical vuln −40, high −25, deprecated −35, likely abandoned −25, major version behind −8 to −20 plus up to −10 for libyear drift, native-now −6. Several advisories on one package are capped at −60 together. The HTML report lists each deduction next to the finding.

## CI mode

```bash
dephealth --ci --fail-on "vuln:high,deprecated:direct"
```

| Rule | Fails when |
| --- | --- |
| `vuln:<severity>` | any vulnerability at or above `critical`/`high`/`moderate`/`low` |
| `vuln-direct:<severity>` | same, direct dependencies only |
| `deprecated` / `deprecated:direct` | any deprecated package |
| `abandoned` / `abandoned:direct` | any package judged abandoned (includes deprecated/archived) |
| `outdated:major` | a direct dependency is a major version behind |
| `score<N` | a direct dependency scores below N |
| `avg<N` | the average direct-dependency score is below N |
| `libyear>N` | total libyears across direct dependencies exceeds N |

Exit codes: `0` passed, `1` a rule was violated, `2` the check couldn't complete or dephealth itself failed.

**"Couldn't check" never counts as "all clear".** If OSV.dev or a registry is unreachable, or nothing could be resolved (no lockfile and nothing installed), the report says the results are incomplete and CI mode exits `2`, even if no problems were found. Use `--allow-incomplete` to accept partial results anyway.

## GitHub Action

```yaml
# .github/workflows/dependency-health.yml
name: dependency health
on: [pull_request, push, workflow_dispatch]
permissions:
  contents: read
  security-events: write   # to upload findings to code scanning
jobs:
  dephealth:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: wylan24/dephealth@v0
        with:
          fail-on: vuln:high,deprecated:direct
```

On each run the Action:

* checks the project and writes the terminal summary to the job summary;
* uploads the findings to **GitHub code scanning**, so they show in the Security tab and as annotations on pull requests, on the exact line of `package.json`, `pyproject.toml` or the requirements file that declares the dependency (the lockfile for indirect ones);
* uploads the interactive HTML report as a workflow artifact;
* fails the job if a `fail-on` rule is broken.

| Input | Default | |
| --- | --- | --- |
| `path` | `.` | Project folder to check |
| `fail-on` | from config | CI rules, as above |
| `fail` | `true` | Set `false` to report without failing the job |
| `upload-sarif` | `true` | Upload to code scanning (needs `security-events: write`; skipped quietly on pull requests from forks) |
| `sarif-category` | `dephealth` | Keeps several runs apart, e.g. one per folder |
| `upload-report` | `true` | Upload the HTML report artifact |
| `args` | | Extra options, e.g. `--prod --deep` |
| `token` | `github.token` | Used for repository health signals |

Outputs: `exit-code`, `sarif`, `report`. Code scanning alerts keep the same identity when you bump a still-affected package, so they update instead of piling up.

Outside GitHub, run the CLI with `--ci --sarif dephealth.sarif` and feed the file to any SARIF viewer.

## Configuration

`.dephealthrc.json` in the project root, a `"dephealth"` key in `package.json`, or `[tool.dephealth]` in `pyproject.toml` (kebab-case keys such as `fail-on` and `python-target` work there). See [`.dephealthrc.example.json`](.dephealthrc.example.json).

```json
{
  "failOn": ["vuln:high", "deprecated:direct"],
  "nodeTarget": "20",
  "pythonTarget": "3.11",
  "ignore": [
    { "package": "left-pad", "checks": ["abandoned"], "reason": "Vendored; replacing in Q3", "until": "2026-12-31" },
    { "package": "@internal/*", "reason": "Internal packages, reviewed separately" }
  ]
}
```

Every ignore entry **must** say why. The reason is shown in the report next to the package, and an optional `until` date makes it expire. Ignored findings stay visible but don't count towards the score or CI rules.

## Project layouts

* **npm lockfiles**: `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `pnpm-lock.yaml` (v5–v9), `yarn.lock` (classic and Berry). Without a lockfile only the direct dependencies installed in `node_modules` are checked.
* **Python**: direct dependencies come from `pyproject.toml` (`[project]` dependencies and optional-dependencies, PEP 735 `[dependency-groups]`, `[tool.uv] dev-dependencies`, Poetry's `[tool.poetry.*dependencies]` and groups). Resolved versions come from, in order: `uv.lock`, `poetry.lock`, pinned `requirements*.txt` / `requirements/*.txt`, or an installed `.venv`. pip-compile/uv `# via` annotations supply the dependency tree and tell direct requirements from transitive ones; without them every pinned line is treated as direct. Groups named like dev/test/lint/docs, and files like `requirements-dev.txt`, count as dev.
* **Monorepos**: npm/yarn `workspaces`, `pnpm-workspace.yaml` and uv `[tool.uv.workspace]` members are expanded. Each workspace's dependencies are resolved separately, and workspace packages depending on each other are treated as internal.
* **Private registries**: `.npmrc` is respected. Packages from a scoped private registry, git or local paths, and anything the public registry 404s are shown as **not assessed** rather than failing the run. A non-public *default* registry is treated as a mirror of npm. Python packages installed from git or a local path, and anything PyPI doesn't know, are also **not assessed**.

## Architecture

```
src/
  parsers/     npm: package.json + package-lock / pnpm-lock / yarn.lock
               PyPI: pyproject.toml + uv.lock / poetry.lock / requirements / .venv
  fetchers/    npm registry, PyPI, OSV, GitHub, GitLab, deps.dev — disk-cached (24h), rate-limited, retrying
  analyzers/   abandoned, outdated, insecure, weight
  advisor/     replacement lookup + effort rating
  report/      scoring, actions, HTML / JSON / SARIF / terminal renderers, CI rules
  ecosystems.ts  per-ecosystem adapter: parser, registry, version scheme (semver / PEP 440), fix wording
  analyze.ts   orchestration
  cli.ts
```

Analyzers are pure functions over a `DependencyGraph` and fetched metadata. Adding an ecosystem means writing an adapter in `ecosystems.ts`: a parser, a registry fetcher and a version scheme. See [ROADMAP.md](ROADMAP.md).

## Privacy: what is sent where

dephealth reads your manifests and lockfiles locally and never uploads them. To check packages it sends **package names and versions** (and nothing else from your project) to these public services:

| Service | What for |
| --- | --- |
| [OSV.dev](https://osv.dev) (Google) | Known vulnerabilities |
| registry.npmjs.org, api.npmjs.org | Versions, publish dates, deprecations, weekly downloads |
| pypi.org, pypistats.org | The same for Python packages |
| [deps.dev](https://deps.dev) (Google) | Repository stats and OpenSSF Scorecard |
| api.github.com, gitlab.com | Archived flag and commit activity of each dependency's source repository |

Packages from a private scoped registry, git or local paths are never looked up (they're shown as *not assessed*). Your GitHub/GitLab tokens are only sent to their own hosts. Responses are cached on your machine for 24 hours (`--cache-dir`, `--no-cache`). If your dependency list itself is confidential, run dephealth only where you're comfortable sending package names to these services.

## Troubleshooting

* **`'dephealth' is not recognized` right after `npx @wylan24/dephealth`** inside a clone of the dephealth repo: npx uses the local copy there. Run it from your own project folder instead.
* **"Nothing was checked: there is no lockfile"**: dephealth reads lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `uv.lock`, `poetry.lock`, pinned requirements) or installed packages. Run `npm install` / `uv lock` / `poetry lock` first.
* **"Results are incomplete" / CI exits 2**: a service was unreachable or rate-limited. Check your connection and retry; partial results can be accepted with `--allow-incomplete`.
* **Behind a corporate proxy**: Node's `fetch` ignores `HTTPS_PROXY` unless you also set `NODE_USE_ENV_PROXY=1`, which recent Node 22 and 24+ releases support.
* **"GitHub API rate limit reached"**: set `GITHUB_TOKEN` (any token, no scopes needed); with the `gh` CLI: `GITHUB_TOKEN=$(gh auth token) npx @wylan24/dephealth`.
* **The first run is slow on a big monorepo** (a minute or two for hundreds of dependencies): responses are cached for 24 hours, so the next runs take seconds.
* **A finding is wrong for your project**: add an `ignore` entry with a reason (see [Configuration](#configuration)), and please [open an issue](https://github.com/wylan24/dephealth/issues) so the rule can be improved.

## Development

```bash
npm ci
npm test          # node:test, runs the TypeScript sources directly
npm run typecheck
npm run dev -- path/to/project
```

Tests never touch the network: [`test/mock-fetch.ts`](test/mock-fetch.ts) stubs `fetch`, the fetcher tests simulate npm, PyPI, OSV, GitHub, GitLab and deps.dev responses, and [`test/e2e.test.ts`](test/e2e.test.ts) runs the whole analysis on a mixed npm + Python fixture. CI also runs the GitHub Action itself against the repo and against a known-vulnerable fixture.

## License

MIT, see [LICENSE](LICENSE). Dependencies and the data sources dephealth queries have their own licenses and terms, listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
