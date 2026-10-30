# Roadmap

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Parse lockfiles (npm, pnpm, yarn; workspaces) and run the outdated and insecure checks | ✅ done |
| 2 | Abandonment signals and the combined multi-signal rule | ✅ done |
| 3 | Weight analysis: install size, duplicates, bundle size (esbuild), native-now | ✅ done |
| 4 | Replacement advisor: author notice → curated (e18e) → search candidates, with effort | ✅ done |
| 5 | Interactive HTML report, JSON output and CI mode | ✅ done |
| 6 | Second ecosystem: PyPI via `pyproject.toml` / `requirements*.txt` / `poetry.lock` / `uv.lock` + OSV | ⏳ next |

## Milestone 6: PyPI

* `parsers/pypi/`: produce the same `DependencyGraph` from `uv.lock`, `poetry.lock`, or pinned `requirements*.txt`; `pyproject.toml` for direct dependencies and groups (dev/optional).
* `fetchers/pypi.ts`: PyPI JSON API (`/pypi/<name>/json`) for release times, yanked flags and project URLs; `Development Status :: 7 - Inactive` classifier as a deprecation signal.
* OSV already supports the `PyPI` ecosystem; parameterise `OsvFetcher` by ecosystem.
* Version comparison via PEP 440 rather than semver.
* Native-now / replacement data for Python (e.g. `six`, `mock` → `unittest.mock`, `pytz` → `zoneinfo`, `toml` → `tomllib`).

## Later

* Reachability analysis for vulnerabilities (import graph + vulnerable symbol data from OSV `ecosystem_specific.imports` where available).
* A history mode: store each JSON report and chart libyear and score drift over time.
* SARIF output for GitHub code scanning.
* Bun (`bun.lock`) support.
