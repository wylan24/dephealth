# Roadmap

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Parse lockfiles (npm, pnpm, yarn; workspaces) and run the outdated and insecure checks | ✅ done |
| 2 | Abandonment signals and the combined multi-signal rule | ✅ done |
| 3 | Weight analysis: install size, duplicates, bundle size (esbuild), native-now | ✅ done |
| 4 | Replacement advisor: author notice → curated (e18e) → search candidates, with effort | ✅ done |
| 5 | Interactive HTML report, JSON output and CI mode | ✅ done |
| 6 | Second ecosystem: PyPI via `pyproject.toml` / `uv.lock` / `poetry.lock` / `requirements*.txt` / `.venv` + OSV | ✅ done |

## Later

* `pylock.toml` (PEP 751) and `Pipfile.lock`.
* Python bundle/install size (wheel sizes per platform) and a larger standard-library replacement list.
* Reachability analysis for vulnerabilities (import graph + vulnerable symbol data from OSV `ecosystem_specific.imports` where available).
* A history mode: store each JSON report and chart libyear and score drift over time.
* SARIF output for GitHub code scanning.
* Bun (`bun.lock`) and Cargo / Go modules as further ecosystems.
