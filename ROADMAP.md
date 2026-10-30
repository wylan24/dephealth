# Roadmap

| # | Milestone | Status |
| --- | --- | --- |
| 1 | Parse lockfiles (npm, pnpm, yarn; workspaces) and run the outdated and insecure checks | ✅ done |
| 2 | Abandonment signals and the combined multi-signal rule | ✅ done |
| 3 | Weight analysis: install size, duplicates, bundle size (esbuild), native-now | ✅ done |
| 4 | Replacement advisor: author notice → curated (e18e) → search candidates, with effort | ✅ done |
| 5 | Interactive HTML report, JSON output and CI mode | ✅ done |
| 6 | Second ecosystem: PyPI via `pyproject.toml` / `uv.lock` / `poetry.lock` / `requirements*.txt` / `.venv` + OSV | ✅ done |

## Done since

* Mocked-network test suite and an end-to-end test; CI runs the GitHub Action itself.
* SARIF output and a reusable GitHub Action (code scanning, job summary, HTML artifact).
* GitLab repository signals (archived, activity, stars, issues), including nested groups.

## Later

* Publish to npm (`npx dephealth`) and the GitHub Marketplace.
* Codeberg/Gitea and Bitbucket repository signals.

* `pylock.toml` (PEP 751) and `Pipfile.lock`.
* Python bundle/install size (wheel sizes per platform) and a larger standard-library replacement list.
* Reachability analysis for vulnerabilities (import graph + vulnerable symbol data from OSV `ecosystem_specific.imports` where available).
* A history mode: store each JSON report and chart libyear and score drift over time.
* Bun (`bun.lock`) and Cargo / Go modules as further ecosystems.
