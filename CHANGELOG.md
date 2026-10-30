# Changelog

## Unreleased
- THIRD_PARTY_NOTICES.md (dependency licenses and data-source terms); the HTML report credits OSV.dev, deps.dev and OpenSSF Scorecard.
- Release workflow waits for a just-published version to finish npm's processing before deciding to publish.

## 0.4.0

**Results you can trust when something goes wrong**
- If OSV.dev or a registry is unreachable, or nothing could be resolved (no lockfile and nothing installed), the report now says the results are **incomplete** and `--ci` exits `2` instead of passing. Previously an offline run could report "0 vulnerabilities" and pass CI. `--allow-incomplete` accepts partial results.
- A malformed answer from OSV.dev is an error rather than "no vulnerabilities"; an advisory whose details can't be loaded is kept with unknown severity instead of being dropped.
- Repeated per-package warnings are grouped into one line.

**Easier to install and use**
- esbuild is now an optional peer dependency (only `--bundle` needs it, and it uses your project's copy). Installs are about 10 MB smaller and no longer trigger npm's install-script warning.
- Clear messages for unknown options, a too-old Node.js, and running outside a project folder.
- README: quick start, privacy (what is sent where), troubleshooting. Added SECURITY.md and an issue template.
- CI now runs on Linux, macOS and Windows and tests the published Action tag.

## 0.3.1 — first npm release
- Published as `@wylan24/dephealth` (the unscoped name belongs to another package); release workflow with npm provenance.

## 0.3.0
- SARIF output (`--sarif`) anchored to the line that declares each dependency; reusable GitHub Action (`wylan24/dephealth@v0`).
- GitLab repository signals, including nested groups.
- Test suite with simulated network responses and an end-to-end test.
- `@types/node` pinned to your minimum Node major is no longer "outdated".

## 0.2.1
- Tuned against 10 real projects: pnpm 10 lockfiles, batched npm download counts, activity-gated abandonment rules, recently archived repos, type stub packages.

## 0.2.0
- Python support: `pyproject.toml`, `uv.lock`, `poetry.lock`, pinned requirements, `.venv`; PEP 440 versions; PyPI and OSV.

## 0.1.0
- npm, pnpm and yarn lockfiles; insecure, abandoned, outdated and weight checks; replacement suggestions; HTML/JSON reports; CI mode.
