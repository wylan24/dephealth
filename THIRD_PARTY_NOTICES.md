# Third-party notices

dephealth itself is released under the [MIT License](LICENSE). It uses the software and data below, each under its own license. None of the third-party code is copied into the dephealth package; npm installs each dependency separately together with its own license file.

## Runtime dependencies

| Package | License | Used for |
| --- | --- | --- |
| [yaml](https://github.com/eemeli/yaml) | ISC | Reading `pnpm-lock.yaml` and yarn Berry lockfiles |
| [semver](https://github.com/npm/node-semver) | ISC | npm version ranges and comparisons |
| [smol-toml](https://github.com/squirrelchat/smol-toml) | BSD-3-Clause | Reading `pyproject.toml`, `uv.lock`, `poetry.lock` |
| [@yarnpkg/lockfile](https://github.com/yarnpkg/yarn/tree/master/packages/lockfile) | BSD-2-Clause | Reading yarn classic lockfiles |
| [module-replacements](https://github.com/e18e/module-replacements) (e18e) | MIT | npm "native now" and replacement suggestions |
| [esbuild](https://github.com/evanw/esbuild) (optional peer, `--bundle` only) | MIT | Measuring browser bundle sizes |

The GitHub Action additionally uses `actions/setup-node`, `actions/upload-artifact` and `github/codeql-action` (MIT) at run time.

## Curated data in this repository

`data/replacements.json` and `data/pypi-replacements.json` were written for dephealth and are covered by its MIT license. `data/replacements.json` adds effort ratings and extra entries *on top of* the e18e dataset, which is read from the `module-replacements` package at run time rather than copied.

## Data fetched at run time

dephealth doesn't ship any third-party data: it queries these services when it runs, and shows parts of their responses (advisory titles and IDs, repository statistics) in its reports, with links back to the source. That data stays under its providers' terms:

| Source | Data | Terms |
| --- | --- | --- |
| [OSV.dev](https://osv.dev) | Vulnerability advisories, aggregated from databases such as the [GitHub Advisory Database](https://github.com/github/advisory-database) (CC BY 4.0) and the [PyPA Advisory Database](https://github.com/pypa/advisory-database) (CC BY 4.0) | Each record keeps its source database's license; see [OSV data sources](https://google.github.io/osv.dev/data/) |
| [deps.dev](https://deps.dev) | Repository statistics and [OpenSSF Scorecard](https://securityscorecards.dev) results | CC BY 4.0, per the deps.dev API documentation |
| npm registry, PyPI, pypistats.org, GitHub API, GitLab API | Package metadata, download counts, repository activity | Each service's terms of use |

If you publish dephealth reports (for example the HTML report from a public CI run), keep the advisory links and the "Data from" line at the bottom of the report, which provide the attribution these licenses ask for.
