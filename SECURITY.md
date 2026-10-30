# Security policy

## Reporting a vulnerability in dephealth

Please report security problems privately through GitHub: on this repository open **Security → Report a vulnerability** ([direct link](https://github.com/wylan24/dephealth/security/advisories/new)). Don't open a public issue for them.

You'll get a reply within a week. Fixes are released as a new npm version and noted in [CHANGELOG.md](CHANGELOG.md).

Things that count as security problems here include: the HTML report executing content from a registry or advisory (it is built to treat all of that as untrusted text), tokens being sent anywhere other than their own host, dephealth executing code from the project it checks, or a result that reports "no vulnerabilities" when the vulnerability check did not actually run.

## Vulnerabilities dephealth reports in *your* dependencies

dephealth only reports advisories published in [OSV.dev](https://osv.dev). If you think an advisory is wrong or missing, that belongs with the advisory database (e.g. the GitHub Advisory Database or PyPA advisory database), not here.

## Supported versions

Only the latest release on npm gets fixes.
