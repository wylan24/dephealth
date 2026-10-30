# Releasing

dephealth is published to npm as [`@wylan24/dephealth`](https://www.npmjs.com/package/@wylan24/dephealth); the command it installs is `dephealth`. (The unscoped name `dephealth` belongs to an unrelated package.)

## First release (once, by hand)

The package has to exist on npm before automated publishing can be set up.

1. Make sure your npm username is `wylan24`, or change the scope in `package.json` to your npm username or an npm organisation you own.
2. Log in and publish from a clean checkout of `main`:

   ```bash
   npm login
   npm publish
   ```

   `prepublishOnly` typechecks, runs the tests and builds `dist/` first, and `publishConfig` makes the scoped package public. (Provenance is only added by the release workflow, since it can only be generated in CI.)

3. Check it: `npx @wylan24/dephealth --version`.
4. Tag that version so the release workflow creates the GitHub release and moves the `v0` Action tag (it sees the version is already on npm and skips publishing):

   ```bash
   git tag v0.3.1
   git push origin v0.3.1
   ```

## Automated releases after that

`.github/workflows/release.yml` publishes when a version tag is pushed, with npm provenance (a signed link from the package to the exact commit and workflow that built it). Pick one way to authenticate:

* **Trusted publishing (recommended, no secret to leak):** on npmjs.com open the package → *Settings* → *Trusted publishing* → add GitHub Actions with repository `wylan24/dephealth`, workflow `release.yml`, environment `npm`.
* **Or a token:** create an npm *granular access token* with publish rights for this package and add it to the repository as the `NPM_TOKEN` secret (*Settings → Secrets and variables → Actions*).

Then, for each release:

```bash
npm version minor          # or patch / major: bumps package.json and creates the v-tag
git push origin main --follow-tags
```

The workflow checks that the tag matches `package.json`, publishes to npm, creates a GitHub release with generated notes, and moves the major tag (`v0`, `v1`, …) that `uses: wylan24/dephealth@v0` points to.

## GitHub Marketplace (optional)

`action.yml` already has a name, description and branding. To list the Action, open a GitHub release, tick *Publish this Action to the GitHub Marketplace*, and accept the Marketplace agreement (required once per account).
