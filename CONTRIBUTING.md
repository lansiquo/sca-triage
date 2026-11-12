# Contributing

sca-triage is plain Node.js (20 or newer) with no dependencies, so there is nothing to install
before you work on it. [ARCHITECTURE.md](ARCHITECTURE.md) describes the components and the rules
the code keeps. Report a vulnerability in the tool privately, as [SECURITY.md](SECURITY.md) says,
not in a public issue.

## Run from a clone

To run it from a clone, use `node sca-triage/bin/sca-triage.js` in place of `npx sca-triage`:

```bash
git clone https://github.com/lansiquo/sca-triage.git
node sca-triage/bin/sca-triage.js --version
```

## Tests

Run both in the clone:

```bash
npm test
npm run test:pack
```

- `npm test` runs every `test/*.test.js` with `node --test`. `test/npm-integration.test.js` runs
  `fix` with real npm against a registry it starts on this machine.
- `npm run test:pack` packs the package, installs it in a throwaway project and runs it there. It
  also checks the docs in the package, which are what npm shows: no README `bash` block runs the
  tool from a clone path such as `node sca-triage/bin/sca-triage.js`, every pinned `@vX.Y.Z`
  matches `package.json`, the README usage block matches `--help`, and CHANGELOG.md has an entry
  and a link for the version.
- CI runs both on Node.js 20, 22 and 24 on Linux, macOS and Windows. It also runs the GitHub Action
  itself on a clean project and on a vulnerable one.
- CI also scans the code with [sast-triage](https://github.com/lansiquo/sast-triage): a pull
  request fails only on a P1 finding it adds, and a push to `main` fails on any P1 in a full scan.

## Releases

Versions after 1.3.0 are published to npm from GitHub by the
[publish workflow](.github/workflows/publish.yml), when their GitHub release is published. It packs
the commit of the release tag and publishes that tarball with npm trusted publishing, so no npm
token is stored, and with [provenance](https://docs.npmjs.com/generating-provenance-statements):
npm shows the commit and the workflow run a version was built from. Releases are published one at
a time.

Drafts, prereleases and releases whose tag is not `vX.Y.Z` (SemVer, no leading zeros) are skipped.
Publishing is refused, and the run fails with nothing published, when:

- the tag no longer points at the commit of the release, or `package.json` has another name or
  version than the tag;
- npm on the runner is older than 11.5.1, a test fails, or the tests leave the checkout changed;
- the registry does not say whether the version is published, or the version is already on npm
  with other contents (with the same contents the run passes and publishes nothing);
- npm's `latest` version cannot be read, is not `X.Y.Z`, is not one of the published versions, or
  is not lower than the release. So an older version never becomes `latest`, and a package that is
  not on npm yet cannot be published this way;
- an earlier publication is still running after an hour.

After publishing, the run fails if npm does not serve the same tarball as `latest` within three
minutes.

The workflow then moves the `v1` tag to the release, only forwards and only for 1.x versions. If
GitHub refuses that push, the job fails after the npm release is complete and prints the command
that moves `v1` by hand.
