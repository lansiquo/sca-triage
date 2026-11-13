# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Releases: a GitHub workflow now publishes each stable release to npm when its GitHub release is
  published, with npm trusted publishing (no stored token) and provenance, so npm shows the commit
  a version was built from. Stable means a `vX.Y.Z` tag (SemVer, no leading zeros) that is not a
  draft or prerelease. A version is published only if it is higher than npm's `latest`, and it is
  refused when `latest` cannot be read. The workflow then moves the `v1` tag to the release, only
  forwards and only for 1.x versions; if GitHub refuses that push, the job fails and prints the
  command that moves `v1` by hand. [W-sca-triage-11]

### Fixed
- README: rewritten for new users. It opens with the problem and a quick start, says each thing
  once instead of repeating this changelog, and corrects statements that were wrong: registry
  responses are retried for 429, 500, 502, 503 and 504, for example, not for every 5xx. The
  release checks and how to run from a clone moved to a new CONTRIBUTING.md, which also covers the
  tests; internal detail moved to ARCHITECTURE.md. [W-sca-triage-13]
- Tests: the hostile-input (no ReDoS) test no longer fails on a slow or busy CI runner. It required
  the scan to finish in under 1000 ms and took 1150 ms on one Windows runner for a README-only
  commit. It now checks growth instead: 4 times the input must take well under 8 times as long
  (linear is about 4, quadratic 16), so a real slowdown still fails it. [W-sca-triage-16]

## [1.3.0] - 2026-11-12

Compatibility: gate results and `fix` command behavior can change in 1.3.0. Major upgrades
are held unless `--allow-major` is passed; name-loaded production dependencies now count as
loaded, and config-only development tools no longer rank P1. Consumers of JSON findings
should accept the `named` and `config-only` reachability levels. Review gate expectations
and planned upgrades before updating.

### Changed
- `plan` and `fix` no longer apply major upgrades by default. They list them under "Major upgrades,
  not applied without --allow-major"; pass `--allow-major` to apply them. A project's tests were
  the only guard against a breaking major upgrade, and many projects test too little for that.
- `fix` installs the direct upgrades first, rescans, and writes npm overrides only for the copies
  that are still vulnerable. An upgraded dependency often brings safe copies itself, and an
  override stays in `package.json` for good, so `fix` no longer writes ones that aren't needed. It
  lists the planned overrides it skipped.

### Fixed
- Ranking: a production dependency loaded by name, like a view engine Express loads with
  `app.set('view engine', 'ejs')`, was "not imported", so a critical advisory in it ranked P2 and
  passed the default gate. A string in runtime code that is exactly the name of a direct
  production dependency now counts as loaded (level `named`).
- Ranking: a development-only package that only tool config files load, like `vite` in
  `vite.config.js`, was "imported" and ranked P1. It is now `config-only`, which doesn't count as
  loaded. A config file that loads a production package still counts as runtime code.

### Security
- Reachability: `/*` or `//` in JSX text, like `<code>src/*.js</code>`, was read as the start of a
  comment, so imports after it could be missed and a vulnerable package could rank below the
  default gate. An import after such text is now found whenever the same import is found without
  it: `import`, `require`, `import()`, template literals and `createRequire` aliases of any name.
  After a comment that might be JSX text, anything that looks like an import or require counts as
  loaded, even inside a comment or a string (GHSA-vgjq-gfc7-fjvv) [W-sca-triage-4]

## [1.2.4] - 2026-11-10

### Fixed
- README: the "Fix your own project" steps still ran the tool from a clone
  (`node sca-triage/bin/sca-triage.js`). They now use `npx sca-triage`, like the rest of the README.
- ARCHITECTURE.md: the diagram, component table and evidence list now include the install check,
  manual upgrades, the stricter lockfile checks and the snapshot and command files.
- CHANGELOG.md: the version links at the bottom include 1.2.3 and 1.2.4.

No code changes.

### Added
- The packed-package check in CI also checks the docs: README commands use `npx`, pinned versions
  match `package.json`, the usage block matches `--help`, and the changelog has this version.

## [1.2.3] - 2026-11-10

### Fixed
- **Advisory ranges with partial versions.** Real advisories use ranges like `>=13.0 <14.2.30`
  (`next`) and `>0 <=5.10.9` (`tinymce`). They couldn't be read, so every upgrade counted as
  vulnerable and those packages showed "no fixed version published". They are now read the way npm
  reads them, and so are hyphen ranges.
- **Imports in comments counted.** A commented-out `require` counted as an import. In OWASP
  NodeGoat, `helmet` is commented out, so `debug@2.2.0` "via helmet" was a false P1 (NodeGoat now
  has 12 P1, not 13).
- **Reachability.** Imports are tied to the installed copy they load and followed through its
  dependencies, including packages imported without being declared, hoisted copies and workspaces.
  A test folder that links to source code no longer makes that code test-only. Files over 2 MB,
  which aren't read, are named in a warning. Long import lists and files with many imports no
  longer slow the scan down quadratically. In `.vue`, `.svelte` and `.astro` files only the script
  blocks are read as code, and text the scanner can't read reliably is searched for imports
  anyway, so it leans toward "loaded".
- **Lockfile and advisory checks.** A malformed lockfile, one missing a declared dependency, an
  entry whose name or version doesn't match its registry tarball, or an advisory with a missing or
  unknown severity is now an error (exit 2) instead of a quieter scan. Lockfiles written with
  `--legacy-peer-deps` and `file:` folders outside the project still load. A git, file or URL
  dependency with no version in the lockfile is skipped with a warning, and imports through it
  still count for what it depends on.
- **Pre-release versions.** Advisory ranges are matched the way `npm audit` matches them, so a
  pre-release such as `1.0.0-alpha.4` is inside `>0 <=5.10.9`.
- **Option values.** `fix --min-priority --dry-run`, with the value missing, took `--dry-run` as the
  priority and applied the upgrades. A missing value or unknown priority is now a usage error
  before anything runs.
- **Dependency types.** Pins keep each dependency's type, including optional and peer dependencies
  and names listed in two fields. With `--save-prod`, npm moved an optional dependency to
  `dependencies` and kept the old version. Aliases (`"x": "npm:y@1"`) stay aliases.
- **Overrides that reached too far.** An override could also change copies outside the plan,
  including safe ones (one test project ended up with a dependency forced down a major version),
  and two versions of a parent that needed different targets let the last one win. `fix` now
  writes an override only when it reaches nothing else, lists the other upgrades as "needs a manual
  upgrade" with the reason, and applies the rest. Existing nested overrides are kept.
- **Local packages.** A dependency declared by a local `file:` package that isn't a workspace made
  `fix` run `npm install --workspace`, which failed and rolled back every upgrade. It is now
  listed as a manual upgrade and the others are applied.
- **Install check.** After installing, `fix` checks that every package that used a planned copy now
  gets the safe version, before the tests run. If npm installed anything else, everything is
  rolled back.
- **`.npmrc`.** A project's `.npmrc` could make npm run another program as `git`, even with
  `--no-tests`. `fix` now always uses the system `git`.
- **Evidence.** The baseline scan, snapshots and npm commands are written before anything changes
  and kept when the final rescan fails. A symlinked default `evidence/` folder is refused. Large test
  logs are captured in full, and the SBOM file contains only npm's JSON. A target not confirmed
  against the registry after 5 lookups is no longer applied automatically.
- **Output.** Output piped to another program was cut off at 64 KB. Error messages are cleaned of
  terminal control characters, and the Action stops workflow commands while the scan prints, so
  names from the scanned project can't add annotations to the log.

### Added
- Published to npm: run it with `npx sca-triage` or install it with `npm install -g sca-triage`.
  The README uses `npx` in its examples.
- `sca-triage --version`. The default `evidence/` folder gets a `.gitignore`.
- MIT license, and package metadata for the npm page: author, repository, homepage and issue
  tracker. ARCHITECTURE.md, CHANGELOG.md and SECURITY.md are in the package.
- Regression tests for each fix, tests that run `fix` with real npm against a local registry, a
  packed-package check, and CI on Node 20, 22 and 24 on Linux, macOS and Windows. CI also runs the
  GitHub Action itself on a clean project and on a vulnerable one.

## [1.2.2] - 2026-11-09

### Fixed
- **Bundled dependencies.** A vulnerable copy that ships inside another package's tarball can't be
  changed by npm overrides, but `plan` and `fix` used to propose overrides for it anyway. Those
  copies now get no pin or override: `scan` shows `bundled in <package>: upgrade <package>`, and
  `plan` and `fix` list them grouped by the package to upgrade. A copy bundled by the project
  itself is still fixed normally.

### Added
- This changelog.
- README: a step-by-step guide to running `fix` on your own project.

## [1.2.1] - 2026-11-09

### Fixed
- **`fix` replaces old copies that npm left behind.** npm keeps a locked nested copy that an
  override rejects and lists it as invalid. `fix` now removes those lockfile entries before
  installing, so npm resolves them again.
- **Pinned direct dependencies reach every parent.** When a package requires an exact older
  version of a dependency that `fix` pins (for example `express` requiring `body-parser` 1.18.3),
  `fix` adds a scoped override so that copy is upgraded too.

On OWASP NodeGoat, one `fix --min-priority P1` run now leaves 1 P1 finding (swig, which has no
fixed release) instead of 3.

### Added
- `ARCHITECTURE.md`: components, ranking, upgrade planning, trust boundaries and failure handling.
- README: OWASP NodeGoat as the worked example (scan, plan, fix and rescan).

### Removed
- The intentionally vulnerable lab app, `npm run lab` and the CI job that scanned the lab on every
  push. CI runs the unit tests on Node 20 and 22.

## [1.2.0] - 2026-11-09

### Changed
- Triage looks up published versions for vulnerable packages 8 at a time instead of one by one.
- `fix` runs one `npm install` per manifest and dependency type instead of one per package.
  `REPORT.md` lists each install command as it ran, and the CLI says how many packages were
  upgraded.

### Fixed
- Registry requests retry network errors, timeouts, 429 and 5xx responses (3 attempts, honouring
  `Retry-After`) before failing.
- If an install fails before the post-upgrade tests, `package.json`, any workspace manifests it
  pinned and `package-lock.json` are restored, `REPORT.md` records the failed command, and the CLI
  exits 2. Run `npm ci` afterwards, since `node_modules` is not restored. Failing tests after a
  clean upgrade still keep the changes.

## [1.1.0] - 2026-11-09

### Added
- `plan`: a dry run that shows the upgrades and changes nothing. `fix --dry-run` is the same.
- `npm run lab`: the whole lab in one command (removed in 1.2.1).

### Changed
- **Breaking:** `fix` on its own now applies the upgrades; in 1.0.0 it was a dry run. Use `plan`
  to preview. `fix --apply` still works.

### Fixed
- Upgrade targets are checked against advisories that affect newer versions. A target could have
  its own advisory (for example `moment` 2.29.1 → 2.29.4); it now picks the smallest version
  outside every range (2.31.0).
- Reachability traces aliased packages, workspaces and peer dependencies, and detects more import
  forms (Vue, Svelte, Astro, extensionless scripts, template-literal `require`, `createRequire`).
- Fix planning gives each copy its own target on its release line, and nested vulnerable copies
  get scoped `overrides`.
- Hardening: bounded import patterns, the registry must be HTTPS (or localhost), malformed
  registry responses fail closed, report text is escaped, and a package named `constructor` no
  longer crashes the scan.
- CLI: a second directory is a usage error (exit 2) instead of being ignored, `--help` exits 0,
  and when tests already failed before the upgrade, `fix` says so.

## [1.0.0] - 2026-11-05

### Added
- `scan`: reads `package-lock.json` and checks every installed package against the GitHub
  Advisory Database, via the npm registry, then ranks each vulnerable package P1–P3 by severity
  and whether your code loads it. Fails CI on P1 by default (`--fail-on P1`).
- `fix`: shows the smallest safe upgrade for each finding; with `--apply` it applies them, runs
  your tests, rescans and saves the evidence (a report, before and after JSON, both lockfiles,
  both test logs and a CycloneDX SBOM).
- GitHub Action (`lansiquo/sca-triage@v1`).
- A lab app with known-vulnerable dependencies (`lab/`) to try it on (removed in 1.2.1).

[Unreleased]: https://github.com/lansiquo/sca-triage/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/lansiquo/sca-triage/compare/v1.2.4...v1.3.0
[1.2.4]: https://github.com/lansiquo/sca-triage/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/lansiquo/sca-triage/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/lansiquo/sca-triage/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/lansiquo/sca-triage/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/lansiquo/sca-triage/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/lansiquo/sca-triage/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lansiquo/sca-triage/releases/tag/v1.0.0
