# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.2.3] - 2026-11-09

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
  dependency with no version in the lockfile is skipped with a warning.
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

[Unreleased]: https://github.com/lansiquo/sca-triage/compare/v1.2.2...HEAD
[1.2.2]: https://github.com/lansiquo/sca-triage/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/lansiquo/sca-triage/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/lansiquo/sca-triage/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/lansiquo/sca-triage/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/lansiquo/sca-triage/releases/tag/v1.0.0
