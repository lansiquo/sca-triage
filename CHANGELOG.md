# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Reject missing option values, invalid priorities, malformed lockfiles and advisories without valid severity.
- Preserve optional, peer, dual-field and aliased dependency declarations during upgrades.
- Qualify parent overrides by version, reject conflicting/unsafe scopes and retain nested override rules.
- Resolve imports to installed copies, including hoisted transitive dependencies and workspace boundaries.
- Scan long import/export declarations without fixed length limits; keep dense source scanning linear.
- Drain large CLI output completely and sanitize terminal control characters in errors.
- Persist recovery evidence before mutation and after failed post-install verification.
- Capture large npm/test logs without the default pipe buffer limit; separate SBOM JSON from diagnostics.
- Reject multi-target scoped override plans on npm older than 11.9.0 before mutation; npm 10 can collapse them to one incorrect version.
- Confirm applied upgrade targets before reporting success; exclude unconfirmed candidates from auto-fixing.

### Release checks

- Add regression tests for all 16 audit findings and real npm integration scenarios.
- Include linked documentation and repository metadata in the npm package.
- Test packed consumers and Node 20/22/24 across Linux, macOS and Windows in CI.

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
