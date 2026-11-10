# sca-triage

A dependency-free SCA scanner for npm projects, run from the command line or as a GitHub Action.
It finds known vulnerabilities in the tree locked in `package-lock.json`, ranks them by severity
and by whether your code loads the vulnerable package, applies the smallest safe upgrades, and
checks them with your project's own tests.

`npm audit` reports every advisory with the same urgency. `sca-triage` uses the same advisory data
(the GitHub Advisory Database, via the npm registry) and adds the triage: what to fix now, what to
schedule, and evidence that the fix didn't break anything. Its SAST companion,
[sast-triage](https://github.com/lansiquo/sast-triage), ranks Semgrep findings P1–P3 the same way.

## Example: OWASP NodeGoat

I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Node.js app
with 1,479 locked packages. The results below are from its latest commit, `c5cb68a` (June 2023).
It needs Node.js 20 or newer and access to `registry.npmjs.org`. `scan` and `plan` only read its
lockfile and source; `fix` installs its dependencies with install scripts disabled, and none of
NodeGoat's code runs. From any folder:

```bash
git clone https://github.com/OWASP/NodeGoat.git
npx sca-triage scan NodeGoat                    # ranked findings
npx sca-triage plan NodeGoat --min-priority P1  # dry run: the P1 upgrades
cp -r NodeGoat NodeGoat-fixed
npx sca-triage fix NodeGoat-fixed --min-priority P1 --no-tests --evidence evidence
npx sca-triage scan NodeGoat-fixed              # rescan
```

The P1 findings, condensed to one line each (the tool prints a few lines per finding; counts and
versions follow the advisory database at scan time):

```text
owasp-nodejs-goat: 1479 packages scanned, 180 vulnerable (P1: 12, P2: 122, P3: 46)

[P1] bson@1.0.9            CRITICAL  via mongodb                         fix: 1.1.4 (override)
[P1] minimist@0.0.10       CRITICAL  via swig                            fix: 0.2.4 (major, override)
[P1] proxy-addr@2.0.4      CRITICAL  via express                         fix: 2.0.8 (override)
[P1] underscore@1.9.1      CRITICAL  imported (config/config.js:1)       fix: 1.13.8
[P1] body-parser@1.18.3    HIGH      imported (server.js:5)              fix: 1.20.9
[P1] marked@0.3.5          HIGH      imported (server.js:13)             fix: 4.0.10 (major)
[P1] mongodb@2.2.36        HIGH      imported (artifacts/db-reset.js:9)  fix: 3.1.13 (major)
[P1] path-to-regexp@0.1.7  HIGH      via express                         fix: 0.1.13 (override)
[P1] qs@6.5.2              HIGH      via express                         fix: 6.16.1 (override)
[P1] semver@5.6.0          HIGH      via mongodb                         fix: 5.7.2 (override)
[P1] swig@1.4.2            HIGH      imported (server.js:9)              fix: none published
[P1] uglify-js@2.4.24      HIGH      via swig                            fix: 2.6.0 (override)

… 122 P2 and 46 P3 findings omitted

Gate (--fail-on P1): FAIL
```

The scan matches 437 advisories across 180 vulnerable packages and narrows "fix now" to 12 P1
packages the app loads, either directly or through an imported dependency such as `express` or
`mongodb`. `plan` lists 7 upgrades for them: 2 direct dependencies pinned with `npm install` and 5
transitive packages fixed with npm `overrides`. `express` requires `body-parser` 1.18.3 exactly, so
it also gets an override for the new version. Three have only a major upgrade (`marked` 0.3.5 to
4.0.10, `mongodb` 2.2.36 to 3.1.13, `minimist` 0.0.10 to 0.2.4), so `plan` lists them for review
and `fix` applies them only with `--allow-major`. Two are left for you: `swig` has no fixed release,
so it needs replacing rather than upgrading, and
`qs` needs a manual upgrade, because the override that would reach it (`"request" > "qs"`) would
also force `zaproxy`'s `qs` 0.6.6 up to 6.16.1, a major jump nobody asked for.

The example passes `--min-priority P1`, so `fix` upgrades only P1 packages: the ones the app loads,
which are the ones to fix now. Of the other 168 findings, 130 are in development-only packages such
as build and test tools, 61 are bundled inside other packages, which overrides can't change, and 10
have no fixed release. These groups overlap: a development-only package can also be bundled.
Without `--min-priority`, `fix` works through every priority.

`fix` installs the 2 pins, rescans, writes the overrides still needed, and confirms all 7 upgrades
in the new lockfile. NodeGoat's `npm test` runs no tests (its unit-test folder doesn't exist), so
the run uses `--no-tests` and the report marks the upgrades unverified. The rescan finds 173
vulnerable packages and 5 P1: the three majors, `swig` and `qs`. With `--allow-major`, `fix` also
applies the majors; `mongodb` 3.1.13 brings a safe `bson`, so that override isn't written, and the
rescan finds 170 vulnerable packages and 2 P1. Counts follow the advisory database and the versions
npm installs at the time, so a new run can differ slightly. The
[case study](https://dotrobin.dev/sca-triage.html) shows the full output of each step from
version 1.2.3.

## Use it on your project

Requires Node.js 20 or newer and access to `registry.npmjs.org`. A scan reads `package.json` and
`package-lock.json`, workspace manifests and source files; it does not need `node_modules`.
Registry timeouts, network errors, 429 and 5xx responses are retried (3 attempts, honouring
`Retry-After`) before a registry error.

```bash
npx sca-triage scan /path/to/project   # ranked findings
npx sca-triage plan /path/to/project   # dry run: planned upgrades
npx sca-triage fix  /path/to/project   # upgrade, test, rescan
```

`npx` downloads sca-triage from npm the first time and asks before it does. To install it instead,
run `npm install -g sca-triage` and drop the `npx`. To run it from a clone, use
`node sca-triage/bin/sca-triage.js` in place of `npx sca-triage`.

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage plan [dir] [--min-priority P1|P2|P3] [--allow-major]
sca-triage fix  [dir] [--min-priority P1|P2|P3] [--allow-major] [--evidence <dir>] [--no-tests]
sca-triage --version
```

`--json` prints the full result; `--markdown <file>` also writes the findings table as Markdown.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 22
- uses: lansiquo/sca-triage@v1.2.4
  with:
    path: .        # directory with package.json and package-lock.json
    fail-on: P1    # P1, P2, P3 or none
```

Both inputs are optional (defaults shown). The step fails when the gate fails and adds the findings
table to the job summary. No dependency install is needed. Pin a release tag such as `@v1.2.4`,
or a full commit SHA for the strictest supply-chain safety.

## How ranking works

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

Each finding gets a reachability level:

- `imported`: your runtime code requires or imports it.
- `named`: your runtime code names a production dependency in a string, as Express does to load a
  view engine (`app.set('view engine', 'ejs')`). Counts as loaded.
- `via-imported`: an imported or named dependency pulls it in.
- `config-only`: a development-only package loaded only by tool config files such as
  `vite.config.js`. Doesn't count as loaded.
- `test-only` or `not-imported`.

The check covers `require`, `import`, dynamic `import()` and `createRequire()` across JS, TS,
JSX/TSX, Vue, Svelte and Astro sources, and follows workspaces and aliased packages.

## Fix your own project

`fix` edits your project, so start from a clean git working tree. It runs your `npm test` before
and after upgrading, so use it only on projects whose tests you trust.

1. **Preview.** Lists each upgrade and changes nothing (`fix --dry-run` does the same):

   ```bash
   npx sca-triage plan /path/to/project
   ```

2. **Apply.** Upgrades, runs your tests, rescans and saves an evidence folder:

   ```bash
   npx sca-triage fix /path/to/project
   ```

   - `--min-priority P1` fixes only P1 findings. By default every priority is fixed.
   - `--allow-major` also applies major upgrades. Without it, `plan` and `fix` list them for you
     to review first.
   - `--no-tests` skips the tests; the upgrades are then marked **unverified**. A project with no
     `test` script gets the same.
   - `--evidence <dir>` saves the evidence elsewhere (default `<project>/evidence/<timestamp>`).

3. **Check the result.** The last lines show whether your tests passed after the upgrade and how
   many vulnerable packages are left. `REPORT.md` in the evidence folder lists the findings before
   and after, every change and both test runs.

4. **Keep or undo.** Review the changes with `git diff`, then commit them. To undo, restore the
   files and reinstall (also restore any workspace `package.json` that changed):

   ```bash
   git restore package.json package-lock.json
   ```

   ```bash
   npm ci
   ```

If an install fails, `fix` puts `package.json` and `package-lock.json` back itself and exits with
code 2; run `npm ci` to reset `node_modules`. If your tests fail after the upgrade, the changes stay
so you can see what broke, and it exits with code 1.

### What `fix` changes

1. Runs `npm test` for a baseline.
2. Pins each vulnerable direct dependency to its safe version with
   `npm install name@version --save-exact`, preserving production, development, optional and peer
   declarations. Multiple declarations are updated in place, retaining peer metadata and aliases.
3. Rescans, then fixes the vulnerable packages your dependencies still pull in with npm
   `overrides` in `package.json`, scoped to the packages that require them. An upgraded dependency
   often brings safe copies itself, and an override stays in `package.json` until you remove it,
   so `fix` only writes the ones still needed. A package that requires a version the pin excludes
   gets an override too, and existing overrides are kept. Old nested copies the overrides cover are
   removed from `package-lock.json` first, so npm installs the new version instead of keeping the
   old one.
4. Installs with `--ignore-scripts`, so no install scripts run.
5. Checks the new `package-lock.json`: every manifest that declared a pinned package, and every
   package that used a copy an override targets, must now get the safe version. If npm installed
   anything else, everything is rolled back and the tests don't run.
6. Runs `npm test` again and rescans. If the tests also failed in the baseline run, the output says
   so, since the failure may not be caused by the upgrade.
7. Records the baseline scan and original manifests/lockfile before mutation. The evidence folder
   contains `REPORT.md`, `before.json`, `after.json` (after a successful rescan), `before/` and `after/`
   snapshots, both lockfiles, test logs, `commands.txt`, and a CycloneDX SBOM when npm can generate it.
   SBOM stderr is saved separately; malformed JSON is never saved as an SBOM.

Some upgrades are left for you. An npm override applies to every version of the package it is
scoped to and to everything below it, so `fix` doesn't write one that would also change other
copies (an already-safe copy on another major version, say) or that would need two versions under
one key. `plan` and `fix` list those as **Needs a manual upgrade**, with the reason, and apply the
rest. The same goes for a dependency declared by a local `file:` package that isn't a workspace:
npm can't install into it, so you change the version there. Copies bundled inside another package
are listed under the package to upgrade.

Without `--evidence`, the evidence goes to `evidence/<timestamp>/` in the project, with a
`.gitignore` so reports and test logs stay out of your commits.

If the final rescan fails (the registry is down, say), `fix` exits 2 and keeps the tested changes,
with the evidence and snapshots needed to review or undo them. Normal test failures exit 1.
Test output is captured to temporary files, so large logs don't cut a passing run short.

### How upgrades are chosen

The target is the smallest published version outside every advisory range, including advisories
that only affect versions newer than the installed one. The registry reports only advisories that
affect the versions it is asked about, so each candidate target is looked up too (one batched request
per round, up to 5 rounds), and the pick is repeated until the target is clean. A target that is
still unconfirmed after 5 rounds is displayed with a warning and excluded from automatic fixes. If a lookup fails, the command
stops with exit code 2.

It prefers a fix on the same release line. A major upgrade is chosen only when no same-major fix
exists; `plan` and `fix` list it, and `fix` applies it only with `--allow-major`. Overrides pin
exact versions, the ones the tool checked; a later scan flags any new advisory, and `fix` raises
the override.

## Exit codes

| Code | `scan` | `plan` / `fix` |
|---|---|---|
| 0 | No finding meets `--fail-on` | Plan shown, or upgrades applied and tests passed (or marked unverified) |
| 1 | A finding meets `--fail-on` (default `P1`) | Tests failed after the upgrade |
| 2 | Usage or input error: bad option, more than one directory, missing, v1, malformed or out-of-date lockfile, invalid `SCA_TRIAGE_REGISTRY`, registry error or malformed response | Same, plus a failed install, an install that didn't produce the planned versions (rolled back), or a failed rescan |

## Scope and limits

- **npm projects** with `package-lock.json` v2 or v3 (npm 7+). A v1 lockfile is rejected with a
  message to regenerate it. A malformed lockfile, one missing a required dependency, or an entry
  whose name or version doesn't match its registry tarball is rejected. A git, file or URL
  dependency with no version is skipped with a warning. Missing optional and peer
  dependencies are allowed (npm skips peers with `legacy-peer-deps`), and so are `file:` folders
  outside the project.
- **Import-level reachability.** "Imported" means your code loads the package, not that the
  vulnerable function runs. Imports resolve from their source file to the matching installed copy, then follow its
  dependency graph. A package loaded by a name built at runtime, or named only in a config file
  that isn't JavaScript, isn't seen. Reachability only lowers priority; it never hides a finding.
- **Tests are the safety net.** An upgrade is only as verified as the project's test suite.
  `fix` runs that suite, and npm reads the project's `.npmrc`, so use `fix` on projects you trust.
  It ignores install scripts and always uses the system `git`.
- **Bundled dependencies** ship inside another package's tarball, so overrides can't change them.
  `scan`, `plan` and `fix` name the package that bundles them; upgrading it is up to you.
- **Results reflect the advisory database at scan time.** Zero findings is not a certification.
- **Mirrors:** `SCA_TRIAGE_REGISTRY` points at another registry. It must be `https://`
  (`http://` only for this machine) with no credentials in the URL.

## More

- [SECURITY.md](SECURITY.md): how the tool treats untrusted input, and how to report an issue
- [ARCHITECTURE.md](ARCHITECTURE.md): components, ranking, upgrade planning, trust boundaries and failure handling, with a diagram
- [CHANGELOG.md](CHANGELOG.md): what changed in each release
- [Case study](https://dotrobin.dev/sca-triage.html): design and a run on OWASP NodeGoat

## License

MIT. See [LICENSE](LICENSE).
