# sca-triage

npm projects collect more vulnerability alerts than anyone can work through: it is unclear which
ones matter, and the upgrades that clear them can break things. `sca-triage` finds the known
vulnerabilities in the tree locked in `package-lock.json`, ranks them by severity and by whether
your code loads the package, applies the smallest safe upgrades, and checks them with your
project's own tests.

It runs from the command line or as a GitHub Action, has no dependencies, and uses the advisory
data `npm audit` uses: the GitHub Advisory Database, via the npm registry. Its companion for source
code, [sast-triage](https://github.com/lansiquo/sast-triage), ranks Semgrep findings P1–P3.

## Quick start

You need Node.js 20 or newer and access to `registry.npmjs.org`. In the folder of a project that
has a `package-lock.json`:

```bash
npx sca-triage scan .   # ranked findings
npx sca-triage plan .   # dry run: planned upgrades
npx sca-triage fix .    # upgrade, test, rescan
```

`scan` and `plan` only read `package.json`, `package-lock.json`, workspace manifests and source
files; they don't need `node_modules`. Before you run `fix`, read
[Fix your own project](#fix-your-own-project).

`npx` downloads sca-triage from [npm](https://www.npmjs.com/package/sca-triage) the first time and
asks before it does. To install it instead, run `npm install -g sca-triage` and drop the `npx`.

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage plan [dir] [--min-priority P1|P2|P3] [--allow-major]
sca-triage fix  [dir] [--min-priority P1|P2|P3] [--allow-major] [--evidence <dir>] [--no-tests]
sca-triage --version
```

`[dir]` defaults to the current folder. `--fail-on` is the lowest priority that fails the scan
(default `P1`). `--json` prints the full result; `--markdown <file>` also writes the findings table
as Markdown.

### GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 22
- uses: lansiquo/sca-triage@v1.3.0
  with:
    path: .        # directory with package.json and package-lock.json
    fail-on: P1    # P1, P2, P3 or none
```

The Action runs `scan`. Both inputs are optional (defaults shown). The step fails when the gate
fails and adds the findings table to the job summary. Pin a release tag such as `@v1.3.0`, or a
full commit SHA for the strictest supply-chain safety.

## Example: OWASP NodeGoat

I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a deliberately vulnerable Node.js app
with 1,479 locked packages, at its latest commit, `c5cb68a` (June 2023). NodeGoat's `npm test` runs
no tests (its unit-test folder doesn't exist), so the run uses `--no-tests`: none of NodeGoat's
code runs, and the report marks the upgrades unverified. From any folder:

```bash
git clone https://github.com/OWASP/NodeGoat.git
npx sca-triage scan NodeGoat                    # ranked findings
npx sca-triage plan NodeGoat --min-priority P1  # dry run: the P1 upgrades
cp -r NodeGoat NodeGoat-fixed
npx sca-triage fix NodeGoat-fixed --min-priority P1 --no-tests --evidence evidence
npx sca-triage scan NodeGoat-fixed              # rescan
```

The P1 findings, condensed to one line each (the tool prints a few lines per finding):

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
`mongodb`. Of the other 168 findings, 130 are in development-only packages such as build and test
tools, 61 are bundled inside other packages and 10 have no fixed release. These groups overlap: a
development-only package can also be bundled.

`plan` lists 7 upgrades for the P1 packages: 2 direct dependencies pinned with `npm install` and 5
transitive packages fixed with npm `overrides`. `express` requires `body-parser` 1.18.3 exactly, so
it also gets an override for the new version. `marked`, `mongodb` and `minimist` have only a major
upgrade. Two are left for you: `swig` has no fixed release, so it needs replacing rather than
upgrading, and `qs` needs a manual upgrade, because the override that would reach it
(`"request" > "qs"`) would also force `zaproxy`'s `qs` 0.6.6 up to 6.16.1, a major jump.

`fix` installs the 2 pins, rescans, writes the overrides still needed, and confirms all 7 upgrades
in the new lockfile. The rescan finds 173 vulnerable packages and 5 P1: the three majors, `swig`
and `qs`. With `--allow-major`, `fix` also applies the majors; `mongodb` 3.1.13 brings a safe
`bson`, so that override isn't written, and the rescan finds 170 vulnerable packages and 2 P1.
Counts follow the advisory database and the versions npm installs at the time, so a new run can
differ slightly. The [case study](https://dotrobin.dev/sca-triage.html) explains how the tool works
and shows the full output of each step from version 1.2.3.

## How ranking works

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

Each finding gets a reachability level. Three count as loaded:

- `imported`: your runtime code requires or imports it.
- `named`: a string in your runtime code is exactly the name of a direct production dependency, as
  Express needs to load a view engine (`app.set('view engine', 'ejs')`).
- `via-imported`: an imported or named dependency pulls it in.

`config-only` (a development-only package loaded only by tool config files such as
`vite.config.js`), `test-only` and `not-imported` don't.

The check covers `require`, `import`, `export … from`, dynamic `import()` and `createRequire()`
across JS, TS, JSX/TSX, Vue, Svelte and Astro sources, and follows workspaces and aliased packages.

## Fix your own project

`fix` edits your project and runs its `npm test` before and after upgrading, so start from a clean
git working tree and use it only on projects you trust.

1. **Preview.** `npx sca-triage plan .` lists each upgrade and changes nothing (`fix --dry-run`
   does the same).

2. **Apply.** `npx sca-triage fix .` upgrades, runs your tests, rescans and saves an evidence
   folder:

   - `--min-priority P1` fixes only P1 findings. By default every priority is fixed.
   - `--allow-major` also applies major upgrades. Without it, `plan` and `fix` list them for you
     to review first.
   - `--no-tests` skips the tests; the upgrades are then marked **unverified**. A project with no
     `test` script gets the same.
   - `--evidence <dir>` saves the evidence elsewhere. The default is `evidence/<timestamp>/` in
     the project, with a `.gitignore` so reports and test logs stay out of your commits.

3. **Check the result.** The last lines show whether your tests passed after the upgrade and how
   many vulnerable packages are left. `REPORT.md` in the evidence folder lists the findings before
   and after, every change and both test runs.

4. **Keep or undo.** Review the changes with `git diff`, then commit them. To undo, restore the
   files and reinstall (also restore any workspace `package.json` that changed):

   ```bash
   git restore package.json package-lock.json
   npm ci
   ```

### What `fix` changes

`fix` pins each vulnerable direct dependency with `npm install name@version --save-exact`, then
rescans and fixes the packages your dependencies still pull in with npm `overrides` in
`package.json`. Existing overrides are kept. Installs use `--ignore-scripts`, so no install scripts
run.

The target is the smallest published, non-prerelease version above the installed one that is
outside every advisory range. A fix on the same release line (what npm's `^` range allows) is
preferred; anything beyond it counts as a major upgrade.

If an install fails, or npm installs anything other than the plan, `fix` puts `package.json`, any
workspace `package.json` it pinned and `package-lock.json` back and stops before the second test
run. Run `npm ci` to reset `node_modules`. If your tests fail after the upgrade, the changes stay
so you can see what broke. If the final rescan fails (the registry is down, say), `fix` exits with
code 2 but keeps the tested changes, unlike a failed install.

`plan` and `fix` list what they leave for you: upgrades an override can't make without changing
other copies (**Needs a manual upgrade**, with the reason), copies bundled inside another package,
which overrides can't change, and packages with no fixed version.
[ARCHITECTURE.md](ARCHITECTURE.md#upgrade-planning) has the planning rules, the failure handling
and the contents of the evidence folder in full.

## Exit codes

| Code | `scan` | `plan` / `fix` |
|---|---|---|
| 0 | No finding meets `--fail-on` | Plan shown, or upgrades applied and tests passed (or marked unverified) |
| 1 | A finding meets `--fail-on` | Tests failed after the upgrade |
| 2 | Usage or input error: bad option, more than one directory, missing, v1, malformed or out-of-date lockfile, invalid `SCA_TRIAGE_REGISTRY`, registry error or malformed response | Same, plus a failed install, an install that didn't produce the planned versions (rolled back), or a failed rescan |

## Scope and limits

- **Import-level reachability.** "Imported" means your code loads the package, not that the
  vulnerable function runs. A package loaded by a name built at runtime, or named only in a file
  that isn't scanned source (a JSON config, say), isn't seen. Reachability only lowers priority; it
  never hides a finding.
- **Tests are the safety net.** An upgrade is only as verified as the project's test suite. During
  `fix`, npm also reads the project's `.npmrc`; `fix` always uses the system `git`.
- **npm projects** with `package-lock.json` v2 or v3 (npm 7+); the error for a v1 lockfile says
  how to regenerate it. A lockfile entry whose name or version doesn't match its registry tarball
  is rejected. A git, file or URL dependency with no version is skipped with a warning.
- **Results reflect the advisory database at scan time.** Zero findings is not a certification.
- **Registry.** Timeouts, network errors and 429, 500, 502, 503 and 504 responses are retried (3
  attempts, honouring `Retry-After`) before a registry error. `SCA_TRIAGE_REGISTRY` points at
  another registry: `https://` only (`http://` only for this machine), with no credentials in the
  URL.

## Releases

[CHANGELOG.md](CHANGELOG.md) lists what changed in each release. Versions after 1.3.0 are
published to npm from GitHub by the [publish workflow](.github/workflows/publish.yml) with
[provenance](https://docs.npmjs.com/generating-provenance-statements): npm shows the commit and the
workflow run a version was built from. The workflow then moves the `v1` tag to the release, for 1.x
versions. [CONTRIBUTING.md](CONTRIBUTING.md#releases) lists the checks a release must pass.

## More

- [SECURITY.md](SECURITY.md): how the tool treats untrusted input, and how to report an issue
- [ARCHITECTURE.md](ARCHITECTURE.md): components, ranking, upgrade planning, trust boundaries and failure handling, with a diagram
- [CONTRIBUTING.md](CONTRIBUTING.md): running from a clone, the tests and the release process

## License

MIT. See [LICENSE](LICENSE).
