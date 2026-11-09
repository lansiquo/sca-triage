# sca-triage

A dependency-free SCA scanner for npm projects, run from the command line or as a GitHub Action.
It finds known vulnerabilities in the tree locked in `package-lock.json`, ranks them by severity
and by whether your code loads the vulnerable package, applies the smallest safe upgrades, and
checks them with your project's own tests.

`npm audit` reports every advisory with the same urgency. `sca-triage` uses the same advisory data
(the GitHub Advisory Database, via the npm registry) and adds the triage: what to fix now, what to
schedule, and evidence that the fix didn't break anything. Its SAST companion,
[sast-triage](https://github.com/lansiquo/sast-triage), ranks Semgrep findings P1–P3 the same way.

> [!WARNING]
> [`lab/vulnerable-app`](lab/vulnerable-app) is **intentionally vulnerable**. It pins known-vulnerable
> versions of `minimist`, `axios`, `semver` and `tar` so the tool has something real to find and fix.
> Use it locally only; don't deploy it or copy its versions. Dependabot alerts on this repository are
> expected. The scanner itself (`bin/`, `src/`) has no dependencies.

## Try the lab

One command runs the whole lab (Node.js 20 or newer, with access to `registry.npmjs.org`):

```bash
git clone https://github.com/lansiquo/sca-triage.git
cd sca-triage
npm run lab
```

It runs these steps in order, prints each command before it runs, and stops if any result is not
the expected one:

```bash
npm ci --prefix lab/vulnerable-app --ignore-scripts --no-audit --no-fund   # install the vulnerable app
node bin/sca-triage.js scan lab/vulnerable-app                             # 4 vulnerable, P1 gate fails (expected)
node bin/sca-triage.js plan lab/vulnerable-app                             # dry run: the 4 upgrades
cp -r lab/vulnerable-app <run>/app                                         # copy to a new temp folder
node bin/sca-triage.js fix <run>/app --evidence <run>/evidence             # upgrade, test, rescan
node bin/sca-triage.js scan <run>/app                                      # 0 vulnerable, gate passes
cat <run>/evidence/REPORT.md                                               # the saved report
```

`<run>` is a new temporary folder for each run, so `lab/vulnerable-app` never changes and you can run
the lab again without cleaning up. The last lines print where the fixed copy and evidence are.

What the first scan finds (one line per finding; counts and versions follow the advisory database):

```text
intentionally-vulnerable-export-job: 33 packages scanned, 4 vulnerable (P1: 3, P2: 1, P3: 0)

[P1] minimist@1.2.5  CRITICAL   imported by your code (src/export-job.js:7)   fix: 1.2.6
[P1] axios@1.6.0     HIGH       imported by your code (src/notify.js:7)       fix: 1.20.0
[P1] semver@7.5.1    HIGH       imported by your code (src/export-job.js:8)   fix: 7.5.2
[P2] tar@6.1.0       CRITICAL   not imported                                  fix: 7.5.21 (major)

Gate (--fail-on P1): FAIL
```

`tar` has a critical advisory but ranks P2 because nothing loads it. After `fix`, the copy scans 37
packages with none vulnerable, the 5 functional tests still pass, and the lab's minimist
prototype-pollution test (GHSA-xvch-5gv4-984h) goes from failing to passing. The
[CI lab gate](.github/workflows/ci.yml) checks this on every push to `main` and every pull request.

## On a real project: OWASP NodeGoat

Beyond the lab, I scanned [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) at commit `c5cb68a`,
a deliberately vulnerable Node.js app with 1,479 locked packages. The scan only reads its lockfile
and source; nothing from NodeGoat is installed or run. From the folder containing `sca-triage`:

```bash
git clone https://github.com/OWASP/NodeGoat.git
git -C NodeGoat checkout c5cb68a
node sca-triage/bin/sca-triage.js scan NodeGoat
```

One line per P1 finding (counts and versions follow the advisory database at scan time):

```text
owasp-nodejs-goat: 1479 packages scanned, 180 vulnerable (P1: 13, P2: 123, P3: 44)

[P1] bson@1.0.9            CRITICAL  via mongodb                         fix: 1.1.4 (override)
[P1] minimist@0.0.10       CRITICAL  via swig                            fix: 0.2.4 (major, override)
[P1] proxy-addr@2.0.4      CRITICAL  via express                         fix: 2.0.8 (override)
[P1] underscore@1.9.1      CRITICAL  imported (config/config.js:1)       fix: 1.13.8
[P1] body-parser@1.18.3    HIGH      imported (server.js:5)              fix: 1.20.9
[P1] debug@2.2.0           HIGH      via helmet                          fix: 2.6.9 (override)
[P1] marked@0.3.5          HIGH      imported (server.js:13)             fix: 4.0.10 (major)
[P1] mongodb@2.2.36        HIGH      imported (artifacts/db-reset.js:9)  fix: 3.1.13 (major)
[P1] path-to-regexp@0.1.7  HIGH      via express                         fix: 0.1.13 (override)
[P1] qs@6.5.2              HIGH      via body-parser                     fix: 6.16.1 (override)
[P1] semver@5.6.0          HIGH      via mongodb                         fix: 5.7.2 (override)
[P1] swig@1.4.2            HIGH      imported (server.js:9)              fix: none published
[P1] uglify-js@2.4.24      HIGH      via swig                            fix: 2.6.0 (override)

… 123 P2 and 44 P3 findings omitted

Gate (--fail-on P1): FAIL
```

The scan matches 437 advisories across 180 vulnerable packages and narrows "fix now" to 13 P1
packages the app loads, either directly or through an imported dependency such as `express` or
`mongodb`. Transitive packages are fixed with npm `overrides`. `swig` has no fixed release, so it
needs replacing rather than upgrading.

## Use it on your project

Requires Node.js 20 or newer and access to `registry.npmjs.org`. A scan reads `package.json` and
`package-lock.json` only, so it doesn't need `node_modules`.

```bash
git clone https://github.com/lansiquo/sca-triage.git
node sca-triage/bin/sca-triage.js scan /path/to/project   # ranked findings
node sca-triage/bin/sca-triage.js plan /path/to/project   # dry run: planned upgrades
node sca-triage/bin/sca-triage.js fix  /path/to/project   # upgrade, test, rescan
```

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage plan [dir] [--min-priority P1|P2|P3]
sca-triage fix  [dir] [--min-priority P1|P2|P3] [--evidence <dir>] [--no-tests]
```

`--json` prints the full result; `--markdown <file>` also writes the findings table as Markdown.

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 22
- uses: lansiquo/sca-triage@v1.1.0
  with:
    path: .        # directory with package.json and package-lock.json
    fail-on: P1    # P1, P2, P3 or none
```

Both inputs are optional (defaults shown). The step fails when the gate fails and adds the findings
table to the job summary. No dependency install is needed. Pin a release tag such as `@v1.1.0`,
or a full commit SHA for the strictest supply-chain safety.

## How ranking works

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

Each finding gets a reachability level: `imported` (your runtime code requires or imports it),
`via-imported` (an imported dependency pulls it in), `test-only` or `not-imported`. The check
covers `require`, `import`, dynamic `import()` and `createRequire()` across JS, TS, JSX/TSX, Vue,
Svelte and Astro sources, and follows workspaces and aliased packages.

## What `fix` does

Preview first with `plan` (or `fix --dry-run`); it changes nothing. Then `fix`:

1. Runs `npm test` for a baseline.
2. Pins vulnerable direct dependencies to the safe version (`--save-exact`). Transitive ones get npm
   `overrides`, scoped to their parent when copies need different versions.
3. Installs with `--ignore-scripts`.
4. Runs `npm test` again and rescans. If the tests also failed in the baseline run, the output
   says so, since the failure may not be caused by the upgrade.
5. Writes an evidence folder (`--evidence <dir>`, default `<project>/evidence/<timestamp>`):
   `REPORT.md`, `before.json`, `after.json`, both lockfiles, both test logs and a CycloneDX SBOM.

The target is the smallest published version outside every advisory range, including advisories
that only affect versions newer than the installed one. The registry reports only advisories that
affect the versions it is asked about, so each candidate target is looked up too (one batched request
per round, up to 5 rounds), and the pick is repeated until the target is clean. A target that is
still unconfirmed after 5 rounds is kept and flagged with a warning. If a lookup fails, the command
stops with exit code 2.

It prefers a fix on the same release line. A major upgrade is applied only when no same-major fix
exists, and it is flagged. `--min-priority P1` limits fixes to P1. If there's no `test` script, or
you pass `--no-tests`, the changes are applied and marked **unverified**.

> **Changed since v1.0.0:** `fix` on its own now applies the upgrades; it used to be a dry run.
> Use `plan` to preview. `fix --apply` still works.

## Exit codes

| Code | `scan` | `plan` / `fix` |
|---|---|---|
| 0 | No finding meets `--fail-on` | Plan shown, or upgrades applied and tests passed (or marked unverified) |
| 1 | A finding meets `--fail-on` (default `P1`) | Tests failed after the upgrade |
| 2 | Usage or input error: bad option, more than one directory, missing or v1 lockfile, invalid `SCA_TRIAGE_REGISTRY`, registry error | Same, plus a failed `npm install` |

## Scope and limits

- **npm projects** with `package-lock.json` v2 or v3 (npm 7+). A v1 lockfile is rejected with a
  message to regenerate it.
- **Import-level reachability.** "Imported" means your code loads the package, not that the
  vulnerable function runs. Reachability only lowers priority; it never hides a finding.
- **Tests are the safety net.** An upgrade is only as verified as the project's test suite.
  `fix` runs that suite, so use it on projects whose test scripts you trust.
- **Results reflect the advisory database at scan time.** Zero findings is not a certification.
- **Mirrors:** `SCA_TRIAGE_REGISTRY` points at another registry. It must be `https://`
  (`http://` only for this machine) with no credentials in the URL.

## More

- [SECURITY.md](SECURITY.md): how the tool treats untrusted input, and how to report an issue
- [Case study](https://dotrobin.dev/sca-triage.html): design and a run on OWASP NodeGoat
- [Browser demo](https://dotrobin.dev/demos/sca.html): replay of one recorded run
