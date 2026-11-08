# sca-triage

`sca-triage` is a dependency-free npm SCA scanner, run from the command line or as a GitHub Action. It finds
known vulnerabilities in your installed dependency tree, **ranks them by whether your code
actually loads the vulnerable package**, applies the smallest safe upgrade, and proves the result
with your own tests, with an evidence folder you can hand to an auditor.

**Status: v1.0, functional end-to-end npm SCA scanner and lab.**
Its SAST companion, [sast-triage](https://github.com/lansiquo/sast-triage), reviews pull requests with Semgrep, labels each finding new or pre-existing, and ranks it P1–P3 the same way.

The implemented workflow scans npm dependencies, prioritizes findings using import evidence,
applies proposed upgrades, runs the project’s tests, rescans and saves remediation evidence.
The [CI lab gate](.github/workflows/ci.yml) exercises the vulnerable baseline and remediated copy.
Functional describes this local/CI workflow; the [scope and limits](#limits) still apply.
The [portfolio browser demo](https://dotrobin.dev/demos/sca.html) is a recorded replay, separate
from the working CLI and GitHub Action.

> [!WARNING]
> **This repository contains an intentionally vulnerable application.**
> [`lab/vulnerable-app`](lab/vulnerable-app) pins known-vulnerable versions of `minimist`,
> `axios`, `semver` and `tar` on purpose, so the tool has something real to find and fix.
> Use it locally for learning only. Don't deploy it, don't expose it to a network, and don't
> copy its dependency versions into real projects. Dependabot alerts on this repository are expected.
> The `sca-triage` scanner itself (`bin/` and `src/`) has no dependencies and is safe to use.

## Why

`npm audit` and Dependabot report every advisory with the same urgency, so teams drown in alerts
and start ignoring them. Most of the work in software composition analysis (SCA) is deciding
what matters. `sca-triage` automates that triage:

| | `npm audit` | `sca-triage` |
|---|---|---|
| Finds known vulnerabilities | ✅ | ✅ same GitHub Advisory Database data |
| Ranks by whether your code loads the package | ❌ | ✅ import-level reachability |
| Picks the smallest safe upgrade, flags major bumps | partly | ✅ |
| Verifies the upgrade with your tests | ❌ | ✅ before/after runs |
| Writes audit evidence (reports, SBOM, lockfiles) | ❌ | ✅ |
| CI gate that fails only on what matters | ❌ | ✅ `--fail-on P1` |

## Quick start

Requires Node.js 20 or newer and network access to `registry.npmjs.org`.

```bash
git clone https://github.com/lansiquo/sca-triage.git
cd sca-triage
npm run lab:install   # installs the INTENTIONALLY VULNERABLE lab app (no install scripts)
npm run lab:scan      # rank the lab app's vulnerabilities
npm run lab:plan      # show the smallest safe upgrades (dry run)
```

To apply the fixes, use a copy so the lab keeps its vulnerable starting point:

```bash
cp -r lab/vulnerable-app /tmp/lab-copy
node bin/sca-triage.js fix /tmp/lab-copy --apply --evidence /tmp/lab-evidence
```

On your own project:

```bash
node /path/to/sca-triage/bin/sca-triage.js scan .
```

## What it found in the lab (real output)

```text
intentionally-vulnerable-export-job: 33 packages scanned, 4 vulnerable (P1: 3, P2: 1, P3: 0)

[P1] minimist@1.2.5  CRITICAL, 1 advisory
     reachability: imported by your code (src/export-job.js:7)
     fix: 1.2.5 -> 1.2.6
[P1] axios@1.6.0  HIGH, 31 advisories
     reachability: imported by your code (src/notify.js:7)
     fix: 1.6.0 -> 1.20.0
[P1] semver@7.5.1  HIGH, 1 advisory
     reachability: imported by your code (src/export-job.js:8)
     fix: 7.5.1 -> 7.5.2
[P2] tar@6.1.0  CRITICAL, 18 advisories
     reachability: not imported
     fix: 6.1.0 -> 7.5.21 (major upgrade)

Gate (--fail-on P1): FAIL
```

`tar` has the most severe advisories but drops to P2, because nothing in the app loads it.
After `fix --apply`:

| | Before | After |
|---|---|---|
| Vulnerable packages | 4 (3 × P1, 1 × P2) | 0 |
| Functional tests | 5/5 pass | 5/5 pass |
| Security test (minimist prototype pollution) | **fails** | passes |
| CI gate | fails | passes |

The functional tests pass on both versions. That's the point of the lab: compatibility tests
alone don't catch the vulnerability, so the lab adds a security test for the one advisory it
demonstrates end to end (minimist, GHSA-xvch-5gv4-984h).

Exact counts and fix versions depend on the advisory database on the day you run it.

## What it found on a real project (OWASP NodeGoat)

To see it work at scale on a real dependency tree, I ran it against
[OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a well-known deliberately vulnerable training app:

```text
owasp-nodejs-goat: 1,479 packages scanned, 180 vulnerable
437 advisories  ->  P1: 13   P2: 123   P3: 44
```

437 advisories across 180 packages is exactly the alert-fatigue problem. Reachability ranking narrows
"fix now" to **13 P1 packages** — the ones that are both severe and actually loaded. A few:

| Priority | Package | Severity | Why |
|---|---|---|---|
| P1 | `underscore@1.9.1` | critical | imported by the app's code |
| P1 | `marked@0.3.5` | high | imported by the app's code (only a major upgrade fixes it, flagged) |
| P1 | `bson@1.0.9` | critical | pulled in through `mongodb`, which the app imports |
| P2 | `form-data@2.3.3` | critical | **nothing imports it**, so it ranks below the reachable highs |

That `form-data` row is the whole point: a critical advisory that isn't the first thing to fix, because
the code never loads it. Advisory data is the GitHub Advisory Database via the npm registry, so exact
counts move as the database changes.

## Commands

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage fix  [dir] [--apply] [--min-priority P1|P2|P3] [--evidence <dir>] [--no-tests]
```

- **`scan`** exits with code 1 when a finding meets `--fail-on` (default `P1`), so it works as a CI gate.
- **`fix`** is a dry run unless you pass `--apply`. With `--apply` it:
  1. runs `npm test` to record a baseline,
  2. pins direct dependencies to the safe version (`npm install pkg@x.y.z --save-exact --ignore-scripts`,
     with `--workspace <path>` for a dependency a workspace declares; an alias keeps its alias,
     e.g. `npm install foo@npm:lodash@4.17.21`),
  3. adds npm `overrides` for vulnerable transitive dependencies. Each vulnerable copy gets the
     smallest safe version on its own release line, so a 1.x copy and a 2.x copy aren't forced onto
     one version. A plain `"pkg": "x.y.z"` override is used only when every installed copy wants the
     same version and none is a direct dependency; otherwise the override is scoped to the packages
     that require each copy (`"parent": { "pkg": "x.y.z" }`), which npm accepts alongside a direct pin,
  4. runs `npm test` again and rescans,
  5. writes `REPORT.md`, `before.json`, `after.json`, both lockfiles, both test logs and a CycloneDX SBOM to the evidence folder.

  It exits with code 1 if the tests fail after the upgrade, so you know not to merge it.
  If the tests can't run (no `test` script, or `--no-tests`), it still exits 0, but the output
  and `REPORT.md` mark the changes as **unverified**.

### Priorities

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

Reachability levels: `imported` (your runtime code requires or imports it), `via-imported`
(an imported dependency pulls it in), `test-only`, and `not-imported`.

What counts as "loading" a package: `require()`, `require.resolve()`, static `import` and
`export ... from`, dynamic `import()` (comments inside the parentheses are fine), functions made by
`createRequire()`, and template literals with a static package name (``require(`pkg/${x}`)``).
It scans `.js`, `.cjs`, `.mjs`, `.ts`, `.cts`, `.mts`, `.jsx`, `.tsx`, `.vue`, `.svelte` and `.astro`
files, plus extensionless scripts with a `node` shebang (like `bin/cli`). `node_modules` and `.git`
are skipped everywhere; `dist`, `build`, `coverage`, `evidence` and `.next` only at the top of the
project or a workspace, so a source folder that happens to be called `build` is still scanned.
Test code is `test/`, `tests/` or `spec/` at the top of the project or a workspace, any `__tests__/`
folder, and `*.test.*` / `*.spec.*` files. Symlinks are followed only inside the project.

Dependency chains follow `dependencies`, `optionalDependencies` and `peerDependencies`, start from
the root `package.json` and from every workspace package, and use installed names, so an alias
(`"foo": "npm:lodash@..."`) is matched to `require('foo')` and reported as `foo (npm:lodash)`.

If an advisory's version range can't be parsed, the installed version is treated as vulnerable and
the scan prints a warning, rather than dropping the advisory or aborting the scan.

The advisory source can be changed with `SCA_TRIAGE_REGISTRY` (for a registry mirror). It must be
`https://`; plain `http://` is accepted only for `localhost`. A response that isn't the expected
shape is an error (exit code 2), never "no vulnerabilities".

## Use it in GitHub Actions

```yaml
- uses: actions/checkout@v4
- uses: actions/setup-node@v4
  with:
    node-version: 22
- run: npm ci --ignore-scripts
- uses: lansiquo/sca-triage@v1
  with:
    path: .
    fail-on: P1
```

Pin `@v1` to get v1 fixes automatically, or pin a full commit SHA for the strictest supply-chain safety.

The findings table is added to the job summary. This repository's own [CI](.github/workflows/ci.yml)
runs the tool against the lab app on every push: the gate must **fail** on the vulnerable
baseline and **pass** after remediation, and the evidence folder is uploaded as an artifact.

## Why I built it this way

I kept running `npm audit` on projects and getting a wall of advisories with no sense of which ones
mattered, so the choice was fix everything (and break things) or ignore everything. The one question
that actually changed my decision was "does our code even load this?" — so that became the core of the
tool. The reachability check is deliberately simple: it looks for imports, not a call graph. I'd rather
ship an honest "lower priority" signal than a clever one that quietly lies, so reachability only
down-ranks findings, it never hides them. Keeping the tool dependency-free was a principle too — a thing
that scans dependencies shouldn't drag in its own. The parts I'd tackle next are an OSV data source for
other ecosystems and EPSS/KEV scoring so the ranking knows what's actually being exploited in the wild.

## Limits

- **Reachability is import-level.** "Imported" means your code loads the package, not that the
  vulnerable function is proven to run. It doesn't build a call graph, so treat P2/P3 as
  "lower priority", not "safe".
- **npm only,** using `package-lock.json` v2 or v3. Other ecosystems aren't supported yet.
- **Results reflect the advisory database at scan time.** Zero findings is not a security certification.
- **Major upgrades are applied when no same-major fix exists,** and flagged. Below 1.0.0 a minor
  bump (0.9 → 0.10) counts as major, as npm's caret ranges treat it. The scanned project's
  own tests (`npm test`) are the safety net, so the verdict on an upgrade is only as good as that
  project's test suite. If it has no tests, the upgrade is reported as unverified.

## Architecture

```text
bin/sca-triage.js
      |
      v
src/triage.js ------> src/lockfile.js
      |               src/advisories.js
      |               src/reachability.js
      |               src/semver.js
      v
ranked findings (P1 / P2 / P3)
      |
      +------> src/fix.js       (fix --apply)
      '------> src/report.js
```

`fix --apply` calls `triage.js` twice (before and after the upgrade) and uses `report.js` to write `REPORT.md`.

- `bin/sca-triage.js` reads the command and flags, calls the modules below, prints the result and sets the exit code.
- `src/triage.js` checks each installed package against its advisories, assigns P1/P2/P3 and picks the smallest safe upgrade.
- `src/lockfile.js` reads `package.json` and `package-lock.json` into a list of installed packages and who depends on each.
- `src/advisories.js` asks the npm registry for known advisories and published versions.
- `src/reachability.js` finds the packages your source files `require` or `import`.
- `src/semver.js` compares versions and matches the version ranges advisories use.
- `src/fix.js` applies the upgrades with npm, runs your tests, rescans and writes the evidence folder.
- `src/report.js` formats results as the terminal table and the Markdown report.

## Layout

```text
bin/sca-triage.js          command-line entry point
src/                       lockfile graph, advisories, reachability, triage, fixes, reports
test/                      unit tests (offline, run with npm test)
action.yml                 reusable GitHub Action
lab/vulnerable-app/        INTENTIONALLY VULNERABLE demo app
```

Write-up: [dotrobin.dev/sca-triage](https://dotrobin.dev/sca-triage.html)
