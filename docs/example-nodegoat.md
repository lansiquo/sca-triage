# Example: OWASP NodeGoat

This walkthrough runs sca-triage on [OWASP NodeGoat](https://github.com/OWASP/NodeGoat), a
deliberately vulnerable Node.js app with 1,479 locked packages, at its latest commit, `c5cb68a`
(June 2023). The [README](../README.md) covers installing and running the tool.

NodeGoat's `npm test` runs no tests (its unit-test folder doesn't exist), so the run uses
`--no-tests`: none of NodeGoat's code runs, and the report marks the upgrades unverified. From any
folder:

```bash
git clone https://github.com/OWASP/NodeGoat.git
npx sca-triage scan NodeGoat                    # ranked findings
npx sca-triage plan NodeGoat --min-priority P1  # dry run: the P1 upgrades
cp -r NodeGoat NodeGoat-fixed
npx sca-triage fix NodeGoat-fixed --min-priority P1 --no-tests --evidence evidence
npx sca-triage scan NodeGoat-fixed              # rescan
```

## Scan

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

The scan matches 437 advisories across 180 vulnerable packages. It narrows "fix now" to 12 P1
packages the app loads, either directly or through an imported dependency such as `express` or
`mongodb`. Of the other 168 findings, 130 are in development-only packages such as build and test
tools, 61 are bundled inside other packages and 10 have no fixed release. These groups overlap: a
development-only package can also be bundled.

## Plan

`plan` lists 7 upgrades for the P1 packages: 2 direct dependencies pinned with `npm install` and 5
transitive packages fixed with npm `overrides`. `express` requires `body-parser` 1.18.3 exactly, so
it also gets an override for the new version. `marked`, `mongodb` and `minimist` have only a major
upgrade.

Two are left for you. `swig` has no fixed release, so it needs replacing rather than upgrading.
`qs` needs a manual upgrade, because the override that would reach it (`"request" > "qs"`) would
also force `zaproxy`'s `qs` 0.6.6 up to 6.16.1, a major jump.

## Fix and rescan

`fix` installs the 2 pins, rescans, writes the overrides still needed, and confirms all 7 upgrades
in the new lockfile. The rescan finds 173 vulnerable packages and 5 P1: the three majors, `swig`
and `qs`.

With `--allow-major`, `fix` also applies the majors. `mongodb` 3.1.13 brings a safe `bson`, so that
override isn't written, and the rescan finds 170 vulnerable packages and 2 P1.

Counts follow the advisory database and the versions npm installs at the time, so a new run can
differ slightly. The [case study](https://dotrobin.dev/sca-triage.html) explains how the tool works
and shows the full output of each step from version 1.2.3.
