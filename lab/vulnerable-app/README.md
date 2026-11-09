# Intentionally vulnerable demo app

> [!WARNING]
> **Intentionally vulnerable.** Dependencies are pinned to known-vulnerable versions for `sca-triage` to scan, test and upgrade. Don't deploy it, expose it to a network, or reuse its versions.

| Dependency | Version | Imported? | Purpose |
|---|---|---|---|
| `minimist` | 1.2.5 | yes | Prototype pollution (GHSA-xvch-5gv4-984h), proven by a test |
| `semver` | 7.5.1 | yes | ReDoS (GHSA-c2qf-rxjj-qqgw) |
| `axios` | 1.6.0 | yes (never sends) | Many advisories; a large upgrade |
| `tar` | 6.1.0 | **no** | Critical but never loaded, so ranked P2 |

`test/functional.test.js` passes before and after the fix; `test/security.test.js` fails on minimist 1.2.5 and passes after.

Run `npm run lab` from the repository root. It installs with `--ignore-scripts`, scans, and fixes a temporary **copy**, leaving this folder unchanged.
