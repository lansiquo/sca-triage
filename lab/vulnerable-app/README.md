# Intentionally vulnerable demo app

> [!WARNING]
> **This app is intentionally vulnerable.** Its dependencies are pinned to known-vulnerable
> versions on purpose. It exists only to be scanned, tested and upgraded by `sca-triage`.
> Don't deploy it, don't expose it to a network, and don't reuse its dependency versions.

A small "evidence export job" that parses option tokens from a less-trusted submitter.

| Dependency | Pinned version | Used by the code? | Why it's here |
|---|---|---|---|
| `minimist` | 1.2.5 | yes, parses options | Prototype pollution (GHSA-xvch-5gv4-984h), proven by `test/security.test.js` |
| `semver` | 7.5.1 | yes, checks client versions | ReDoS advisory (GHSA-c2qf-rxjj-qqgw) |
| `axios` | 1.6.0 | yes, builds a notification (never sends it) | Many advisories; shows a large upgrade jump |
| `tar` | 6.1.0 | **no** | Critical advisories but never loaded, so it ranks lower (P2) and needs a major upgrade |

Tests:

- `test/functional.test.js` passes on both the vulnerable and the fixed versions.
- `test/security.test.js` fails on minimist 1.2.5 and passes after the upgrade.

Install it with `--ignore-scripts` (the repo's `npm run lab:install` does this). To try the
upgrade, run `sca-triage fix` on a **copy** of this folder, so the lab keeps its
vulnerable starting point.
