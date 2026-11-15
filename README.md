# sca-triage

npm projects collect more vulnerability alerts than anyone can work through. It is unclear which
ones matter, and the upgrades that clear them can break things. `sca-triage` finds the known
vulnerabilities in the tree locked in `package-lock.json`. It ranks them by severity and by whether
your code loads the package. It can then apply the smallest safe upgrades and check them with your
project's own tests.

It runs from the command line or as a GitHub Action and has no dependencies. It uses the
advisory data `npm audit` uses: the GitHub Advisory Database, via the npm registry. Its companion
for source code, [sast-triage](https://github.com/lansiquo/sast-triage), ranks Semgrep findings
P1–P3.

## Status

sca-triage is published on [npm](https://www.npmjs.com/package/sca-triage) and as a GitHub Action.
[CHANGELOG.md](CHANGELOG.md) lists what changed in each release. The
[publish workflow](.github/workflows/publish.yml) on GitHub publishes each version after 1.3.0 to
npm with [provenance](https://docs.npmjs.com/generating-provenance-statements): npm shows the
commit and the workflow run that built it. [CONTRIBUTING.md](CONTRIBUTING.md#releases) covers the
release checks and the `v1` tag.

## Quick start

You need Node.js 20 or newer and access to `registry.npmjs.org`. In the folder of a project that
has a `package-lock.json`:

```bash
npx sca-triage scan .   # ranked findings
npx sca-triage plan .   # dry run: planned upgrades
npx sca-triage fix .    # upgrade, test, rescan
```

`scan` and `plan` only read the manifests, the lockfile and source files. They don't need
`node_modules`. `fix` changes your project, so read [Fix your project](#fix-your-project) first.

`npx` asks before it first downloads sca-triage. To install it instead, run
`npm install -g sca-triage` and drop the `npx`.

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

## Commands

```text
sca-triage scan [dir] [--json] [--markdown <file>] [--fail-on P1|P2|P3|none]
sca-triage plan [dir] [--min-priority P1|P2|P3] [--allow-major]
sca-triage fix  [dir] [--min-priority P1|P2|P3] [--allow-major] [--evidence <dir>] [--no-tests]
sca-triage --version
```

- `[dir]` is the project folder. It defaults to the current folder.
- `--fail-on` is the lowest priority that fails `scan` (default `P1`).
- `--allow-major` lets `plan` and `fix` apply major upgrades. Without it, they only list them.

[The usage guide](docs/usage.md#commands-and-options) lists every option.

## Ranking

| | Meaning | What to do |
|---|---|---|
| **P1** | High or critical, and your code loads the package directly or through a dependency | Fix now |
| **P2** | High or critical but not loaded at runtime, or moderate and loaded | Schedule it |
| **P3** | Everything else | Batch with routine upgrades |

[How ranking works](docs/usage.md#how-ranking-works) explains what counts as loaded.

## Fix your project

`fix` edits your project and runs its `npm test` before and after upgrading. Start from a clean git
working tree, and use it only on projects you trust.

1. Run `npx sca-triage plan .` to preview the upgrades. It changes nothing.
2. Run `npx sca-triage fix .` to pin vulnerable direct dependencies and add npm `overrides` for the
   copies still vulnerable. It then runs your tests, rescans and saves an evidence folder with a
   `REPORT.md`.
3. Review the changes with `git diff`, then commit them. To undo, restore the files and reinstall.
   Also restore any workspace `package.json` that changed.

   ```bash
   git restore package.json package-lock.json
   npm ci
   ```

If an install fails, `fix` restores the manifests and the lockfile and exits with code 2. The guide
covers [what `fix` changes](docs/usage.md#what-fix-changes) and
[what it leaves for you](docs/usage.md#what-fix-leaves-for-you).

## Exit codes

| Code | `scan` | `plan` / `fix` |
|---|---|---|
| 0 | No finding meets `--fail-on` | Plan shown, or upgrades applied and tests passed (or marked unverified) |
| 1 | A finding meets `--fail-on` | Tests failed after the upgrade |
| 2 | Usage, input or registry error | Same, plus a failed install or a failed rescan |

[Exit codes](docs/usage.md#exit-codes) lists every error.

## Example

[OWASP NodeGoat](https://github.com/OWASP/NodeGoat) is a deliberately vulnerable app with 1,479
locked packages. One scan found 180 vulnerable packages and narrowed "fix now" to 12 P1.
[The NodeGoat walkthrough](docs/example-nodegoat.md) shows every step.

## Limits and safety

- **Import-level reachability.** "Imported" means your code loads the package, not that the
  vulnerable function runs. Reachability only lowers priority; it never hides a finding.
- **Tests are the safety net.** An upgrade is only as verified as the project's test suite. `fix`
  runs `npm test` with your permissions, and npm reads the project's `.npmrc`. Installs use
  `--ignore-scripts`, so no install scripts run.
- **npm only.** The tool reads `package-lock.json` v2 or v3 (npm 7+).
- **Results reflect the advisory database at scan time.** Zero findings is not a certification.

[Scope and limits](docs/usage.md#scope-and-limits) has the full list, including registry retries
and `SCA_TRIAGE_REGISTRY`.

## More

- [docs/usage.md](docs/usage.md): every option, ranking, `fix` in detail, exit codes and limits
- [docs/example-nodegoat.md](docs/example-nodegoat.md): a full run on a vulnerable app
- [SECURITY.md](SECURITY.md): how the tool treats untrusted input, and how to report an issue
- [ARCHITECTURE.md](ARCHITECTURE.md): components, upgrade planning, trust boundaries and failure handling
- [CONTRIBUTING.md](CONTRIBUTING.md): running from a clone, the tests and the release process

## License

MIT. See [LICENSE](LICENSE).
