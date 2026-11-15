# Using sca-triage

This guide has the detail behind the [README](../README.md): every option, how ranking works, what
`fix` changes, every exit code, and the limits. [ARCHITECTURE.md](../ARCHITECTURE.md) explains the
design, and [SECURITY.md](../SECURITY.md) explains how the tool treats untrusted input.

## Install and run

You need Node.js 20 or newer and access to `registry.npmjs.org`. Run the commands in the folder of
a project that has a `package-lock.json`.

`npx sca-triage` downloads sca-triage from [npm](https://www.npmjs.com/package/sca-triage) the
first time and asks before it does. To install it instead, run `npm install -g sca-triage` and drop
the `npx`.

`scan` and `plan` only read `package.json`, `package-lock.json`, workspace manifests and source
files. They don't need `node_modules`. `fix` changes the project: read
[Fix your project](#fix-your-project) before you run it.

## Commands and options

| Option | Commands | What it does |
|---|---|---|
| `[dir]` | all | The project folder. The default is the current folder. |
| `--fail-on P1\|P2\|P3\|none` | `scan` | The lowest priority that fails the scan. The default is `P1`. |
| `--json` | `scan` | Prints the full result as JSON. |
| `--markdown <file>` | `scan` | Also writes the findings table as Markdown. |
| `--min-priority P1\|P2\|P3` | `plan`, `fix` | Covers only findings at this priority or higher. By default every priority is covered. |
| `--allow-major` | `plan`, `fix` | Also applies major upgrades. Without it, `plan` and `fix` list them for you to review first. |
| `--evidence <dir>` | `fix` | Saves the evidence folder here instead of the default. |
| `--no-tests` | `fix` | Skips the tests. The upgrades are then marked **unverified**. |
| `--dry-run` | `fix` | Does the same as `plan`. |
| `--version` | none | Prints the version. |

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
across JS, TS, JSX/TSX, Vue, Svelte and Astro sources. It follows workspaces and aliased packages.

## Fix your project

`fix` edits your project and runs its `npm test` before and after upgrading. Start from a clean git
working tree, and use it only on projects you trust.

1. **Preview.** `npx sca-triage plan .` lists each upgrade and changes nothing. `fix --dry-run`
   does the same.

2. **Apply.** `npx sca-triage fix .` upgrades, runs your tests, rescans and saves an evidence
   folder:

   - `--min-priority P1` fixes only P1 findings. By default every priority is fixed.
   - `--allow-major` also applies major upgrades. Without it, `plan` and `fix` list them for you
     to review first.
   - `--no-tests` skips the tests. The upgrades are then marked **unverified**. A project with no
     `test` script gets the same.
   - `--evidence <dir>` saves the evidence elsewhere. The default is `evidence/<timestamp>/` in
     the project, with a `.gitignore` so reports and test logs stay out of your commits.

3. **Check the result.** The last lines show whether your tests passed after the upgrade and how
   many vulnerable packages are left. `REPORT.md` in the evidence folder lists the findings before
   and after, every change and both test runs.

4. **Keep or undo.** Review the changes with `git diff`, then commit them. To undo, restore the
   files and reinstall. Also restore any workspace `package.json` that changed.

   ```bash
   git restore package.json package-lock.json
   npm ci
   ```

### What `fix` changes

`fix` pins each vulnerable direct dependency with `npm install name@version --save-exact`. It then
rescans and fixes the packages your dependencies still pull in with npm `overrides` in
`package.json`. It keeps existing overrides. Installs use `--ignore-scripts`, so no install scripts
run.

The target is the smallest published, non-prerelease version above the installed one that is
outside every advisory range. `fix` prefers a fix on the same release line (what npm's `^` range
allows). Anything beyond it counts as a major upgrade.

### When something goes wrong

- **A failed install.** If an install fails, or npm installs anything other than the plan, `fix`
  puts back `package.json`, any workspace `package.json` it pinned and `package-lock.json`. It
  stops before the second test run. Run `npm ci` to reset `node_modules`.
- **Failing tests.** If your tests fail after the upgrade, the changes stay so you can see what
  broke.
- **A failed rescan.** If the final rescan fails (the registry is down, say), `fix` exits with code
  2 but keeps the tested changes, unlike a failed install.

### What `fix` leaves for you

`plan` and `fix` list what they leave for you:

- upgrades an override can't make without changing other copies (**Needs a manual upgrade**, with
  the reason);
- copies bundled inside another package, which overrides can't change;
- packages with no fixed version.

[ARCHITECTURE.md](../ARCHITECTURE.md#upgrade-planning) has the planning rules, the failure handling
and the contents of the evidence folder in full.

## Exit codes

| Code | `scan` | `plan` / `fix` |
|---|---|---|
| 0 | No finding meets `--fail-on` | Plan shown, or upgrades applied and tests passed (or marked unverified) |
| 1 | A finding meets `--fail-on` | Tests failed after the upgrade |
| 2 | Usage or input error: bad option, more than one directory, missing, v1, malformed or out-of-date lockfile, invalid `SCA_TRIAGE_REGISTRY`, registry error or malformed response | Same, plus a failed install, an install that didn't produce the planned versions (rolled back), or a failed rescan |

## Scope and limits

- **Import-level reachability.** "Imported" means your code loads the package, not that the
  vulnerable function runs. The tool doesn't see a package loaded by a name built at runtime, or
  named only in a file that isn't scanned source (a JSON config, say). Reachability only lowers
  priority; it never hides a finding.
- **Tests are the safety net.** An upgrade is only as verified as the project's test suite. During
  `fix`, npm also reads the project's `.npmrc`. `fix` always uses the system `git`.
- **npm projects** with `package-lock.json` v2 or v3 (npm 7+). The error for a v1 lockfile says
  how to regenerate it. The tool rejects a lockfile entry whose name or version doesn't match its
  registry tarball. It skips a git, file or URL dependency with no version, with a warning.
- **Results reflect the advisory database at scan time.** Zero findings is not a certification.
- **Registry.** The tool retries timeouts, network errors and 429, 500, 502, 503 and 504 responses
  (3 attempts, honouring `Retry-After`) before it reports a registry error.
  `SCA_TRIAGE_REGISTRY` points the tool at another registry: `https://` only (`http://` only for
  this machine), with no credentials in the URL.
