# Security

## Untrusted input

`sca-triage` treats the scanned project and registry responses as untrusted:

- **Registry:** `https://` only, except plain `http://` to `localhost`, `127.0.0.1` or `[::1]`; `SCA_TRIAGE_REGISTRY` URLs can't contain credentials. A malformed response, including an advisory without a version range or valid severity, stops the scan with exit code 2. An unparseable range counts as vulnerable, with a warning.
- **Lockfiles:** malformed v2/v3 inventories, missing required dependencies and unsupported links fail the scan; they never become an empty clean result.
- **Reports:** untrusted names and paths are escaped in Markdown, and terminal control characters are replaced in console output.
- **Fix plans:** dependency types and alias identities are preserved. Overrides are version-scoped, retain nested rules and are checked for conflicting targets and unintended downgrades before mutation. Unconfirmed candidate targets are excluded from automatic fixes.
- **npm:** `fix` installs with `--ignore-scripts` and refuses any npm argument that isn't a plain package name, version or path.
- **Source scanning:** symlinks are followed only inside the project, and imports are tokenized in a linear pass, including long declarations. Evidence is deduplicated with sets.

`fix` runs the project's own `npm test` before and after upgrading, so use it only on projects whose tests you trust.

Reachability is import-level: "imported" means the code loads the package, not that the vulnerable function runs, and results reflect the advisory database at scan time. Zero findings is not a security certification.

## Reporting a vulnerability

Report issues in the tool (`bin/`, `src/`, `action.yml`) privately via GitHub's **Security** tab → **Report a vulnerability**, not in a public issue.
