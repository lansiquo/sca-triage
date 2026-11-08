# Security

## Intentionally vulnerable code

`lab/vulnerable-app` is **intentionally vulnerable**. It pins known-vulnerable dependency
versions so `sca-triage` can demonstrate detection, prioritization and remediation. Dependabot
and code-scanning alerts about that folder are expected and won't be fixed in place, because
they're the point of the lab. Use it locally only.

## How the tool handles the project it scans

`sca-triage` treats the scanned project's files and the registry's responses as untrusted input:

- **Registry:** advisories are fetched over `https://`. `SCA_TRIAGE_REGISTRY` can point at a mirror,
  but plain `http://` is accepted only for this machine (`localhost`, `127.0.0.1`, `[::1]`), and the
  URL can't contain credentials. A response that isn't the documented shape, including an advisory
  without a version range, stops the scan with exit code 2 rather than reporting "no vulnerabilities".
  An advisory range the tool can't parse counts as vulnerable, with a warning.
- **Reports:** package names, lockfile paths and failing test names are escaped before they reach the
  Markdown report or job summary, and terminal control characters are replaced in console output.
- **npm commands:** `fix` installs with `--ignore-scripts`, and refuses to pass npm any
  argument built from lockfile or registry data that isn't a plain package name, version or path.
- **Source scanning:** symlinks are followed only inside the project, and the import patterns are
  bounded so a hostile file can't make the scan backtrack without limit.

`fix` runs the project's own `npm test` before and after the upgrade, so run it only on
projects whose test scripts you trust (the CI lab gate does this inside a disposable runner).

Reachability is import-level: "imported" means the code loads the package, not that the vulnerable
function is proven to run, and results reflect the advisory database at scan time. Zero findings is
not a security certification.

## Reporting a vulnerability in sca-triage

If you find a security issue in the tool itself (`bin/`, `src/` or `action.yml`), please report
it privately through GitHub (**Security** tab → **Report a vulnerability**) rather than opening a
public issue.
