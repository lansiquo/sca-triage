// Minimal semver: parse, compare, and match the range syntax npm advisories use
// (">=1.0.0 <1.2.6", "<=7.5.2", "<2.0.0 || >=3.0.0 <3.1.0", "*").
// Kept dependency-free on purpose: a supply-chain tool shouldn't need a supply chain.

const VERSION_RE = /^v?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parse(version) {
  const m = VERSION_RE.exec(String(version).trim());
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: Number(m[3]),
    pre: m[4] ? m[4].split('.') : [],
  };
}

function comparePre(a, b) {
  if (!a.length && !b.length) return 0;
  if (!a.length) return 1; // release > prerelease
  if (!b.length) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const an = /^\d+$/.test(a[i]);
    const bn = /^\d+$/.test(b[i]);
    if (an && bn) {
      const d = Number(a[i]) - Number(b[i]);
      if (d) return Math.sign(d);
    } else if (an !== bn) {
      return an ? -1 : 1;
    } else if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  return 0;
}

export function compare(a, b) {
  const pa = typeof a === 'string' ? parse(a) : a;
  const pb = typeof b === 'string' ? parse(b) : b;
  if (!pa || !pb) throw new Error(`invalid version: ${!pa ? a : b}`);
  return (
    Math.sign(pa.major - pb.major) ||
    Math.sign(pa.minor - pb.minor) ||
    Math.sign(pa.patch - pb.patch) ||
    comparePre(pa.pre, pb.pre)
  );
}

export function isPrerelease(version) {
  const p = parse(version);
  return Boolean(p && p.pre.length);
}

const COMPARATOR_RE = /^(<=|>=|<|>|=)?\s*(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)$/;

function matchesComparator(version, comparator) {
  const m = COMPARATOR_RE.exec(comparator);
  if (!m) throw new Error(`unsupported range comparator: "${comparator}"`);
  const c = compare(version, m[2]);
  switch (m[1] || '=') {
    case '<': return c < 0;
    case '<=': return c <= 0;
    case '>': return c > 0;
    case '>=': return c >= 0;
    default: return c === 0;
  }
}

// True if `version` is inside `range`. Ranges are OR-ed sets of AND-ed comparators.
export function satisfies(version, range) {
  const r = String(range).trim();
  if (r === '' || r === '*') return true;
  return r.split('||').some((set) => {
    // Join operators to their versions: ">= 1.0.0" -> ">=1.0.0"
    const parts = set.trim().replace(/(<=|>=|<|>|=)\s+/g, '$1').split(/\s+/).filter(Boolean);
    return parts.every((p) => matchesComparator(version, p));
  });
}

export function sortVersions(versions) {
  return [...versions].filter((v) => parse(v)).sort(compare);
}

// The release line a version belongs to under npm's caret rules: "2" for 2.x.y,
// "0.3" for 0.3.y and "0.0.4" for 0.0.4, since below 1.0.0 a minor (or, below 0.1.0,
// a patch) bump may break callers. Moving to another line is a breaking upgrade.
export function releaseLine(version) {
  const p = typeof version === 'string' ? parse(version) : version;
  if (!p) return null;
  if (p.major > 0) return String(p.major);
  if (p.minor > 0) return `0.${p.minor}`;
  return `0.0.${p.patch}`;
}
