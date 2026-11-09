// Look up known vulnerabilities for installed packages using the npm registry's
// bulk advisory API (the same GitHub Advisory Database data `npm audit` uses),
// and list published versions so we can pick the smallest safe upgrade.

const DEFAULT_REGISTRY = 'https://registry.npmjs.org';
const SEVERITY_RANK = { info: 0, low: 1, moderate: 2, high: 3, critical: 4 };

export function severityRank(severity) {
  return typeof severity === 'string' && Object.hasOwn(SEVERITY_RANK, severity) ? SEVERITY_RANK[severity] : 0;
}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// The registry decides what counts as vulnerable, so it must be reached over HTTPS.
// Plain HTTP is allowed only for a registry on this machine (tests, local mirrors).
export function registryUrl(value = process.env.SCA_TRIAGE_REGISTRY) {
  const raw = (value || DEFAULT_REGISTRY).replace(/\/+$/, '');
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`SCA_TRIAGE_REGISTRY is not a valid URL: ${raw}`);
  }
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && local)) {
    throw new Error(`SCA_TRIAGE_REGISTRY must use https:// (plain http is allowed only for localhost): ${raw}`);
  }
  if (url.username || url.password) throw new Error('SCA_TRIAGE_REGISTRY must not contain credentials');
  return raw;
}

async function fetchJson(url, init) {
  const res = await fetch(url, { ...init, signal: AbortSignal.timeout(30_000) });
  if (!res.ok) throw new Error(`${init?.method || 'GET'} ${url} -> HTTP ${res.status}`);
  try {
    return await res.json();
  } catch {
    throw new Error(`${init?.method || 'GET'} ${url} -> response is not JSON`);
  }
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

// installs: [{name, version}] -> { [name]: [{ghsa, title, severity, vulnerableVersions, url, cwe, cvss}] }
// The registry returns only advisories that affect at least one of the versions sent,
// so triage also sends its candidate upgrade targets through here.
export async function fetchAdvisories(installs) {
  const query = new Map();
  for (const { name, version } of installs) {
    if (!query.has(name)) query.set(name, new Set());
    query.get(name).add(version);
  }
  if (!query.size) return Object.create(null);
  const body = Object.fromEntries([...query].map(([n, v]) => [n, [...v]]));
  const raw = await fetchJson(`${registryUrl()}/-/npm/v1/security/advisories/bulk`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  return normalizeAdvisories(raw);
}

// The response decides what is reported as vulnerable, so anything that isn't the
// documented shape is an error (exit 2), never "no advisories".
export function normalizeAdvisories(raw) {
  if (!isPlainObject(raw)) throw new Error('advisory response is not an object of {package: [advisory]}');
  const out = Object.create(null);
  for (const [name, list] of Object.entries(raw)) {
    if (!Array.isArray(list)) throw new Error(`advisory response for "${name}" is not a list`);
    for (const a of list) {
      if (!isPlainObject(a) || typeof a.vulnerable_versions !== 'string') {
        throw new Error(`advisory response for "${name}" has an entry without vulnerable_versions`);
      }
    }
    out[name] = list.map((a) => ({
      ghsa: String(a.url || '').split('/').pop() || String(a.id),
      title: a.title,
      severity: a.severity,
      vulnerableVersions: a.vulnerable_versions,
      url: a.url,
      cwe: a.cwe || [],
      cvss: a.cvss?.score ?? null,
    }));
  }
  return out;
}

// All published versions of a package (abbreviated metadata keeps this small).
export async function fetchVersions(name) {
  const encoded = name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
  const doc = await fetchJson(`${registryUrl()}/${encoded}`, {
    headers: { accept: 'application/vnd.npm.install-v1+json' },
  });
  if (!isPlainObject(doc) || !isPlainObject(doc.versions)) {
    throw new Error(`registry response for "${name}" has no versions object`);
  }
  return Object.keys(doc.versions);
}
