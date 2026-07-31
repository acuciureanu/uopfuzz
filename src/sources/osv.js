import { compareVersions } from './version-scanner.js';
import { readCache, writeCache, clearNamespace } from './http-cache.js';

/**
 * OSV.dev API client — live known-vulnerability lookups.
 *
 * OSV (https://osv.dev, Google's Open Source Vulnerabilities database) aggregates
 * GHSA + CVE + many ecosystem advisory sources. We use it to back the disclosure-status
 * classification so "known-cve" reflects the live advisory ecosystem, not just the
 * hand-curated snapshot in known-gadgets.js.
 *
 * Mirrors src/sources/cdnjs.js conventions (rate limit, retry/backoff, headers)
 * with one deliberate divergence: this client is ENRICHMENT and must NEVER throw.
 * A thrown error here would abort the whole scan for something optional. Every
 * failure mode (offline, policy-blocked egress, DNS/TLS, timeout, 5xx, malformed
 * JSON) resolves to a safe `{ ok:false, vulns:[] }` so classification degrades to
 * static-DB-only.
 */

const BASE_URL = 'https://api.osv.dev/v1';
const RATE_LIMIT_MS = 500;
const MAX_RETRIES = 3;
const DEFAULT_TIMEOUT_MS = 5000;

let _lastRequestTime = 0;

async function _rateLimit() {
  const now = Date.now();
  const elapsed = now - _lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS - elapsed));
  }
  _lastRequestTime = Date.now();
}

// Dedupe identical (ecosystem, name, version) lookups across Orchestrator
// instances spawned by MassRunner/VersionRunner within one process.
const _cache = new Map();

/**
 * POST with retry/backoff. Throws on exhaustion / non-ok (caller catches).
 * Bounded by an AbortController so a hung connection can't stall scan startup.
 */
async function _postWithRetry(url, body, timeoutMs, attempt = 1) {
  await _rateLimit();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let response;
  try {
    response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'User-Agent': 'uopfuzz/1.0 (security-research)',
        // Do NOT keep the socket alive. An idle undici keep-alive socket left in
        // the fuzzer process becomes a landmine once fuzzing pollutes
        // Object.prototype: the socket's idle-timeout callback reads the polluted
        // `timeout` off the prototype chain and throws in undici's parser,
        // crashing the whole process. Closing the connection removes the socket.
        'Connection': 'close',
      },
      body: JSON.stringify(body),
      signal: controller.signal,
    });
  } catch (networkError) {
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, 200 * attempt));
      return _postWithRetry(url, body, timeoutMs, attempt + 1);
    }
    throw new Error(`Network error querying OSV: ${networkError.message}`);
  } finally {
    clearTimeout(timer);
  }

  if (response.status >= 500 && attempt < MAX_RETRIES) {
    await new Promise(r => setTimeout(r, 300 * attempt));
    return _postWithRetry(url, body, timeoutMs, attempt + 1);
  }
  if (!response.ok) {
    throw new Error(`OSV API responded ${response.status}`);
  }
  return response.json();
}

/**
 * Query OSV.dev for vulnerabilities affecting a package@version.
 * NEVER throws — always resolves to `{ ok, vulns, error? }`.
 *
 * @param {string} packageName
 * @param {string} version
 * @param {{ ecosystem?: string, timeoutMs?: number }} [opts]
 * @returns {Promise<{ok: boolean, vulns: Array, error?: string}>}
 */
export async function fetchOsvVulns(packageName, version, { ecosystem = 'npm', timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!packageName || !version) return { ok: false, vulns: [], error: 'missing package or version' };
  const cacheKey = `${ecosystem}:${packageName}@${version}`;
  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  // Tier 2: on-disk cache, shared across the forked subprocesses that each
  // Orchestrator runs in (where the in-process _cache above is always empty).
  // A hit here avoids the network POST, its 500 ms rate-gate, and re-leaking
  // the analyzed package@version to a third party.
  const disk = readCache('osv', cacheKey);
  if (disk) {
    const hit = { ok: true, vulns: Array.isArray(disk.vulns) ? disk.vulns : [], cached: true };
    _cache.set(cacheKey, hit);
    return hit;
  }

  let result;
  try {
    const data = await _postWithRetry(
      `${BASE_URL}/query`,
      { version, package: { name: packageName, ecosystem } },
      timeoutMs,
    );
    result = { ok: true, vulns: Array.isArray(data?.vulns) ? data.vulns : [] };
    // Only persist SUCCESSFUL lookups. Caching a failure (offline, 5xx) on disk
    // would wrongly suppress a real advisory on the next run within the TTL.
    writeCache('osv', cacheKey, { vulns: result.vulns });
  } catch (err) {
    result = { ok: false, vulns: [], error: err.message };
  }
  _cache.set(cacheKey, result);
  return result;
}

/** Test-only: clear both the in-process and on-disk caches between test cases. */
export function _clearOsvCache() {
  _cache.clear();
  clearNamespace('osv');
}

// ─── Pure helpers (no network) ───────────────────────────────────────────────

/**
 * Does `version` fall within any affected range of this OSV vuln?
 * Walks affected[].ranges[].events (introduced/fixed/last_affected) and the
 * explicit affected[].versions[] list, reusing compareVersions.
 */
export function isVersionAffected(vuln, version) {
  for (const aff of vuln?.affected || []) {
    if (Array.isArray(aff.versions) && aff.versions.includes(version)) return true;
    for (const range of aff.ranges || []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      if (_rangeContains(range.events || [], version)) return true;
    }
  }
  return false;
}

function _rangeContains(events, version) {
  let introduced = null;
  for (const ev of events) {
    if (ev.introduced !== undefined) {
      introduced = ev.introduced;
    } else if (ev.fixed !== undefined || ev.last_affected !== undefined) {
      if (introduced === null) continue; // malformed pair
      const fromOk = introduced === '0' || compareVersions(version, introduced) >= 0;
      const toOk = ev.fixed !== undefined
        ? compareVersions(version, ev.fixed) < 0
        : compareVersions(version, ev.last_affected) <= 0;
      if (fromOk && toOk) return true;
      introduced = null; // OSV allows multiple disjoint introduced/fixed pairs
    }
  }
  // Trailing unbounded interval (introduced with no terminating event).
  return introduced !== null && (introduced === '0' || compareVersions(version, introduced) >= 0);
}

/**
 * Is this OSV vuln a prototype-pollution-class advisory?
 *
 * OSV answers at package@version granularity and returns EVERY advisory for that
 * version. Only PP-class advisories may flip a finding's disclosure status to known-cve —
 * otherwise an unrelated CVE (ReDoS, path traversal…) at the same version would
 * bury a genuine undocumented PP vulnerability. Matches on CWE-1321 or PP keywords.
 */
export function isPrototypePollution(vuln) {
  if (!vuln) return false;
  const cweLists = [
    vuln.database_specific?.cwe_ids,
    ...(vuln.affected || []).map(a => a.database_specific?.cwe_ids),
  ];
  for (const list of cweLists) {
    if (Array.isArray(list) && list.some(c => String(c).toUpperCase() === 'CWE-1321')) return true;
  }
  const text = `${vuln.summary || ''} ${vuln.details || ''}`;
  return /prototype pollution|__proto__|proto\s*pollution/i.test(text);
}

/** Prefer a CVE alias for reporting parity with the static DB; else the OSV/GHSA id. */
export function preferredVulnId(vuln) {
  const cve = (vuln?.aliases || []).find(a => /^CVE-/i.test(a));
  return cve || vuln?.id || null;
}

/** Human-readable range string covering `version`, for report parity ('matchedRange'). */
export function describeMatchedRange(vuln, version) {
  for (const aff of vuln?.affected || []) {
    for (const range of aff.ranges || []) {
      if (range.type !== 'SEMVER' && range.type !== 'ECOSYSTEM') continue;
      let introduced = null;
      for (const ev of range.events || []) {
        if (ev.introduced !== undefined) {
          introduced = ev.introduced;
        } else if (ev.fixed !== undefined || ev.last_affected !== undefined) {
          if (introduced === null) continue;
          const fromOk = introduced === '0' || compareVersions(version, introduced) >= 0;
          const toOk = ev.fixed !== undefined
            ? compareVersions(version, ev.fixed) < 0
            : compareVersions(version, ev.last_affected) <= 0;
          if (fromOk && toOk) {
            if (ev.fixed !== undefined) {
              return introduced === '0' ? `<${ev.fixed}` : `>=${introduced} <${ev.fixed}`;
            }
            return introduced === '0' ? `<=${ev.last_affected}` : `>=${introduced} <=${ev.last_affected}`;
          }
          introduced = null;
        }
      }
    }
    if (Array.isArray(aff.versions) && aff.versions.includes(version)) return `=${version}`;
  }
  return null;
}

/**
 * First PP-class OSV advisory covering `version`, or null.
 * The single decision primitive the disclosure classifier consumes.
 *
 * @returns {{ cve: string, matchedRange: string|null, vuln: object } | null}
 */
export function osvKnownCve(osvVulns, version) {
  if (!Array.isArray(osvVulns)) return null;
  for (const vuln of osvVulns) {
    if (isPrototypePollution(vuln) && isVersionAffected(vuln, version)) {
      return { cve: preferredVulnId(vuln), matchedRange: describeMatchedRange(vuln, version), vuln };
    }
  }
  return null;
}

/** Count of non-PP advisories covering `version` (for an FYI note only). */
export function osvOtherAdvisories(osvVulns, version) {
  if (!Array.isArray(osvVulns)) return [];
  return osvVulns
    .filter(v => !isPrototypePollution(v) && isVersionAffected(v, version))
    .map(preferredVulnId)
    .filter(Boolean);
}
