import { readCache, writeCache, clearNamespace } from './http-cache.js';

/**
 * npm / GitHub Advisory Database client — live known-vulnerability lookups via
 * the npm registry's bulk advisory endpoint.
 *
 * WHY THIS EXISTS (alongside osv.js): OSV.dev aggregates many sources but is NOT
 * a complete mirror of the GitHub Advisory Database. Real npm PP advisories are
 * missing from OSV — e.g. deep-defaults (GHSA-h6xg-rg33-9mf4 / CVE-2021-25944)
 * and deep-set (GHSA-wgxm-rg53-h2c6) are both absent from OSV yet present here.
 * With OSV as the ONLY "known" source, the disclosure classifier mislabels those
 * as `undocumented-vulnerability`, i.e. manufactures false 0-day candidates. This
 * endpoint (the same source `npm audit` uses, no auth) closes that gap so a
 * finding is only `undocumented` when NEITHER OSV NOR the GitHub Advisory DB
 * knows it.
 *
 * The endpoint answers at package@version granularity and returns ONLY advisories
 * that AFFECT the queried version — so any advisory it returns is, by
 * construction, in range (no client-side range math needed).
 *
 * Mirrors osv.js exactly on the non-negotiable contract: this client is
 * ENRICHMENT and must NEVER throw. Every failure mode (offline, egress-blocked,
 * DNS/TLS, timeout, 5xx, malformed JSON) resolves to `{ ok:false, advisories:[] }`
 * so classification degrades gracefully to whatever OSV + the static DB provide.
 */

const BULK_URL = 'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk';
const RATE_LIMIT_MS = 300;
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

const _cache = new Map();

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
        // Same reasoning as osv.js: never leave an idle keep-alive socket in a
        // process that is about to pollute Object.prototype — its idle-timeout
        // callback would read a polluted `timeout` off the prototype and crash
        // undici. Close the connection so no such socket lingers.
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
    throw new Error(`Network error querying npm advisories: ${networkError.message}`);
  } finally {
    clearTimeout(timer);
  }

  if (response.status >= 500 && attempt < MAX_RETRIES) {
    await new Promise(r => setTimeout(r, 300 * attempt));
    return _postWithRetry(url, body, timeoutMs, attempt + 1);
  }
  if (!response.ok) {
    throw new Error(`npm advisory API responded ${response.status}`);
  }
  return response.json();
}

/**
 * Query the npm bulk advisory endpoint for advisories affecting package@version.
 * NEVER throws — always resolves to `{ ok, advisories, error? }`. `advisories`
 * are the raw endpoint objects: `{ id, url, title, severity, vulnerable_versions,
 * cwe: string[], cvss }`.
 *
 * @param {string} packageName
 * @param {string} version
 * @param {{ timeoutMs?: number }} [opts]
 * @returns {Promise<{ok: boolean, advisories: Array, error?: string}>}
 */
export async function fetchNpmAdvisories(packageName, version, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  if (!packageName || !version) return { ok: false, advisories: [], error: 'missing package or version' };
  const cacheKey = `npm:${packageName}@${version}`;
  if (_cache.has(cacheKey)) return _cache.get(cacheKey);

  const disk = readCache('ghsa', cacheKey);
  if (disk) {
    const hit = { ok: true, advisories: Array.isArray(disk.advisories) ? disk.advisories : [], cached: true };
    _cache.set(cacheKey, hit);
    return hit;
  }

  let result;
  try {
    const data = await _postWithRetry(BULK_URL, { [packageName]: [version] }, timeoutMs);
    const advisories = Array.isArray(data?.[packageName]) ? data[packageName] : [];
    result = { ok: true, advisories };
    // Only persist successful lookups (caching a failure would wrongly suppress a
    // real advisory within the TTL) — identical policy to osv.js.
    writeCache('ghsa', cacheKey, { advisories });
  } catch (err) {
    result = { ok: false, advisories: [], error: err.message };
  }
  _cache.set(cacheKey, result);
  return result;
}

/** Test-only: clear both the in-process and on-disk caches between test cases. */
export function _clearNpmAdvisoryCache() {
  _cache.clear();
  clearNamespace('ghsa');
}

// ─── Pure helpers (no network) ───────────────────────────────────────────────

/** Pull the GHSA id out of an advisory's html url (…/advisories/GHSA-xxxx-…). */
function ghsaIdFromUrl(url) {
  const m = String(url || '').match(/GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}/i);
  return m ? m[0] : null;
}

/**
 * Adapt a raw npm-bulk advisory into the SAME minimal shape osv.js's pure
 * helpers consume (`isPrototypePollution`, `isVersionAffected`, `preferredVulnId`,
 * `osvKnownCve`). This lets the orchestrator merge GitHub-Advisory-DB results
 * into the existing `osvVulns` array so the disclosure classifier needs ZERO
 * changes — it already knows how to read this shape.
 *
 * - `database_specific.cwe_ids` carries the advisory's CWE list, so a CWE-1321
 *   advisory is recognised as prototype-pollution even if the title didn't say so.
 * - `affected[].versions = [version]` marks the version affected. Safe because the
 *   endpoint ONLY returns advisories that affect the queried version — so
 *   isVersionAffected is trivially and correctly true.
 * - `id` is the GHSA id; `aliases` carries any CVE so preferredVulnId still
 *   prefers the CVE for report parity with the static DB.
 *
 * @param {object} adv  raw endpoint advisory
 * @param {string} version  the version that was queried
 * @returns {object} OSV-vuln-shaped object
 */
export function npmAdvisoryToOsvVuln(adv, version) {
  const cves = Array.isArray(adv?.cves) ? adv.cves.filter(c => /^CVE-/i.test(c)) : [];
  const id = ghsaIdFromUrl(adv?.url) || (adv?.id != null ? `GHSA-${adv.id}` : null);
  return {
    id,
    aliases: cves,
    summary: adv?.title || '',
    details: adv?.title || '',
    database_specific: { cwe_ids: Array.isArray(adv?.cwe) ? adv.cwe : [] },
    // Provenance marker so a merged advisory is identifiable downstream.
    _source: 'ghsa',
    affected: [{
      package: { ecosystem: 'npm' },
      versions: [version],
    }],
  };
}
