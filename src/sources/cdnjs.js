/**
 * cdnjs API client
 *
 * Provides rate-limited, retrying access to the cdnjs.com REST API.
 * All requests use native fetch (Node.js ≥ 18 — no extra deps).
 *
 * Rate limit: 500 ms between consecutive requests to avoid hammering the CDN.
 * Retry policy: up to 3 attempts with exponential backoff on 5xx / network error.
 */

import { readCache, writeCache, clearNamespace } from './http-cache.js';

const BASE_URL = 'https://api.cdnjs.com';
const RATE_LIMIT_MS = 500;
const MAX_RETRIES = 3;
// cdnjs library/version metadata is effectively static; a day-old copy is fine
// and saves a network round-trip (plus the 500 ms rate-gate) on repeat sweeps.
const CDNJS_TTL_MS = 24 * 60 * 60 * 1000;

let _lastRequestTime = 0;

/**
 * Serve `key` from the on-disk cache when fresh, else run `fetcher`, cache its
 * (successful) result, and return it. Only successful fetches reach here —
 * `fetcher` throwing (network/5xx) propagates and nothing is cached, so a
 * transient failure is never memoized. Shared across the forked subprocesses a
 * mass/version sweep spawns, where an in-process cache would be empty each time.
 */
async function _cachedFetch(key, fetcher) {
  const hit = readCache('cdnjs', key, CDNJS_TTL_MS);
  if (hit !== null && hit !== undefined) return hit;
  const data = await fetcher();
  writeCache('cdnjs', key, data);
  return data;
}

/** Test-only: clear the on-disk cdnjs cache between test cases. */
export function _clearCdnjsCache() {
  clearNamespace('cdnjs');
}

async function _rateLimit() {
  const now = Date.now();
  const elapsed = now - _lastRequestTime;
  if (elapsed < RATE_LIMIT_MS) {
    await new Promise(resolve => setTimeout(resolve, RATE_LIMIT_MS - elapsed));
  }
  _lastRequestTime = Date.now();
}

async function _fetchWithRetry(url, attempt = 1) {
  await _rateLimit();
  let response;
  try {
    response = await fetch(url, {
      headers: { 'Accept': 'application/json', 'User-Agent': 'uopfuzz/1.0 (security-research)' }
    });
  } catch (networkError) {
    if (attempt < MAX_RETRIES) {
      await new Promise(r => setTimeout(r, 200 * attempt));
      return _fetchWithRetry(url, attempt + 1);
    }
    throw new Error(`Network error fetching ${url}: ${networkError.message}`);
  }

  if (response.status >= 500 && attempt < MAX_RETRIES) {
    await new Promise(r => setTimeout(r, 300 * attempt));
    return _fetchWithRetry(url, attempt + 1);
  }
  if (!response.ok) {
    throw new Error(`cdnjs API responded ${response.status} for ${url}`);
  }
  return response.json();
}

/**
 * Browse / search cdnjs libraries.
 *
 * @param {object} opts
 * @param {string} [opts.search=''] - Free-text search query
 * @param {number} [opts.limit=50]  - Max results (cdnjs cap: no hard cap, but keep reasonable)
 * @param {string} [opts.fields=''] - Extra fields to include (comma-separated)
 * @returns {Promise<Array>} Array of library objects
 */
export async function fetchLibraries({ search = '', limit = 50, fields = '' } = {}) {
  const baseFields = 'name,version,description,github,autoupdate';
  const allFields = fields ? `${baseFields},${fields}` : baseFields;
  const params = new URLSearchParams({ fields: allFields, limit: String(limit) });
  if (search) params.set('search', search);
  return _cachedFetch(`libraries?${params}`, async () => {
    const data = await _fetchWithRetry(`${BASE_URL}/libraries?${params}`);
    return data.results || [];
  });
}

/**
 * Fetch a single library's full metadata, including all available versions.
 *
 * @param {string} name - cdnjs library name (e.g. 'lodash')
 * @returns {Promise<object>} Library object with versions[], autoupdate, github, description
 */
export async function fetchLibrary(name) {
  const params = new URLSearchParams({ fields: 'name,version,versions,description,github,autoupdate,fileType,keywords' });
  return _cachedFetch(`library:${name}`, () =>
    _fetchWithRetry(`${BASE_URL}/libraries/${encodeURIComponent(name)}?${params}`));
}

/**
 * Fetch metadata for a specific version of a library.
 *
 * @param {string} name    - cdnjs library name
 * @param {string} version - Version string (e.g. '4.17.21')
 * @returns {Promise<object>} Version metadata (files, rawFiles, sri)
 */
export async function fetchLibraryVersion(name, version) {
  return _cachedFetch(`version:${name}@${version}`, () =>
    _fetchWithRetry(
      `${BASE_URL}/libraries/${encodeURIComponent(name)}/${encodeURIComponent(version)}`
    ));
}

/**
 * Resolve the npm package name for a cdnjs library.
 *
 * Prefers the npm autoupdate target (when source === 'npm') because that is
 * the installable package. Falls back to the library name itself.
 *
 * @param {object} lib - Library object from fetchLibrary / fetchLibraries
 * @returns {string}
 */
export function resolveNpmPackage(lib) {
  if (lib.autoupdate?.source === 'npm' && lib.autoupdate?.target) {
    return lib.autoupdate.target;
  }
  return lib.name;
}

/**
 * Filter a library list to JavaScript libraries only.
 *
 * Keeps libraries whose fileType is 'js' or whose latest distribution file
 * ends with '.js', and excludes CSS frameworks.
 *
 * @param {Array} libs - Array of library objects
 * @returns {Array}
 */
export function filterJSLibraries(libs) {
  return libs.filter(lib => {
    if (lib.fileType === 'js') return true;
    if (lib.fileType && lib.fileType !== 'js') return false;
    // Infer from latest file path if available
    const latestFile = lib.latest || '';
    return latestFile.endsWith('.js') || latestFile.endsWith('.min.js');
  });
}

/**
 * Sort libraries by GitHub star count (descending) and return the top N.
 *
 * Libraries without GitHub metadata are placed last (star count = 0).
 *
 * @param {Array}  libs - Array of library objects
 * @param {number} topN - Maximum items to return (0 = all)
 * @returns {Array}
 */
export function rankByStars(libs, topN = 0) {
  const sorted = [...libs].sort((a, b) => {
    const sa = a.github?.stargazers_count || 0;
    const sb = b.github?.stargazers_count || 0;
    return sb - sa;
  });
  return topN > 0 ? sorted.slice(0, topN) : sorted;
}
