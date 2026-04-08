/**
 * Version scanner helpers
 *
 * Provides version enumeration and selection strategies on top of the cdnjs API.
 * Version comparison uses semver-like logic with a string-comparison fallback.
 */

import { fetchLibrary } from './cdnjs.js';

/**
 * Fetch and sort all available versions for a cdnjs library.
 *
 * Versions are returned newest → oldest (semver descending).
 *
 * @param {string} cdnjsLibName - cdnjs library name
 * @returns {Promise<string[]>} Sorted version strings
 */
export async function getVersions(cdnjsLibName) {
  const lib = await fetchLibrary(cdnjsLibName);
  const versions = lib.versions || [];
  return sortVersionsDesc(versions);
}

/**
 * Select a subset of versions according to a strategy.
 *
 * @param {string[]} versions - Full sorted version list (newest → oldest)
 * @param {object}   strategy - Selection strategy
 * @param {'last'|'all'|'range'} strategy.mode
 * @param {number}  [strategy.count]  - For mode 'last': how many to take
 * @param {string}  [strategy.from]   - For mode 'range': start version (inclusive)
 * @param {string}  [strategy.to]     - For mode 'range': end version (inclusive)
 * @returns {string[]} Selected versions (newest → oldest)
 */
export function selectVersions(versions, strategy) {
  if (!strategy || strategy.mode === 'all') {
    return [...versions];
  }

  if (strategy.mode === 'last') {
    const count = Math.max(1, strategy.count || 1);
    return versions.slice(0, count);
  }

  if (strategy.mode === 'first') {
    // Oldest N versions (newest→oldest list, so take from the end)
    const count = Math.max(1, strategy.count || 1);
    return versions.slice(-count).reverse(); // oldest → newest order
  }

  if (strategy.mode === 'range') {
    const { from, to } = strategy;
    return versions.filter(v => {
      const afterFrom = !from || compareVersions(v, from) <= 0;  // v <= from (from is newer or equal)
      const beforeTo  = !to   || compareVersions(v, to)   >= 0;  // v >= to   (to is older or equal)
      return afterFrom && beforeTo;
    });
  }

  return [...versions];
}

/**
 * Build an installable package descriptor for a cdnjs library at a given version.
 *
 * @param {string} cdnjsLibName - cdnjs library name (for display)
 * @param {string} npmPackage   - The npm-installable package name (from resolveNpmPackage)
 * @param {string} version      - Exact version string
 * @returns {{ cdnjsName: string, npmPackage: string, version: string, installSpec: string }}
 */
export function resolveInstallable(cdnjsLibName, npmPackage, version) {
  return {
    cdnjsName: cdnjsLibName,
    npmPackage,
    version,
    installSpec: `${npmPackage}@${version}`
  };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Parse a version string into a numeric tuple for comparison.
 * Strips leading 'v' and ignore pre-release/build suffixes for ordering purposes.
 *
 * @param {string} v
 * @returns {number[]}
 */
function parseVersion(v) {
  return String(v)
    .replace(/^v/, '')
    .split(/[.\-+]/)
    .map(part => {
      const n = parseInt(part, 10);
      return isNaN(n) ? 0 : n;
    });
}

/**
 * Check if a version string contains a pre-release tag (alpha, beta, rc, dev, etc.)
 * @param {string} v
 * @returns {boolean}
 */
function isPreRelease(v) {
  return /[-.](?:alpha|beta|rc|dev|pre|canary|next|nightly|snapshot)\b/i.test(v);
}

/**
 * Compare two version strings.
 * Returns:
 *   > 0  if a is NEWER than b
 *   < 0  if a is OLDER than b
 *     0  if equal
 *
 * Pre-release versions (alpha, beta, rc, etc.) sort below their
 * corresponding release version: 4.0.0-beta.2 < 4.0.0.
 *
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const diff = (pa[i] || 0) - (pb[i] || 0);
    if (diff !== 0) return diff;
  }
  // Numeric parts are equal — pre-release sorts lower than stable
  const aPre = isPreRelease(a);
  const bPre = isPreRelease(b);
  if (aPre && !bPre) return -1; // a is pre-release, b is stable → a < b
  if (!aPre && bPre) return 1;  // a is stable, b is pre-release → a > b
  return 0;
}

/**
 * Sort an array of version strings newest → oldest.
 * @param {string[]} versions
 * @returns {string[]}
 */
export function sortVersionsDesc(versions) {
  return [...versions].sort((a, b) => compareVersions(b, a));
}
