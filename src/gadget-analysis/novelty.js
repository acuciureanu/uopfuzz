import { compareVersions } from '../sources/version-scanner.js';
import { getGadgetsForPackage } from './known-gadgets.js';

/**
 * Novelty / 0-day classifier.
 *
 * "0-day" means a previously-unknown vulnerability. A tool that re-discovers a
 * documented CVE has not found a 0-day. This module cross-references a
 * reproduction-proven finding against the built-in known-vulnerability database
 * (known-gadgets.js) using semver-range matching, and labels it:
 *
 *   - 'known-cve'  : package + property + version-in-documented-range matches a
 *                    known advisory. Good for regression, NOT a 0-day.
 *   - 'novel-0day' : no known advisory covers this package/property/version.
 *                    A candidate 0-day (still needs human confirmation before
 *                    disclosure). `regressionSuspect` is set when the property
 *                    matches a known CVE but the installed version is documented
 *                    as patched — genuinely ambiguous (real regression vs a
 *                    DB/range error), flagged for human triage.
 */

/**
 * Test whether `version` satisfies a range string as they appear in
 * known-gadgets.js: '*', '<x.y.z', '<=x.y.z', '>=x.y.z', exact 'x.y.z', or a
 * compound 'from..to' (inclusive). Returns false on unparseable input.
 *
 * @param {string} version
 * @param {string} range
 * @returns {boolean}
 */
export function versionInRange(version, range) {
  if (!version || !range) return false;
  const r = String(range).trim();
  if (r === '*') return true;

  // compound range: "4.0.0..4.17.0" (inclusive)
  if (r.includes('..')) {
    const [from, to] = r.split('..').map(s => s.trim());
    return compareVersions(version, from) >= 0 && compareVersions(version, to) <= 0;
  }

  const m = r.match(/^(<=|>=|<|>|=)?\s*(.+)$/);
  if (!m) return false;
  const op = m[1] || '=';
  const target = m[2].trim();
  const cmp = compareVersions(version, target);
  switch (op) {
    case '<':  return cmp < 0;
    case '<=': return cmp <= 0;
    case '>':  return cmp > 0;
    case '>=': return cmp >= 0;
    case '=':
    default:   return cmp === 0;
  }
}

/**
 * Extract the property name(s) associated with a finding for matching.
 * @param {object} finding
 * @returns {Set<string>}
 */
function findingProperties(finding) {
  const props = new Set();
  if (finding.source?.property) props.add(finding.source.property);
  for (const p of finding.differential?.pollutedProperties || []) {
    // pollutedProperties look like "Object.prototype.polluted" — take last key
    props.add(String(p).split('.').pop());
  }
  for (const p of finding.coPolluteProperties || []) props.add(p);
  return props;
}

/**
 * Classify a reproduction-proven finding as a known CVE or a novel 0-day.
 *
 * @param {object} finding - a confirmed chain (has source.property, etc.)
 * @param {{ package: string, version: string }} ctx
 * @returns {{ label: 'known-cve'|'novel-0day', cve?: string, matchedRange?: string, regressionSuspect?: boolean, note?: string }}
 */
export function classifyFinding(finding, ctx) {
  const pkg = (ctx.package || '').split('@')[0];
  const version = ctx.version || '';
  const props = findingProperties(finding);
  const known = getGadgetsForPackage(pkg);

  let propertyMatchOutsideRange = null;

  for (const entry of known) {
    const entryProp = entry.property || entry.payload?.property;
    // Sources are keyed by function; also allow function-name overlap for source bugs.
    const propMatch = entryProp && props.has(entryProp);
    const fnMatch = entry.function && finding.input?.entryPoint &&
      String(finding.input.entryPoint).split('.').pop() === entry.function;
    if (!propMatch && !fnMatch) continue;

    if (versionInRange(version, entry.versions)) {
      return { label: 'known-cve', cve: entry.cve || null, matchedRange: entry.versions };
    }
    // Property/function matches a known advisory but version is outside its range.
    propertyMatchOutsideRange = entry;
  }

  if (propertyMatchOutsideRange) {
    return {
      label: 'novel-0day',
      regressionSuspect: true,
      cve: propertyMatchOutsideRange.cve || null,
      note: `Reproduced on ${pkg}@${version}, documented as patched by ${propertyMatchOutsideRange.cve || 'advisory'} (${propertyMatchOutsideRange.versions}). Either a regression or a database/range error — human triage required.`,
    };
  }

  return { label: 'novel-0day' };
}
