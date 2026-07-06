import { compareVersions } from '../sources/version-scanner.js';
import { getGadgetsForPackage, PP_SOURCES } from './known-gadgets.js';
import { osvKnownCve, osvOtherAdvisories } from '../sources/osv.js';
import { findPriorSighting } from './discovery-store.js';
import { packageBaseName } from '../utils/package-name.js';

/**
 * Novelty / undocumented-vulnerability classifier.
 *
 * "Undocumented" means no public advisory (static DB or OSV.dev) covers this
 * finding. A tool that re-discovers a documented CVE has not found anything
 * undocumented. This module cross-references a reproduction-proven finding
 * against (1) the built-in static known-vulnerability database
 * (known-gadgets.js), (2) — when available — live OSV.dev advisories, and (3)
 * this tool's own durable discovery store, labelling it:
 *
 *   - 'known-cve'                  : a documented advisory (static DB and/or OSV)
 *                                    covers this package@version. Good for
 *                                    regression, not undocumented.
 *   - 'undocumented-vulnerability' : no known advisory covers it and this tool
 *                                    has never recorded it before. A candidate
 *                                    undocumented vulnerability (still needs
 *                                    human confirmation before disclosure).
 *   - 'previously-discovered'      : no public advisory, but this tool recorded
 *                                    the same bug on an earlier run — a
 *                                    rediscovery, not a first sighting. Carries
 *                                    `priorSighting.{discoveredAt,version}`.
 *
 * `regressionSuspect` marks the ambiguous case where the static DB documents the
 * package as patched at this version yet it still reproduced (label stays
 * 'undocumented-vulnerability' with the flag set — a regression triage signal,
 * distinct from a clean first sighting).
 *
 * `source` records provenance of a known-cve label: 'static' | 'osv' | 'static+osv'.
 *
 * OSV is class-aware: only prototype-pollution advisories (see
 * src/sources/osv.js `isPrototypePollution`) may flip a finding to known-cve.
 * An unrelated CVE at the same version must never bury a genuine undocumented PP vulnerability.
 */

/**
 * Test whether `version` satisfies a range string as they appear in
 * known-gadgets.js: '*', '<x.y.z', '<=x.y.z', '>=x.y.z', exact 'x.y.z', or a
 * compound 'from..to' (inclusive). Returns false on unparseable input.
 */
export function versionInRange(version, range) {
  if (!version || !range) return false;
  const r = String(range).trim();
  if (r === '*') return true;

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

/** Extract property name(s) associated with a finding for static-DB matching. */
function findingProperties(finding) {
  const props = new Set();
  if (finding.source?.property) props.add(finding.source.property);
  for (const p of finding.differential?.pollutedProperties || []) {
    props.add(String(p).split('.').pop());
  }
  for (const p of finding.coPolluteProperties || []) props.add(p);
  return props;
}

/**
 * Merge the static-DB verdict with the OSV signal per the decision table.
 * OSV is already class-filtered to prototype-pollution advisories.
 */
function combineWithOsv({ pkg, version, staticInRange, staticOutOfRange, regressionNote, osvVulns }) {
  const osv = osvKnownCve(osvVulns, version);            // PP-class match or null
  const otherAdv = osvOtherAdvisories(osvVulns, version); // non-PP ids (FYI only)
  const osvNote = otherAdv.length
    ? `OSV lists ${otherAdv.length} other (non-prototype-pollution) advisor${otherAdv.length !== 1 ? 'ies' : 'y'} at this version: ${otherAdv.slice(0, 3).join(', ')}${otherAdv.length > 3 ? '…' : ''}.`
    : null;
  const withNote = (obj) => (osvNote ? { ...obj, osvNote } : obj);

  // Static DB confirms a documented range covering this version.
  if (staticInRange) {
    return withNote({
      label: 'known-cve',
      cve: staticInRange.cve || osv?.cve || null,
      matchedRange: staticInRange.versions,
      source: osv ? 'static+osv' : 'static',
    });
  }

  // Static DB documents the package but this version is outside its range.
  if (staticOutOfRange) {
    if (osv) {
      // OSV independently confirms this version IS affected → static DB is stale,
      // not a regression. Clean known-cve, no human triage needed.
      return withNote({
        label: 'known-cve',
        cve: osv.cve,
        matchedRange: osv.matchedRange,
        source: 'osv',
        note: `OSV advisory ${osv.cve} confirms ${pkg}@${version} is affected; the static DB's documented range (${staticOutOfRange.versions}) appears stale.`,
      });
    }
    return withNote({
      label: 'undocumented-vulnerability',
      regressionSuspect: true,
      cve: staticOutOfRange.cve || null,
      note: regressionNote,
      source: 'static',
    });
  }

  // Static DB has nothing for this package/property.
  if (osv) {
    return withNote({
      label: 'known-cve',
      cve: osv.cve,
      matchedRange: osv.matchedRange,
      source: 'osv',
    });
  }

  // Nothing known anywhere → candidate undocumented vulnerability.
  return withNote({ label: 'undocumented-vulnerability' });
}

/**
 * Classify a reproduction-proven finding as a known CVE, a rediscovery, or a
 * first-sighting undocumented vulnerability.
 *
 * Precedence (highest first):
 *   1. Static-DB / OSV documented advisory          → 'known-cve'
 *   2. Documented as patched yet still reproduces   → 'undocumented-vulnerability'
 *      with `regressionSuspect: true` (triage signal)
 *   3. No public advisory, but a prior sighting in
 *      `ctx.priorDiscoveries` (this tool's own store) → 'previously-discovered'
 *   4. Otherwise (first sighting, no advisory)      → 'undocumented-vulnerability'
 *
 * Steps 1–2 are unchanged from before; step 3 is the new rediscovery
 * recognition. `ctx.priorDiscoveries` defaults to `[]` (same backward-compatible
 * pattern `osvVulns` already uses — passing nothing is identical to today).
 *
 * @param {object} finding - a confirmed chain (has source.property, etc.)
 * @param {{ package: string, version: string, proofType?: 'pp'|'rce', osvVulns?: Array|null, priorDiscoveries?: Array }} ctx
 * @returns {{ label: 'known-cve'|'undocumented-vulnerability'|'previously-discovered', cve?: string, matchedRange?: string, regressionSuspect?: boolean, note?: string, source?: string, osvNote?: string, priorSighting?: { discoveredAt: string, version: string } }}
 */
export function classifyFinding(finding, ctx) {
  const pkg = packageBaseName(ctx.package || '');
  const version = ctx.version || '';
  const osvVulns = ctx.osvVulns;

  // ── PP SOURCE bugs (proofType 'pp') ────────────────────────────────────────
  // A prototype-pollution *source* (a merge/clone/set function that writes an
  // attacker-chosen key onto a prototype) is ONE bug regardless of which property
  // demonstrates it. Novelty keys on package + version, not the arbitrary property.
  let verdict;
  if (ctx.proofType === 'pp') {
    const pkgSources = PP_SOURCES.filter(s => s.package === pkg);
    const staticInRange = pkgSources.find(s => versionInRange(version, s.versions)) || null;
    const staticOutOfRange = !staticInRange && pkgSources.length > 0 ? pkgSources[0] : null;
    const regressionNote = staticOutOfRange
      ? `Reproduced prototype-pollution source in ${pkg}@${version}; the package has a documented PP source (${staticOutOfRange.cve || 'advisory'} ${staticOutOfRange.versions}) but this version is outside that range — regression or DB/range error, human triage required.`
      : null;
    verdict = combineWithOsv({ pkg, version, staticInRange, staticOutOfRange, regressionNote, osvVulns });
    // A PP source is one bug per polluting function — match prior sightings
    // property-agnostically, mirroring the static-DB logic above.
    return applyPriorSighting(verdict, ctx.priorDiscoveries, { package: pkg, entryPoint: finding.input?.entryPoint });
  }

  // ── PP GADGET bugs (proofType 'rce') ───────────────────────────────────────
  const props = findingProperties(finding);
  const known = getGadgetsForPackage(pkg);

  let staticInRange = null;
  let staticOutOfRange = null;
  for (const entry of known) {
    const entryProp = entry.property || entry.payload?.property;
    const propMatch = entryProp && props.has(entryProp);
    const fnMatch = entry.function && finding.input?.entryPoint &&
      String(finding.input.entryPoint).split('.').pop() === entry.function;
    if (!propMatch && !fnMatch) continue;

    if (versionInRange(version, entry.versions)) { staticInRange = entry; break; }
    staticOutOfRange = entry; // property/function matches but version out of range
  }

  const regressionNote = staticOutOfRange
    ? `Reproduced on ${pkg}@${version}, documented as patched by ${staticOutOfRange.cve || 'advisory'} (${staticOutOfRange.versions}). Either a regression or a database/range error — human triage required.`
    : null;

  verdict = combineWithOsv({ pkg, version, staticInRange, staticOutOfRange, regressionNote, osvVulns });
  return applyPriorSighting(verdict, ctx.priorDiscoveries, {
    package: pkg,
    entryPoint: finding.input?.entryPoint,
    property: finding.source?.property,
  });
}

/**
 * Precedence step: a clean first-sighting (undocumented, not a regression
 * suspect) becomes `previously-discovered` when this tool already recorded it.
 * Static-DB / OSV / regression-suspect verdicts are returned untouched — they
 * outrank a prior sighting.
 */
function applyPriorSighting(verdict, priorDiscoveries, key) {
  if (!verdict || verdict.label !== 'undocumented-vulnerability' || verdict.regressionSuspect) {
    return verdict;
  }
  const prior = findPriorSighting(priorDiscoveries || [], key);
  if (!prior) return verdict;
  return {
    ...verdict,
    label: 'previously-discovered',
    priorSighting: {
      discoveredAt: prior.discoveredAt || null,
      version: prior.version || null,
    },
  };
}
