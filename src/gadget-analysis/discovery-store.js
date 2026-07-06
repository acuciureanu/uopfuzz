import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from '../utils/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Durable, append-only store of every vulnerability this tool has ever
 * confirmed — the cross-run memory that makes "what has UoPFuzz found?" an
 * answerable question.
 *
 * Storage is one JSONL file (`data/discovered-gadgets.jsonl`), one JSON object
 * per line, never rewritten. "Has this been seen before" is a forward scan for
 * any earlier line with a matching identity key — no read-modify-write. This
 * also keeps concurrent appends safe: each append is a single `write()` syscall
 * (atomic on POSIX for sub-pipe-buffer writes), so parallel orchestrator
 * instances (`MassRunner`/`VersionRunner`, `--parallel N`) can't interleave.
 *
 * The whole module is fail-soft, mirroring `src/sources/osv.js`: a persistence
 * failure is logged at debug level and otherwise swallowed — it must never
 * abort a scan that has already reproduced a real vulnerability.
 */

/** Default location: `<repo-root>/data/discovered-gadgets.jsonl`. */
export const DEFAULT_DISCOVERY_STORE_PATH = path.resolve(
  __dirname, '..', '..', 'data', 'discovered-gadgets.jsonl'
);

/**
 * Read and parse the JSONL store into an array of records.
 *
 * Never throws. A missing file, an unreadable file, or a malformed line all
 * degrade gracefully — `[]` for a wholly missing/empty store, or the valid
 * subset when only some lines are malformed (a bad line is skipped, not fatal
 * to the whole read). Mirrors the defensive contract `src/sources/osv.js`
 * already uses for OSV.dev lookups.
 *
 * @param {string} [filePath=DEFAULT_DISCOVERY_STORE_PATH]
 * @returns {Array<object>}
 */
export function loadDiscoveries(filePath = DEFAULT_DISCOVERY_STORE_PATH) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    if (err.code !== 'ENOENT') {
      logger.debug(`discovery-store: could not read ${filePath}: ${err.message}`);
    }
    return [];
  }
  const records = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const rec = JSON.parse(trimmed);
      if (rec && typeof rec === 'object') records.push(rec);
    } catch {
      logger.debug(`discovery-store: skipping malformed line in ${filePath}`);
    }
  }
  return records;
}

/**
 * Append one record to the store as a single JSON line.
 *
 * Never throws: a persistence failure is logged at debug level and otherwise
 * swallowed. Ensures the parent directory exists (first-ever discovery should
 * still persist on a fresh checkout). Appends a trailing newline so each record
 * is a standalone line.
 *
 * @param {object} record - the discovery record to append.
 * @param {string} [filePath=DEFAULT_DISCOVERY_STORE_PATH]
 */
export function appendDiscovery(record, filePath = DEFAULT_DISCOVERY_STORE_PATH) {
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, JSON.stringify(record) + '\n');
  } catch (err) {
    logger.debug(`discovery-store: could not append to ${filePath}: ${err.message}`);
  }
}

/**
 * Find the earliest prior sighting of the same bug in `discoveries`.
 *
 * Identity key (version-agnostic): `package + entryPoint + property`. If
 * `property` is omitted/empty, the match is property-agnostic (used for PP
 * *source* bugs, where the attacker property is arbitrary and the bug is tied
 * to the polluting function — same model the novelty classifier already uses
 * for PP sources). Returns the earliest matching record by `discoveredAt`, or
 * `null` if none.
 *
 * @param {Array<object>} discoveries
 * @param {{ package: string, entryPoint: string, property?: string }} key
 * @returns {object|null}
 */
export function findPriorSighting(discoveries, key) {
  if (!Array.isArray(discoveries) || !key) return null;
  const pkg = (key.package || '').split('@')[0];
  const entryPoint = key.entryPoint || '';
  const property = key.property || '';
  if (!pkg || !entryPoint) return null;

  let earliest = null;
  for (const rec of discoveries) {
    if (!rec || rec.package !== pkg) continue;
    if ((rec.entryPoint || '') !== entryPoint) continue;
    if (property && (rec.property || '') !== property) continue;
    if (!earliest || (rec.discoveredAt || '') < (earliest.discoveredAt || '')) {
      earliest = rec;
    }
  }
  return earliest;
}

/**
 * Build a store record from a confirmed chain. The store label collapses the
 * novelty verdict into the distinct audit-trail buckets the store tracks:
 * `known-cve`, `regression-suspect`, `previously-discovered`, or
 * `undocumented-vulnerability`. (A regression-suspect is recorded as such, not
 * as an undocumented-vulnerability, so the audit trail can distinguish them.)
 *
 * @param {object} chain - a confirmed chain (carries `chain.novelty`)
 * @param {{ package: string, version: string, proofType?: string }} ctx
 * @returns {object}
 */
export function buildRecord(chain, ctx) {
  const nov = chain.novelty || {};
  let label;
  if (nov.label === 'known-cve') {
    label = 'known-cve';
  } else if (nov.label === 'previously-discovered') {
    label = 'previously-discovered';
  } else if (nov.regressionSuspect) {
    label = 'regression-suspect';
  } else {
    label = 'undocumented-vulnerability';
  }

  const proofType = ctx.proofType || (chain.proof?.type === 'code-execution' ? 'rce' : 'pp');
  const property = chain.source?.property || '';
  const entryPoint = chain.input?.entryPoint || '';
  const kind = proofType === 'rce' ? 'CODE-EXECUTION' : 'PROTOTYPE-POLLUTION';

  return {
    discoveredAt: new Date().toISOString(),
    package: (ctx.package || '').split('@')[0],
    version: ctx.version || '',
    entryPoint,
    property,
    proofType,
    label,
    description: `CONFIRMED ${kind}: Object.prototype.${property} via ${entryPoint}`,
    cvssVector: chain.metadata?.cvssVector || null,
    riskLevel: chain.riskLevel ?? null,
    standalonePoC: chain.standalonePoC || null,
  };
}
