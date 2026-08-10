import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from '../utils/logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Registry of proven prototype-pollution *sources* — the merge/set-style
 * functions that, fed attacker JSON, write to Object.prototype. A source is the
 * first half of a full `attacker-input -> source -> gadget -> sink` exploit; the
 * gadget half (a polluted property reaching a sink) is what the fuzzer already
 * proves. Pairing a proven gadget with a proven source and reproducing the whole
 * sequence in fresh processes is what makes a finding an end-to-end exploit
 * rather than a lead (see reproduceChain in ./reproduce.js).
 *
 * Because prototype pollution is a *global* effect, a source is
 * property-agnostic: a recursive merge can plant ANY attacker-named property, so
 * one registry entry satisfies any gadget's precondition. The registry is
 * therefore small and grows on its own — every `pp` finding the tool reproduces
 * is a new proven source (sourceFromPpProof + auto-append in the orchestrator).
 *
 * Storage mirrors gadget-analysis/discovery-store.js exactly: one append-only
 * JSONL file, never rewritten, fail-soft (a persistence error is logged at debug
 * and swallowed — it must never abort a scan).
 */

/** Default location: `<repo-root>/data/proven-sources.jsonl`. */
export const DEFAULT_SOURCES_PATH = path.resolve(
  __dirname, '..', '..', 'data', 'proven-sources.jsonl'
);

/**
 * A hermetic reference source shipped with the repo: a recursive deep-merge with
 * no __proto__ guard (tests/fixtures/vuln-merge). It reproduces the *universal*
 * PP-source primitive offline and deterministically, so chain reproduction never
 * depends on the network. Real currently-shipping sources (registry entries) are
 * the ones named in a finding's PoC; this fixture is the always-available
 * fallback the mechanism itself is validated against.
 */
export const REFERENCE_SOURCE = Object.freeze({
  package: path.resolve(__dirname, '..', '..', 'tests', 'fixtures', 'vuln-merge'),
  version: null,
  entryPoint: 'merge',
  callConvention: 'fn(target, payload)',
  payloadKind: 'proto-json',
  fixture: true,
  label: 'reference recursive-merge source (vuln-merge fixture)',
});

/**
 * Read the JSONL registry into an array of source entries. Never throws; a
 * missing/unreadable file yields `[]`, a malformed line is skipped. Mirrors
 * loadDiscoveries.
 *
 * @param {string} [filePath=DEFAULT_SOURCES_PATH]
 * @returns {Array<object>}
 */
export function loadSources(filePath = DEFAULT_SOURCES_PATH) {
  let raw;
  try {
    raw = fs.readFileSync(filePath, 'utf8');
  } catch (err) {
    if (err.code !== 'ENOENT') {
      logger.debug(`source-registry: could not read ${filePath}: ${err.message}`);
    }
    return [];
  }
  const sources = [];
  for (const line of raw.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const rec = JSON.parse(trimmed);
      if (rec && typeof rec === 'object' && rec.package && rec.entryPoint) sources.push(rec);
    } catch {
      logger.debug(`source-registry: skipping malformed line in ${filePath}`);
    }
  }
  return sources;
}

function sourceIdentity(s) {
  return `${s.package || ''}|${s.entryPoint || ''}|${s.callConvention || ''}|${s.payloadKind || ''}`;
}

/**
 * Append a source only if the registry holds no entry with the same identity
 * (package + entryPoint + callConvention + payloadKind). Best-effort/fail-soft,
 * same read-before-write contract as appendDiscoveryIfNew.
 *
 * @param {object} source
 * @param {string} [filePath=DEFAULT_SOURCES_PATH]
 * @returns {boolean} true when written, false when already present
 */
export function appendSourceIfNew(source, filePath = DEFAULT_SOURCES_PATH) {
  if (!source?.package || !source?.entryPoint) return false;
  const existing = loadSources(filePath);
  const id = sourceIdentity(source);
  if (existing.some(s => sourceIdentity(s) === id)) return false;
  try {
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.appendFileSync(filePath, JSON.stringify(source) + '\n');
  } catch (err) {
    logger.debug(`source-registry: could not append to ${filePath}: ${err.message}`);
    return false;
  }
  return true;
}

/**
 * Build a registry entry from a reproduced `pp` finding. The reproduction worker
 * (reproPP) returns exactly the two facts a source needs — the calling
 * convention that polluted and the payload kind — so a confirmed source is
 * self-describing.
 *
 * @param {{ callConvention?: string, payloadKind?: string }} proof - reproduceProto result
 * @param {{ package: string, version?: string, entryPoint: string }} ctx
 * @returns {object|null} a registry entry, or null if the proof lacks the shape
 */
export function sourceFromPpProof(proof, ctx) {
  if (!proof || !ctx?.package || !ctx?.entryPoint) return null;
  const payloadKind = proof.payloadKind;
  const callConvention = proof.callConvention;
  // Only merge/set-shaped sources are usable for chaining. A source whose proof
  // did not record a usable payload kind/convention is skipped rather than
  // guessed at.
  if (!payloadKind || !callConvention) return null;
  return {
    package: ctx.package,
    version: ctx.version || null,
    entryPoint: ctx.entryPoint,
    callConvention,
    payloadKind,
    discoveredAt: new Date().toISOString(),
  };
}
