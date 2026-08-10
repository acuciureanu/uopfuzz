/**
 * Runtime gadget miner — the dynamic half.
 *
 * GHunter (USENIX Security '24) enumerates universal-gadget candidates with a
 * patched V8 and validates them by hand (820 candidates → 56 gadgets, 31
 * person-hours). This miner harvests the same candidate set statically from
 * the runtime's own source (harvest.js) and validates every candidate
 * AUTOMATICALLY with UoPFuzz's oracles on a stock runtime:
 *
 *   1. value-differential — the class driver runs clean vs polluted in a
 *      sandbox worker; an observable output/error change means the runtime
 *      USED the polluted value → LIVE. A getter-trap read with no behavior
 *      change → READ-ONLY. Nothing → INERT.
 *   2. worker death during the polluted run, or a READ-ONLY/LIVE candidate,
 *      escalates to the exit-code oracle (plain process, clean vs polluted):
 *      a polluted-only non-zero exit → DoS (GHunter §4.3).
 *   3. LIVE candidates get a sink probe (2× fresh-process reproduction): if
 *      the marker reaches a recorded sink, the impact is classified from the
 *      PROVEN sink via gadget-analysis/sink-impact.js.
 *
 * Verdicts never rest on sink recording alone: the recorder intentionally
 * walks inherited properties, so any pollution is "visible" in any options
 * argument — only a behavior change or an exit-code difference proves use.
 */

import path from 'node:path';
import { fork } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { harvestClass, API_CLASSES } from './harvest.js';
import { executeInSandbox } from '../utils/sandbox.js';
import { reproduceRce } from '../verification/reproduce.js';
import { sinkImpact } from '../gadget-analysis/sink-impact.js';
import { RUNTIME_GADGETS } from '../../benchmark/runtime-gadgets/corpus.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DRIVERS_PACKAGE = path.resolve(__dirname, '../../benchmark/runtime-gadgets/drivers');
const MARKER = 'UOPF_MINE_9f2c7e';
// Second, distinct marker for severity grading (see below).
const MARKER_B = 'UOPF_MINEB_4d81aa';
// Typed markers for READ-ONLY candidates: a property the runtime validates by
// type is inert to a string but live to the right type. GHunter had the same
// string+object limitation; we cover the practical scalar/container set.
const TYPED_MARKERS = [
  { type: 'number', value: 1337 },
  { type: 'boolean', value: true },
  { type: 'object', value: { uopf: 'marker' } },
  { type: 'array', value: ['UOPF_ARR_MARK'] },
];

// Properties already encoded in the committed corpus per API — skipped unless
// the operator passes includeKnown (re-verifying them is the corpus's job).
function knownProps(classId) {
  const set = new Set();
  for (const e of RUNTIME_GADGETS) if (e.api === classId) set.add(e.property);
  return set;
}

/** Step 1: value-differential in a sandbox worker. */
export async function differentialProbe(driver, property, value = MARKER) {
  const res = await executeInSandbox(DRIVERS_PACKAGE, driver, [], {
    mode: 'differential',
    timeoutMs: 6000,
    blockNetwork: true,
    pollution: { property, value },
  });
  if (!res) return { verdict: 'UNSTABLE', detail: 'no result' };
  // Worker died mid-run: the pollution itself is a crash suspect — confirm
  // with the exit-code oracle before claiming anything.
  if (res.error && !('outputChanged' in res)) return { verdict: 'CRASH-SUSPECT', detail: res.error };
  if (res.outputChanged || res.errorChanged) return { verdict: 'LIVE', detail: 'behavior changed under pollution', res };
  if (res.pollutionWasRead || res.prototypePolluted) return { verdict: 'READ-ONLY', detail: 'read but inert with a string marker', res };
  return { verdict: 'INERT', detail: 'not read', res };
}

/**
 * Severity grading for a LIVE candidate — the automated analogue of the
 * triage GHunter does by hand. A second differential run with a DISTINCT
 * marker value separates:
 *   value-sensitive       — different polluted values give different observable
 *                           behavior (the value itself is consumed: real gadget)
 *   definedness-sensitive — any defined value flips the same branch (a truthy
 *                           gate or a validation that rejects any value alike)
 */
async function gradeLive(driver, property, firstRes, valueB = MARKER_B) {
  const second = await differentialProbe(driver, property, valueB);
  if (second.verdict !== 'LIVE') {
    return { grade: 'unstable', detail: 'not reproducible with a second marker' };
  }
  const a = firstRes?.polluted || {};
  const b = second.res?.polluted || {};
  const valueSensitive = a.output !== b.output || a.error !== b.error;
  return valueSensitive
    ? { grade: 'value-sensitive', detail: 'distinct marker values give distinct behavior' }
    : { grade: 'definedness-sensitive', detail: 'any defined value flips the same branch' };
}

/** A second, distinct value of the same type, for grading typed upgrades. */
function secondTypedValue(type) {
  const found = TYPED_MARKERS.find(t => t.type === type);
  if (!found) return MARKER_B;
  if (type === 'number') return 7331;
  if (type === 'boolean') return false;
  if (type === 'object') return { uopf: 'marker-b' };
  if (type === 'array') return ['UOPF_ARR_MARK_B'];
  return MARKER_B;
}

/**
 * Typed-marker upgrade for a READ-ONLY candidate: try number/boolean/object/
 * array markers; the first one that changes behavior upgrades the candidate
 * to LIVE and records which type the runtime actually consumes.
 */
async function typedMarkerUpgrade(driver, property) {
  for (const { type, value } of TYPED_MARKERS) {
    const r = await differentialProbe(driver, property, value);
    if (r.verdict === 'LIVE') {
      return { upgraded: true, markerType: type, res: r.res, verdict: 'LIVE' };
    }
    if (r.verdict === 'CRASH-SUSPECT') return { upgraded: true, markerType: type, verdict: 'CRASH-SUSPECT' };
  }
  return { upgraded: false };
}

/** Step 2: exit-code oracle in a plain process (GHunter §4.3). */
function dosProbe(driver, property, { type = 'string', value = MARKER } = {}) {
  const harness = path.join(DRIVERS_PACKAGE, 'dos-harness.js');
  const run = (polluted) => new Promise((resolve) => {
    const env = { ...process.env, UOPF_DOS_DRIVER: 'dos-mine', UOPF_DOS_PROBE: driver };
    delete env.UOPF_DOS_PROP;
    delete env.UOPF_DOS_TYPE;
    if (polluted) {
      env.UOPF_DOS_PROP = property;
      const isJson = type === 'object' || type === 'array';
      env.UOPF_DOS_VALUE = isJson ? JSON.stringify(value) : String(value);
      env.UOPF_DOS_TYPE = isJson ? 'json' : type;
    }
    const child = fork(harness, [], { env, stdio: 'ignore' });
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } resolve(9); }, 10000);
    child.on('exit', (code, signal) => { clearTimeout(timer); resolve(signal ? 9 : (code ?? 9)); });
    child.on('error', () => { clearTimeout(timer); resolve(9); });
  });
  return Promise.all([run(false), run(true)]).then(([clean, polluted]) => ({
    isDos: clean === 0 && polluted !== 0 && polluted !== 9,
    detail: `clean exit ${clean}, polluted exit ${polluted}`,
  }));
}

/** Step 3: sink probe for impact classification of LIVE candidates. */
async function sinkProbe(driver, property) {
  const res = await reproduceRce(DRIVERS_PACKAGE, driver, {
    property, minimalArgs: [],
  }, { blockNetwork: true, timeoutMs: 8000 });
  if (!res?.verified) return { sink: null, impact: null };
  const impact = res.sink ? sinkImpact(res.sink) : null;
  return { sink: res.sink || null, impact };
}

/**
 * Mine one API class. @returns {Promise<{classId, findings: object[]}>}
 * findings: { property, verdict, detail, sink?, impact? } — only non-INERT.
 */
export async function mineClass(classId, { maxProperties, includeKnown } = {}) {
  const cls = API_CLASSES[classId];
  if (!cls) throw new Error(`unknown API class: ${classId}`);
  const { properties } = harvestClass(classId);
  const known = includeKnown ? new Set() : knownProps(classId);
  let candidates = properties.filter(p => !known.has(p));
  if (maxProperties) candidates = candidates.slice(0, maxProperties);

  const findings = [];
  for (const property of candidates) {
    // Sink-primary classes (blocked APIs: child_process, worker_threads): the
    // sandbox stubs the call before behavior can differ, so the differential
    // oracle is blind. The sink recorder sees the arguments BEFORE the stub
    // throws — a marker landing in them is the proof of flow.
    if (cls.primaryOracle === 'sink') {
      const { sink, impact } = await sinkProbe(cls.driver, property);
      if (sink) {
        findings.push({
          property, verdict: 'LIVE', grade: 'value-sensitive',
          detail: `marker reached sink ${sink} (2x fresh processes)`,
          sink, impact: impact?.category || null,
        });
        continue;
      }
      // no sink hit — fall through to the differential path below
    }

    const step1 = await differentialProbe(cls.driver, property);
    let { verdict, detail } = step1;
    let grade = null;
    let markerType = 'string';
    let liveRes = step1.res;

    // L3: a string-inert candidate may be live to the right type.
    if (verdict === 'READ-ONLY') {
      const up = await typedMarkerUpgrade(cls.driver, property);
      if (up.upgraded) {
        verdict = up.verdict;
        markerType = up.markerType;
        liveRes = up.res;
        detail = `live with a ${up.markerType} marker (string-inert)`;
      }
    }
    // L1: grade every LIVE candidate with a second, distinct value of the type
    // that proved it (string markers for string finds, typed for typed finds).
    if (verdict === 'LIVE') {
      const g = await gradeLive(cls.driver, property, liveRes, secondTypedValue(markerType));
      grade = g.grade;
      detail = `${detail}; ${g.detail}`;
    }

    if (verdict === 'LIVE' || verdict === 'READ-ONLY' || verdict === 'CRASH-SUSPECT') {
      const dosValue = markerType === 'string' ? { value: MARKER } : { type: markerType, value: TYPED_MARKERS.find(t => t.type === markerType).value };
      const dos = await dosProbe(cls.driverDos || cls.driver, property, dosValue);
      if (dos.isDos) { verdict = 'DoS'; detail = dos.detail; }
      else if (verdict === 'CRASH-SUSPECT') { verdict = 'UNSTABLE'; detail = `${step1.detail}; no exit-code difference (${dos.detail})`; }
    }
    if (verdict === 'INERT' || verdict === 'UNSTABLE') continue;

    const finding = { property, verdict, detail };
    if (grade) finding.grade = grade;
    if (markerType !== 'string') finding.markerType = markerType;
    if (verdict === 'LIVE') {
      const { sink, impact } = await sinkProbe(cls.driver, property);
      if (sink) { finding.sink = sink; finding.impact = impact?.category || null; }
    }
    findings.push(finding);
  }
  return { classId, findings };
}

/** Mine several classes sequentially. */
export async function mine({ classes, maxProperties, includeKnown, onFinding } = {}) {
  const ids = classes || Object.keys(API_CLASSES);
  const results = [];
  for (const classId of ids) {
    const r = await mineClass(classId, { maxProperties, includeKnown });
    for (const f of r.findings) onFinding?.(classId, f);
    results.push(r);
  }
  return results;
}
