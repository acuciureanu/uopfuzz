#!/usr/bin/env node
/**
 * Runtime-gadget benchmark — UoPFuzz vs GHunter, head-to-head.
 *
 * Runs the GHunter Node gadget corpus (benchmark/runtime-gadgets/corpus.js)
 * through UoPFuzz's own oracles and reports, per gadget, whether the flow is
 * observed on THIS Node version:
 *
 *   DETECTED        — pollution observably reached the API (sink-token proof,
 *                     behavior change, or polluted-only crash for DoS entries)
 *   NOT-DETECTED    — no observation; a capability gap on a live gadget
 *   FIXED-UPSTREAM  — no observation AND the entry is documented as fixed in a
 *                     Node version <= the running one (the correct outcome)
 *
 * Usage:
 *   node benchmark/runtime-gadgets/run.js            # run + print the table
 *   node benchmark/runtime-gadgets/run.js --write    # also write RESULTS.md
 *   node benchmark/runtime-gadgets/run.js --self-test  # validate the classifier
 *
 * RESULTS.md is a committed artifact — like the main benchmark, it is only
 * regenerated with an explicit --write, never as a side effect.
 */
import { fork } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { reproduceRce } from '../../src/verification/reproduce.js';
import { executeInSandbox } from '../../src/utils/sandbox.js';
import { RUNTIME_GADGETS, DRIVERS_PACKAGE } from './corpus.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const NODE_VERSION = process.versions.node;

function versionGte(a, b) {
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) {
    if ((pa[i] || 0) !== (pb[i] || 0)) return (pa[i] || 0) > (pb[i] || 0);
  }
  return true;
}

/** Documented fix (fixedIn) or empirically-verified incidental hardening. */
function fixedOrMitigated(entry) {
  return (entry.fixedIn && versionGte(NODE_VERSION, entry.fixedIn)) || !!entry.mitigated;
}

/** Pure classification — separated from execution so --self-test can drive it. */
export function classify(entry, observation) {
  if (observation.detected) return 'DETECTED';
  if (entry.fixedIn && versionGte(NODE_VERSION, entry.fixedIn)) return 'FIXED-UPSTREAM';
  if (entry.mitigated) return 'MITIGATED-UPSTREAM';
  return 'NOT-DETECTED';
}

/** An entry's outcome is "as expected" unless it reveals a regression. */
export function isExpected(entry, verdict) {
  if (fixedOrMitigated(entry)) {
    return verdict === 'FIXED-UPSTREAM' || verdict === 'MITIGATED-UPSTREAM' || verdict === 'DETECTED-ANYWAY';
  }
  return verdict === 'DETECTED';
}

export async function probeRepro(entry) {
  const res = await reproduceRce(DRIVERS_PACKAGE, entry.entryPoint, {
    property: entry.property,
    minimalArgs: [{}],
  }, { blockNetwork: true, timeoutMs: 8000 });
  if (!res?.verified) return { detected: false, detail: res?.error || 'not verified' };
  const sinkOk = entry.expectSink == null || res.sink === entry.expectSink;
  return {
    detected: sinkOk,
    detail: sinkOk
      ? `${res.payloadType} @ ${res.sink || 'n/a'} (${res.runs}x)`
      : `verified but unexpected sink ${res.sink} (wanted ${entry.expectSink})`,
  };
}

export async function probeDifferential(entry) {
  const marker = `UOPF_MARK_${entry.id}`;
  const res = await executeInSandbox(DRIVERS_PACKAGE, entry.entryPoint, [{}], {
    mode: 'differential',
    timeoutMs: 8000,
    blockNetwork: true,
    pollution: { property: entry.property, value: marker },
  });
  if (!res || res.error) return { detected: false, detail: res?.error || 'no result' };
  const detected = !!(res.pollutionWasRead || res.outputChanged || res.errorChanged || res.prototypePolluted);
  const how = [
    res.pollutionWasRead && 'trap-read',
    res.outputChanged && 'output-changed',
    res.errorChanged && 'error-changed',
    res.prototypePolluted && 'prototype-mutated',
  ].filter(Boolean).join('+');
  return { detected, detail: how || 'no observable difference' };
}

/**
 * Multi-property combo probe — the conjunctive-gadget capability GHunter does
 * not have (it pollutes one property at a time). All descriptors are polluted
 * simultaneously; DETECTED requires BOTH markers to land in the expected
 * sink's recorded arguments in the same run.
 */
export async function probeMulti(entry) {
  const descriptors = entry.properties.map((p, i) => ({ property: p, value: `UOPF_COMBO_${entry.id}_${i}` }));
  const res = await executeInSandbox(DRIVERS_PACKAGE, entry.entryPoint, [], {
    mode: 'multi_property',
    timeoutMs: 8000,
    blockNetwork: true,
    pollution: { descriptors },
  });
  if (!res || res.error) return { detected: false, detail: res?.error || 'no result' };
  const hits = res.sinkAccesses?.filter(s => s.sink === entry.expectSink) || [];
  const allLanded = descriptors.every(d =>
    hits.some(h => (h.args || []).some(a => typeof a === 'string' && a.includes(d.value))));
  return {
    detected: allLanded,
    detail: allLanded
      ? `${descriptors.length}-property combo proved @ ${entry.expectSink}`
      : `combo incomplete (sink hits: ${hits.length}, read: ${(res.firedProperties || []).join('+') || 'none'})`,
  };
}

/**
 * Behavioral oracle: run a probe in a PLAIN process (stock runtime, loopback
 * allowed), clean vs polluted, and compare the printed fingerprints. For
 * gadgets whose effect only materializes in a live exchange (e.g. TLS
 * certificate verification) — invisible to both the sandbox (network blocked)
 * and the sink recorder (the option never appears as a call argument).
 */
export function probeBehavioral(entry) {
  const harness = path.join(DRIVERS_PACKAGE, 'behavioral-harness.js');
  const run = (polluted) => new Promise((resolve) => {
    const env = { ...process.env, UOPF_BHV_PROBE: entry.bhvProbe };
    delete env.UOPF_BHV_PROP;
    if (polluted) { env.UOPF_BHV_PROP = entry.property; env.UOPF_BHV_VALUE = entry.value; }
    if (polluted && entry.bhvType) env.UOPF_BHV_TYPE = entry.bhvType;
    const child = fork(harness, [], { env, stdio: ['ignore', 'pipe', 'ignore', 'ipc'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } resolve('TIMEOUT'); }, 15000);
    child.on('exit', () => { clearTimeout(timer); resolve(out.trim() || 'NO-OUTPUT'); });
    child.on('error', () => { clearTimeout(timer); resolve('SPAWN-ERROR'); });
  });
  // Sequential: behavioral probes bind FIXED loopback ports — parallel runs
  // would collide (EADDRINUSE) and corrupt both fingerprints.
  return (async () => {
    const clean = await run(false);
    const polluted = await run(true);
    return {
      detected: clean !== polluted && !['TIMEOUT', 'NO-OUTPUT', 'SPAWN-ERROR'].includes(polluted),
      detail: `clean "${clean}", polluted "${polluted}"`,
    };
  })();
}

/** GHunter §4.3: polluted-only unexpected termination on the STOCK runtime. */
export function probeDos(entry) {
  const harness = path.join(DRIVERS_PACKAGE, 'dos-harness.js');
  const run = (polluted) => new Promise((resolve) => {
    const env = { ...process.env };
    delete env.UOPF_DOS_PROP;
    if (polluted) {
      env.UOPF_DOS_PROP = entry.property;
      env.UOPF_DOS_VALUE = entry.value;
    }
    env.UOPF_DOS_DRIVER = entry.dosDriver;
    const child = fork(harness, [], { env, stdio: 'ignore' });
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch { /* gone */ } resolve(9); }, 15000);
    child.on('exit', (code, signal) => { clearTimeout(timer); resolve(signal ? 9 : (code ?? 9)); });
    child.on('error', () => { clearTimeout(timer); resolve(9); });
  });
  return Promise.all([run(false), run(true)]).then(([clean, polluted]) => {
    const detected = clean === 0 && polluted !== 0 && polluted !== 9;
    return {
      detected,
      detail: `clean exit ${clean}, polluted exit ${polluted}${polluted === 3 ? ' (hang)' : ''}`,
    };
  });
}

async function runCorpus() {
  const rows = [];
  for (const entry of RUNTIME_GADGETS) {
    const observation = entry.via === 'repro' ? await probeRepro(entry)
      : entry.via === 'differential' ? await probeDifferential(entry)
        : entry.via === 'multi' ? await probeMulti(entry)
          : entry.via === 'behavioral' ? await probeBehavioral(entry)
            : await probeDos(entry);
    let verdict = classify(entry, observation);
    // A fixed/mitigated gadget that IS still observable is noteworthy, not a failure.
    if (verdict === 'DETECTED' && fixedOrMitigated(entry)) {
      verdict = 'DETECTED-ANYWAY';
    }
    rows.push({ entry, observation, verdict, expected: isExpected(entry, verdict) });
    console.log(`${verdict.padEnd(16)} ${entry.id.padEnd(32)} ${entry.api.padEnd(26)} ${observation.detail}`);
  }
  return rows;
}

function renderResults(rows) {
  const detected = rows.filter(r => r.verdict === 'DETECTED' || r.verdict === 'DETECTED-ANYWAY').length;
  const fixed = rows.filter(r => r.verdict === 'FIXED-UPSTREAM' || r.verdict === 'MITIGATED-UPSTREAM').length;
  const missed = rows.filter(r => r.verdict === 'NOT-DETECTED').length;
  let md = `# Runtime-Gadget Benchmark — UoPFuzz vs GHunter\n\n`;
  md += `Corpus: GHunter's published Node.js universal-gadget PoCs (KTH-LangSec/server-side-prototype-pollution, nodejs/), property-level.\n\n`;
  md += `Node ${NODE_VERSION} — ${new Date().toISOString().slice(0, 10)}\n\n`;
  md += `**${detected} detected · ${fixed} confirmed fixed/mitigated upstream · ${missed} not detected** (${rows.length} entries)\n\n`;
  md += `| Verdict | Gadget | API | Property | Category | Observation |\n`;
  md += `|---|---|---|---|---|---|\n`;
  for (const { entry, observation, verdict } of rows) {
    const prop = entry.property || (entry.properties || []).join('+');
    md += `| ${verdict} | ${entry.id} | ${entry.api} | ${prop} | ${entry.category} | ${observation.detail} |\n`;
  }
  md += `\nVerdicts: DETECTED = flow observed by UoPFuzz's oracles (2x fresh-process proof for sink flows); FIXED-UPSTREAM = no effect and the gadget is documented as fixed in this Node version; MITIGATED-UPSTREAM = no documented fix, but direct experiment on this Node shows the gadget is dead (reason in the corpus entry); NOT-DETECTED = capability gap.\n`;
  return md;
}

function selfTest() {
  const fake = [
    { id: 'a', fixedIn: null },
    { id: 'b', fixedIn: '18.19.0' },
    { id: 'c', fixedIn: '99.0.0' },
    { id: 'd', mitigated: 'verified dead on this Node' },
  ];
  const cases = [
    [fake[0], { detected: true }, 'DETECTED'],
    [fake[0], { detected: false }, 'NOT-DETECTED'],
    [fake[1], { detected: false }, 'FIXED-UPSTREAM'],
    [fake[2], { detected: false }, 'NOT-DETECTED'], // fixed in a FUTURE version — still a gap
    [fake[3], { detected: false }, 'MITIGATED-UPSTREAM'],
    [fake[3], { detected: true }, 'DETECTED'],
  ];
  let failures = 0;
  for (const [entry, obs, want] of cases) {
    const got = classify(entry, obs);
    if (got !== want) { failures++; console.error(`self-test FAIL: ${entry.id} got ${got}, want ${want}`); }
  }
  if (failures) { console.error(`[runtime-gadgets] SELF-TEST FAILED (${failures})`); process.exit(1); }
  console.log('[runtime-gadgets] SELF-TEST PASSED — classifier verdicts correct.');
}

// Only run when invoked directly — the probe functions are imported by
// tests/integration/runtime-gadgets.test.js, which must not trigger a corpus run.
const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
const args = isMain ? process.argv.slice(2) : [];
if (isMain && args.includes('--self-test')) {
  selfTest();
} else if (isMain) {
  const rows = await runCorpus();
  const detected = rows.filter(r => r.verdict.startsWith('DETECTED')).length;
  const fixed = rows.filter(r => r.verdict === 'FIXED-UPSTREAM' || r.verdict === 'MITIGATED-UPSTREAM').length;
  const missed = rows.filter(r => r.verdict === 'NOT-DETECTED').length;
  console.log(`\n${detected} detected · ${fixed} fixed/mitigated upstream · ${missed} not detected (of ${rows.length})`);
  if (args.includes('--write')) {
    const out = path.join(__dirname, 'RESULTS.md');
    fs.writeFileSync(out, renderResults(rows));
    console.log(`wrote ${out}`);
  }
  const unexpected = rows.filter(r => !r.expected);
  if (unexpected.length) {
    console.error(`UNEXPECTED verdicts: ${unexpected.map(r => `${r.entry.id}=${r.verdict}`).join(', ')}`);
    process.exit(1);
  }
}
