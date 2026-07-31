#!/usr/bin/env node
// Triage a sweep: read every results-*.json under a hunt directory, classify each
// reproduced gadget by disclosure label, and surface the UNDOCUMENTED ones (the
// candidate 0-days) with their standalone PoC for responsible disclosure.
//
// "Undocumented" here already means: reproduced 2x in fresh processes AND unknown
// to the static DB, OSV.dev, AND the GitHub Advisory DB (see
// src/gadget-analysis/disclosure.js). It still requires HUMAN confirmation before
// any disclosure — the maintainer is the disclosure channel, never this tool.
//
// Usage:
//   node scripts/discovery/triage.mjs [hunt-dir] [--json summary.json]
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';

const positional = process.argv.slice(2).filter(a => !a.startsWith('--'));
const jsonIdx = process.argv.indexOf('--json');
const JSON_OUT = jsonIdx !== -1 ? process.argv[jsonIdx + 1] : null;
const ROOT = path.resolve(positional[0] || 'results/hunt');

const rows = [];
const candidates = [];

for (const dir of readdirSync(ROOT)) {
  const d = path.join(ROOT, dir);
  if (!statSync(d).isDirectory()) continue;
  const jsons = readdirSync(d).filter(f => f.startsWith('results-') && f.endsWith('.json')).sort();
  if (!jsons.length) { rows.push({ target: dir, status: 'no-result' }); continue; }
  let res;
  try { res = JSON.parse(readFileSync(path.join(d, jsons[jsons.length - 1]), 'utf8')); }
  catch { rows.push({ target: dir, status: 'unreadable-result' }); continue; }
  const target = res.config ? `${res.config.name}@${res.config.version}` : dir;
  const chains = res.confirmedChains || [];
  if (!chains.length) { rows.push({ target, status: 'clean' }); continue; }
  for (const c of chains) {
    const label = c.disclosure?.label || 'unknown';
    rows.push({
      target, status: label,
      prop: c.source?.property, entry: c.input?.entryPoint,
      proof: c.proof?.type, cve: c.disclosure?.cve || '',
      source: c.disclosure?.source || '',
    });
    if (label === 'undocumented-vulnerability') {
      candidates.push({
        target, prop: c.source?.property, entry: c.input?.entryPoint,
        proof: c.proof?.type, regressionSuspect: !!c.disclosure?.regressionSuspect,
        poc: c.standalonePoC || null,
      });
    }
  }
}

const clean = rows.filter(r => r.status === 'clean').length;
console.log(`\n=== SWEEP TRIAGE (${ROOT}) ===`);
console.log(`  scanned: ${rows.length}   clean: ${clean}\n`);
for (const r of rows) {
  if (r.status === 'clean' || r.status === 'no-result' || r.status === 'unreadable-result') {
    console.log(`  ${r.target.padEnd(34)} ${r.status}`);
  } else {
    const src = r.source ? ` src=${r.source}` : '';
    console.log(`  ${r.target.padEnd(34)} ${r.status.toUpperCase()}  prop=${r.prop} entry=${r.entry} proof=${r.proof} ${r.cve}${src}`);
  }
}

console.log(`\n=== UNDOCUMENTED CANDIDATES (reproduced; unknown to static DB + OSV + GitHub Advisory DB): ${candidates.length} ===`);
for (const c of candidates) {
  console.log(`\n### ${c.target}  —  Object.prototype.${c.prop} via ${c.entry}  (${c.proof}${c.regressionSuspect ? ', regression-suspect' : ''})`);
  console.log(c.poc || '(no standalone PoC captured)');
}
if (!candidates.length) {
  console.log('  none — every reproduced gadget is a known advisory, or the targets are patched.');
}

if (JSON_OUT) {
  writeFileSync(JSON_OUT, JSON.stringify({
    scanned: rows.length, clean, candidateCount: candidates.length, candidates, rows,
  }, null, 2));
  console.log(`\nwrote machine-readable summary -> ${JSON_OUT}`);
}

// Non-zero exit ONLY when a candidate needs human eyes, so a scheduler can gate on it.
process.exit(candidates.length > 0 ? 2 : 0);
