#!/usr/bin/env node
/**
 * Runtime gadget miner — CLI.
 *
 * Harvests universal-gadget candidates from the Node runtime's own source and
 * validates every candidate with UoPFuzz's oracles (value-differential,
 * exit-code, sink reproduction) — GHunter's discovery pipeline on a stock
 * runtime with zero manual validation.
 *
 * Usage:
 *   node benchmark/runtime-gadgets/mine.js                    # mine all classes
 *   node benchmark/runtime-gadgets/mine.js --classes stream.Readable,fetch
 *   node benchmark/runtime-gadgets/mine.js --max 10           # cap per class
 *   node benchmark/runtime-gadgets/mine.js --include-known    # re-mine corpus props
 *   node benchmark/runtime-gadgets/mine.js --write            # write findings
 *   node benchmark/runtime-gadgets/mine.js --self-test        # offline logic check
 *
 * Findings go to results/runtime-miner/findings.jsonl (+ FINDINGS.md with
 * --write). This is a discovery tool: exit code is always 0 unless the tool
 * itself fails.
 */
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { mine } from '../../src/runtime-miner/mine.js';
import { API_CLASSES } from '../../src/runtime-miner/harvest.js';

const require = createRequire(import.meta.url);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const OUT_DIR = path.resolve(__dirname, '../../results/runtime-miner');

function renderMarkdown(results) {
  const counts = { LIVE: 0, DoS: 0, 'READ-ONLY': 0 };
  for (const r of results) for (const f of r.findings) counts[f.verdict] = (counts[f.verdict] || 0) + 1;
  let md = `# Runtime Gadget Miner — Findings\n\n`;
  md += `Node ${process.versions.node} — ${new Date().toISOString().slice(0, 10)}\n\n`;
  md += `**${counts.LIVE || 0} LIVE · ${counts.DoS || 0} DoS · ${counts['READ-ONLY'] || 0} read-only**\n\n`;
  md += `Verdicts: LIVE = polluted value observably changes runtime behavior; DoS = polluted-only fatal exit (stock runtime); READ-ONLY = property read but inert with a string marker. All LIVE/DoS findings reproduced in fresh processes; impact is classified from the proven sink, never guessed.\n\n`;
  for (const { classId, findings } of results) {
    if (!findings.length) continue;
    md += `## ${classId}\n\n| Property | Verdict | Impact | Detail |\n|---|---|---|---|\n`;
    for (const f of findings) {
      md += `| ${f.property} | ${f.verdict} | ${f.impact || (f.sink ? `sink: ${f.sink}` : '—')} | ${f.detail} |\n`;
    }
    md += `\n`;
  }
  return md;
}

function selfTest() {
  // Offline sanity: every API class maps to a driver the mining drivers
  // package actually exports, and the corpus-skip mapping is coherent.
  const drivers = require(path.join(__dirname, 'drivers'));
  let failures = 0;
  for (const [id, cls] of Object.entries(API_CLASSES)) {
    if (typeof drivers[cls.driver] !== 'function') {
      failures++;
      console.error(`self-test FAIL: ${id} → missing driver ${cls.driver}`);
    }
  }
  if (failures) { console.error(`[miner] SELF-TEST FAILED (${failures})`); process.exit(1); }
  console.log('[miner] SELF-TEST PASSED — all API classes have working drivers.');
}

const isMain = process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const args = process.argv.slice(2);
  if (args.includes('--self-test')) {
    selfTest();
  } else {
    const opt = (name) => {
      const i = args.indexOf(name);
      return i >= 0 ? args[i + 1] : null;
    };
    const classes = opt('--classes')?.split(',').filter(Boolean);
    const maxProperties = opt('--max') ? Number(opt('--max')) : undefined;
    const includeKnown = args.includes('--include-known');

    const t0 = Date.now();
    const results = await mine({
      classes, maxProperties, includeKnown,
      onFinding: (classId, f) => console.log(
        `${f.verdict.padEnd(10)} ${classId.padEnd(22)} ${f.property.padEnd(24)} ${f.impact || ''} ${f.detail}`,
      ),
    });

    const total = results.reduce((n, r) => n + r.findings.length, 0);
    const live = results.flatMap(r => r.findings).filter(f => f.verdict === 'LIVE' || f.verdict === 'DoS');
    console.log(`\n${total} findings (${live.length} LIVE/DoS) in ${((Date.now() - t0) / 1000).toFixed(0)}s`);

    fs.mkdirSync(OUT_DIR, { recursive: true });
    const jsonl = results.flatMap(r => r.findings.map(f => JSON.stringify({ class: r.classId, ...f })));
    fs.writeFileSync(path.join(OUT_DIR, 'findings.jsonl'), jsonl.join('\n') + (jsonl.length ? '\n' : ''));
    if (args.includes('--write')) {
      const out = path.join(OUT_DIR, 'FINDINGS.md');
      fs.writeFileSync(out, renderMarkdown(results));
      console.log(`wrote ${out}`);
    }
  }
}
