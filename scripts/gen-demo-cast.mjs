#!/usr/bin/env node
// Generates assets/demo.cast — a curated, faithful recording of a real
// `--target lodash@4.17.4` run (see the transcript this was distilled from).
// Render to GIF with:  agg assets/demo.cast assets/demo.gif
//
// The lines below are the real tool output, tightened into a ~15s narrative.
import { writeFileSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(root, 'assets', 'demo.cast');
mkdirSync(dirname(out), { recursive: true });

const C = {
  reset: '\x1b[0m', dim: '\x1b[90m', bold: '\x1b[1m',
  green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m',
  blue: '\x1b[34m', cyan: '\x1b[36m', prompt: '\x1b[1;32m',
};
const info = (m) => `${C.green}info${C.reset}  ${m}`;

// [pause-before (s), text]. \r\n added automatically.
const script = [
  [0.4, `${C.prompt}$${C.reset} node src/cli.js --target lodash@4.17.4`, { type: true }],
  [0.6, ''],
  [0.2, `${C.blue}${C.bold}UoPFuzz — Prototype Pollution Gadget Hunter${C.reset}`],
  [0.5, info('Installing package: lodash@4.17.4')],
  [1.3, info('Auto-discovering target: lodash@4.17.4')],
  [1.1, info(`Auto-discovery complete: ${C.bold}966${C.reset} entry points, ${C.bold}17${C.reset} pollution candidates`)],
  [0.9, info('Differential oracle: clean vs. polluted execution …')],
  [1.2, ''],
  [0.7, `${C.yellow}${C.bold}✔ PROVEN PROTOTYPE-POLLUTION${C.reset}  ${C.bold}[KNOWN CVE CVE-2018-3721]${C.reset}`],
  [0.25, `  Object.prototype.polluted via ${C.cyan}merge${C.reset} — reproduced ${C.bold}2×${C.reset} in fresh processes`],
  [1.4, ''],
  [0.3, info('Analysis complete: 1 confirmed gadget, 1 unconfirmed candidate')],
  [0.6, info(`Report:  results/report.md   ${C.dim}(standalone PoC included)${C.reset}`)],
  [1.0, ''],
  [0.3, `${C.red}${C.bold}1 PROVEN vulnerability${C.reset} — reproduced in fresh processes`],
  [0.5, `${C.dim}1 unproven lead (did not reproduce — NOT a vulnerability)${C.reset}`],
  [2.6, ''],
];

const events = [];
let t = 0;
for (const [pause, text, opts] of script) {
  t += pause;
  if (opts?.type) {
    // Type the command out character by character for a live feel.
    for (const ch of text) { events.push([Number(t.toFixed(3)), 'o', ch]); t += 0.035; }
    events.push([Number(t.toFixed(3)), 'o', '\r\n']);
  } else {
    events.push([Number(t.toFixed(3)), 'o', text + '\r\n']);
  }
}

const header = { version: 2, width: 96, height: 20, timestamp: 0, env: { TERM: 'xterm-256color', SHELL: '/bin/zsh' } };
writeFileSync(out, [JSON.stringify(header), ...events.map((e) => JSON.stringify(e))].join('\n') + '\n');
console.log(`wrote ${out} (${events.length} events, ~${t.toFixed(1)}s)`);
