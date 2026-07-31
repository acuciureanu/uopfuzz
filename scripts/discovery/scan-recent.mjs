#!/usr/bin/env node
// Discover PP-gadget-prone npm packages PUBLISHED RECENTLY (default: today, UTC)
// and emit a `pkg@version` targets file for the container sweep (sweep.sh).
//
// WHY relevance-filtered, not the full firehose: npm publishes thousands of
// versions/hour; scanning random packages for prototype pollution is pointless
// unless they expose a merge/clone/set/defaults/parse-style API. We query the
// registry search endpoint per PP-relevant keyword — each result carries the
// package's LAST-PUBLISH date and a popularity score — then keep the ones
// published since --since. This trades full coverage for signal; the coverage
// it does NOT provide (brand-new packages outside the top results for a keyword)
// is logged, never silently dropped.
//
// Usage:
//   node scan-recent.mjs [--since ISO] [--max N] [--min-downloads N] [--out FILE]
//   node scan-recent.mjs --since 2026-07-31 --max 40 --out targets-today.txt

const args = Object.fromEntries(
  process.argv.slice(2).join(' ').match(/--[\w-]+(?:\s+[^\s-][^\s]*)?/g)?.map(s => {
    const [k, ...v] = s.replace(/^--/, '').split(/\s+/);
    return [k, v.length ? v.join(' ') : true];
  }) || [],
);

const SINCE = args.since ? new Date(args.since) : new Date(new Date().toISOString().slice(0, 10)); // today 00:00 UTC
const MAX = parseInt(args.max || '40', 10);
const MIN_DL = parseInt(args['min-downloads'] || '50', 10);
const OUT = args.out || 'targets-recent.txt';

// Keywords that select for a fuzzable PP surface (recursive merge / deep set /
// object-path / config+format parsing). Extend freely.
const KEYWORDS = (args.keywords || [
  'merge', 'deepmerge', 'deep-merge', 'extend', 'defaults', 'assign',
  'set-value', 'object-path', 'dot-prop', 'clone-deep', 'mixin',
  'prototype', 'config', 'unflatten', 'query-string',
].join(',')).split(',').map(s => s.trim()).filter(Boolean);

// A package whose NAME carries one of these tokens is very likely to expose a
// fuzzable PP surface (a merge/clone/set/defaults/object-path API) — a far
// stronger relevance signal than a keyword match in the description, which
// surfaces unrelated giants (@aws-sdk/*, @wordpress/*). On by default; disable
// with --no-name-filter to scan every keyword hit.
const NAME_TOKENS = /(merge|deep|extend|defaults?|assign|set-?value|set-?in|clone|mixin|dot-?prop|object-?path|unflatten|flatten|pollut|proto)/i;
const NAME_FILTER = args['no-name-filter'] !== true;

const UA = { headers: { 'User-Agent': 'uopfuzz-recent/1.0 (security-research)', 'Accept': 'application/json' } };

async function searchKeyword(kw) {
  const url = `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(kw)}&size=250`;
  try {
    const r = await fetch(url, UA);
    if (!r.ok) return [];
    const j = await r.json();
    return (j.objects || []).map(o => ({
      name: o.package?.name,
      date: o.package?.date,
      popularity: o.score?.detail?.popularity ?? 0,
    })).filter(o => o.name && o.date);
  } catch { return []; }
}

async function weeklyDownloads(name) {
  try {
    const r = await fetch(`https://api.npmjs.org/downloads/point/last-week/${encodeURIComponent(name)}`, UA);
    if (!r.ok) return 0;
    return (await r.json()).downloads || 0;
  } catch { return 0; }
}

async function latestVersion(name) {
  try {
    const r = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name).replace('%40', '@')}/latest`, UA);
    if (!r.ok) return null;
    return (await r.json()).version || null;
  } catch { return null; }
}

console.error(`Discovering PP-relevant packages published since ${SINCE.toISOString()} …`);
console.error(`Keywords (${KEYWORDS.length}): ${KEYWORDS.join(', ')}`);

const byName = new Map();
for (const kw of KEYWORDS) {
  const hits = await searchKeyword(kw);
  for (const h of hits) {
    if (new Date(h.date) < SINCE) continue;              // not published today
    if (NAME_FILTER && !NAME_TOKENS.test(h.name)) continue; // name doesn't look PP-prone
    const prev = byName.get(h.name);
    if (!prev || h.popularity > prev.popularity) byName.set(h.name, h);
  }
  console.error(`  ${kw.padEnd(14)} ${hits.length} results, ${[...byName.keys()].length} fresh so far`);
}

let fresh = [...byName.values()];
console.error(`\n${fresh.length} distinct packages published since ${SINCE.toISOString().slice(0, 10)}.`);

// Enrich the shortlist with weekly downloads + the exact fresh version.
fresh.sort((a, b) => b.popularity - a.popularity);
const shortlist = fresh.slice(0, MAX * 3); // over-fetch, then filter by downloads
const enriched = [];
for (const p of shortlist) {
  const [dl, ver] = await Promise.all([weeklyDownloads(p.name), latestVersion(p.name)]);
  if (dl < MIN_DL || !ver) continue;
  enriched.push({ ...p, downloads: dl, version: ver });
}
enriched.sort((a, b) => b.downloads - a.downloads);
const picked = enriched.slice(0, MAX);

console.error(`\n=== SELECTED ${picked.length} (min ${MIN_DL} dl/wk, capped at ${MAX}; ${enriched.length - picked.length} more met the bar) ===`);
for (const p of picked) {
  console.error(`  ${String(p.downloads).padStart(9)}/wk  ${p.name}@${p.version}   (published ${p.date.slice(0, 10)})`);
}

const fs = await import('node:fs');
fs.writeFileSync(OUT, picked.map(p => `${p.name}@${p.version}`).join('\n') + '\n');
console.error(`\nWrote ${picked.length} targets → ${OUT}`);
