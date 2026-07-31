import { benchmarkDetection, getGadgetsForPackage } from '../gadget-analysis/known-gadgets.js';

/**
 * Markdown Report Generator
 *
 * Three public functions:
 *   generateSingleReport(results, config)   — full analysis for one library@version
 *   generateMassReport(allResults)          — summary table across many libraries
 *   generateVersionReport(versionResults)   — version timeline for a single library
 *
 * Output is optimised for AI consumption (Claude Code, GPT-4, etc.) by using
 * standard Markdown headings, tables, and fenced code blocks throughout.
 */

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ts() {
  return new Date().toISOString();
}

function durationStr(startTime, endTime) {
  if (!startTime || !endTime) return 'N/A';
  const ms = new Date(endTime) - new Date(startTime);
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

function pct(n, d) {
  if (!d) return '0.0%';
  return `${((n / d) * 100).toFixed(1)}%`;
}

function riskBadge(riskLevel) {
  const score = parseFloat(riskLevel) || 0;
  if (score >= 9.0) return '**CRITICAL**';
  if (score >= 7.0) return '**HIGH**';
  if (score >= 4.0) return '**MEDIUM**';
  if (score >= 0.1) return '**LOW**';
  return 'NONE';
}

function escMd(str) {
  return String(str || '')
    .replace(/\|/g, '&#124;')
    .replace(/\n/g, ' ');
}

// ─── Single-scan report ───────────────────────────────────────────────────────

/**
 * Generate a comprehensive Markdown report for a single library scan.
 *
 * @param {object} results - The `results` object returned by Orchestrator.run()
 * @param {object} config  - The target config (name, version, entryPoints, sinks…)
 * @returns {string} Markdown document
 */
export function generateSingleReport(results, config) {
  const confirmedChains = results.confirmedChains || [];
  const potentialChains = results.potentialChains || [];
  const cs = results.coverageStats || {};
  const se = results.strategyEffectiveness || {};
  const ci = results.convergenceInfo;
  const libName = config?.name || 'Unknown';
  const libVersion = config?.version || '?';

  let md = '';

  // ── Header ──────────────────────────────────────────────────────────────────
  md += `# UoPFuzz Security Analysis: ${libName}@${libVersion}\n\n`;
  md += `> **Generated:** ${ts()}  \n`;
  md += `> **Duration:** ${durationStr(results.startTime, results.endTime)}  \n`;
  md += `> **Iterations:** ${results.iterationsCompleted || 0} | **Inputs:** ${results.inputsGenerated || 0}\n\n`;

  // ── Executive Summary ────────────────────────────────────────────────────────
  md += `## Executive Summary\n\n`;
  const confirmed = confirmedChains.length;
  const candidates = potentialChains.length;
  const errors = (results.errors || []).length;

  // Disclosure-status split — every confirmed chain carries a proof + disclosure label.
  const undocumented = confirmedChains.filter(c => c.disclosure?.label === 'undocumented-vulnerability');
  const rediscovered = confirmedChains.filter(c => c.disclosure?.label === 'previously-discovered');
  const knownCves = confirmedChains.filter(c => c.disclosure?.label === 'known-cve');
  const unprovenLeads = (results.candidateChains || []).length;

  if (confirmed > 0) {
    md += `> **VULNERABLE** — ${confirmed} independently-reproduced prototype-pollution vulnerabilit${confirmed !== 1 ? 'ies' : 'y'} `;
    md += `(${undocumented.length} undocumented, ${rediscovered.length} previously discovered, ${knownCves.length} known CVE). `;
    md += `Each was reproduced in fresh, isolated processes — not inferred from a behavioral heuristic.\n\n`;
  } else if (candidates > 0 || unprovenLeads > 0) {
    md += `> **INCONCLUSIVE** — no finding reproduced independently. `;
    md += `${unprovenLeads + candidates} unproven lead${(unprovenLeads + candidates) !== 1 ? 's' : ''} recorded for manual review (NOT vulnerabilities).\n\n`;
  } else {
    md += `> **CLEAN** — No vulnerabilities reproduced within the parameters tested. `;
    md += `Note: a CLEAN result is bounded by the search (per-call timeouts, entry points probed, prototypes/sinks monitored) and is not a proof of absence.\n\n`;
  }

  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Proven vulnerabilities | ${confirmed} |\n`;
  md += `| — Undocumented vulnerabilities | ${undocumented.length} |\n`;
  md += `| — Previously discovered | ${rediscovered.length} |\n`;
  md += `| — Known CVEs | ${knownCves.length} |\n`;
  md += `| Unproven leads (manual review) | ${unprovenLeads + candidates} |\n`;
  md += `| Errors during scan | ${errors} |\n`;
  if (cs.coveredEdges !== undefined) {
    md += `| AFL edge coverage | ${cs.coveredEdges} edges (${pct(cs.coveredEdges, 65536)} bitmap) |\n`;
  }
  if (cs.saturationRate !== undefined) {
    md += `| Coverage saturation | ${(cs.saturationRate * 100).toFixed(1)}% |\n`;
  }
  if (ci) {
    md += `| Converged at iteration | ${ci.convergedAt} (${ci.reason}) |\n`;
  }
  md += '\n';

  // ── Proven Vulnerabilities ───────────────────────────────────────────────────
  if (confirmed > 0) {
    md += `## Proven Vulnerabilities\n\n`;
    md += `Each finding below was **independently reproduced in fresh, isolated Node processes** `;
    md += `(twice) — real prototype mutation or real code execution, not a behavioral heuristic.\n\n`;

    for (const [i, chain] of confirmedChains.entries()) {
      const poc = chain.poc || {};
      const isURL = poc.type === 'url_gadget';
      const score = parseFloat(chain.riskLevel) || 0;
      const disc = chain.disclosure || {};
      const srcTag = disc.source === 'osv' ? ' (OSV.dev)'
        : disc.source === 'static+osv' ? ' (built-in DB + OSV.dev)'
        : disc.source === 'static' ? ' (built-in DB)' : '';
      const discLabel = disc.label === 'known-cve'
        ? `KNOWN CVE${disc.cve ? ' — ' + disc.cve : ''}${srcTag}`
        : disc.label === 'previously-discovered'
          ? `PREVIOUSLY DISCOVERED`
          : `UNDOCUMENTED VULNERABILITY${disc.regressionSuspect ? ' (REGRESSION SUSPECT)' : ''}`;
      const proof = chain.proof || {};

      md += `### Finding #${i + 1} — ${discLabel} — ${riskBadge(chain.riskLevel)} (${score.toFixed(1)}/10)\n\n`;
      md += `| Field | Value |\n|-------|-------|\n`;
      md += `| Library | \`${libName}@${libVersion}\` |\n`;
      md += `| Entry point | \`${escMd(chain.input?.entryPoint)}\` |\n`;
      md += `| Polluted property | \`Object.prototype.${escMd(chain.source?.property)}\` |\n`;
      md += `| Payload | \`${escMd(String(chain.source?.payload || '').substring(0, 80))}\` |\n`;
      const proofText = proof.type === 'code-execution'
        ? 'Code execution (canary fired)'
        : proof.type === 'sink-reachability'
          ? 'Sink reachability (polluted value reached a sink argument as a string; execution not proven, sanitization not checked)'
          : 'Prototype pollution (own-property added)';
      md += `| Proof | ${proofText} — reproduced ${proof.runs || 2}× |\n`;
      if (proof.newProps?.length) {
        md += `| Polluted prototype key(s) | ${proof.newProps.map(p => `\`${p}\``).join(', ')} |\n`;
      }
      if (proof.payloadType) {
        md += `| Execution payload | \`${escMd(proof.payloadType)}\` |\n`;
      }
      md += `| Disclosure | ${discLabel} |\n`;
      if (chain.metadata?.cvssVector) {
        md += `| CVSS vector | \`${chain.metadata.cvssVector}\` |\n`;
      }
      md += `| Type | ${isURL ? 'URL gadget' : (chain.multiProperty ? 'Multi-property gadget' : 'Direct prototype pollution')} |\n`;
      if (chain.coPolluteProperties?.length > 0) {
        md += `| Co-polluted properties | ${chain.coPolluteProperties.map(p => `\`${p}\``).join(' + ')} |\n`;
      }
      md += '\n';

      if (disc.regressionSuspect && disc.note) {
        md += `> ⚠ **Regression suspect:** ${disc.note}\n\n`;
      } else if (disc.label === 'previously-discovered' && disc.priorSighting) {
        const ps = disc.priorSighting;
        md += `> ℹ Previously discovered by this tool`;
        if (ps.discoveredAt) md += ` on \`${ps.discoveredAt}\``;
        if (ps.version) md += ` at \`${libName}@${ps.version}\``;
        md += ` — no public CVE.\n\n`;
      } else if (disc.source === 'osv' && disc.note) {
        md += `> ℹ ${disc.note}\n\n`;
      }
      if (disc.osvNote) {
        md += `> ℹ ${disc.osvNote}\n\n`;
      }

      if (chain.standalonePoC) {
        md += `#### Reproduction (standalone PoC)\n\n`;
        md += `\`\`\`javascript\n${chain.standalonePoC}\n\`\`\`\n\n`;
      }

      if (isURL && poc.attackerInput?.url) {
        md += `#### Attacker-Controlled Input\n\n`;
        md += `\`\`\`\n${poc.attackerInput.url}\n\`\`\`\n\n`;
      }

      if (poc.exploit?.code && !chain.standalonePoC) {
        md += `#### Proof of Concept\n\n`;
        md += `\`\`\`javascript\n${poc.exploit.code}\n\`\`\`\n\n`;
      }

      if (isURL && poc.vulnerablePattern?.description) {
        md += `#### Attack Chain\n\n`;
        md += `${poc.vulnerablePattern.description}\n\n`;
      }

      if (chain.differential?.pollutedProperties?.length > 0) {
        md += `#### Polluted Properties\n\n`;
        md += chain.differential.pollutedProperties.map(p => `- \`${p}\``).join('\n');
        md += '\n\n';
      }
    }
  }

  // ── Unproven Leads (discovery-oracle signals that did NOT reproduce) ─────────
  const candidateChains = results.candidateChains || [];
  if (candidateChains.length > 0) {
    md += `## Unproven Leads (NOT vulnerabilities)\n\n`;
    md += `The discovery oracle observed a signal for these, but they **did not reproduce** in an `;
    md += `independent fresh process, so they are **not** reported as vulnerabilities. Kept only as `;
    md += `leads for manual review (e.g. browser-only packages that can't load in the child, `;
    md += `sequence/async gadgets, or non-deterministic behavior).\n\n`;
    md += `| Property | Entry Point | Signal | Proof attempted | Reason |\n|----------|-------------|--------|-----------------|--------|\n`;
    for (const c of candidateChains.slice(0, 40)) {
      md += `| \`${escMd(c.property)}\` | \`${escMd(c.entryPoint)}\` | ${escMd(c.signal)} | ${escMd(c.proofType)} | ${escMd(c.reason)} |\n`;
    }
    if (candidateChains.length > 40) md += `\n*… and ${candidateChains.length - 40} more*\n`;
    md += '\n';
  }

  // ── Candidate Properties (Tier 5 — read but no behavior change) ──────────────
  const candidateProps = results.candidateProperties || [];
  if (candidateProps.length > 0) {
    md += `## Candidate Properties (Manual Review Recommended)\n\n`;
    md += `These properties were read via \`Object.prototype\` during polluted execution, but no observable behavior change was detected. `;
    md += `They may still be exploitable in specific contexts (e.g., conjunctive pollution, async flows).\n\n`;
    md += `| Property | Entry Point | Confidence |\n|----------|-------------|------------|\n`;
    for (const c of candidateProps.slice(0, 30)) {
      md += `| \`${escMd(c.property)}\` | \`${escMd(c.entryPoint)}\` | ${((c.confidence || 0) * 100).toFixed(0)}% |\n`;
    }
    if (candidateProps.length > 30) md += `\n*… and ${candidateProps.length - 30} more*\n`;
    md += '\n';
  }

  // ── Attack Surface ───────────────────────────────────────────────────────────
  if (config?.entryPoints?.length > 0 || se.discoveredUOPProperties?.length > 0) {
    md += `## Attack Surface\n\n`;

    if (config?.entryPoints?.length > 0) {
      md += `### Entry Points Tested\n\n`;
      md += `| Entry Point | Input Type |\n|-------------|------------|\n`;
      for (const ep of config.entryPoints) {
        md += `| \`${escMd(ep.name)}\` | ${escMd(ep.inputType)} |\n`;
      }
      md += '\n';
    }

    if (se.discoveredUOPProperties?.length > 0) {
      const props = se.discoveredUOPProperties;
      md += `### UOP Pollution Candidates\n\n`;
      md += `Properties the library reads as \`undefined\` from \`Object.prototype\` (discovered via Proxy taint tracking):\n\n`;
      md += props.slice(0, 50).map(p => `- \`${p}\``).join('\n');
      if (props.length > 50) md += `\n- … and ${props.length - 50} more`;
      md += '\n\n';
    }
  }

  // ── Coverage Analysis ────────────────────────────────────────────────────────
  md += `## Coverage Analysis\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;

  if (cs.coveredEdges !== undefined) {
    md += `| AFL edges discovered | ${cs.coveredEdges} |\n`;
    md += `| Bitmap density | ${(cs.bitmapDensity * 100).toFixed(4)}% |\n`;
    md += `| Saturation rate | ${(cs.saturationRate * 100).toFixed(1)}% |\n`;
    md += `| Total inputs processed | ${cs.totalInputsProcessed || 0} |\n`;
  } else {
    md += `| Coverage data | Not available (dry-run) |\n`;
  }

  if (cs.v8CoverageEnabled && cs.v8Metrics) {
    const v8 = cs.v8Metrics;
    md += `| V8 block coverage | ${v8.coveredBlocks}/${v8.totalBlocks} (${pct(v8.coveredBlocks, v8.totalBlocks)}) |\n`;
    md += `| V8 branch coverage | ${v8.coveredBranches}/${v8.totalBranches} (${pct(v8.coveredBranches, v8.totalBranches)}) |\n`;
    md += `| V8 function coverage | ${v8.coveredFunctions}/${v8.totalFunctions} (${pct(v8.coveredFunctions, v8.totalFunctions)}) |\n`;
  }
  md += '\n';

  // ── Strategy Effectiveness ───────────────────────────────────────────────────
  if (se.strategyEffectiveness && Object.keys(se.strategyEffectiveness).length > 0) {
    md += `## Mutation Strategy Effectiveness\n\n`;
    md += `> Thompson Sampling with Beta posteriors — strategies with higher past success rates receive more mutations.\n\n`;
    md += `| Strategy | Success Rate | Mutations |\n|----------|-------------|----------|\n`;
    for (const [strategy, stats] of Object.entries(se.strategyEffectiveness)) {
      md += `| ${escMd(strategy)} | ${(stats.successRate * 100).toFixed(1)}% | ${stats.totalMutations} |\n`;
    }
    md += '\n';
    md += `**Seed corpus:** ${se.seedCount || 0} seeds\n\n`;
  }

  // ── Known Gadget Benchmark ───────────────────────────────────────────────────
  const knownGadgets = getGadgetsForPackage(libName);
  if (knownGadgets.length > 0) {
    const benchmark = benchmarkDetection(confirmedChains, libName);
    md += `## Known Gadget Benchmark\n\n`;
    md += `Comparing results against ${knownGadgets.length} publicly documented vulnerabilities for \`${libName}\`.\n\n`;
    md += `| Metric | Value |\n|--------|-------|\n`;
    md += `| Known vulnerabilities | ${knownGadgets.length} |\n`;
    md += `| Detected | ${benchmark.detected.length} |\n`;
    md += `| Missed | ${benchmark.missed.length} |\n`;
    md += `| Detection rate | ${(benchmark.detectionRate * 100).toFixed(0)}% |\n\n`;

    if (benchmark.detected.length > 0) {
      md += `**Detected:**\n`;
      for (const g of benchmark.detected) {
        md += `- \`${g.property || g.function}\` (${g.cve || 'no CVE'}) — ${g.impact}\n`;
      }
      md += '\n';
    }
    if (benchmark.missed.length > 0) {
      md += `**Missed (may require more iterations or different payload):**\n`;
      for (const g of benchmark.missed) {
        md += `- \`${g.property || g.function}\` (${g.cve || 'no CVE'}) — ${g.description || g.impact}\n`;
      }
      md += '\n';
    }
  }

  // ── Unconfirmed Candidates ───────────────────────────────────────────────────
  if (candidates > 0) {
    md += `## Unconfirmed Candidates\n\n`;
    md += `> These were flagged by timestamp correlation but **not** confirmed by the differential oracle.  \n`;
    md += `> Manual verification recommended for high-scoring entries.\n\n`;
    md += `| # | Description | Risk | Confidence |\n|---|-------------|------|------------|\n`;
    for (const [i, chain] of potentialChains.slice(0, 20).entries()) {
      md += `| ${i + 1} | ${escMd(chain.description || 'Unknown')} | ${escMd(chain.riskLevel || 'N/A')}/10 | ${((chain.confidence || 0) * 100).toFixed(1)}% |\n`;
    }
    if (candidates > 20) md += `\n> _… and ${candidates - 20} more candidates not shown._\n`;
    md += '\n';
  }

  // ── Methodology ─────────────────────────────────────────────────────────────
  md += `## Methodology\n\n`;
  md += `| Technique | Description |\n|-----------|-------------|\n`;
  md += `| Differential oracle | Clean vs. polluted execution — causal confirmation, not correlation |\n`;
  md += `| UOP property discovery | Proxy-based detection of \`undefined\` property reads on \`Object.prototype\` |\n`;
  md += `| Merge-PP attack | Crafted input that mutates \`Object.prototype\` through deep merge |\n`;
  md += `| URL gadget detection | Attacker-controlled URL query string → parser → polluted prototype |\n`;
  md += `| Reproduction gate | Every reported finding is re-proven in fresh child processes |\n`;
  md += `| Coverage guidance | AFL-style 64 KB edge bitmap (Böhme et al., CCS 2016) |\n`;
  md += `| V8 precise coverage | Real block/branch/function coverage via Node.js Inspector protocol |\n`;
  md += `| Taint tracking | ES6 Proxy deep property interception |\n`;
  md += `| Severity | Coarse heuristic by sink class (not a computed CVSS score) |\n`;
  md += `| Strategy selection | Thompson sampling over per-strategy success |\n`;
  md += `| Gadget taxonomy | "Silent Spring" (Shcherbakov et al., USENIX 2023) |\n`;
  md += '\n';

  // ── Raw JSON (collapsible) ───────────────────────────────────────────────────
  md += `## Raw Results\n\n`;
  md += `<details>\n<summary>Full JSON results (click to expand)</summary>\n\n`;
  md += `\`\`\`json\n${JSON.stringify(results, null, 2)}\n\`\`\`\n\n`;
  md += `</details>\n`;

  return md;
}

// ─── Mass-scan report ─────────────────────────────────────────────────────────

/**
 * Generate a Markdown summary report for a mass cdnjs scan.
 *
 * @param {Array} allResults  - Array of { library, version, results, config, error?, stars? }
 * @returns {string} Markdown document
 */
export function generateMassReport(allResults) {
  const total = allResults.length;
  const vulnerable = allResults.filter(r => (r.results?.confirmedChains?.length || 0) > 0);
  const candidates = allResults.filter(r => !r.error && (r.results?.confirmedChains?.length || 0) === 0 && (r.results?.potentialChains?.length || 0) > 0);
  const clean = allResults.filter(r => !r.error && (r.results?.confirmedChains?.length || 0) === 0 && (r.results?.potentialChains?.length || 0) === 0);
  const failed = allResults.filter(r => !!r.error);

  let md = '';
  md += `# UoPFuzz Mass Scan Report — cdnjs Top Libraries\n\n`;
  md += `> **Generated:** ${ts()}  \n`;
  md += `> **Libraries scanned:** ${total}  \n`;
  md += `> **Vulnerable:** ${vulnerable.length} | **Candidates:** ${candidates.length} | **Clean:** ${clean.length} | **Failed:** ${failed.length}\n\n`;

  // ── Summary table ────────────────────────────────────────────────────────────
  md += `## Summary Table\n\n`;
  md += `| Library | Version | Stars | Confirmed | Risk | Unconfirmed | Status |\n`;
  md += `|---------|---------|-------|-----------|------|-------------|--------|\n`;

  const sorted = [...allResults].sort((a, b) => {
    const ca = a.results?.confirmedChains?.length || 0;
    const cb = b.results?.confirmedChains?.length || 0;
    if (cb !== ca) return cb - ca;
    return (b.stars || 0) - (a.stars || 0);
  });

  for (const r of sorted) {
    if (r.error) {
      md += `| ${escMd(r.library)} | ${escMd(r.version || '?')} | ${r.stars || '?'} | — | — | — | FAILED |\n`;
      continue;
    }
    const confirmed = r.results?.confirmedChains?.length || 0;
    const potential = r.results?.potentialChains?.length || 0;
    const topRisk = confirmed > 0
      ? Math.max(...(r.results.confirmedChains.map(c => parseFloat(c.riskLevel) || 0)))
      : 0;
    const status = confirmed > 0 ? 'VULNERABLE' : potential > 0 ? 'CANDIDATES' : 'CLEAN';
    md += `| \`${escMd(r.library)}\` | ${escMd(r.version || '?')} | ${r.stars || '?'} | ${confirmed} | ${topRisk > 0 ? topRisk.toFixed(1) : 'N/A'} | ${potential} | ${status} |\n`;
  }
  md += '\n';

  // ── Vulnerable details ───────────────────────────────────────────────────────
  if (vulnerable.length > 0) {
    md += `## Vulnerable Libraries\n\n`;
    for (const r of vulnerable) {
      const confirmed = r.results.confirmedChains;
      md += `### \`${r.library}@${r.version}\`\n\n`;
      md += `**${confirmed.length} confirmed gadget${confirmed.length !== 1 ? 's' : ''}**\n\n`;
      md += `| # | Property | Entry Point | Risk | Confidence |\n|---|----------|-------------|------|------------|\n`;
      for (const [i, chain] of confirmed.entries()) {
        md += `| ${i + 1} | \`Object.prototype.${escMd(chain.source?.property)}\` | \`${escMd(chain.input?.entryPoint)}\` | ${escMd(chain.riskLevel || 'N/A')}/10 | ${((chain.confidence || 0) * 100).toFixed(0)}% |\n`;
      }
      md += '\n';
    }
  }

  // ── Candidates ───────────────────────────────────────────────────────────────
  if (candidates.length > 0) {
    md += `## Libraries with Unconfirmed Candidates\n\n`;
    md += `| Library | Version | Candidates | Top Risk |\n|---------|---------|------------|----------|\n`;
    for (const r of candidates) {
      const potential = r.results.potentialChains;
      const topRisk = potential.length > 0
        ? Math.max(...potential.map(c => parseFloat(c.riskLevel) || 0))
        : 0;
      md += `| \`${escMd(r.library)}\` | ${escMd(r.version || '?')} | ${potential.length} | ${topRisk > 0 ? topRisk.toFixed(1) : 'N/A'} |\n`;
    }
    md += '\n';
  }

  // ── Failed ───────────────────────────────────────────────────────────────────
  if (failed.length > 0) {
    md += `## Failed Scans\n\n`;
    md += `| Library | Error |\n|---------|-------|\n`;
    for (const r of failed) {
      md += `| \`${escMd(r.library)}\` | ${escMd(r.error)} |\n`;
    }
    md += '\n';
  }

  // ── Statistics ───────────────────────────────────────────────────────────────
  md += `## Scan Statistics\n\n`;
  md += `| Metric | Value |\n|--------|-------|\n`;
  md += `| Total libraries | ${total} |\n`;
  md += `| Vulnerable | ${vulnerable.length} (${pct(vulnerable.length, total)}) |\n`;
  md += `| With candidates only | ${candidates.length} (${pct(candidates.length, total)}) |\n`;
  md += `| Clean | ${clean.length} (${pct(clean.length, total)}) |\n`;
  md += `| Failed / skipped | ${failed.length} (${pct(failed.length, total)}) |\n`;
  const totalConfirmed = allResults.reduce((s, r) => s + (r.results?.confirmedChains?.length || 0), 0);
  md += `| Total confirmed gadgets | ${totalConfirmed} |\n`;
  md += '\n';

  return md;
}

// ─── Version-sweep report ─────────────────────────────────────────────────────

/**
 * Generate a Markdown version-sweep report for a single library scanned across
 * multiple versions.
 *
 * @param {Array} versionResults - Array of { version, results, config, error? }
 *                                 ordered newest → oldest
 * @param {string} libraryName   - Display name for the library
 * @returns {string} Markdown document
 */
export function generateVersionReport(versionResults, libraryName = 'Unknown') {
  const total = versionResults.length;
  const vulnerable = versionResults.filter(r => (r.results?.confirmedChains?.length || 0) > 0);
  const failed = versionResults.filter(r => !!r.error);

  let md = '';
  md += `# UoPFuzz Version Sweep: ${libraryName}\n\n`;
  md += `> **Generated:** ${ts()}  \n`;
  md += `> **Versions tested:** ${total}  \n`;
  md += `> **Vulnerable versions:** ${vulnerable.length} | **Failed:** ${failed.length}\n\n`;

  // ── Version timeline table ────────────────────────────────────────────────────
  md += `## Version Timeline\n\n`;
  md += `| Version | Confirmed | Risk | Candidates | Status |\n`;
  md += `|---------|-----------|------|------------|--------|\n`;

  for (const r of versionResults) {
    if (r.error) {
      md += `| ${escMd(r.version)} | — | — | — | FAILED |\n`;
      continue;
    }
    const confirmed = r.results?.confirmedChains?.length || 0;
    const potential = r.results?.potentialChains?.length || 0;
    const topRisk = confirmed > 0
      ? Math.max(...(r.results.confirmedChains.map(c => parseFloat(c.riskLevel) || 0)))
      : 0;
    const status = confirmed > 0 ? 'VULNERABLE' : potential > 0 ? 'CANDIDATES' : 'CLEAN';
    md += `| ${escMd(r.version)} | ${confirmed} | ${topRisk > 0 ? topRisk.toFixed(1) : 'N/A'} | ${potential} | ${status} |\n`;
  }
  md += '\n';

  // ── Regression analysis ──────────────────────────────────────────────────────
  md += `## Regression Analysis\n\n`;

  const vulnVersions = versionResults
    .filter(r => (r.results?.confirmedChains?.length || 0) > 0)
    .map(r => r.version);

  if (vulnVersions.length === 0) {
    md += `No vulnerabilities found across ${total} versions.\n\n`;
  } else {
    md += `Vulnerable versions: ${vulnVersions.map(v => `\`${v}\``).join(', ')}\n\n`;

    // Try to find introduction and fix points
    // versionResults is ordered newest → oldest
    const lastVulnIndex = versionResults.findIndex(r => (r.results?.confirmedChains?.length || 0) > 0);
    const firstVulnIndex = [...versionResults].reverse().findIndex(r => (r.results?.confirmedChains?.length || 0) > 0);
    const reversedFirstIdx = firstVulnIndex >= 0 ? total - 1 - firstVulnIndex : -1;

    if (reversedFirstIdx >= 0) {
      const introducedVersion = versionResults[reversedFirstIdx].version;
      md += `- **Vulnerability first appeared in:** \`${introducedVersion}\`\n`;
    }
    if (lastVulnIndex >= 0 && lastVulnIndex > 0) {
      const fixedVersion = versionResults[lastVulnIndex - 1].version;
      md += `- **Last clean version (newer):** \`${fixedVersion}\` (may be the fix)\n`;
    } else if (lastVulnIndex === 0) {
      md += `- **Vulnerability present in latest tested version** (not yet fixed)\n`;
    }
    md += '\n';

    // collect all unique confirmed properties across vulnerable versions
    const allProps = new Set();
    for (const r of versionResults) {
      for (const chain of (r.results?.confirmedChains || [])) {
        if (chain.source?.property) allProps.add(chain.source.property);
      }
    }
    if (allProps.size > 0) {
      md += `### Vulnerable Properties\n\n`;
      md += `Properties confirmed across all versions:\n\n`;
      for (const p of allProps) {
        md += `- \`Object.prototype.${p}\`\n`;
      }
      md += '\n';
    }
  }

  // ── Per-version details ───────────────────────────────────────────────────────
  if (vulnerable.length > 0) {
    md += `## Per-Version Details\n\n`;
    for (const r of vulnerable) {
      md += `### Version ${r.version}\n\n`;
      md += `${r.results.confirmedChains.length} confirmed gadget${r.results.confirmedChains.length !== 1 ? 's' : ''}\n\n`;
      md += `| # | Property | Entry Point | Risk | Confidence |\n|---|----------|-------------|------|------------|\n`;
      for (const [i, chain] of r.results.confirmedChains.entries()) {
        md += `| ${i + 1} | \`Object.prototype.${escMd(chain.source?.property)}\` | \`${escMd(chain.input?.entryPoint)}\` | ${escMd(chain.riskLevel || 'N/A')}/10 | ${((chain.confidence || 0) * 100).toFixed(0)}% |\n`;
      }
      md += '\n';
    }
  }

  return md;
}
