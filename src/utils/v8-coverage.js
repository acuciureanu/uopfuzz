/**
 * V8 Coverage Collector
 *
 * Uses the V8 Inspector protocol to collect precise block-level
 * coverage data from actual JavaScript execution.
 *
 * This provides real edge/branch coverage data (not simulated),
 * enabling true coverage-guided greybox fuzzing as described in
 * Böhme et al., "Coverage-based Greybox Fuzzing as Markov Chain"
 * (CCS 2016).
 *
 * The V8 Profiler.takePreciseCoverage API returns:
 * - Per-function coverage with block-level ranges
 * - Exact execution counts per basic block
 * - Branch coverage (which if/else/switch arms were taken)
 *
 * Reference: V8 Inspector Protocol - Profiler domain
 * https://chromedevtools.github.io/devtools-protocol/v8/Profiler
 */

import { Session } from 'node:inspector/promises';

export class V8CoverageCollector {
  constructor() {
    this.session = null;
    this.isActive = false;
  }

  /**
   * Start a V8 coverage collection session.
   * Must be called before any code you want to measure.
   */
  async start() {
    if (this.isActive) return;

    this.session = new Session();
    this.session.connect();

    await this.session.post('Profiler.enable');
    await this.session.post('Profiler.startPreciseCoverage', {
      callCount: true,
      detailed: true  // Block-level (not just function-level)
    });

    this.isActive = true;
  }

  /**
   * Take a coverage snapshot without stopping collection.
   * Returns coverage data for all scripts executed since last take/start.
   *
   * Filters out Node.js internal modules to only return coverage
   * for user code and npm packages.
   *
   * @returns {Array} Array of V8 ScriptCoverage objects
   */
  async takeCoverage() {
    if (!this.isActive) return [];

    const { result } = await this.session.post('Profiler.takePreciseCoverage');

    // Filter to only target library code (exclude node internals)
    return result.filter(script =>
      !script.url.startsWith('node:') &&
      script.url !== '' &&
      !script.url.includes('node_modules/uopfuzz')
    );
  }

  /**
   * Stop coverage collection and disconnect.
   */
  async stop() {
    if (!this.isActive) return;

    try {
      await this.session.post('Profiler.stopPreciseCoverage');
      await this.session.post('Profiler.disable');
      this.session.disconnect();
    } catch (e) {
      // Session may already be disconnected
    }

    this.session = null;
    this.isActive = false;
  }

  /**
   * Extract coverage metrics from V8 coverage data.
   *
   * Converts V8's range-based coverage into:
   * - Block hit counts (for AFL-style bitmap)
   * - Branch pairs (for edge coverage)
   * - Function-level coverage summary
   *
   * @param {Array} coverageData - from takeCoverage()
   * @returns {object} { blocks, branches, functions, summary }
   */
  extractMetrics(coverageData) {
    const blocks = [];
    const branches = [];
    const functions = [];
    let totalBlocks = 0;
    let coveredBlocks = 0;
    let totalFunctions = 0;
    let coveredFunctions = 0;

    for (const script of coverageData) {
      for (const func of script.functions) {
        totalFunctions++;
        const isCovered = func.ranges.some(r => r.count > 0);
        if (isCovered) coveredFunctions++;

        functions.push({
          scriptUrl: script.url,
          name: func.functionName || '(anonymous)',
          covered: isCovered
        });

        // Each range is a basic block
        for (const range of func.ranges) {
          totalBlocks++;
          if (range.count > 0) coveredBlocks++;

          blocks.push({
            scriptId: script.scriptId,
            scriptUrl: script.url,
            functionName: func.functionName,
            startOffset: range.startOffset,
            endOffset: range.endOffset,
            count: range.count
          });
        }

        // Detect branches: when a function has multiple ranges,
        // ranges after the first represent branch arms
        if (func.isBlockCoverage && func.ranges.length > 1) {
          for (let i = 1; i < func.ranges.length; i++) {
            branches.push({
              scriptUrl: script.url,
              functionName: func.functionName,
              arm: i,
              startOffset: func.ranges[i].startOffset,
              endOffset: func.ranges[i].endOffset,
              taken: func.ranges[i].count > 0,
              count: func.ranges[i].count
            });
          }
        }
      }
    }

    return {
      blocks,
      branches,
      functions,
      summary: {
        totalBlocks,
        coveredBlocks,
        blockCoverage: totalBlocks > 0 ? coveredBlocks / totalBlocks : 0,
        totalFunctions,
        coveredFunctions,
        functionCoverage: totalFunctions > 0 ? coveredFunctions / totalFunctions : 0,
        totalBranches: branches.length,
        coveredBranches: branches.filter(b => b.taken).length,
        branchCoverage: branches.length > 0
          ? branches.filter(b => b.taken).length / branches.length
          : 0
      }
    };
  }
}
