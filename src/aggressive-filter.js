#!/usr/bin/env node

/**
 * Aggressive False Positive Filter
 * Filters out noise from fuzzing results
 */

import fs from 'fs/promises';
import { logger } from './utils/logger.js';

class AggressiveFilter {
  constructor(resultsFile) {
    this.resultsFile = resultsFile;
  }

  async filter() {
    const content = await fs.readFile(this.resultsFile, 'utf8');
    const results = JSON.parse(content);

    const chains = results.potentialChains || [];
    logger.info(`Filtering ${chains.length} potential chains...`);

    const filtered = {
      highValue: [],
      maybeValid: [],
      likelyFalse: [],
      definitelyFalse: []
    };

    for (const chain of chains) {
      const category = this.categorizeChain(chain);
      filtered[category].push(chain);
    }

    this.printReport(filtered);
    return filtered;
  }

  categorizeChain(chain) {
    // DEFINITE FALSE POSITIVES
    if (this.isDefinitelyFalse(chain)) {
      return 'definitelyFalse';
    }

    // HIGH VALUE (worth investigating)
    if (this.isHighValue(chain)) {
      return 'highValue';
    }

    // MAYBE VALID (needs manual check)
    if (this.isMaybeValid(chain)) {
      return 'maybeValid';
    }

    // LIKELY FALSE (probably noise)
    return 'likelyFalse';
  }

  isDefinitelyFalse(chain) {
    // Simulated/dry-run chains
    if (chain.source?.type === 'simulated_pollution') return true;
    if (chain.source?.type === 'mock_pollution') return true;

    // No sink reached
    if (!chain.sink || chain.sink === 'unknown') return true;
    if (chain.sink?.name === 'unknown') return true;

    // Risk too low
    if (chain.riskLevel < 3) return true;

    // Type coercion only (rarely exploitable)
    if (chain.type === 'coercion' && chain.riskLevel < 7) return true;

    // No pollution source
    if (!chain.source || chain.source === 'unknown') return true;

    return false;
  }

  isHighValue(chain) {
    // Direct chain to eval/Function with high risk
    if (chain.type === 'direct' &&
        chain.riskLevel >= 8 &&
        ['eval', 'Function'].includes(chain.sink?.name)) {
      return true;
    }

    // Multi-step chain with very high risk
    if (chain.type === 'multi-step' &&
        chain.riskLevel >= 9) {
      return true;
    }

    // Known dangerous sinks with clear path
    const dangerousSinks = ['eval', 'Function', 'child_process.exec'];
    if (dangerousSinks.includes(chain.sink?.name) &&
        chain.steps?.length >= 2 &&
        chain.riskLevel >= 7) {
      return true;
    }

    return false;
  }

  isMaybeValid(chain) {
    // Reaches dangerous sink but lower confidence
    const dangerousSinks = ['eval', 'Function', 'child_process.exec', 'vm.runInThisContext'];
    if (dangerousSinks.includes(chain.sink?.name) &&
        chain.riskLevel >= 5) {
      return true;
    }

    // Multi-step with moderate risk
    if (chain.type === 'multi-step' &&
        chain.riskLevel >= 6) {
      return true;
    }

    return false;
  }

  printReport(filtered) {
    console.log('\n' + '='.repeat(70));
    console.log('🔍 AGGRESSIVE FILTERING REPORT');
    console.log('='.repeat(70));

    const total = Object.values(filtered).reduce((sum, arr) => sum + arr.length, 0);

    console.log(`\nTotal Chains: ${total}`);
    console.log(`🎯 High Value: ${filtered.highValue.length} (INVESTIGATE THESE!)`);
    console.log(`⚠️  Maybe Valid: ${filtered.maybeValid.length} (manual review)`);
    console.log(`📊 Likely False: ${filtered.likelyFalse.length} (low priority)`);
    console.log(`❌ Definitely False: ${filtered.definitelyFalse.length} (ignore)`);

    console.log('\n' + '─'.repeat(70));
    console.log(`FALSE POSITIVE RATE: ${Math.round((filtered.definitelyFalse.length + filtered.likelyFalse.length) / total * 100)}%`);
    console.log(`ACTIONABLE FINDINGS: ${filtered.highValue.length + filtered.maybeValid.length}`);
    console.log('='.repeat(70));

    if (filtered.highValue.length > 0) {
      console.log('\n🎯 HIGH VALUE FINDINGS (Priority 1):');
      filtered.highValue.forEach((chain, i) => {
        console.log(`\n${i + 1}. ${chain.description}`);
        console.log(`   Type: ${chain.type}`);
        console.log(`   Risk: ${chain.riskLevel}/10`);
        console.log(`   Sink: ${chain.sink?.name}`);
        console.log(`   Source: ${chain.source?.property || 'unknown'}`);
      });
    }

    if (filtered.maybeValid.length > 0) {
      console.log('\n⚠️  MAYBE VALID (Priority 2 - Manual Review):');
      filtered.maybeValid.slice(0, 5).forEach((chain, i) => {
        console.log(`  ${i + 1}. ${chain.type} → ${chain.sink?.name} (risk: ${chain.riskLevel})`);
      });
      if (filtered.maybeValid.length > 5) {
        console.log(`  ... and ${filtered.maybeValid.length - 5} more`);
      }
    }

    console.log('\n💡 RECOMMENDATIONS:');
    if (filtered.highValue.length > 0) {
      console.log('✅ Focus on HIGH VALUE findings - create PoCs for these');
    } else if (filtered.maybeValid.length > 0) {
      console.log('⚠️  No high-value findings. Review MAYBE VALID manually.');
    } else {
      console.log('❌ No actionable findings. Try:');
      console.log('   - Increase iterations (--max-iterations 10000)');
      console.log('   - Run without --dry-run');
      console.log('   - Try different target packages');
    }
  }
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🔍 Aggressive False Positive Filter

Usage:
  node src/aggressive-filter.js <results-file.json>

Example:
  node src/aggressive-filter.js results/pug/results-*.json

This filter is MORE aggressive than the validator.
Use this to cut through the noise and find real vulnerabilities.
`);
    process.exit(0);
  }

  const filter = new AggressiveFilter(args[0]);
  filter.filter()
    .then(() => process.exit(0))
    .catch(err => {
      console.error(err);
      process.exit(1);
    });
}

export { AggressiveFilter };
