#!/usr/bin/env node

/**
 * Compare different filtering approaches
 * Shows improvement from ML-enhanced filtering
 */

import { AggressiveFilter } from './aggressive-filter.js';
import { MLEnhancedFilter } from './ml-filter.js';
import { logger } from './utils/logger.js';

class FilterComparison {
  constructor(resultsFile) {
    this.resultsFile = resultsFile;
  }

  async compare() {
    logger.info('🔬 Comparing filtering approaches...\n');

    // 1. Aggressive (rule-based) filtering
    logger.info('Running aggressive (rule-based) filter...');
    const aggressiveFilter = new AggressiveFilter(this.resultsFile);
    const aggressiveResults = await aggressiveFilter.filter();

    console.log('\n' + '─'.repeat(70) + '\n');

    // 2. ML-enhanced filtering
    logger.info('Running ML-enhanced filter...');
    const mlFilter = new MLEnhancedFilter();
    await mlFilter.initialize();
    const mlResults = await mlFilter.filterWithML(this.resultsFile);

    console.log('\n' + '='.repeat(70));
    console.log('📊 FILTER COMPARISON SUMMARY');
    console.log('='.repeat(70));

    this.printComparison(aggressiveResults, mlResults);
  }

  printComparison(aggressive, ml) {
    const aggressiveActionable = aggressive.highValue.length + aggressive.maybeValid.length;
    const aggressiveFP = aggressive.likelyFalse.length + aggressive.definitelyFalse.length;
    const aggressiveTotal = aggressiveActionable + aggressiveFP;

    const mlActionable = ml.highConfidence.length + ml.mediumConfidence.length;
    const mlFP = ml.lowConfidence.length + ml.falsePositive.length;
    const mlTotal = mlActionable + mlFP;

    console.log('\n📈 METRICS COMPARISON:\n');

    console.log('┌─────────────────────────┬──────────────┬──────────────┐');
    console.log('│ Metric                  │ Rule-Based   │ ML-Enhanced  │');
    console.log('├─────────────────────────┼──────────────┼──────────────┤');
    console.log(`│ Total Chains            │ ${String(aggressiveTotal).padEnd(12)} │ ${String(mlTotal).padEnd(12)} │`);
    console.log(`│ Actionable Findings     │ ${String(aggressiveActionable).padEnd(12)} │ ${String(mlActionable).padEnd(12)} │`);
    console.log(`│ False Positives         │ ${String(aggressiveFP).padEnd(12)} │ ${String(mlFP).padEnd(12)} │`);
    console.log(`│ FP Rate                 │ ${String(Math.round(aggressiveFP/aggressiveTotal*100) + '%').padEnd(12)} │ ${String(Math.round(mlFP/mlTotal*100) + '%').padEnd(12)} │`);
    console.log(`│ Precision               │ ${String(Math.round(aggressiveActionable/aggressiveTotal*100) + '%').padEnd(12)} │ ${String(Math.round(mlActionable/mlTotal*100) + '%').padEnd(12)} │`);
    console.log('└─────────────────────────┴──────────────┴──────────────┘');

    const fpReduction = ((aggressiveFP - mlFP) / aggressiveFP * 100).toFixed(1);
    const precisionGain = ((mlActionable/mlTotal - aggressiveActionable/aggressiveTotal) * 100).toFixed(1);

    console.log('\n💡 IMPROVEMENT:');
    if (fpReduction > 0) {
      console.log(`   ✅ False Positive Reduction: ${fpReduction}%`);
    }
    if (precisionGain > 0) {
      console.log(`   ✅ Precision Gain: ${precisionGain}%`);
    }

    console.log('\n🎯 BREAKDOWN BY CONFIDENCE:\n');

    console.log('Rule-Based Filter:');
    console.log(`   🎯 High Value:    ${aggressive.highValue.length}`);
    console.log(`   ⚠️  Maybe Valid:   ${aggressive.maybeValid.length}`);
    console.log(`   📊 Likely False:  ${aggressive.likelyFalse.length}`);
    console.log(`   ❌ Definitely False: ${aggressive.definitelyFalse.length}`);

    console.log('\nML-Enhanced Filter:');
    console.log(`   ✅ High Confidence:   ${ml.highConfidence.length}`);
    console.log(`   ⚠️  Medium Confidence: ${ml.mediumConfidence.length}`);
    console.log(`   ℹ️  Low Confidence:    ${ml.lowConfidence.length}`);
    console.log(`   ❌ False Positive:    ${ml.falsePositive.length}`);

    console.log('\n🏆 RECOMMENDATION:');
    if (mlActionable < aggressiveActionable * 0.7 && mlFP < aggressiveFP) {
      console.log('   ✅ ML-Enhanced filter is SIGNIFICANTLY better!');
      console.log('   ✅ Use ML filter for this workload.');
    } else if (mlFP < aggressiveFP) {
      console.log('   ✅ ML-Enhanced filter provides modest improvement.');
      console.log('   ✅ Consider using ML filter for better precision.');
    } else {
      console.log('   ⚠️  Filters perform similarly on this dataset.');
      console.log('   💡 ML filter may improve with more training data.');
    }

    console.log('\n' + '='.repeat(70));
  }
}

// CLI
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🔬 Filter Comparison Tool

Usage:
  node src/compare-filters.js <results-file.json>

Example:
  node src/compare-filters.js results/pug/results-*.json

This compares:
  - Aggressive (rule-based) filtering
  - ML-enhanced filtering

Shows which performs better on your data.
`);
    process.exit(0);
  }

  const comparison = new FilterComparison(args[0]);
  await comparison.compare();
}

export { FilterComparison };
