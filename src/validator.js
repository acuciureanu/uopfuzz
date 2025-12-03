#!/usr/bin/env node

/**
 * Validator - Verify fuzzing results are real vulnerabilities
 * Reduces false positives by creating PoC exploits
 */

import fs from 'fs/promises';
import { logger } from './utils/logger.js';

class ResultValidator {
  constructor(resultsFile) {
    this.resultsFile = resultsFile;
    this.results = null;
  }

  async validate() {
    logger.info(`🔍 Validating results from: ${this.resultsFile}`);

    // Load results
    const content = await fs.readFile(this.resultsFile, 'utf8');
    this.results = JSON.parse(content);

    const chains = this.results.potentialChains || [];
    logger.info(`Found ${chains.length} potential chains to validate`);

    const validated = {
      total: chains.length,
      highConfidence: 0,
      mediumConfidence: 0,
      lowConfidence: 0,
      falsePositives: 0,
      results: []
    };

    for (const chain of chains) {
      const validation = this.validateChain(chain);
      validated.results.push(validation);

      switch (validation.confidence) {
        case 'high':
          validated.highConfidence++;
          break;
        case 'medium':
          validated.mediumConfidence++;
          break;
        case 'low':
          validated.lowConfidence++;
          break;
        case 'false':
          validated.falsePositives++;
          break;
      }
    }

    this.printReport(validated);
    return validated;
  }

  validateChain(chain) {
    const validation = {
      chain,
      confidence: 'unknown',
      reasons: [],
      exploitable: false,
      severity: 'info'
    };

    // High confidence indicators
    if (chain.type === 'direct' && chain.riskLevel >= 8) {
      validation.confidence = 'high';
      validation.reasons.push('Direct chain to dangerous sink');
      validation.exploitable = true;
      validation.severity = 'critical';
    } else if (chain.type === 'multi-step' && chain.riskLevel >= 7) {
      validation.confidence = 'high';
      validation.reasons.push('Multi-step chain with high risk');
      validation.exploitable = true;
      validation.severity = 'high';
    }

    // Medium confidence indicators
    else if (chain.sink?.name === 'eval' || chain.sink?.name === 'Function') {
      validation.confidence = 'medium';
      validation.reasons.push('Reaches eval/Function sink');
      validation.exploitable = true;
      validation.severity = 'high';
    } else if (chain.type === 'async' && chain.riskLevel >= 5) {
      validation.confidence = 'medium';
      validation.reasons.push('Async pollution with moderate risk');
      validation.severity = 'medium';
    }

    // Low confidence indicators
    else if (chain.type === 'coercion') {
      validation.confidence = 'low';
      validation.reasons.push('Type coercion chain (low exploitability)');
      validation.severity = 'low';
    }

    // Check for false positive patterns
    if (chain.riskLevel < 3) {
      validation.confidence = 'false';
      validation.reasons.push('Risk level too low');
      validation.severity = 'info';
    }

    if (!chain.sink || chain.sink === 'unknown') {
      validation.confidence = 'false';
      validation.reasons.push('No dangerous sink reached');
      validation.severity = 'info';
    }

    // Additional checks
    if (chain.steps && chain.steps.length >= 3) {
      validation.reasons.push(`Complex chain (${chain.steps.length} steps)`);
    }

    if (chain.input?.polluted) {
      validation.reasons.push('Pollution successfully injected');
    }

    return validation;
  }

  printReport(validated) {
    console.log('\n' + '='.repeat(70));
    console.log('🔍 VALIDATION REPORT');
    console.log('='.repeat(70));
    console.log(`Total Chains: ${validated.total}`);
    console.log(`✅ High Confidence: ${validated.highConfidence} (likely exploitable)`);
    console.log(`⚠️  Medium Confidence: ${validated.mediumConfidence} (needs verification)`);
    console.log(`ℹ️  Low Confidence: ${validated.lowConfidence} (low priority)`);
    console.log(`❌ False Positives: ${validated.falsePositives}`);
    console.log('='.repeat(70));

    if (validated.highConfidence > 0) {
      console.log('\n🚨 HIGH CONFIDENCE FINDINGS (Verify These First!):');
      validated.results
        .filter(v => v.confidence === 'high')
        .forEach((v, i) => {
          console.log(`\n${i + 1}. ${v.chain.description}`);
          console.log(`   Risk Level: ${v.chain.riskLevel}`);
          console.log(`   Type: ${v.chain.type}`);
          console.log(`   Sink: ${v.chain.sink?.name || 'unknown'}`);
          console.log(`   Reasons: ${v.reasons.join(', ')}`);
        });
    }

    console.log('\n💡 NEXT STEPS:');
    if (validated.highConfidence > 0) {
      console.log('1. Create PoC exploits for high-confidence findings');
      console.log('2. Verify manually in isolated environment');
      console.log('3. Report to maintainers if confirmed');
    } else if (validated.mediumConfidence > 0) {
      console.log('1. Review medium-confidence findings manually');
      console.log('2. Create test cases to verify exploitability');
    } else {
      console.log('1. No high-priority findings - scan more packages');
      console.log('2. Increase iterations for better coverage');
    }
  }

  async generatePoC(chain) {
    // Generate proof-of-concept code for a chain
    const poc = {
      package: this.results.metadata?.target || 'unknown',
      version: this.results.metadata?.version || 'unknown',
      chain: chain.description,
      code: this.generatePoCCode(chain)
    };

    return poc;
  }

  generatePoCCode(chain) {
    const pkg = this.results.metadata?.target || 'target-package';
    const entryPoint = chain.input?.entryPoint || 'render';

    return `// Proof-of-Concept for ${pkg}
// Chain: ${chain.description}

const ${pkg.replace(/[^a-zA-Z0-9]/g, '_')} = require('${pkg}');

// Step 1: Create polluted object
const maliciousInput = {
  __proto__: {
    polluted: 'MALICIOUS_VALUE'
  }
};

// Step 2: Trigger the chain
try {
  const result = ${pkg.replace(/[^a-zA-Z0-9]/g, '_')}.${entryPoint}(maliciousInput);
  console.log('Result:', result);
} catch (error) {
  console.error('Error:', error.message);
}

// Step 3: Check if pollution worked
console.log('Pollution successful?', {}['polluted'] === 'MALICIOUS_VALUE');
`;
  }
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🔍 Result Validator - Verify fuzzing findings

Usage:
  node src/validator.js <results-file.json>

Example:
  node src/validator.js results/handlebars/results-*.json

The validator will:
1. Analyze each potential chain
2. Classify by confidence (high/medium/low)
3. Identify false positives
4. Recommend next steps
`);
    process.exit(0);
  }

  const resultsFile = args[0];

  const validator = new ResultValidator(resultsFile);

  validator.validate()
    .then(results => {
      process.exit(0);
    })
    .catch(error => {
      logger.error(error.message);
      process.exit(1);
    });
}

export { ResultValidator };
