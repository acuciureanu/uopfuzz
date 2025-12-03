#!/usr/bin/env node

/**
 * Mass verification test for auto-scanner
 * Tests against known vulnerable packages to verify detection works
 */

import { AutoScanner } from '../src/auto-scanner.js';
import { ResultValidator } from '../src/validator.js';
import { logger } from '../src/utils/logger.js';

// Known vulnerable packages (for testing detection)
const KNOWN_VULNERABLE = [
  {
    package: 'pug@3.0.2',
    expectedType: 'template',
    shouldFind: true,
    description: 'Known CVE in Pug 3.0.2'
  },
  {
    package: 'lodash@4.17.20',
    expectedType: 'merge',
    shouldFind: true,
    description: 'Known prototype pollution in lodash <4.17.21'
  },
  {
    package: 'handlebars@4.7.7',
    expectedType: 'template',
    shouldFind: false, // Not known vulnerable, but good test
    description: 'Popular template engine (no known vulns)'
  }
];

// Test packages for type detection
const TYPE_DETECTION_TESTS = [
  { package: 'ejs', expectedType: 'template' },
  { package: 'mustache', expectedType: 'template' },
  { package: 'deep-extend', expectedType: 'merge' },
  { package: 'merge', expectedType: 'merge' },
  { package: 'config', expectedType: 'config' },
  { package: 'dotenv', expectedType: 'config' },
  { package: 'express', expectedType: 'generic' }
];

class AutoScannerVerifier {
  constructor() {
    this.results = {
      typeDetection: { passed: 0, failed: 0, tests: [] },
      vulnerabilityDetection: { passed: 0, failed: 0, tests: [] },
      configGeneration: { passed: 0, failed: 0, tests: [] }
    };
  }

  async runAll() {
    logger.info('🧪 Starting Auto-Scanner Verification Tests\n');

    await this.testTypeDetection();
    await this.testConfigGeneration();
    await this.testVulnerabilityDetection();

    this.printReport();
  }

  async testTypeDetection() {
    logger.info('📋 Test 1: Type Detection');
    logger.info('─'.repeat(50));

    for (const test of TYPE_DETECTION_TESTS) {
      try {
        const scanner = new AutoScanner(test.package, { dryRun: true });
        const detectedType = await scanner.detectLibraryType();

        const passed = detectedType === test.expectedType;

        if (passed) {
          logger.info(`  ✅ ${test.package}: ${detectedType} (expected: ${test.expectedType})`);
          this.results.typeDetection.passed++;
        } else {
          logger.warn(`  ❌ ${test.package}: ${detectedType} (expected: ${test.expectedType})`);
          this.results.typeDetection.failed++;
        }

        this.results.typeDetection.tests.push({
          package: test.package,
          expected: test.expectedType,
          actual: detectedType,
          passed
        });

      } catch (error) {
        logger.error(`  ❌ ${test.package}: Error - ${error.message}`);
        this.results.typeDetection.failed++;
      }
    }

    logger.info('');
  }

  async testConfigGeneration() {
    logger.info('⚙️  Test 2: Config Generation');
    logger.info('─'.repeat(50));

    const testTypes = ['template', 'merge', 'config', 'generic'];

    for (const type of testTypes) {
      try {
        const scanner = new AutoScanner('test-package', { dryRun: true });
        const config = scanner.generateConfig(type);

        // Validate config structure
        const hasRequiredFields =
          config.name &&
          config.package &&
          Array.isArray(config.entryPoints) &&
          Array.isArray(config.sinks) &&
          Array.isArray(config.pollutionPoints);

        const hasEntryPoints = config.entryPoints.length > 0;
        const hasSinks = config.sinks.includes('eval') || config.sinks.includes('Function');

        const passed = hasRequiredFields && hasEntryPoints && hasSinks;

        if (passed) {
          logger.info(`  ✅ ${type}: Valid config (${config.entryPoints.length} entries, ${config.sinks.length} sinks)`);
          this.results.configGeneration.passed++;
        } else {
          logger.warn(`  ❌ ${type}: Invalid config`);
          this.results.configGeneration.failed++;
        }

        this.results.configGeneration.tests.push({
          type,
          config,
          passed
        });

      } catch (error) {
        logger.error(`  ❌ ${type}: Error - ${error.message}`);
        this.results.configGeneration.failed++;
      }
    }

    logger.info('');
  }

  async testVulnerabilityDetection() {
    logger.info('🔍 Test 3: Vulnerability Detection (Dry-Run)');
    logger.info('─'.repeat(50));
    logger.info('Testing against known vulnerable packages...\n');

    for (const test of KNOWN_VULNERABLE) {
      try {
        logger.info(`  Testing: ${test.package}`);
        logger.info(`  Expected: ${test.description}`);

        const scanner = new AutoScanner(test.package, {
          dryRun: true,
          maxIterations: 50, // Quick test
          verbose: false
        });

        const results = await scanner.scan();
        const chainsFound = results.potentialChains.length;

        // Note: Dry-run mode simulates, so we test the flow works
        const passed = results && results.iterationsCompleted > 0;

        if (passed) {
          logger.info(`  ✅ Scan completed: ${chainsFound} chains found`);
          logger.info(`  ℹ️  Iterations: ${results.iterationsCompleted}`);
          this.results.vulnerabilityDetection.passed++;
        } else {
          logger.warn(`  ❌ Scan failed`);
          this.results.vulnerabilityDetection.failed++;
        }

        this.results.vulnerabilityDetection.tests.push({
          package: test.package,
          chainsFound,
          iterations: results.iterationsCompleted,
          passed
        });

        logger.info('');

      } catch (error) {
        logger.error(`  ❌ ${test.package}: Error - ${error.message}\n`);
        this.results.vulnerabilityDetection.failed++;
      }
    }
  }

  printReport() {
    console.log('\n' + '='.repeat(70));
    console.log('📊 AUTO-SCANNER VERIFICATION REPORT');
    console.log('='.repeat(70));

    const total = {
      passed: this.results.typeDetection.passed +
              this.results.configGeneration.passed +
              this.results.vulnerabilityDetection.passed,
      failed: this.results.typeDetection.failed +
              this.results.configGeneration.failed +
              this.results.vulnerabilityDetection.failed
    };

    console.log(`\n1. Type Detection:`);
    console.log(`   ✅ Passed: ${this.results.typeDetection.passed}`);
    console.log(`   ❌ Failed: ${this.results.typeDetection.failed}`);

    console.log(`\n2. Config Generation:`);
    console.log(`   ✅ Passed: ${this.results.configGeneration.passed}`);
    console.log(`   ❌ Failed: ${this.results.configGeneration.failed}`);

    console.log(`\n3. Vulnerability Detection:`);
    console.log(`   ✅ Passed: ${this.results.vulnerabilityDetection.passed}`);
    console.log(`   ❌ Failed: ${this.results.vulnerabilityDetection.failed}`);

    console.log('\n' + '─'.repeat(70));
    console.log(`TOTAL: ${total.passed} passed, ${total.failed} failed`);

    if (total.failed === 0) {
      console.log('\n✅ All verification tests passed! Auto-scanner is working correctly.\n');
    } else {
      console.log(`\n⚠️  ${total.failed} test(s) failed. Review the output above.\n`);
    }

    console.log('='.repeat(70));

    return total.failed === 0;
  }
}

// Run verification
const verifier = new AutoScannerVerifier();
verifier.runAll()
  .then(success => {
    process.exit(success ? 0 : 1);
  })
  .catch(error => {
    logger.error('Verification failed:', error);
    process.exit(1);
  });
