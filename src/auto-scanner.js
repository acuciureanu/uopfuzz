#!/usr/bin/env node

/**
 * Auto-Scanner - Scan npm packages without manual configs
 * Usage: node src/auto-scanner.js handlebars@4.7.8
 */

import { execSync } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { Orchestrator } from './orchestrator/index.js';
import { logger } from './utils/logger.js';

// Common patterns for different library types
const LIBRARY_PATTERNS = {
  template: {
    entryPoints: ['render', 'compile', 'renderFile', 'template'],
    pollutionPoints: ['template', 'options', 'cache', 'helpers', 'partials', 'data']
  },
  merge: {
    entryPoints: ['merge', 'extend', 'assign', 'defaults', 'defaultsDeep', 'mergeWith'],
    pollutionPoints: ['isAdmin', 'role', 'permissions', 'trusted', 'safe']
  },
  config: {
    entryPoints: ['load', 'parse', 'get', 'set', 'loadConfig'],
    pollutionPoints: ['config', 'settings', 'options', 'env']
  },
  generic: {
    entryPoints: ['parse', 'process', 'handle', 'execute', 'run'],
    pollutionPoints: ['options', 'config', 'debug', 'trusted']
  }
};

// Standard dangerous sinks
const STANDARD_SINKS = [
  'eval',
  'Function',
  'child_process.exec',
  'child_process.spawn',
  'vm.runInThisContext',
  'vm.runInNewContext'
];

class AutoScanner {
  constructor(packageSpec, options = {}) {
    this.packageSpec = packageSpec;
    this.options = options;

    // Parse package@version
    const [name, version] = packageSpec.includes('@')
      ? packageSpec.split('@')
      : [packageSpec, 'latest'];

    this.packageName = name;
    this.packageVersion = version;
  }

  async scan() {
    logger.info(`🔍 Auto-scanning: ${this.packageSpec}`);

    try {
      // 1. Detect library type
      const libraryType = await this.detectLibraryType();
      logger.info(`Detected type: ${libraryType}`);

      // 2. Generate config
      const config = this.generateConfig(libraryType);

      // 3. Run fuzzer
      const orchestrator = new Orchestrator({
        configPath: null, // We'll pass config directly
        outputDir: this.options.output || `./results/${this.packageName}/`,
        timeout: this.options.timeout || 60,
        dryRun: this.options.dryRun || false,
        maxIterations: this.options.maxIterations || 1000,
        parallelWorkers: this.options.parallel || 1,
        verbose: this.options.verbose || false
      });

      // Inject our generated config
      orchestrator.config = config;

      const results = await orchestrator.run();

      logger.info(`✅ Scan complete for ${this.packageName}`);
      return results;

    } catch (error) {
      logger.error(`❌ Auto-scan failed: ${error.message}`);
      throw error;
    }
  }

  async detectLibraryType() {
    try {
      // Fetch package info from npm
      const packageInfo = JSON.parse(
        execSync(`npm view ${this.packageSpec} --json`, {
          encoding: 'utf8',
          stdio: ['pipe', 'pipe', 'ignore']
        })
      );

      const keywords = packageInfo.keywords || [];
      const description = (packageInfo.description || '').toLowerCase();
      const name = this.packageName.toLowerCase();

      // Detect by keywords/description/name
      if (keywords.includes('template') ||
          description.includes('template') ||
          description.includes('render')) {
        return 'template';
      }

      if (keywords.includes('merge') ||
          name.includes('merge') ||
          name.includes('extend') ||
          description.includes('merge') ||
          description.includes('deep')) {
        return 'merge';
      }

      if (keywords.includes('config') ||
          name.includes('config') ||
          description.includes('configuration')) {
        return 'config';
      }

      return 'generic';

    } catch (error) {
      logger.warn(`Could not detect type, using generic: ${error.message}`);
      return 'generic';
    }
  }

  generateConfig(libraryType) {
    const pattern = LIBRARY_PATTERNS[libraryType] || LIBRARY_PATTERNS.generic;

    return {
      name: this.packageName,
      package: this.packageName,
      version: this.packageVersion,
      description: `Auto-generated config for ${this.packageSpec}`,
      entryPoints: pattern.entryPoints.map(name => ({
        name,
        inputType: libraryType === 'template' ? 'template' : 'object',
        description: `Auto-discovered: ${name}`
      })),
      sinks: STANDARD_SINKS,
      pollutionPoints: pattern.pollutionPoints,
      testConfig: {
        timeout: 30,
        maxDepth: 3,
        enableAsyncTesting: true
      }
    };
  }
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🔍 Auto-Scanner - Scan npm packages without configs

Usage:
  node src/auto-scanner.js <package[@version]> [options]

Examples:
  node src/auto-scanner.js handlebars
  node src/auto-scanner.js ejs@3.1.9
  node src/auto-scanner.js lodash --parallel 4 --max-iterations 1000

Options:
  --parallel <num>        Number of workers (default: 1)
  --max-iterations <num>  Max iterations (default: 1000)
  --timeout <seconds>     Timeout per iteration (default: 60)
  --output <dir>          Output directory
  --dry-run               Simulate without real execution
  --verbose               Verbose logging

The scanner will:
1. Detect library type (template, merge, config, generic)
2. Auto-generate appropriate config
3. Scan for prototype pollution chains
4. Report findings
`);
    process.exit(0);
  }

  const packageSpec = args[0];
  const options = {
    parallel: parseInt(args.find((_, i) => args[i - 1] === '--parallel')) || 1,
    maxIterations: parseInt(args.find((_, i) => args[i - 1] === '--max-iterations')) || 1000,
    timeout: parseInt(args.find((_, i) => args[i - 1] === '--timeout')) || 60,
    output: args.find((_, i) => args[i - 1] === '--output'),
    dryRun: args.includes('--dry-run'),
    verbose: args.includes('--verbose')
  };

  const scanner = new AutoScanner(packageSpec, options);

  scanner.scan()
    .then(results => {
      if (results.potentialChains.length > 0) {
        logger.warn(`⚠️  Found ${results.potentialChains.length} potential gadget chains`);
      } else {
        logger.info('No chains found');
      }
      process.exit(0);
    })
    .catch(error => {
      logger.error(error.message);
      process.exit(1);
    });
}

export { AutoScanner };
