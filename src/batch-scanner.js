#!/usr/bin/env node

/**
 * Batch Scanner - Scan many packages from a list
 * Usage: node src/batch-scanner.js targets.txt
 */

import fs from 'fs/promises';
import { AutoScanner } from './auto-scanner.js';
import { logger } from './utils/logger.js';

class BatchScanner {
  constructor(targetFile, options = {}) {
    this.targetFile = targetFile;
    this.options = options;
    this.results = [];
  }

  async scan() {
    // Read target list
    const content = await fs.readFile(this.targetFile, 'utf8');
    const targets = content
      .split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'));

    logger.info(`📦 Found ${targets.length} packages to scan`);

    const concurrency = this.options.concurrency || 3;
    const chunks = this.chunkArray(targets, concurrency);

    let completed = 0;
    const totalResults = {
      scanned: 0,
      vulnerable: 0,
      failed: 0,
      chains: []
    };

    // Process in batches
    for (const chunk of chunks) {
      const promises = chunk.map(async (packageSpec) => {
        try {
          logger.info(`[${completed + 1}/${targets.length}] Scanning ${packageSpec}...`);

          const scanner = new AutoScanner(packageSpec, {
            ...this.options,
            output: `${this.options.output || './batch-results'}/${packageSpec.replace(/[@\/]/g, '_')}/`
          });

          const result = await scanner.scan();

          totalResults.scanned++;
          if (result.potentialChains.length > 0) {
            totalResults.vulnerable++;
            totalResults.chains.push({
              package: packageSpec,
              chains: result.potentialChains.length,
              topRisk: Math.max(...result.potentialChains.map(c => c.riskLevel))
            });
          }

          completed++;
          return { packageSpec, success: true, result };

        } catch (error) {
          totalResults.failed++;
          completed++;
          logger.error(`Failed ${packageSpec}: ${error.message}`);
          return { packageSpec, success: false, error: error.message };
        }
      });

      await Promise.all(promises);
    }

    // Summary report
    this.printSummary(totalResults, targets.length);

    // Save detailed results
    await this.saveResults(totalResults);

    return totalResults;
  }

  chunkArray(array, size) {
    const chunks = [];
    for (let i = 0; i < array.length; i += size) {
      chunks.push(array.slice(i, i + size));
    }
    return chunks;
  }

  printSummary(results, total) {
    console.log('\n' + '='.repeat(60));
    console.log('📊 BATCH SCAN SUMMARY');
    console.log('='.repeat(60));
    console.log(`Total Packages: ${total}`);
    console.log(`✅ Successfully Scanned: ${results.scanned}`);
    console.log(`❌ Failed: ${results.failed}`);
    console.log(`🚨 Vulnerable: ${results.vulnerable}`);
    console.log(`🔗 Total Chains Found: ${results.chains.reduce((sum, c) => sum + c.chains, 0)}`);
    console.log('='.repeat(60));

    if (results.vulnerable > 0) {
      console.log('\n🚨 VULNERABLE PACKAGES:');
      results.chains
        .sort((a, b) => b.topRisk - a.topRisk)
        .forEach(({ package: pkg, chains, topRisk }) => {
          console.log(`  • ${pkg} - ${chains} chains (max risk: ${topRisk})`);
        });
    }
  }

  async saveResults(results) {
    const outputPath = `${this.options.output || './batch-results'}/summary.json`;
    await fs.mkdir(this.options.output || './batch-results', { recursive: true });
    await fs.writeFile(outputPath, JSON.stringify(results, null, 2));
    logger.info(`\n💾 Summary saved to: ${outputPath}`);
  }
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
📦 Batch Scanner - Scan multiple packages

Usage:
  node src/batch-scanner.js <targets-file> [options]

Target File Format (one package per line):
  handlebars@4.7.8
  ejs@3.1.9
  lodash
  # Comments are ignored
  mustache

Options:
  --concurrency <num>     Parallel scans (default: 3)
  --max-iterations <num>  Iterations per package (default: 500)
  --parallel <num>        Workers per scan (default: 2)
  --timeout <seconds>     Timeout (default: 60)
  --output <dir>          Output directory (default: ./batch-results)
  --dry-run               Dry run mode

Example:
  node src/batch-scanner.js top-packages.txt --concurrency 5 --max-iterations 1000
`);
    process.exit(0);
  }

  const targetFile = args[0];
  const options = {
    concurrency: parseInt(args.find((_, i) => args[i - 1] === '--concurrency')) || 3,
    maxIterations: parseInt(args.find((_, i) => args[i - 1] === '--max-iterations')) || 500,
    parallel: parseInt(args.find((_, i) => args[i - 1] === '--parallel')) || 2,
    timeout: parseInt(args.find((_, i) => args[i - 1] === '--timeout')) || 60,
    output: args.find((_, i) => args[i - 1] === '--output'),
    dryRun: args.includes('--dry-run')
  };

  const scanner = new BatchScanner(targetFile, options);

  scanner.scan()
    .then(results => {
      process.exit(results.failed === 0 ? 0 : 1);
    })
    .catch(error => {
      logger.error(error.message);
      process.exit(1);
    });
}

export { BatchScanner };
