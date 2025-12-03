#!/usr/bin/env node

/**
 * Multi-Source Scanner - Scan packages from npm, cdnjs, unpkg, jsdelivr
 * Expands beyond just npm registry
 */

import https from 'https';
import { AutoScanner } from './auto-scanner.js';
import { logger } from './utils/logger.js';

class MultiSourceScanner {
  constructor(options = {}) {
    this.options = options;
    this.sources = {
      npm: 'https://registry.npmjs.org',
      cdnjs: 'https://api.cdnjs.com/libraries',
      unpkg: 'https://unpkg.com',
      jsdelivr: 'https://data.jsdelivr.com/v1/packages/npm'
    };
  }

  async fetchJSON(url) {
    return new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          try {
            resolve(JSON.parse(data));
          } catch (error) {
            reject(error);
          }
        });
      }).on('error', reject);
    });
  }

  // Get popular packages from cdnjs
  async getPopularFromCdnjs(limit = 100) {
    logger.info('📦 Fetching popular packages from cdnjs...');

    try {
      const url = `${this.sources.cdnjs}?fields=name,version&limit=${limit}`;
      const data = await this.fetchJSON(url);

      const packages = data.results || [];
      logger.info(`Found ${packages.length} packages on cdnjs`);

      return packages.map(pkg => ({
        name: pkg.name,
        version: pkg.version,
        source: 'cdnjs'
      }));

    } catch (error) {
      logger.error(`Failed to fetch from cdnjs: ${error.message}`);
      return [];
    }
  }

  // Get package info from jsdelivr
  async getPackageFromJsdelivr(packageName) {
    logger.info(`📦 Fetching ${packageName} from jsdelivr...`);

    try {
      const url = `${this.sources.jsdelivr}/${packageName}`;
      const data = await this.fetchJSON(url);

      if (data && data.tags && data.tags.latest) {
        return {
          name: packageName,
          version: data.tags.latest,
          source: 'jsdelivr',
          files: data.versions ? Object.keys(data.versions) : []
        };
      }

      return null;

    } catch (error) {
      logger.error(`Failed to fetch ${packageName} from jsdelivr: ${error.message}`);
      return null;
    }
  }

  // Search cdnjs by keyword
  async searchCdnjs(keyword, limit = 50) {
    logger.info(`🔍 Searching cdnjs for: ${keyword}`);

    try {
      const url = `${this.sources.cdnjs}?search=${encodeURIComponent(keyword)}&fields=name,version,description&limit=${limit}`;
      const data = await this.fetchJSON(url);

      const packages = data.results || [];
      logger.info(`Found ${packages.length} packages matching "${keyword}"`);

      return packages.map(pkg => ({
        name: pkg.name,
        version: pkg.version,
        description: pkg.description,
        source: 'cdnjs'
      }));

    } catch (error) {
      logger.error(`Search failed: ${error.message}`);
      return [];
    }
  }

  // Scan packages from multiple sources
  async scanMultiSource(target) {
    const results = {
      target,
      sources: [],
      scans: []
    };

    logger.info(`🌐 Multi-source scan for: ${target}`);

    // Try npm (default)
    try {
      logger.info('  Checking npm...');
      const npmScanner = new AutoScanner(target, this.options);
      const npmResults = await npmScanner.scan();

      results.sources.push('npm');
      results.scans.push({
        source: 'npm',
        success: true,
        results: npmResults
      });

      logger.info('  ✅ npm scan complete');

    } catch (error) {
      logger.warn(`  ⚠️  npm scan failed: ${error.message}`);
      results.scans.push({
        source: 'npm',
        success: false,
        error: error.message
      });
    }

    // Try cdnjs
    try {
      logger.info('  Checking cdnjs...');
      const [packageName] = target.split('@');
      const cdnjsPackages = await this.searchCdnjs(packageName, 1);

      if (cdnjsPackages.length > 0) {
        const pkg = cdnjsPackages[0];
        logger.info(`  Found on cdnjs: ${pkg.name}@${pkg.version}`);

        results.sources.push('cdnjs');
        results.scans.push({
          source: 'cdnjs',
          success: true,
          available: true,
          package: pkg
        });
      } else {
        logger.info('  Not found on cdnjs');
      }

    } catch (error) {
      logger.warn(`  ⚠️  cdnjs check failed: ${error.message}`);
    }

    // Try jsdelivr
    try {
      logger.info('  Checking jsdelivr...');
      const [packageName] = target.split('@');
      const jsdelivrPkg = await this.getPackageFromJsdelivr(packageName);

      if (jsdelivrPkg) {
        logger.info(`  Found on jsdelivr: ${jsdelivrPkg.name}@${jsdelivrPkg.version}`);

        results.sources.push('jsdelivr');
        results.scans.push({
          source: 'jsdelivr',
          success: true,
          available: true,
          package: jsdelivrPkg
        });
      } else {
        logger.info('  Not found on jsdelivr');
      }

    } catch (error) {
      logger.warn(`  ⚠️  jsdelivr check failed: ${error.message}`);
    }

    return results;
  }

  // Scan popular packages from cdnjs
  async scanCdnjsTop(limit = 20) {
    logger.info(`🚀 Scanning top ${limit} packages from cdnjs`);

    const packages = await this.getPopularFromCdnjs(limit);
    const results = [];

    for (const pkg of packages) {
      try {
        logger.info(`\nScanning ${pkg.name}@${pkg.version} (from cdnjs)...`);

        const scanner = new AutoScanner(`${pkg.name}@${pkg.version}`, {
          ...this.options,
          output: `${this.options.output || './cdnjs-results'}/${pkg.name}/`
        });

        const scanResults = await scanner.scan();

        results.push({
          package: pkg,
          success: true,
          results: scanResults
        });

        logger.info(`✅ Complete: ${scanResults.potentialChains.length} chains found`);

      } catch (error) {
        logger.error(`❌ Failed ${pkg.name}: ${error.message}`);
        results.push({
          package: pkg,
          success: false,
          error: error.message
        });
      }
    }

    this.printSummary(results);
    return results;
  }

  printSummary(results) {
    console.log('\n' + '='.repeat(60));
    console.log('📊 CDNJS SCAN SUMMARY');
    console.log('='.repeat(60));

    const successful = results.filter(r => r.success).length;
    const failed = results.filter(r => !r.success).length;
    const vulnerable = results.filter(r => r.success && r.results.potentialChains.length > 0).length;

    console.log(`Total Scanned: ${results.length}`);
    console.log(`✅ Successful: ${successful}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`🚨 Vulnerable: ${vulnerable}`);
    console.log('='.repeat(60));

    if (vulnerable > 0) {
      console.log('\n🚨 VULNERABLE PACKAGES:');
      results
        .filter(r => r.success && r.results.potentialChains.length > 0)
        .forEach(r => {
          console.log(`  • ${r.package.name}@${r.package.version} - ${r.results.potentialChains.length} chains`);
        });
    }
  }
}

// CLI usage
if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);

  if (args.length === 0) {
    console.log(`
🌐 Multi-Source Scanner - Scan from npm, cdnjs, jsdelivr

Usage:
  node src/multi-source-scanner.js <command> [options]

Commands:
  search <keyword>              Search cdnjs for packages
  scan <package>                Multi-source scan (npm + cdnjs + jsdelivr)
  cdnjs-top <limit>             Scan top N popular packages from cdnjs
  popular                       Scan top 20 from cdnjs

Examples:
  # Search cdnjs for template engines
  node src/multi-source-scanner.js search template

  # Multi-source scan
  node src/multi-source-scanner.js scan handlebars

  # Scan top 50 from cdnjs
  node src/multi-source-scanner.js cdnjs-top 50

Options:
  --dry-run                    Dry run mode
  --max-iterations <num>       Max iterations (default: 500)
  --parallel <num>             Workers (default: 2)
  --output <dir>               Output directory
`);
    process.exit(0);
  }

  const command = args[0];
  const target = args[1];

  const options = {
    dryRun: args.includes('--dry-run'),
    maxIterations: parseInt(args.find((_, i) => args[i - 1] === '--max-iterations')) || 500,
    parallel: parseInt(args.find((_, i) => args[i - 1] === '--parallel')) || 2,
    output: args.find((_, i) => args[i - 1] === '--output')
  };

  const scanner = new MultiSourceScanner(options);

  switch (command) {
    case 'search':
      scanner.searchCdnjs(target || 'template')
        .then(results => {
          console.log(`\nFound ${results.length} packages:`);
          results.forEach(pkg => {
            console.log(`  • ${pkg.name}@${pkg.version}`);
            if (pkg.description) {
              console.log(`    ${pkg.description}`);
            }
          });
        });
      break;

    case 'scan':
      scanner.scanMultiSource(target)
        .then(results => {
          console.log(`\nAvailable on: ${results.sources.join(', ')}`);
          results.scans.forEach(scan => {
            console.log(`\n${scan.source}:`);
            if (scan.success && scan.results) {
              console.log(`  Chains found: ${scan.results.potentialChains.length}`);
            } else if (scan.available) {
              console.log(`  Available: ${scan.package.name}@${scan.package.version}`);
            } else {
              console.log(`  ${scan.error || 'Not available'}`);
            }
          });
        });
      break;

    case 'cdnjs-top':
    case 'popular':
      const limit = command === 'cdnjs-top' ? (parseInt(target) || 20) : 20;
      scanner.scanCdnjsTop(limit)
        .then(() => {
          logger.info('Scan complete!');
        });
      break;

    default:
      logger.error(`Unknown command: ${command}`);
      process.exit(1);
  }
}

export { MultiSourceScanner };
