#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { Orchestrator } from './orchestrator/index.js';
import { MassRunner, VersionRunner } from './orchestrator/mass-runner.js';
import { logger } from './utils/logger.js';

const program = new Command();

program
  .name('uopfuzz')
  .description('UoPFuzz - Prototype pollution gadget hunting framework')
  .version('1.0.0')
  .enablePositionalOptions();

program
  .option('-c, --config <path>', 'Target configuration file (YAML)')
  .option('--target <package>', 'Target package (e.g., pug@3.0.2) — auto-discovers everything')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '60')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--dry-run', 'Simulate execution without running actual tests')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations', '1000')
  .option('--parallel <num>', 'Number of parallel workers', '1')
  // Supply chain security options
  .option('--allow-scripts', 'Allow npm lifecycle scripts during install (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run target code in isolated child process (recommended)', true)
  .option('--no-sandbox', 'Disable child process isolation (faster, less safe)')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-osv', 'Disable live OSV.dev advisory lookups (disclosure labels use the built-in DB only). Note: an OSV query reveals the analyzed package@version to a third party');

program.action(async (options) => {
  try {
    if (options.verbose) {
      logger.level = 'debug';
    }

    logger.info(chalk.blue.bold('UoPFuzz - Prototype Pollution Gadget Hunter'));
    logger.info('Starting fuzzing session...');

    if (!options.config && !options.target) {
      logger.error(chalk.red('Either --config <path> or --target <package@version> is required'));
      logger.info('Examples:');
      logger.info('  uopfuzz --target pug@3.0.2');
      logger.info('  uopfuzz --target squirrelly@8.0.8 --max-iterations 500');
      logger.info('  uopfuzz --config config/targets/pug.yaml');
      process.exit(1);
    }

    // Security warnings
    if (options.allowScripts) {
      logger.warn(chalk.red('⚠ --allow-scripts: npm lifecycle scripts will run during install'));
      logger.warn(chalk.red('  Malicious packages can execute arbitrary code via postinstall'));
    }
    if (!options.sandbox) {
      logger.warn(chalk.yellow('⚠ --no-sandbox: target code runs in the fuzzer process'));
      logger.warn(chalk.yellow('  A malicious package can access your filesystem and network'));
    }
    if (options.allowNetwork) {
      logger.warn(chalk.yellow('⚠ --allow-network: target code can make outbound connections'));
    }

    if (!options.dryRun) {
      logger.info(chalk.yellow(
        'Only analyze packages you are authorized to test. Target code IS executed — ' +
        'run untrusted packages inside the dev container (the real isolation boundary). See the Safety model in README.md.'
      ));
      if (!process.env.UOPFUZZ_CONTAINER) {
        logger.info(chalk.yellow(
          'Tip: Run inside the dev container for isolation:\n' +
          '  devcontainer up --workspace-folder . && devcontainer exec --workspace-folder . node src/cli.js --target <pkg>'
        ));
      }
    }

    const orchestratorOpts = {
      configPath: options.config || null,
      targetPackage: options.target || null,
      outputDir: options.output,
      timeout: parseInt(options.timeout),
      dryRun: options.dryRun || false,
      maxIterations: parseInt(options.maxIterations),
      parallelWorkers: parseInt(options.parallel),
      verbose: options.verbose || false,
      // Security options
      allowScripts: options.allowScripts || false,
      allowSuspicious: options.allowSuspicious || false,
      skipIntegrityCheck: options.skipIntegrityCheck || false,
      sandbox: options.sandbox !== false,
      blockNetwork: !options.allowNetwork,
      noOsv: options.osv === false,
    };

    const orchestrator = new Orchestrator(orchestratorOpts);
    const results = await orchestrator.run();

    logger.info(chalk.green.bold('Fuzzing session completed'));
    logger.info(`Results saved to: ${options.output}`);

    const confirmedChains = results.confirmedChains || [];
    const confirmed = confirmedChains.length;
    const undocumented = confirmedChains.filter(c => c.disclosure?.label === 'undocumented-vulnerability').length;
    const rediscovered = confirmedChains.filter(c => c.disclosure?.label === 'previously-discovered').length;
    const knownCves = confirmedChains.filter(c => c.disclosure?.label === 'known-cve').length;
    const unproven = (results.candidateChains?.length || 0);

    if (confirmed > 0) {
      logger.warn(chalk.red.bold(
        `${confirmed} PROVEN vulnerabilit${confirmed !== 1 ? 'ies' : 'y'} ` +
        `(${undocumented} undocumented, ${rediscovered} previously discovered, ${knownCves} known CVE) — reproduced in fresh processes`
      ));
      for (const c of confirmedChains) {
        const srcTag = c.disclosure?.source === 'osv' ? ' via OSV.dev'
          : c.disclosure?.source === 'static+osv' ? ' (built-in DB + OSV.dev)' : '';
        const tag = c.disclosure?.label === 'known-cve'
          ? chalk.yellow(`known CVE${c.disclosure?.cve ? ' ' + c.disclosure.cve : ''}${srcTag}`)
          : c.disclosure?.label === 'previously-discovered'
            ? chalk.blue(`previously discovered${c.disclosure?.priorSighting?.discoveredAt ? ' (first seen ' + c.disclosure.priorSighting.discoveredAt + ')' : ''}`)
            : chalk.red.bold(`UNDOCUMENTED VULNERABILITY${c.disclosure?.regressionSuspect ? ' (regression suspect)' : ''}`);
        logger.warn(`  • ${tag}: Object.prototype.${c.source?.property} via ${c.input?.entryPoint} [${c.proof?.type}]`);
      }
    }
    if (unproven > 0) {
      logger.info(`${unproven} unproven lead${unproven !== 1 ? 's' : ''} (did not reproduce — NOT vulnerabilities; see report)`);
    }
    if (confirmed === 0) {
      logger.info('No vulnerabilities reproduced');
    }

  } catch (error) {
    logger.error(chalk.red.bold('Fatal error:'), error.message);
    if (options.verbose) {
      logger.error(error.stack);
    }
    process.exit(1);
  }
});

// ─── mass subcommand ──────────────────────────────────────────────────────────

program
  .command('mass')
  .description('Mass-test the top cdnjs JavaScript libraries for prototype-pollution gadgets')
  .option('--search <query>', 'Free-text cdnjs search filter', '')
  .option('--top <n>', 'Number of libraries to test (ranked by GitHub stars)', '50')
  .option('--limit <n>', 'How many libraries to fetch from cdnjs before ranking', '200')
  .option('--resume', 'Skip libraries that already have results in the output directory')
  .option('--concurrency <n>', 'Libraries to scan in parallel (use with caution: shares node_modules)', '1')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '30')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations per library', '100')
  .option('--dry-run', 'Simulate without running actual tests')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--allow-scripts', 'Allow npm lifecycle scripts (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run in isolated child process (default: on)', true)
  .option('--no-sandbox', 'Disable child process isolation')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-osv', 'Disable live OSV.dev advisory lookups (disclosure labels use the built-in DB only)')
  .action(async (options) => {
    try {
      if (options.verbose) logger.level = 'debug';
      logger.info(chalk.blue.bold('UoPFuzz — Mass cdnjs Scan'));

      const orchestratorOptions = {
        outputDir: options.output,
        timeout: parseInt(options.timeout),
        dryRun: options.dryRun || false,
        maxIterations: parseInt(options.maxIterations),
        parallelWorkers: 1,
        verbose: options.verbose || false,
        allowScripts: options.allowScripts || false,
        allowSuspicious: options.allowSuspicious || false,
        skipIntegrityCheck: options.skipIntegrityCheck || false,
        sandbox: options.sandbox !== false,
        blockNetwork: !options.allowNetwork,
        noOsv: options.osv === false,
      };

      const runner = new MassRunner({
        search: options.search,
        topN: parseInt(options.top),
        limit: parseInt(options.limit),
        resume: options.resume || false,
        concurrency: parseInt(options.concurrency),
        options: orchestratorOptions,
      });

      const summary = await runner.run();

      logger.info(chalk.green.bold('Mass scan completed'));
      logger.info(`Tested: ${summary.total} | Vulnerable: ${summary.vulnerable} | Failed: ${summary.failed}`);
      logger.info(`Report: ${summary.reportFile}`);

    } catch (error) {
      logger.error(chalk.red.bold('Fatal error:'), error.message);
      if (options.verbose) logger.error(error.stack);
      process.exit(1);
    }
  });

// ─── versions subcommand ──────────────────────────────────────────────────────

program
  .command('versions')
  .description('Scan a single library across multiple versions to track vulnerability introduction/fix')
  .requiredOption('--library <name>', 'cdnjs library name (e.g. lodash.js)')
  .option('--npm-package <name>', 'npm package name override (auto-resolved if omitted)')
  .option('--last <n>', 'Test only the last N versions (newest first)')
  .option('--first <n>', 'Test only the first N versions (oldest first — useful for known-vulnerable older releases)')
  .option('--all', 'Test all available versions (default if no range flags given)')
  .option('--range <from>..<to>', 'Test versions in range from..to (inclusive, semver)')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '30')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations per version', '100')
  .option('--dry-run', 'Simulate without running actual tests')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--allow-scripts', 'Allow npm lifecycle scripts (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run in isolated child process (default: on)', true)
  .option('--no-sandbox', 'Disable child process isolation')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-osv', 'Disable live OSV.dev advisory lookups (disclosure labels use the built-in DB only)')
  .action(async (options) => {
    try {
      if (options.verbose) logger.level = 'debug';
      logger.info(chalk.blue.bold(`UoPFuzz — Version Sweep: ${options.library}`));

      // Build version selection strategy
      let strategy;
      if (options.last) {
        strategy = { mode: 'last', count: parseInt(options.last) };
      } else if (options.first) {
        strategy = { mode: 'first', count: parseInt(options.first) };
      } else if (options.range) {
        const parts = options.range.split('..');
        if (parts.length !== 2) {
          logger.error('--range must be in the form <from>..<to>  e.g.  4.0.0..4.17.0');
          process.exit(1);
        }
        strategy = { mode: 'range', from: parts[0].trim(), to: parts[1].trim() };
      } else {
        strategy = { mode: 'all' };
      }

      const orchestratorOptions = {
        outputDir: options.output,
        timeout: parseInt(options.timeout),
        dryRun: options.dryRun || false,
        maxIterations: parseInt(options.maxIterations),
        parallelWorkers: 1,
        verbose: options.verbose || false,
        allowScripts: options.allowScripts || false,
        allowSuspicious: options.allowSuspicious || false,
        skipIntegrityCheck: options.skipIntegrityCheck || false,
        sandbox: options.sandbox !== false,
        blockNetwork: !options.allowNetwork,
        noOsv: options.osv === false,
      };

      const runner = new VersionRunner({
        cdnjsName: options.library,
        npmPackage: options.npmPackage || null,
        strategy,
        options: orchestratorOptions,
      });

      const summary = await runner.run();

      logger.info(chalk.green.bold('Version sweep completed'));
      logger.info(`${summary.library}: ${summary.versionsTotal} versions tested | Vulnerable: ${summary.vulnerable} | Failed: ${summary.failed}`);
      logger.info(`Report: ${summary.reportFile}`);

    } catch (error) {
      logger.error(chalk.red.bold('Fatal error:'), error.message);
      if (options.verbose) logger.error(error.stack);
      process.exit(1);
    }
  });

program.parse();
