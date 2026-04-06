#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { Orchestrator } from './orchestrator/index.js';
import { logger } from './utils/logger.js';

const program = new Command();

program
  .name('uopfuzz')
  .description('UoPFuzz - Prototype pollution gadget hunting framework')
  .version('1.0.0');

program
  .option('-c, --config <path>', 'Target configuration file (YAML)')
  .option('--target <package>', 'Target package (e.g., pug@3.0.2) — auto-discovers everything')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '60')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--dry-run', 'Simulate execution without running actual tests')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations', '1000')
  .option('--parallel <num>', 'Number of parallel workers', '1');

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

    const orchestratorOpts = {
      configPath: options.config || null,
      targetPackage: options.target || null,
      outputDir: options.output,
      timeout: parseInt(options.timeout),
      dryRun: options.dryRun || false,
      maxIterations: parseInt(options.maxIterations),
      parallelWorkers: parseInt(options.parallel),
      verbose: options.verbose || false
    };

    const orchestrator = new Orchestrator(orchestratorOpts);
    const results = await orchestrator.run();

    logger.info(chalk.green.bold('Fuzzing session completed'));
    logger.info(`Results saved to: ${options.output}`);

    const confirmed = results.confirmedChains?.length || 0;
    const candidates = results.potentialChains?.length || 0;

    if (confirmed > 0) {
      logger.warn(chalk.red.bold(`${confirmed} CONFIRMED gadget chains found`));
    }
    if (candidates > 0) {
      logger.info(`${candidates} unconfirmed candidates`);
    }
    if (confirmed === 0 && candidates === 0) {
      logger.info('No gadget chains found');
    }

  } catch (error) {
    logger.error(chalk.red.bold('Fatal error:'), error.message);
    if (options.verbose) {
      logger.error(error.stack);
    }
    process.exit(1);
  }
});

program.parse();
