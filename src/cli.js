#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import { Orchestrator } from './orchestrator/index.js';
import { MassRunner, VersionRunner, runOrchestratorIsolated } from './orchestrator/mass-runner.js';
import { logger } from './utils/logger.js';
import { assertSandboxedOrRefuse } from './utils/sandbox-guard.js';

const program = new Command();

/**
 * Parse a CLI numeric flag, rejecting garbage instead of silently yielding NaN.
 * `parseInt('foo')` is NaN, which then propagates into loop bounds and timeouts
 * as a silent no-op (0 iterations, a NaN timeout that never fires); fail loudly
 * at the boundary instead. `min` defaults to 1 (all our numeric flags are counts
 * or durations that must be ≥1).
 */
function parseIntFlag(value, name, { min = 1 } = {}) {
  const n = parseInt(value, 10);
  if (!Number.isInteger(n) || n < min) {
    logger.error(chalk.red(`Invalid --${name}: "${value}" (expected an integer ≥ ${min})`));
    process.exit(1);
  }
  return n;
}

program
  .name('uopfuzz')
  .description('UoPFuzz - Prototype pollution gadget hunting framework')
  .version('0.1.0')
  .enablePositionalOptions();

program
  .option('-c, --config <path>', 'Target configuration file (YAML)')
  .option('--target <package>', 'Target package (e.g., pug@3.0.2) — auto-discovers everything')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '60')
  .option('--install-timeout <seconds>', 'Timeout for the npm install of the target package (retried once)', '30')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--dry-run', 'Simulate execution without running actual tests')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations', '1000')
  .option('--parallel <num>', 'Concurrent sandbox workers for Phase-B differential probes (pool-backed; same verdicts as sequential)', '1')
  // Supply chain security options
  .option('--allow-scripts', 'Allow npm lifecycle scripts during install (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run target code in isolated child process (recommended)', true)
  .option('--no-sandbox', 'Disable child process isolation (faster, less safe)')
  .option('--i-understand-untrusted-code', 'Proceed with --target on a non-sandboxed host (installs + EXECUTES an arbitrary npm package). Prefer the dev container / run-sandboxed.sh')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-isolate', 'Run the whole session in this process instead of a crash-isolated child (for debugging; a target that corrupts Node internals can then take the fuzzer down)')
  .option('--no-osv', 'Disable live advisory lookups (OSV.dev AND the GitHub Advisory DB / npm bulk endpoint); disclosure labels then use the built-in DB only. Note: a lookup reveals the analyzed package@version to a third party (the npm registry already sees it on install)')
  .option('--no-chain', 'Disable end-to-end chain synthesis (after a gadget is proven, pair it with a proven prototype-pollution source and reproduce the full attacker-input → source → gadget → sink exploit). On by default; findings are then reported gadget-half only.');

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
        'run untrusted packages inside the dev container (the real isolation boundary). See the Security section in README.md.'
      ));
      if (!process.env.UOPFUZZ_CONTAINER) {
        logger.info(chalk.yellow(
          'Tip: Run inside the dev container for isolation:\n' +
          '  devcontainer up --workspace-folder . && devcontainer exec --workspace-folder . node src/cli.js --target <pkg>'
        ));
      }
    }

    // --target installs and EXECUTES an arbitrary npm package, exactly the risk
    // profile the `mass`/`versions` subcommands already gate. Refuse to run it on
    // a non-sandboxed host unless the operator explicitly accepts the risk. Skip
    // for --dry-run (nothing is executed) and for --config (operator-provided,
    // typically a local/trusted target).
    if (options.target && !options.dryRun) {
      assertSandboxedOrRefuse({ mode: 'target', override: options.iUnderstandUntrustedCode });
    }

    const timeoutSec = parseIntFlag(options.timeout, 'timeout');
    const maxIterations = parseIntFlag(options.maxIterations, 'max-iterations');
    const parallelWorkers = parseIntFlag(options.parallel, 'parallel');
    const installTimeout = parseIntFlag(options.installTimeout, 'install-timeout');

    const orchestratorOpts = {
      configPath: options.config || null,
      targetPackage: options.target || null,
      outputDir: options.output,
      timeout: timeoutSec,
      dryRun: options.dryRun || false,
      maxIterations,
      parallelWorkers,
      installTimeout,
      verbose: options.verbose || false,
      // Security options
      allowScripts: options.allowScripts || false,
      allowSuspicious: options.allowSuspicious || false,
      skipIntegrityCheck: options.skipIntegrityCheck || false,
      sandbox: options.sandbox !== false,
      blockNetwork: !options.allowNetwork,
      noOsv: options.osv === false,
      chain: options.chain !== false,
    };

    // Crash isolation (default): run the whole session in a forked child so a
    // target that corrupts Node's own internals — e.g. a browser-only package
    // whose in-process Object.prototype pollution poisons undici's HTTP parser —
    // dies as a contained, reported failure instead of taking the fuzzer down
    // with an uncaught exception. `--no-isolate` opts out for in-process
    // debugging. The child streams its logs to this terminal (stdio inherited).
    let results;
    if (options.isolate === false) {
      const orchestrator = new Orchestrator(orchestratorOpts);
      results = await orchestrator.run();
    } else {
      const { results: r, error } = await runOrchestratorIsolated(orchestratorOpts, {
        // Interactive single-target run: the operator is watching and can Ctrl-C,
        // so the wall-clock cap is only a backstop against a fully wedged event
        // loop. Scale it to the requested work and floor it generously.
        timeoutMs: Math.max(
          15 * 60 * 1000,
          timeoutSec * 1000 * maxIterations + 60 * 1000,
        ),
      });
      if (error) {
        logger.error(chalk.red.bold('Run failed (isolated child):'), error);
        logger.info('Re-run with --no-isolate to see the crash in this process, or --no-osv if the OSV lookup is implicated.');
        process.exit(1);
      }
      results = r;
    }

    logger.info(chalk.green.bold('Fuzzing session completed'));
    // Name the exact files, not just the directory — a run drops a
    // timestamped pair in there and "./results" leaves the reader guessing
    // which one they just produced.
    if (results?.outputFiles?.report) {
      logger.info(`Report:  ${results.outputFiles.report}`);
      logger.info(`Results: ${results.outputFiles.results}`);
    } else {
      logger.info(`Results saved to: ${options.output}`);
    }

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
  .option('--resume', 'Skip libraries that already have results (this is the default; accepted explicitly for convenience)')
  .option('--no-resume', 'Re-scan every library even if a result already exists (default: resume, skipping done libraries)')
  .option('--concurrency <n>', 'Libraries to scan in parallel (use with caution: shares node_modules)', '1')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '30')
  .option('--install-timeout <seconds>', 'Timeout for each npm install (retried once)', '30')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations per library', '100')
  .option('--dry-run', 'Simulate without running actual tests')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--allow-scripts', 'Allow npm lifecycle scripts (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run in isolated child process (default: on)', true)
  .option('--no-sandbox', 'Disable child process isolation')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-osv', 'Disable live advisory lookups (OSV.dev AND the GitHub Advisory DB); disclosure labels then use the built-in DB only')
  .option('--i-understand-untrusted-code', 'Run untrusted packages OUTSIDE a container (DANGEROUS — bypasses the host-safety gate)')
  .action(async (options) => {
    try {
      if (options.verbose) logger.level = 'debug';
      logger.info(chalk.blue.bold('UoPFuzz — Mass cdnjs Scan'));

      // Host-safety gate: `mass` installs and executes arbitrary top-cdnjs
      // packages. Refuse on a non-sandboxed host unless explicitly overridden.
      // Skipped for --dry-run, which never installs or executes a target.
      if (!options.dryRun) {
        assertSandboxedOrRefuse({ mode: 'mass', override: options.iUnderstandUntrustedCode });
      }

      const orchestratorOptions = {
        outputDir: options.output,
        timeout: parseIntFlag(options.timeout, 'timeout'),
        dryRun: options.dryRun || false,
        maxIterations: parseIntFlag(options.maxIterations, 'max-iterations'),
        installTimeout: parseIntFlag(options.installTimeout, 'install-timeout'),
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
        topN: parseIntFlag(options.top, 'top'),
        limit: parseIntFlag(options.limit, 'limit'),
        // Resume-by-default: a mass sweep is long-running and restartable, so
        // skipping already-scanned libraries is the friendly default. --no-resume
        // (options.resume === false) forces a full re-scan.
        resume: options.resume !== false,
        concurrency: parseIntFlag(options.concurrency, 'concurrency'),
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
  .option('--range <from>..<to>', 'Test versions in range from..to (inclusive, semver; either order)')
  .option('-o, --output <dir>', 'Output directory for results', './results')
  .option('-t, --timeout <seconds>', 'Timeout per iteration in seconds', '30')
  .option('--install-timeout <seconds>', 'Timeout for each npm install (retried once)', '30')
  .option('--max-iterations <num>', 'Maximum fuzzing iterations per version', '100')
  .option('--dry-run', 'Simulate without running actual tests')
  .option('-v, --verbose', 'Enable verbose logging')
  .option('--allow-scripts', 'Allow npm lifecycle scripts (DANGEROUS)')
  .option('--allow-suspicious', 'Allow packages with suspicious install scripts (DANGEROUS)')
  .option('--skip-integrity-check', 'Skip package integrity verification')
  .option('--sandbox', 'Run in isolated child process (default: on)', true)
  .option('--no-sandbox', 'Disable child process isolation')
  .option('--allow-network', 'Allow network access during target execution')
  .option('--no-osv', 'Disable live advisory lookups (OSV.dev AND the GitHub Advisory DB); disclosure labels then use the built-in DB only')
  .option('--i-understand-untrusted-code', 'Run untrusted packages OUTSIDE a container (DANGEROUS — bypasses the host-safety gate)')
  .action(async (options) => {
    try {
      if (options.verbose) logger.level = 'debug';
      logger.info(chalk.blue.bold(`UoPFuzz — Version Sweep: ${options.library}`));

      // Host-safety gate: `versions` installs and executes arbitrary cdnjs-sourced
      // package versions. Refuse on a non-sandboxed host unless explicitly
      // overridden. Skipped for --dry-run, which never installs or executes.
      if (!options.dryRun) {
        assertSandboxedOrRefuse({ mode: 'versions', override: options.iUnderstandUntrustedCode });
      }

      // Build version selection strategy
      let strategy;
      if (options.last) {
        strategy = { mode: 'last', count: parseIntFlag(options.last, 'last') };
      } else if (options.first) {
        strategy = { mode: 'first', count: parseIntFlag(options.first, 'first') };
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
        timeout: parseIntFlag(options.timeout, 'timeout'),
        dryRun: options.dryRun || false,
        maxIterations: parseIntFlag(options.maxIterations, 'max-iterations'),
        installTimeout: parseIntFlag(options.installTimeout, 'install-timeout'),
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
