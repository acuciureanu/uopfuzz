import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { Worker } from 'worker_threads';
import { logger } from '../utils/logger.js';
import { TargetIntegration } from '../target-integration/index.js';
import { InputGeneration } from '../input-generation/index.js';
import { Instrumentation } from '../instrumentation/index.js';
import { GadgetAnalysis } from '../gadget-analysis/index.js';
import { generateSingleReport } from '../reporting/markdown-report.js';
import { reproduceProto, reproduceRce } from '../verification/reproduce.js';
import { classifyFinding } from '../gadget-analysis/disclosure.js';
import { fetchOsvVulns } from '../sources/osv.js';
import {
  loadDiscoveries,
  appendDiscovery,
  buildRecord,
  DEFAULT_DISCOVERY_STORE_PATH,
} from '../gadget-analysis/discovery-store.js';
import { snapshotPrototype, detectAndRestorePrototype } from '../utils/prototype-monitor.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Science-Based Fuzzing Orchestrator
 *
 * Coordinates the fuzzing pipeline with:
 *
 * 1. Coverage-guided feedback loop: Instrumentation produces edge
 *    coverage data that feeds back into input generation power schedules
 *    (Böhme et al., CCS 2016).
 *
 * 2. Statistical convergence detection: Monitors coverage saturation
 *    rate to determine when fuzzing has reached diminishing returns,
 *    following the power law observation of edge discovery.
 *
 * 3. Science-based reporting: Results include CVSS scores, Bayesian
 *    confidence intervals, coverage entropy, and strategy effectiveness.
 */
export class Orchestrator {
  constructor(options) {
    this.config = null;
    this.options = options;
    // Where the durable discovery ledger lives. Injectable so a test run does
    // not append to the repo's real, tracked store — the suite must not mutate
    // the record of what this tool has genuinely found.
    this._discoveryStorePath = options?.discoveryStorePath || DEFAULT_DISCOVERY_STORE_PATH;
    this.targetIntegration = null;
    this.inputGeneration = null;
    this.instrumentation = null;
    this.gadgetAnalysis = null;
    this.results = {
      startTime: null,
      endTime: null,
      iterationsCompleted: 0,
      inputsGenerated: 0,
      potentialChains: [],
      errors: [],
      // Science-based metrics
      coverageStats: null,
      convergenceInfo: null,
      strategyEffectiveness: null
    };
  }

  async run() {
    try {
      this.results.startTime = new Date();

      // Baseline snapshot for the run-end safety net in saveResults(). In-process
      // differential modes (forced-branch, multi-property) install/restore traps
      // around each individual call, but a run of many iterations against a
      // library that itself touches Object.prototype (observed with ejs,
      // handlebars, pug) can still leave residual own-properties behind by the
      // time the run ends — which has crashed fs.writeFile with an internal
      // Node assertion. This baseline lets saveResults() restore a clean state
      // unconditionally before doing I/O, regardless of which call leaked.
      this._startupPrototypeSnapshot = snapshotPrototype();

      logger.info('Loading configuration...');
      await this.loadConfiguration();

      logger.info('Initializing components...');
      await this.initializeComponents();

      logger.info('Setting up target environment...');
      await this.setupTarget();

      // Enrich the disclosure-status classification with live OSV.dev advisories
      // (once per run). Fail-safe: never throws; degrades to static-DB-only if unavailable.
      await this.fetchOsvData();

      // Load this tool's durable discovery store (once per run) so confirmed
      // findings can be recognized as rediscoveries of bugs previously found.
      // Same timing/defensive contract as fetchOsvData: never throws, [] on miss.
      this.priorDiscoveries = loadDiscoveries(this._discoveryStorePath);

      logger.info('Starting fuzzing workflow...');
      await this.executeFuzzingWorkflow();

      logger.info('Analyzing results...');
      await this.analyzeResults();

      this.results.endTime = new Date();

      logger.info('Saving results...');
      await this.saveResults();

      return this.results;

    } catch (error) {
      this.results.endTime = this.results.endTime || new Date();
      this.results.errors.push({
        timestamp: new Date(),
        error: error.message,
        stack: error.stack
      });
      throw error;
    } finally {
      // Tear down the persistent sandbox worker pool so no discovery worker
      // outlives the run (leaked forked processes would otherwise accumulate,
      // especially across mass/version sweeps).
      try { this.instrumentation?.destroy?.(); } catch { /* best effort */ }
    }
  }

  async loadConfiguration() {
    if (this.options.targetPackage) {
      // Auto-discovery mode: config will be generated after install
      logger.info(`Target package: ${this.options.targetPackage} (auto-discovery mode)`);
      this.config = null; // Will be set in setupTarget
      return;
    }

    try {
      const configPath = path.resolve(this.options.configPath);
      logger.debug(`Loading config from: ${configPath}`);

      const configContent = await fs.readFile(configPath, 'utf8');
      const YAML = await import('yaml');
      this.config = YAML.parse(configContent);

      logger.info(`Loaded target: ${this.config.name || 'Unknown'}`);

    } catch (error) {
      throw new Error(`Failed to load configuration: ${error.message}`);
    }
  }

  async initializeComponents() {
    this.targetIntegration = new TargetIntegration(this.options);
    this.inputGeneration = new InputGeneration(this.options);
    this.instrumentation = new Instrumentation(this.options);
    this.gadgetAnalysis = new GadgetAnalysis(this.options);

    // Enable real V8 coverage collection when not in dry-run mode
    if (!this.options.dryRun) {
      await this.instrumentation.enableV8Coverage();
    }

    logger.debug('All components initialized');
  }

  async setupTarget() {
    if (this.options.targetPackage) {
      // Auto-discovery: install, load, inspect, and generate config
      const { config, module: targetModule } = await this.targetIntegration.setupTargetFromPackage(
        this.options.targetPackage
      );
      this.config = config;
      if (!this.options.dryRun) {
        this.instrumentation.setTargetModule(targetModule);
        this.instrumentation.warnIfUnsandboxedBrowserTarget(config);
      }
      logger.info(`Target ${config.name}@${config.version} auto-discovered and ready`);
      return;
    }

    if (this.options.dryRun) {
      logger.info('Dry run mode - skipping actual target setup');
      return;
    }

    const targetModule = await this.targetIntegration.setupTarget(this.config);
    this.instrumentation.setTargetModule(targetModule);
    this.instrumentation.warnIfUnsandboxedBrowserTarget(this.config);
    logger.info(`Target ${this.config.name} setup completed`);
  }

  async executeFuzzingWorkflow() {
    const maxIterations = this.options.maxIterations;
    const parallelWorkers = this.options.parallelWorkers || 1;

    logger.info(`Starting ${maxIterations} fuzzing iterations with ${this.options.timeout}s timeout`);

    if (parallelWorkers > 1) {
      // --parallel is NOT wired for real gadget hunting: the worker-thread path
      // (orchestrator/worker.js) never loads the target module and never runs
      // the differential confirmation phase (Phase B), so it produces ZERO
      // confirmed vulnerabilities and only burns CPU on coverage exploration.
      // Rather than silently find nothing, fall back to the sequential path,
      // which is where real (reproduction-proven) findings come from.
      // TODO: real parallelism should be built on top of the sandbox worker pool
      // (each worker owning a persistent target process), not the current
      // simulate-only thread path.
      logger.warn(
        `--parallel ${parallelWorkers} is not supported for gadget confirmation ` +
        `(the parallel path does coverage exploration only and confirms nothing). ` +
        `Running sequentially so findings are actually reproduced.`
      );
    }
    logger.info('Using sequential execution (single worker)');
    await this.executeSequentialFuzzing(maxIterations);
  }

  /**
   * Sequential fuzzing with coverage feedback loop and differential oracle.
   *
   * Two-phase approach per iteration:
   *
   * Phase A — Coverage exploration (unchanged):
   * 1. Generate inputs with power-scheduled mutations
   * 2. Execute with tracing (V8 coverage + taint proxy)
   * 3. Feed coverage back to input generator
   *
   * Phase B — Differential gadget confirmation (NEW):
   * 4. Discover UOP properties from taint logs
   * 5. Generate pollution descriptors (property + payload pairs)
   * 6. Run differential oracle: clean vs polluted execution
   * 7. Confirmed gadgets are stored with causal evidence
   */
  async executeSequentialFuzzing(maxIterations) {
    const timeout = this.options.timeout * 1000;
    let consecutiveSaturatedIterations = 0;

    // Track confirmed chains separately from candidates.
    // confirmedChains → reproduction-PROVEN vulnerabilities only.
    // candidateChains → discovery-oracle leads that did NOT reproduce
    //                   independently (unproven; manual review, never "VULNERABLE").
    if (!this.results.confirmedChains) {
      this.results.confirmedChains = [];
    }
    if (!this.results.candidateChains) {
      this.results.candidateChains = [];
    }

    for (let iteration = 0; iteration < maxIterations; iteration++) {
      try {
        const iterationStart = Date.now();
        logger.info(`Iteration ${iteration + 1}/${maxIterations} starting...`);

        // === Phase A: Coverage exploration ===
        const inputs = await this.inputGeneration.generateInputs(this.config, iteration);
        this.results.inputsGenerated += inputs.length;
        logger.debug(`Generated ${inputs.length} inputs for iteration ${iteration + 1}`);

        let timeoutTimer;
        const traces = await Promise.race([
          this.instrumentation.executeWithTracing(inputs, this.config),
          new Promise((_, reject) => {
            timeoutTimer = setTimeout(() => reject(new Error('Iteration timeout')), timeout);
          })
        ]);
        clearTimeout(timeoutTimer);

        // Feed coverage results back to input generator
        for (const trace of traces) {
          if (trace.coverageResult && trace.input) {
            this.inputGeneration.integrateCoverageFeedback(
              trace.input, trace.coverageResult
            );
          }
        }

        // Standard chain analysis (timestamp-correlation candidates)
        const chains = await this.gadgetAnalysis.analyzeTraces(traces, this.config);
        this.results.potentialChains.push(...chains);

        // === Phase B: Differential gadget confirmation ===
        if (!this.options.dryRun) {
          await this.executeDifferentialPhase(inputs, iteration);
        }

        const iterationTime = Date.now() - iterationStart;
        logger.debug(`Iteration ${iteration + 1}/${maxIterations} completed in ${iterationTime}ms`);

        // Convergence detection — DUAL metric: both coverage AND gadget discovery rate.
        // Synthetic coverage alone is unreliable (exits too early, missing gadgets).
        // We require BOTH:
        //   1. Coverage saturation (>95%) — no new code paths being discovered
        //   2. No new gadgets in last N iterations — gadget search is exhausted
        // This prevents premature exit when coverage saturates but gadgets remain undiscovered.
        const saturation = this.instrumentation.getCoverageTracker().getSaturationRate();
        const MIN_ITERATIONS_BEFORE_CONVERGENCE = Math.min(20, Math.max(5, Math.floor(maxIterations * 0.3)));
        const CONVERGENCE_WINDOW = Math.min(10, Math.max(3, Math.floor(maxIterations * 0.1)));

        // Track gadget discovery rate
        const currentGadgetCount = (this.results.confirmedChains || []).length;
        if (!this._lastGadgetCount) this._lastGadgetCount = 0;
        if (!this._iterationsSinceLastGadget) this._iterationsSinceLastGadget = 0;

        if (currentGadgetCount > this._lastGadgetCount) {
          this._lastGadgetCount = currentGadgetCount;
          this._iterationsSinceLastGadget = 0;
          consecutiveSaturatedIterations = 0; // Reset — new gadget found
        } else {
          this._iterationsSinceLastGadget++;
        }

        // Both conditions must be true to converge
        const coverageSaturated = saturation > 0.95;
        const gadgetSearchExhausted = this._iterationsSinceLastGadget >= CONVERGENCE_WINDOW * 2;

        if (coverageSaturated && gadgetSearchExhausted && iteration >= MIN_ITERATIONS_BEFORE_CONVERGENCE) {
          consecutiveSaturatedIterations++;
          if (consecutiveSaturatedIterations >= CONVERGENCE_WINDOW) {
            logger.info(`Converged: coverage ${(saturation * 100).toFixed(1)}%, no new gadgets in ${this._iterationsSinceLastGadget} iterations`);
            this.results.convergenceInfo = {
              convergedAt: iteration + 1,
              saturationRate: saturation,
              gadgetCount: currentGadgetCount,
              iterationsSinceLastGadget: this._iterationsSinceLastGadget,
              reason: 'coverage_and_gadget_saturation'
            };
            break;
          }
        } else if (!coverageSaturated || !gadgetSearchExhausted) {
          consecutiveSaturatedIterations = 0;
        }

        if (iteration % 10 === 0) {
          const coverageStats = this.instrumentation.getCoverageStats();
          const confirmedCount = this.results.confirmedChains.length;
          const uopCount = this.inputGeneration.discoveredUOPProperties.size;
          logger.info(
            `Progress: ${iteration + 1}/${maxIterations} | ` +
            `${confirmedCount} confirmed gadgets | ${uopCount} UOP properties | ` +
            `${coverageStats.coveredEdges} edges | ` +
            `saturation: ${(saturation * 100).toFixed(1)}%`
          );
        }

      } catch (error) {
        logger.warn(`Iteration ${iteration + 1} failed: ${error.message}`);
        logger.warn(`Stack: ${error.stack?.split('\n').slice(0,3).join(' | ')}`);
        this.results.errors.push({
          iteration: iteration + 1,
          error: error.message
        });
      }

      this.results.iterationsCompleted = iteration + 1;
    }
  }

  /**
   * Differential gadget confirmation phase.
   *
   * 1. UOP Discovery: Run a clean execution to find what properties the
   *    library reads as undefined. These are pollution candidates.
   * 2. Pollution Testing: For each candidate property × payload combination,
   *    run the differential oracle (clean vs polluted) and confirm gadgets.
   */
  /**
   * Fetch live OSV.dev advisories for the target package@version, once per run,
   * to enrich the disclosure-status classification. Fail-safe: never throws; leaves `this.osvVulns`
   * null (→ static-DB-only classification) when disabled, dry-run, or unreachable
   * (offline / --network=none / egress-blocked). NOT gated on --allow-network:
   * that flag governs the untrusted target's egress, whereas this is a trusted
   * read-only metadata call from the orchestrator itself. Opt out with --no-osv.
   */
  async fetchOsvData() {
    this.osvVulns = null;
    if (this.options.dryRun || this.options.noOsv) return;
    const pkg = this.config?.package;
    const version = this.config?.version;
    if (!pkg || !version) return;

    const result = await fetchOsvVulns(pkg, version, { ecosystem: 'npm' }); // never throws
    if (result.ok && result.vulns.length > 0) {
      this.osvVulns = result.vulns;
      logger.info(`OSV.dev: ${result.vulns.length} advisor${result.vulns.length !== 1 ? 'ies' : 'y'} for ${pkg}@${version}`);
    } else if (!result.ok) {
      logger.debug(`OSV.dev lookup unavailable for ${pkg}@${version}: ${result.error} (using static DB only)`);
    }
  }

  /**
   * The zero-false-positive gate. A discovery-oracle result becomes a reported
   * vulnerability ONLY if it reproduces independently in fresh child processes
   * (real prototype mutation for proofType 'pp', canary code execution for 'rce').
   * Otherwise it is recorded as an unproven candidate — never "VULNERABLE".
   *
   * @returns {Promise<boolean>} true if a proven vulnerability was recorded.
   */
  /**
   * Resolve this target's config.sequences entry (if any) for the entry point
   * under test into plain-data { call, method?, args } steps the reproduction
   * worker can replay over IPC — no functions cross the boundary. Needed
   * because some gadgets (CVE-2022-29078: EJS's compile()) only execute when
   * the function an entry point RETURNS is subsequently invoked; a single call
   * to the entry point alone never reaches the sink, so reproduction must
   * replay the same multi-step chain discovery used.
   */
  buildResolvedSequence(testInput) {
    const seqDef = this.config.sequences?.find(s => s.entryPoint === testInput.entryPoint);
    if (!seqDef) return null;
    return {
      steps: seqDef.steps.map(step => ({
        call: step.call,
        method: step.method,
        args: this.instrumentation.buildCallArgs(step, testInput, this.config),
      })),
    };
  }

  async proveAndRecord(diffResult, testInput, descriptor, extra = {}) {
    const diff = diffResult?.diff;
    if (!diff) return false;
    if (!this.results.candidateChains) this.results.candidateChains = [];

    const pkg = this.config.package;
    const version = this.config.version;
    const entryPoint = testInput.entryPoint;
    const proofType = diff.proofType || (diff.prototypePolluted ? 'pp' : 'rce');

    // Without an installable/require-able package we cannot reproduce in a fresh
    // process, so we cannot prove it → record as a candidate, never confirm.
    let proof = null;
    if (pkg && diff.reproducible !== false) {
      try {
        const browserEnv = this.config.browserEnv === true;
        if (proofType === 'pp') {
          proof = await reproduceProto(pkg, entryPoint,
            { property: descriptor.property, value: descriptor.value },
            { version, blockNetwork: this.options.blockNetwork !== false, browserEnv });
        } else {
          const gates = extra.gates
            || diff.details?.forcedGatesFired
            || (extra.coPolluteProperties || []).filter(p => p !== descriptor.property);
          proof = await reproduceRce(pkg, entryPoint,
            { property: descriptor.property, gates, minimalArgs: [testInput.value ?? {}], sequence: this.buildResolvedSequence(testInput) },
            { version, blockNetwork: this.options.blockNetwork !== false, browserEnv });
        }
      } catch (err) {
        logger.debug(`Reproduction error for ${descriptor.property} via ${entryPoint}: ${err.message}`);
      }
    }

    if (proof?.verified) {
      // Build the chain object, forcing analyzeDifferentialResult to emit it.
      diff.isConfirmedGadget = true;
      const chain = this.gadgetAnalysis.analyzeDifferentialResult(diffResult, testInput, this.config);
      if (!chain) return false;

      // Normalize the displayed property to the bare attacker-supplied key
      // (merge/URL diffs carry a fully-qualified "Object.prototype.x" name).
      if (chain.source) chain.source.property = descriptor.property;

      chain.disclosure = classifyFinding(chain, {
        package: pkg, version, proofType,
        osvVulns: this.osvVulns,
        priorDiscoveries: this.priorDiscoveries || [],
      });

      // Report-level dedup by BUG identity so one merge/source bug does not
      // surface once per property name tried. A PP *source* is one bug per
      // polluting function (the attacker property is irrelevant); an RCE gadget
      // is identified by (entry point + property).
      if (!this._reportedSignatures) this._reportedSignatures = new Set();
      const repSig = proofType === 'pp'
        ? `pp:${entryPoint}`
        : `rce:${entryPoint}:${descriptor.property}`;
      if (this._reportedSignatures.has(repSig)) {
        this.inputGeneration.updatePropertyFeedback(descriptor.property, true);
        return true; // same underlying bug already recorded
      }
      this._reportedSignatures.add(repSig);

      chain.proof = {
        type: proofType === 'pp' ? 'prototype-pollution' : 'code-execution',
        verified: true,
        runs: proof.runs,
        newProps: proof.newProps || null,
        canaryToken: proof.canary || null,
        payloadType: proof.payloadType || null,
        callConvention: proof.callConvention || null,
      };
      chain.standalonePoC = proof.standalonePoC || null;
      chain.exploitVerified = proofType === 'rce';
      Object.assign(chain, extra.chainMeta || {});

      this.results.confirmedChains.push(chain);
      this.inputGeneration.recordConfirmedGadget(descriptor.property, descriptor.value);
      this.inputGeneration.updatePropertyFeedback(descriptor.property, true);

      // Persist every confirmed finding to the durable, append-only discovery
      // store — the full audit trail of what this tool has reproduced (whether
      // a known CVE, a regression suspect, a rediscovery, or a first-sighting
      // undocumented vulnerability). Never throws; a write failure is logged
      // and swallowed.
      appendDiscovery(buildRecord(chain, { package: pkg, version, proofType }), this._discoveryStorePath);

      const disclosureTag = chain.disclosure.label === 'known-cve'
        ? `KNOWN CVE${chain.disclosure.cve ? ' ' + chain.disclosure.cve : ''}`
        : chain.disclosure.label === 'previously-discovered'
          ? `PREVIOUSLY DISCOVERED${chain.disclosure.priorSighting?.discoveredAt ? ' (first seen ' + chain.disclosure.priorSighting.discoveredAt : ''}${chain.disclosure.priorSighting?.version ? ' @ ' + chain.disclosure.priorSighting.version : ''}${chain.disclosure.priorSighting?.discoveredAt ? ')' : ''}`
          : `UNDOCUMENTED VULNERABILITY${chain.disclosure.regressionSuspect ? ' (regression suspect)' : ''}`;
      logger.warn(
        `PROVEN ${chain.proof.type.toUpperCase()} [${disclosureTag}]: ` +
        `Object.prototype.${descriptor.property} via ${entryPoint} ` +
        `(reproduced ${proof.runs}× in fresh processes)`
      );
      return true;
    }

    // Not proven → unproven candidate (never counted as a vulnerability).
    const candSig = `${proofType}:${descriptor.property}:${entryPoint}`;
    if (!this.results.candidateChains.some(c => c.sig === candSig)) {
      this.results.candidateChains.push({
        sig: candSig,
        property: descriptor.property,
        entryPoint,
        proofType,
        confidence: diff.confidence || 0,
        signal: diff.prototypePolluted ? 'prototype-mutation'
          : diff.newSinkAccesses?.length ? 'new-sink'
          : diff.outputChanged ? 'output-changed'
          : diff.errorChanged ? 'error-changed' : 'property-read',
        reason: pkg ? 'did-not-reproduce' : 'no-installable-package',
      });
    }
    return false;
  }

  async executeDifferentialPhase(inputs, iteration) {
    // UOP discovery: probe multiple diverse inputs to find property accesses.
    // Do this every 5 iterations, probing up to 3 different entry points.
    if (iteration % 5 === 0 && inputs.length > 0) {
      // Pick diverse sample inputs — different entry points and types
      const seenEntryPoints = new Set();
      const samples = [];
      for (const inp of inputs) {
        const key = `${inp.entryPoint}:${inp.type}`;
        if (!seenEntryPoints.has(key) && samples.length < 3) {
          seenEntryPoints.add(key);
          samples.push(inp);
        }
      }

      for (const sampleInput of samples) {
        try {
          const uopProps = await this.instrumentation.discoverUOPCandidates(sampleInput, this.config);
          const newCount = this.inputGeneration.integrateUOPDiscovery(uopProps);
          if (newCount > 0) {
            logger.info(`Discovered ${newCount} new UOP properties via ${sampleInput.entryPoint}: ${uopProps.slice(0, 5).join(', ')}${uopProps.length > 5 ? '...' : ''}`);
          }
        } catch (error) {
          logger.debug(`UOP discovery failed for ${sampleInput.entryPoint}: ${error.message}`);
        }
      }
    }

    // Differential testing: generate pollution descriptors and test them
    const descriptors = this.inputGeneration.generatePollutionDescriptors(
      this.config,
      Math.min(10, 3 + Math.floor(iteration / 10))
    );

    // Build test inputs for differential testing.
    // CRITICAL: don't rely on random input generation to include dangerous EPs.
    // Instead, look directly at config.entryPoints to find merge/extend functions
    // and create deterministic test inputs for them.
    const testInputs = [];
    const seenEP = new Set();

    // URL sinks: libraries read url/method/headers/data from option objects passed to these;
    // pre-polluting Object.prototype with those properties is a high-impact gadget class.
    // This list stays by NAME on purpose, and is the one place that is defensible:
    // these functions cannot be identified behaviourally because they must never be
    // called speculatively — invoking ajax/fetch fires a real request. It selects a
    // probing STRATEGY (empty options object, getter trap), never a verdict.
    const urlSinkEPs = new Set(['ajax', 'post', 'getJSON', 'getScript', 'fetch', 'request', 'send']);
    const getBaseName = (name) => name.includes('.') ? name.split('.').pop() : name;

    // Pass 1: Create test inputs directly from config.entryPoints, in order.
    // This is deterministic — not dependent on random input generation.
    //
    // The order IS the priority: discovery ranks entry points behaviourally
    // (merge-like first, then factory-like — see prioritizeExports). This used
    // to filter by a hardcoded name list instead, which inverted the result on
    // any library whose vocabulary did not match ours: a package exposing a SAFE
    // `merge`/`extend`/`clone` alongside a vulnerable `applyPatch` spent its
    // whole deterministic budget on the three harmless decoys and never tested
    // the real gadget. Ranking by what functions DO cannot be fooled that way.
    if (this.config.entryPoints) {
      for (const ep of this.config.entryPoints) {
        if (testInputs.length >= 5) break;
        // URL sinks are handled by Pass 1b, which probes them differently.
        if (urlSinkEPs.has(getBaseName(ep.name))) continue;
        if (seenEP.has(ep.name)) continue;
        seenEP.add(ep.name);
        testInputs.push({
          entryPoint: ep.name,
          type: 'object',
          value: {},
          metadata: { pollution: false, generation: 'differential_probe', energy: 1.0 }
        });
      }
    }

    // Pass 1b: URL sink entry points — tested with an empty options object so the
    // active getter trap can fire when the function reads url/method/headers/data
    // from the (pre-polluted) Object.prototype.
    if (this.config.entryPoints) {
      for (const ep of this.config.entryPoints) {
        if (testInputs.length >= 8) break;
        const base = getBaseName(ep.name);
        if (!urlSinkEPs.has(base)) continue;
        if (seenEP.has(ep.name)) continue;
        seenEP.add(ep.name);
        testInputs.push({
          entryPoint: ep.name,
          type: 'object',
          value: {},
          metadata: { pollution: false, generation: 'url_sink_probe', energy: 1.0 }
        });
      }
    }

    // Pass 2: Keep filling from config.entryPoints in ranked order, preferring
    // shallow names so a deeply-nested method does not crowd out a top-level one.
    if (this.config.entryPoints) {
      for (const ep of this.config.entryPoints) {
        if (testInputs.length >= 8) break;
        if (ep.name.split('.').length > 2) continue;
        if (urlSinkEPs.has(getBaseName(ep.name))) continue;
        if (seenEP.has(ep.name)) continue;
        seenEP.add(ep.name);
        testInputs.push({
          entryPoint: ep.name,
          type: 'object',
          value: {},
          metadata: { pollution: false, generation: 'differential_probe', energy: 1.0 }
        });
      }
    }

    // Pass 3: Fill with diverse entry points from generated inputs
    for (const inp of inputs) {
      if (testInputs.length >= 8) break;
      if (!seenEP.has(inp.entryPoint)) {
        seenEP.add(inp.entryPoint);
        testInputs.push(inp);
      }
    }
    if (testInputs.length === 0 && inputs.length > 0) testInputs.push(inputs[0]);
    if (testInputs.length === 0) return;

    // Track confirmed property+payloadType combos to avoid re-testing
    if (!this._confirmedSignatures) this._confirmedSignatures = new Set();

    logger.info(`Differential phase: ${descriptors.length} descriptors × ${testInputs.length} EPs × 3 modes`);
    let descriptorIdx = 0;

    // Properties accessed by URL-sink functions (ajax, fetch, etc.).
    // URL sinks only fire getter traps for these — skip them for other properties.
    const urlSinkProperties = new Set([
      'url', 'method', 'type', 'data', 'contentType', 'headers', 'async',
      'crossDomain', 'dataType', 'timeout', 'username', 'password', 'processData',
    ]);

    for (const descriptor of descriptors) {
      descriptorIdx++;
      // Skip combos already confirmed — no need to re-verify
      const sig = `${descriptor.property}:${descriptor.payloadType}`;
      if (this._confirmedSignatures.has(sig)) continue;

      // Try each test input until one confirms or all fail.
      // Bail out early if multiple consecutive EPs fail — avoids wasting time
      // on descriptors that won't confirm for any entry point.
      let confirmed = false;
      let consecutiveNullFails = 0; // only count EPs where the fn truly couldn't be called
      // URL sink EPs (ajax, getJSON etc.) are expensive — skip them unless the property
      // being tested is one they actually read from options objects.
      const isUrlSinkProperty = urlSinkProperties.has(descriptor.property);
      for (const testInput of testInputs) {
        if (consecutiveNullFails >= 3) break; // 3 un-callable EPs = descriptor won't confirm
        const epIsUrlSink = urlSinkEPs.has(getBaseName(testInput.entryPoint));
        if (epIsUrlSink && !isUrlSinkProperty) continue; // URL sinks won't fire for non-URL props
        let diffResult = null, mergeResult = null, urlResult = null;
        try {
          // Mode 1: Standard differential (pre-pollute Object.prototype)
          diffResult = await this.instrumentation.executeDifferentialTracing(
            testInput, this.config, descriptor
          );

          if (!diffResult) {
            logger.debug(`Mode1 ${descriptor.property} via ${testInput.entryPoint}: NULL result (fn not found or threw)`);
          }
          if (diffResult) {
            const d = diffResult.diff;
            logger.debug(`Mode1 ${descriptor.property} via ${testInput.entryPoint}: proofType=${d?.proofType} reproducible=${d?.reproducible} read=${d?.pollutionWasRead} outChanged=${d?.outputChanged} errChanged=${d?.errorChanged}`);

            // Feed the co-pollution phase with read-but-unchanged candidates.
            if (d?.isCandidate) {
              if (!this.results.candidateProperties) this.results.candidateProperties = [];
              const candidateSig = `${descriptor.property}:${testInput.entryPoint}`;
              if (!this.results.candidateProperties.some(c => c.sig === candidateSig)) {
                this.results.candidateProperties.push({
                  sig: candidateSig,
                  property: descriptor.property,
                  entryPoint: testInput.entryPoint,
                  confidence: d.confidence,
                });
              }
            }

            // ZERO-FP GATE: only reproduction can confirm.
            if (d && (d.isConfirmedGadget || (d.isCandidate && d.reproducible))) {
              confirmed = await this.proveAndRecord(diffResult, testInput, descriptor);
              if (confirmed) { this._confirmedSignatures.add(sig); break; }
            }
          }

          // Mode 2: Merge-PP test (crafted input causes Object.prototype mutation)
          mergeResult = await this.instrumentation.executeMergePPDifferential(
            testInput, this.config, descriptor
          );

          if (mergeResult?.diff) {
            confirmed = await this.proveAndRecord(mergeResult, testInput, descriptor);
            if (confirmed) { this._confirmedSignatures.add(sig); break; }
          }

          // Mode 3: URL gadget test (URL query string → parser → target function)
          urlResult = await this.instrumentation.executeURLGadgetDifferential(
            testInput, this.config, descriptor
          );

          if (urlResult?.diff) {
            confirmed = await this.proveAndRecord(urlResult, testInput, descriptor);
            if (confirmed) { this._confirmedSignatures.add(sig); break; }
          }

          // Mode 4: Forced branch execution (Dasty technique)
          // If standard differential didn't confirm, try forcing boolean gate
          // properties to true alongside the payload. This opens guarded code paths
          // like: if (opts.debug) { eval(opts.template); }
          if (!confirmed && !epIsUrlSink) {
            const forcedResult = await this.instrumentation.executeForcedBranchDifferentialTracing(
              testInput, this.config, descriptor
            );
            const fd = forcedResult?.diff;
            if (fd && (fd.isConfirmedGadget || (fd.isCandidate && fd.reproducible))) {
              const gates = fd.details?.forcedGatesFired || [];
              confirmed = await this.proveAndRecord(forcedResult, testInput, descriptor, {
                gates,
                chainMeta: { forcedBranch: true, forcedGates: gates },
              });
              if (confirmed) { this._confirmedSignatures.add(sig); break; }
            }
          }
        } catch (error) {
          logger.debug(`Differential test failed for ${descriptor.property} via ${testInput.entryPoint}: ${error.message}`);
        }
        if (!confirmed) {
          // Only count as a null-fail when the function truly couldn't be invoked.
          // A non-null result that didn't confirm is informative — keep trying other EPs.
          const allModesNull = !diffResult && !mergeResult && !urlResult;
          if (allModesNull) consecutiveNullFails++;
          else consecutiveNullFails = 0;
        }
      }
      if (!confirmed) {
        this.inputGeneration.updatePropertyFeedback(descriptor.property, false);
      }
    }

    // ── Pass 2: Multi-property co-pollution ────────────────────────────────────
    // Catch conjunctive gadgets that require 2+ properties polluted simultaneously
    // (e.g., `if (opts.debug) eval(opts.template)` — neither alone triggers the sink).
    const candidateProps = this.results.candidateProperties || [];
    const confirmedProps = [...this._confirmedSignatures].map(sig => sig.split(':')[0]);
    // Combine candidates (Tier 5 reads without behavior change) with confirmed properties
    // — a confirmed prop may gate a candidate, or two candidates may gate each other.
    const allCandidateNames = [...new Set([
      ...candidateProps.map(c => c.property),
      ...confirmedProps,
    ])];

    if (allCandidateNames.length >= 2 && allCandidateNames.length <= 30) {
      const payloads = this.inputGeneration.getPayloads();
      // Use first high-priority entry point for co-pollution testing
      const coTestInput = testInputs[0];
      if (coTestInput) {
        const maxPairs = Math.min(50, allCandidateNames.length * (allCandidateNames.length - 1) / 2);
        let pairsChecked = 0;

        logger.info(`Multi-property phase: testing up to ${maxPairs} property pairs`);
        for (let i = 0; i < allCandidateNames.length && pairsChecked < maxPairs; i++) {
          for (let j = i + 1; j < allCandidateNames.length && pairsChecked < maxPairs; j++) {
            pairsChecked++;
            // Use boolean_true for the "gate" property and sentinel for the "payload" property
            const pairDescriptors = [
              { property: allCandidateNames[i], value: true },
              { property: allCandidateNames[j], value: payloads[0]?.value || '__UOPFUZZ_MARKER_7f3a__' },
            ];

            try {
              const multiResult = await this.instrumentation.executeMultiPropertyDifferentialTracing(
                coTestInput, this.config, pairDescriptors
              );

              const md = multiResult?.diff;
              if (md && (md.isConfirmedGadget || (md.isCandidate && md.reproducible))) {
                const combinedName = pairDescriptors.map(d => d.property).join('+');
                const sig = `multi:${combinedName}`;
                if (!this._confirmedSignatures.has(sig)) {
                  // Reproduce the conjunctive gadget: the second descriptor is the
                  // payload property; the first is the gate (forced true).
                  const payloadDesc = pairDescriptors[1];
                  const gateProp = pairDescriptors[0].property;
                  const proven = await this.proveAndRecord(multiResult, coTestInput, payloadDesc, {
                    gates: [gateProp],
                    coPolluteProperties: pairDescriptors.map(d => d.property),
                    chainMeta: { multiProperty: true, coPolluteProperties: pairDescriptors.map(d => d.property) },
                  });
                  if (proven) this._confirmedSignatures.add(sig);
                }
              }
            } catch (error) {
              logger.debug(`Multi-property test ${allCandidateNames[i]}+${allCandidateNames[j]} failed: ${error.message}`);
            }
          }
        }
      }
    }
  }

  /**
   * DEPRECATED / UNREACHABLE. The worker-thread path (orchestrator/worker.js)
   * never loads the target module and never runs the differential confirmation
   * phase, so it finds zero real vulnerabilities. executeFuzzingWorkflow() now
   * always falls back to the sequential path (with a warning) when
   * --parallel > 1, so this method is no longer called. Kept for reference until
   * real parallelism is rebuilt on top of the sandbox worker pool.
   */
  async executeParallelFuzzing(maxIterations, parallelWorkers) {
    const iterationsPerWorker = Math.ceil(maxIterations / parallelWorkers);
    const workers = [];
    const workerPromises = [];

    for (let workerId = 0; workerId < parallelWorkers; workerId++) {
      const startIteration = workerId * iterationsPerWorker;
      const endIteration = Math.min(startIteration + iterationsPerWorker, maxIterations);

      if (startIteration >= maxIterations) break;

      const workerData = {
        config: this.config,
        options: this.options,
        startIteration,
        endIteration,
        workerId
      };

      const workerFile = path.join(__dirname, 'worker.js');
      const worker = new Worker(workerFile, { workerData });

      workers.push({ worker, workerId, startIteration, endIteration });

      const workerPromise = new Promise((resolve, reject) => {
        const workerResults = {
          workerId,
          results: null,
          error: null
        };

        worker.on('message', (message) => {
          switch (message.type) {
            case 'progress':
              logger.debug(`Worker ${message.workerId}: ${message.message}`);
              if (message.progress) {
                const totalCompleted = workers.reduce((sum, w) => {
                  return sum + (w.completedIterations || 0);
                }, 0);

                if (totalCompleted % 50 === 0) {
                  logger.info(`Overall progress: ~${totalCompleted}/${maxIterations} iterations across ${parallelWorkers} workers`);
                }
              }
              break;

            case 'completed':
              workerResults.results = message.results;
              logger.info(`Worker ${message.workerId} completed with ${message.results.iterationsCompleted} iterations`);
              resolve(workerResults);
              break;

            case 'error':
              workerResults.error = message.error;
              logger.error(`Worker ${message.workerId} failed: ${message.error.message}`);
              reject(new Error(`Worker ${message.workerId} failed: ${message.error.message}`));
              break;
          }
        });

        worker.on('error', (error) => {
          workerResults.error = error;
          logger.error(`Worker ${workerId} error: ${error.message}`);
          reject(error);
        });

        worker.on('exit', (code) => {
          if (code !== 0 && !workerResults.results && !workerResults.error) {
            const error = new Error(`Worker ${workerId} exited with code ${code}`);
            workerResults.error = error;
            reject(error);
          }
        });
      });

      workerPromises.push(workerPromise);

      logger.info(`Started worker ${workerId} for iterations ${startIteration} to ${endIteration - 1}`);
    }

    try {
      logger.info(`Waiting for ${workers.length} workers to complete...`);
      const workerResults = await Promise.allSettled(workerPromises);

      await this.aggregateWorkerResults(workerResults);

    } finally {
      await Promise.all(workers.map(async ({ worker }) => {
        try {
          await worker.terminate();
        } catch (error) {
          logger.debug(`Error terminating worker: ${error.message}`);
        }
      }));
    }
  }

  async aggregateWorkerResults(workerResults) {
    let totalIterationsCompleted = 0;
    let totalInputsGenerated = 0;
    let allPotentialChains = [];
    let allErrors = [];

    for (const result of workerResults) {
      if (result.status === 'fulfilled' && result.value.results) {
        const workerResult = result.value.results;
        totalIterationsCompleted += workerResult.iterationsCompleted;
        totalInputsGenerated += workerResult.inputsGenerated;
        allPotentialChains.push(...workerResult.potentialChains);
        allErrors.push(...workerResult.errors);

        logger.info(`Worker ${workerResult.workerId}: ${workerResult.iterationsCompleted} iterations, ${workerResult.inputsGenerated} inputs, ${workerResult.potentialChains.length} chains`);
      } else {
        allErrors.push({
          worker: result.value?.workerId || 'unknown',
          error: result.reason?.message || 'Worker failed'
        });
        logger.warn(`Worker failed: ${result.reason?.message}`);
      }
    }

    this.results.iterationsCompleted = totalIterationsCompleted;
    this.results.inputsGenerated = totalInputsGenerated;
    this.results.potentialChains = allPotentialChains;
    this.results.errors.push(...allErrors);

    logger.info(`Parallel execution completed: ${totalIterationsCompleted} total iterations, ${allPotentialChains.length} potential chains found`);
  }

  async analyzeResults() {
    // Deduplicate and rank potential chains (timestamp-correlation candidates)
    const uniqueChains = this.gadgetAnalysis.deduplicateChains(this.results.potentialChains);
    const rankedChains = this.gadgetAnalysis.rankChains(uniqueChains);
    this.results.potentialChains = rankedChains;

    // Confirmed chains from differential oracle (causal evidence)
    if (!this.results.confirmedChains) this.results.confirmedChains = [];

    // Collect metrics
    this.results.coverageStats = this.instrumentation.getCoverageStats();
    this.results.strategyEffectiveness = this.inputGeneration.getGenerationStats();

    // Stop V8 coverage collection
    await this.instrumentation.disableV8Coverage();

    const confirmed = this.results.confirmedChains.length;
    const candidates = rankedChains.length;
    logger.info(`Analysis complete: ${confirmed} confirmed gadgets, ${candidates} unconfirmed candidates`);
  }

  async saveResults() {
    // Defensive cleanup net: restore Object.prototype to its run-start baseline
    // before any I/O. See the comment on _startupPrototypeSnapshot in run().
    if (this._startupPrototypeSnapshot) {
      const detection = detectAndRestorePrototype(this._startupPrototypeSnapshot);
      if (detection.polluted) {
        logger.debug(`saveResults: cleaned up ${detection.newProps.length} residual prototype propert${detection.newProps.length === 1 ? 'y' : 'ies'} before writing output: ${detection.newProps.join(', ')}`);
      }
    }

    const outputDir = path.resolve(this.options.outputDir);
    await fs.mkdir(outputDir, { recursive: true });

    const ts = Date.now();
    const resultsFile = path.join(outputDir, `results-${ts}.json`);
    const reportFile = path.join(outputDir, `report-${ts}.md`);

    // Record the exact paths on the results themselves, BEFORE serializing, so
    // the JSON documents where it lives and the CLI can name the report even
    // when the run happened inside the isolated child (results cross that
    // boundary serialized; a field on the instance would not survive).
    this.results.outputFiles = { results: resultsFile, report: reportFile };

    await fs.writeFile(resultsFile, JSON.stringify(this.results, null, 2));

    const report = generateSingleReport(this.results, this.config);
    await fs.writeFile(reportFile, report);

    // debug, not info: the CLI reports these paths to the user from
    // results.outputFiles, and logging here too would print them twice (the
    // isolated child's logs are forwarded to the parent).
    logger.debug(`Report:  ${reportFile}`);
    logger.debug(`Results: ${resultsFile}`);
  }

  /**
   * Generate a science-based analysis report.
   *
   * Includes CVSS-aligned risk scores, Bayesian confidence,
   * coverage metrics, and strategy effectiveness analysis.
   */
  generateReport() {
    const end = this.results.endTime || new Date();
    const start = this.results.startTime || new Date();
    const duration = end - start;
    const durationStr = `${Math.round(duration / 1000)}s`;
    const confirmedChains = this.results.confirmedChains || [];

    let report = '';
    report += '================================================================================\n';
    report += '                              UoPFuzz Report\n';
    report += '================================================================================\n\n';
    report += `Target:    ${this.config?.name || 'Unknown'}@${this.config?.version || '?'}\n`;
    report += `Confirmed: ${confirmedChains.length} gadget${confirmedChains.length !== 1 ? 's' : ''} | Unconfirmed: ${this.results.potentialChains?.length || 0} | Errors: ${this.results.errors?.length || 0}\n`;
    report += `Time:     ${durationStr} | Iterations: ${this.results.iterationsCompleted} | Inputs: ${this.results.inputsGenerated}\n`;
    report += '\n';

    if (confirmedChains.length > 0) {
      for (const [index, chain] of confirmedChains.entries()) {
        const poc = chain.poc;
        const isURL = poc?.type === 'url_gadget';

        report += '--------------------------------------------------------------------------------\n';
        report += `GADGET #${index + 1}  [${chain.riskLevel}/10 RISK]  ${(chain.confidence * 100).toFixed(0)}% confidence\n`;
        report += '--------------------------------------------------------------------------------\n';
        report += `Library:     ${this.config?.name}@${this.config?.version}\n`;
        report += `Function:    ${chain.input?.entryPoint}\n`;
        report += `Property:    Object.prototype.${chain.source?.property} = ${chain.source?.payload}\n`;
        if (chain.metadata?.cvssVector) {
          report += `CVSS:       ${chain.metadata.cvssVector}\n`;
        }
        report += '\n';

        if (isURL && poc?.attackerInput?.url) {
          report += 'ATTACKER INPUT\n';
          report += '==============\n';
          report += `  URL:  ${poc.attackerInput.url}\n\n`;
        }

        report += 'PROOF OF CONCEPT\n';
        report += '=================\n';
        if (chain.standalonePoC) {
          report += '\n' + chain.standalonePoC + '\n';
        } else if (poc?.exploit?.code) {
          report += '\n' + poc.exploit.code + '\n';
        }

        if (isURL && poc?.vulnerablePattern?.description) {
          report += '\nATTACK CHAIN\n';
          report += '============\n';
          report += '  ' + poc.vulnerablePattern.description + '\n';
        }

        if (chain.differential?.pollutedProperties?.length > 0) {
          report += '\nPOLLUTED PROPERTIES: ' + chain.differential.pollutedProperties.join(', ') + '\n';
        }

        report += '\n';
      }
      report += '================================================================================\n';
      report += `Generated by UoPFuzz | ${new Date().toISOString()}\n`;
    } else {
      report += 'No confirmed gadgets found.\n';
    }

    // UOP Property Discovery
    if (this.results.strategyEffectiveness?.discoveredUOPProperties?.length > 0) {
      const props = this.results.strategyEffectiveness.discoveredUOPProperties;
      report += `UOP Property Discovery\n`;
      report += `----------------------\n`;
      report += `Properties the target reads as undefined (pollution candidates):\n`;
      for (const prop of props.slice(0, 30)) {
        report += `  - ${prop}\n`;
      }
      if (props.length > 30) {
        report += `  ... and ${props.length - 30} more\n`;
      }
      report += `\n`;
    }

    // Coverage Analysis
    if (this.results.coverageStats) {
      const cs = this.results.coverageStats;
      report += `Coverage Analysis\n`;
      report += `-----------------\n`;
      report += `  Edge Coverage (AFL-style bitmap):\n`;
      report += `    Edges Discovered: ${cs.coveredEdges}\n`;
      report += `    Bitmap Density: ${(cs.bitmapDensity * 100).toFixed(4)}%\n`;
      report += `    Saturation Rate: ${(cs.saturationRate * 100).toFixed(1)}%\n`;
      report += `    Inputs Processed: ${cs.totalInputsProcessed}\n`;
      if (cs.v8CoverageEnabled && cs.v8Metrics) {
        const v8 = cs.v8Metrics;
        report += `  V8 Precise Coverage (real engine data):\n`;
        report += `    Block Coverage: ${v8.coveredBlocks}/${v8.totalBlocks} (${v8.totalBlocks > 0 ? ((v8.coveredBlocks/v8.totalBlocks)*100).toFixed(1) : 0}%)\n`;
        report += `    Branch Coverage: ${v8.coveredBranches}/${v8.totalBranches} (${v8.totalBranches > 0 ? ((v8.coveredBranches/v8.totalBranches)*100).toFixed(1) : 0}%)\n`;
        report += `    Function Coverage: ${v8.coveredFunctions}/${v8.totalFunctions} (${v8.totalFunctions > 0 ? ((v8.coveredFunctions/v8.totalFunctions)*100).toFixed(1) : 0}%)\n`;
      } else {
        report += `  V8 Precise Coverage: disabled (dry-run mode)\n`;
      }
      report += `\n`;
    }

    // Convergence Info
    if (this.results.convergenceInfo) {
      const ci = this.results.convergenceInfo;
      report += `Convergence Detection\n`;
      report += `---------------------\n`;
      report += `  Converged at iteration: ${ci.convergedAt}\n`;
      report += `  Saturation rate: ${(ci.saturationRate * 100).toFixed(1)}%\n`;
      report += `  Reason: ${ci.reason}\n\n`;
    }

    // Strategy Effectiveness
    if (this.results.strategyEffectiveness) {
      const se = this.results.strategyEffectiveness;
      report += `Mutation Strategy Effectiveness (Thompson Sampling)\n`;
      report += `---------------------------------------------------\n`;
      report += `  Seed Corpus Size: ${se.seedCount}\n`;
      report += `  Corpus Entropy: ${se.corpusEntropy.toFixed(3)} bits\n`;
      if (se.strategyEffectiveness) {
        for (const [strategy, stats] of Object.entries(se.strategyEffectiveness)) {
          report += `  ${strategy}: ${(stats.successRate * 100).toFixed(1)}% success (${stats.totalMutations} mutations)\n`;
        }
      }
      report += `\n`;
    }

    // Unconfirmed candidates (timestamp-correlation based)
    if (this.results.potentialChains.length > 0) {
      report += `Unconfirmed Candidates (timestamp correlation)\n`;
      report += `----------------------------------------------\n`;
      this.results.potentialChains.slice(0, 20).forEach((chain, index) => {
        report += `${index + 1}. ${chain.description || 'Unknown chain'}\n`;
        report += `   CVSS Score: ${chain.riskLevel || 'N/A'}/10.0\n`;
        report += `   Confidence: ${((chain.confidence || 0) * 100).toFixed(1)}%\n`;
        report += `   Source: ${typeof chain.source === 'object' ? JSON.stringify(chain.source) : chain.source}\n`;
        report += `   Sink: ${typeof chain.sink === 'object' ? JSON.stringify(chain.sink) : chain.sink}\n\n`;
      });
      if (this.results.potentialChains.length > 20) {
        report += `... and ${this.results.potentialChains.length - 20} more candidates\n\n`;
      }
    }

    report += `\nMethodology\n`;
    report += `===========\n`;
    report += `This analysis uses evidence-based techniques:\n`;
    report += `- Differential oracle: Clean vs polluted execution comparison (causal confirmation)\n`;
    report += `- UOP discovery: Proxy-based detection of undefined property reads (attack surface mapping)\n`;
    report += `- Real Object.prototype pollution: Actual global pollution with cleanup\n`;
    report += `- Multi-step harnesses: Compile-then-render sequences for template engines\n`;
    report += `- Coverage guidance: AFL-style edge coverage bitmap (Böhme et al., CCS 2016)\n`;
    report += `- V8 precise coverage: Real block/branch coverage via Inspector protocol\n`;
    report += `- Taint tracking: ES6 Proxy deep property interception (Schwartz et al., IEEE S&P 2010)\n`;
    report += `- Risk scoring: CVSS v3.1 aligned base metrics (FIRST, 2019)\n`;
    report += `- Strategy selection: Thompson Sampling with Beta posteriors (Thompson, 1933)\n`;
    report += `- Gadget taxonomy: Silent Spring classification (Shcherbakov et al., USENIX 2023)\n`;

    return report;
  }
}
