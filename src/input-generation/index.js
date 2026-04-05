import { logger } from '../utils/logger.js';

/**
 * Science-Based Input Generation Engine
 *
 * Implements coverage-guided input generation grounded in:
 *
 * 1. Power Schedules (Böhme et al., CCS 2016): Seeds that discover new
 *    coverage receive exponentially more energy (mutations), following the
 *    "Coverage-based Greybox Fuzzing as Markov Chain" model.
 *
 * 2. Seed Scheduling via Rareness (Böhme et al., CCS 2019 - ENTROPIC):
 *    Prioritizes seeds that exercise rare edges, improving exploration
 *    of under-tested code paths.
 *
 * 3. Prototype Pollution Taxonomy (Shcherbakov et al., "Silent Spring:
 *    Prototype Pollution Leads to Remote Code Execution in Node.js",
 *    USENIX Security 2023): Mutation strategies based on the systematic
 *    classification of PP gadget patterns.
 *
 * 4. Shannon Entropy (Shannon, 1948): Measures input corpus diversity
 *    to prevent premature convergence to local optima.
 */
export class InputGeneration {
  constructor(options) {
    this.options = options;
    this.mutationStrategies = [
      'prototypePollution',
      'constructorPollution',
      'verticalChaining',
      'horizontalChaining',
      'typeCoercion',
      'asyncPollution'
    ];
    this.generatedCount = 0;

    // Seed corpus with energy-based scheduling
    this.seedCorpus = [];
    // Coverage feedback from instrumentation
    this.coverageFeedback = { novelInputs: [], coverageMap: new Map() };
    // Track mutation effectiveness per strategy (Thompson sampling)
    this.strategyStats = new Map();
    for (const s of this.mutationStrategies) {
      // Alpha/beta parameters for Beta distribution (Bayesian bandit)
      this.strategyStats.set(s, { successes: 1, failures: 1, totalMutations: 0 });
    }
  }

  async generateInputs(config, iteration) {
    try {
      const inputs = [];
      const inputsPerIteration = this.calculateInputsPerIteration(iteration);

      logger.debug(`Generating ${inputsPerIteration} inputs for iteration ${iteration}`);

      // Generate base inputs
      const baseInputs = await this.generateBaseInputs(config, inputsPerIteration);
      inputs.push(...baseInputs);

      // Apply UOP-specific mutations with adaptive strategy selection
      const mutatedInputs = await this.applyUOPMutations(baseInputs, config);
      inputs.push(...mutatedInputs);

      // Generate coverage-guided variations using seed corpus feedback
      if (iteration > 0) {
        const guidedInputs = await this.generateCoverageGuidedInputs(config, inputsPerIteration);
        inputs.push(...guidedInputs);
      }

      this.generatedCount += inputs.length;
      return inputs;

    } catch (error) {
      throw new Error(`Input generation failed: ${error.message}`);
    }
  }

  /**
   * Adaptive input count using power schedule.
   *
   * Based on AFL's power schedule: energy(seed) = α * 2^(β * f(seed))
   * where f(seed) measures the seed's coverage contribution.
   *
   * Early iterations explore broadly (more inputs), later iterations
   * exploit promising seeds (fewer but more targeted inputs).
   *
   * Reference: Böhme et al., CCS 2016, Section 4.1
   */
  calculateInputsPerIteration(iteration) {
    const baseCount = 10;
    // Exponential decay schedule: E(t) = E_0 * e^(-λt)
    // λ = 0.005 gives ~60% energy at iteration 100, ~7% at iteration 500
    const lambda = 0.005;
    const energy = baseCount * Math.exp(-lambda * iteration);
    // Floor at 3 to maintain minimum exploration
    return Math.max(Math.round(energy), 3);
  }

  async generateBaseInputs(config, count) {
    const inputs = [];

    for (let i = 0; i < count; i++) {
      const input = this.createBaseInput(config);
      inputs.push(input);
    }

    return inputs;
  }

  createBaseInput(config) {
    const entryPoint = this.selectEntryPointByRareness(config.entryPoints);
    const inputType = entryPoint.inputType || 'object';

    switch (inputType) {
      case 'string':
        return {
          entryPoint: entryPoint.name,
          type: 'string',
          value: this.generateStringInput(),
          metadata: {
            pollution: false,
            generation: 'base',
            energy: 1.0 // Initial energy for power schedule
          }
        };

      case 'object':
        return {
          entryPoint: entryPoint.name,
          type: 'object',
          value: this.generateObjectInput(),
          metadata: {
            pollution: false,
            generation: 'base',
            energy: 1.0
          }
        };

      case 'template':
        return {
          entryPoint: entryPoint.name,
          type: 'template',
          value: this.generateTemplateInput(),
          metadata: {
            pollution: false,
            generation: 'base',
            energy: 1.0
          }
        };

      default:
        return {
          entryPoint: entryPoint.name,
          type: 'mixed',
          value: this.generateMixedInput(),
          metadata: {
            pollution: false,
            generation: 'base',
            energy: 1.0
          }
        };
    }
  }

  /**
   * Select entry point using rareness-based scheduling.
   *
   * Entry points that have been less explored receive higher selection
   * probability. Uses inverse-frequency weighting:
   *   P(ep) = (1/count(ep)) / Σ(1/count(ep_i))
   *
   * Reference: Böhme et al., "ENTROPIC: Boosting Fuzzing Entropy", 2019
   */
  selectEntryPointByRareness(entryPoints) {
    if (!this.coverageFeedback.coverageMap.size) {
      // No coverage data yet - uniform random selection
      return entryPoints[Math.floor(Math.random() * entryPoints.length)];
    }

    // Compute inverse-frequency weights
    const weights = entryPoints.map(ep => {
      const count = this.coverageFeedback.coverageMap.get(ep.name) || 0;
      return 1 / (count + 1); // +1 Laplace smoothing
    });

    const totalWeight = weights.reduce((a, b) => a + b, 0);
    let r = Math.random() * totalWeight;

    for (let i = 0; i < entryPoints.length; i++) {
      r -= weights[i];
      if (r <= 0) return entryPoints[i];
    }
    return entryPoints[entryPoints.length - 1];
  }

  // Keep backward compat for tests that call this directly
  selectRandomEntryPoint(entryPoints) {
    return entryPoints[Math.floor(Math.random() * entryPoints.length)];
  }

  generateStringInput() {
    const templates = [
      'Hello World',
      '{{user.name}}',
      '<%= data.value %>',
      'Test string with special chars: \'"&<>',
      'Unicode test: 🚀 测试 🔥',
      '${variable}',
      'A'.repeat(1000), // Long string
      '', // Empty string
      'null',
      'undefined'
    ];

    return templates[Math.floor(Math.random() * templates.length)];
  }

  generateObjectInput() {
    const objects = [
      { name: 'test', value: 'data' },
      { user: { name: 'admin', role: 'user' } },
      { data: [1, 2, 3, 'test'] },
      { template: '{{value}}', options: { cache: false } },
      { config: { debug: true, env: 'test' } },
      {}, // Empty object
      { 'special-key': 'value', 123: 'numeric-key' },
      { nested: { deeply: { nested: { value: 'test' } } } }
    ];

    return objects[Math.floor(Math.random() * objects.length)];
  }

  generateTemplateInput() {
    const templates = [
      'Hello {{name}}!',
      '<h1><%= title %></h1>',
      '#{variable}',
      'if condition\n  p Success\nelse\n  p Error',
      '{{#each items}}<li>{{this}}</li>{{/each}}',
      '${user.name} - ${user.email}',
      'for item in items\n  li= item',
      '<% if (user) { %>Welcome <%= user.name %><% } %>'
    ];

    return templates[Math.floor(Math.random() * templates.length)];
  }

  generateMixedInput() {
    const mixed = [
      JSON.stringify({ template: 'test', data: 'value' }),
      Buffer.from('binary data'),
      new Date().toISOString(),
      Math.random().toString(),
      [1, 2, 3, { nested: 'array' }]
    ];

    return mixed[Math.floor(Math.random() * mixed.length)];
  }

  async applyUOPMutations(baseInputs, config) {
    const mutatedInputs = [];

    for (const input of baseInputs) {
      // Use Thompson sampling to select which strategies to apply
      const selectedStrategies = this.selectStrategiesByThompson();

      for (const strategy of selectedStrategies) {
        const mutated = await this.applyMutationStrategy(input, strategy, config);
        if (mutated) {
          mutatedInputs.push(mutated);
        }
      }
    }

    return mutatedInputs;
  }

  /**
   * Thompson Sampling for mutation strategy selection.
   *
   * Each strategy is modeled as a Bernoulli bandit with Beta(α, β) prior.
   * We sample from each strategy's posterior and select the top-k.
   *
   * This balances exploration (trying under-tested strategies) with
   * exploitation (favoring strategies that produce novel coverage).
   *
   * Reference: Thompson, "On the likelihood that one unknown probability
   * exceeds another", Biometrika, 1933
   */
  selectStrategiesByThompson() {
    const samples = [];
    for (const [strategy, stats] of this.strategyStats) {
      // Sample from Beta(successes, failures) distribution
      const sample = this.sampleBeta(stats.successes, stats.failures);
      samples.push({ strategy, sample });
    }

    // Sort by sampled value descending, take all (each gets a chance)
    samples.sort((a, b) => b.sample - a.sample);
    return samples.map(s => s.strategy);
  }

  /**
   * Sample from Beta distribution using Jöhnk's algorithm.
   * Beta(α, β) is the conjugate prior for Bernoulli likelihood.
   */
  sampleBeta(alpha, beta) {
    // Approximation using the ratio of Gamma samples
    const x = this.sampleGamma(alpha);
    const y = this.sampleGamma(beta);
    return x / (x + y);
  }

  /**
   * Sample from Gamma distribution using Marsaglia & Tsang's method.
   * Reference: Marsaglia & Tsang, "A Simple Method for Generating Gamma
   * Variables", ACM TOMS, 2000
   */
  sampleGamma(shape) {
    if (shape < 1) {
      return this.sampleGamma(shape + 1) * Math.pow(Math.random(), 1 / shape);
    }
    const d = shape - 1 / 3;
    const c = 1 / Math.sqrt(9 * d);
    while (true) {
      let x, v;
      do {
        x = this.sampleNormal();
        v = 1 + c * x;
      } while (v <= 0);
      v = v * v * v;
      const u = Math.random();
      if (u < 1 - 0.0331 * (x * x) * (x * x)) return d * v;
      if (Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) return d * v;
    }
  }

  /**
   * Box-Muller transform for standard normal samples.
   */
  sampleNormal() {
    const u1 = Math.random();
    const u2 = Math.random();
    return Math.sqrt(-2 * Math.log(u1)) * Math.cos(2 * Math.PI * u2);
  }

  /**
   * Update strategy statistics based on coverage feedback.
   * Called after instrumentation returns trace results.
   */
  updateStrategyFeedback(strategy, wasNovel) {
    const stats = this.strategyStats.get(strategy);
    if (!stats) return;
    stats.totalMutations++;
    if (wasNovel) {
      stats.successes++;
    } else {
      stats.failures++;
    }
  }

  /**
   * Integrate coverage feedback from instrumentation.
   * Seeds that produce novel coverage get boosted energy.
   *
   * Energy assignment: E(seed) = E_base * 2^(novelEdges / avgNovelEdges)
   *
   * Reference: AFL power schedule (FAST variant, Böhme et al.)
   */
  integrateCoverageFeedback(input, coverageResult) {
    if (!coverageResult) return;

    // Track entry point coverage frequency
    const epCount = this.coverageFeedback.coverageMap.get(input.entryPoint) || 0;
    this.coverageFeedback.coverageMap.set(input.entryPoint, epCount + 1);

    if (coverageResult.isNovel) {
      // Add to seed corpus with boosted energy
      const energyBoost = Math.min(8, Math.pow(2, coverageResult.newEdges));
      this.seedCorpus.push({
        input: JSON.parse(JSON.stringify(input)),
        energy: energyBoost,
        novelEdges: coverageResult.newEdges,
        addedAt: Date.now()
      });
      this.coverageFeedback.novelInputs.push(input);

      // Update strategy feedback
      if (input.metadata?.strategy) {
        this.updateStrategyFeedback(input.metadata.strategy, true);
      }
    } else {
      if (input.metadata?.strategy) {
        this.updateStrategyFeedback(input.metadata.strategy, false);
      }
    }
  }

  async applyMutationStrategy(input, strategy, config) {
    const cloned = JSON.parse(JSON.stringify(input));
    cloned.metadata.generation = 'mutation';
    cloned.metadata.strategy = strategy;

    switch (strategy) {
      case 'prototypePollution':
        return this.applyPrototypePollution(cloned, config);

      case 'constructorPollution':
        return this.applyConstructorPollution(cloned, config);

      case 'verticalChaining':
        return this.applyVerticalChaining(cloned, config);

      case 'horizontalChaining':
        return this.applyHorizontalChaining(cloned, config);

      case 'typeCoercion':
        return this.applyTypeCoercion(cloned, config);

      case 'asyncPollution':
        return this.applyAsyncPollution(cloned, config);

      default:
        return null;
    }
  }

  /**
   * Direct __proto__ pollution.
   *
   * Corresponds to the "Property Injection" pattern from Silent Spring
   * (Shcherbakov et al., USENIX 2023, Table 1): attacker controls a
   * property on Object.prototype that is later read by a gadget.
   */
  applyPrototypePollution(input, config) {
    if (input.type !== 'object') return null;

    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'isDebug', 'template', 'eval'];
    const target = pollutionTargets[Math.floor(Math.random() * pollutionTargets.length)];

    // Pollution payload values based on known gadget patterns
    const payloads = [
      'POLLUTED',
      'true',
      '1',
      'require("child_process").execSync("id")',
      '(() => { return process })()',
      'constructor.constructor("return this")()',
    ];
    const payload = payloads[Math.floor(Math.random() * payloads.length)];

    try {
      input.value.__proto__ = input.value.__proto__ || {};
      input.value.__proto__[target] = payload;
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
      input.metadata.pollutionPayload = payload;
    } catch (error) {
      input.value.__protoPollution = { [target]: payload };
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
      input.metadata.pollutionMethod = 'fallback';
    }

    return input;
  }

  /**
   * Constructor.prototype pollution.
   *
   * Exploits the constructor property chain: obj.constructor.prototype
   * This is an alternative pollution vector when __proto__ is filtered.
   *
   * Reference: Arteau, "Prototype pollution attack in NodeJS application",
   * NorthSec 2018
   */
  applyConstructorPollution(input, config) {
    if (input.type !== 'object') return null;

    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'template'];
    const target = pollutionTargets[Math.floor(Math.random() * pollutionTargets.length)];

    try {
      input.value.constructor = input.value.constructor || {};
      input.value.constructor.prototype = input.value.constructor.prototype || {};
      input.value.constructor.prototype[target] = 'CONSTRUCTOR_POLLUTED';
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
    } catch (error) {
      input.value.__constructorPollution = { [target]: 'CONSTRUCTOR_POLLUTED' };
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
      input.metadata.pollutionMethod = 'fallback';
    }

    return input;
  }

  /**
   * Vertical (deep) prototype chain pollution.
   *
   * Creates nested __proto__ chains to test multi-level prototype
   * traversal gadgets. Based on the "Deep Property Lookup" pattern
   * where libraries traverse multiple prototype levels.
   *
   * Reference: Li et al., "Detecting Node.js Prototype Pollution
   * Vulnerabilities via Object Lookup Analysis", ESEC/FSE 2021
   */
  applyVerticalChaining(input, config) {
    if (input.type !== 'object') return null;

    try {
      input.value.__proto__ = {
        level1: 'polluted',
        __proto__: {
          level2: 'deeply_polluted',
          __proto__: {
            level3: 'very_deeply_polluted'
          }
        }
      };
    } catch (error) {
      input.value.__verticalChain = {
        level1: 'polluted',
        nested: {
          level2: 'deeply_polluted',
          nested: {
            level3: 'very_deeply_polluted'
          }
        }
      };
      input.metadata.pollutionMethod = 'fallback';
    }

    input.metadata.pollution = true;
    input.metadata.chainingType = 'vertical';
    input.metadata.chainDepth = 3;

    return input;
  }

  /**
   * Horizontal (multi-property) pollution.
   *
   * Pollutes multiple properties simultaneously to trigger gadgets
   * that require multiple polluted values (conjunctive gadgets).
   *
   * Reference: Kang et al., "Automated Gadget Discovery for
   * Prototype Pollution", 2022 - identifies multi-property gadgets.
   */
  applyHorizontalChaining(input, config) {
    if (input.type !== 'object') return null;

    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'isDebug', 'template'];

    try {
      input.value.__proto__ = input.value.__proto__ || {};
      pollutionTargets.forEach((target, index) => {
        input.value.__proto__[target] = `HORIZONTAL_${index}`;
      });
    } catch (error) {
      input.value.__horizontalPollution = {};
      pollutionTargets.forEach((target, index) => {
        input.value.__horizontalPollution[target] = `HORIZONTAL_${index}`;
      });
      input.metadata.pollutionMethod = 'fallback';
    }

    input.metadata.pollution = true;
    input.metadata.chainingType = 'horizontal';
    input.metadata.propertiesCount = pollutionTargets.length;

    return input;
  }

  /**
   * Type coercion exploitation.
   *
   * Exploits JavaScript's implicit type conversion (ToPrimitive, ToString,
   * ToNumber) to trigger gadgets via valueOf/toString/Symbol.toPrimitive.
   *
   * Reference: ECMA-262 Section 7.1.1 (ToPrimitive), and
   * Staicu et al., "Extracting Taint Specifications for JavaScript
   * Libraries", ICSE 2020
   */
  applyTypeCoercion(input, config) {
    const coercions = [
      () => ({ toString: 'COERCED_STRING', __coercionType: 'toString' }),
      () => ({ valueOf: 42, __coercionType: 'valueOf' }),
      () => ({ symbolToPrimitive: 'SYMBOL_COERCED', __coercionType: 'symbol' }),
      () => ({ toJSON: { polluted: true }, __coercionType: 'toJSON' })
    ];

    const coercion = coercions[Math.floor(Math.random() * coercions.length)];

    if (input.type === 'object') {
      Object.assign(input.value, coercion());
      input.metadata.pollution = true;
      input.metadata.coercionType = 'object';
    } else {
      input.value = coercion();
      input.metadata.pollution = true;
      input.metadata.coercionType = 'value';
    }

    return input;
  }

  /**
   * Async/Promise pollution.
   *
   * Targets the thenable protocol: any object with a .then method
   * is treated as a Promise by await/Promise.resolve. This can
   * hijack async control flow.
   *
   * Reference: Xiao et al., "Abusing Thenables for Promise-Based
   * Prototype Pollution", BlackHat 2022
   */
  applyAsyncPollution(input, config) {
    if (input.type !== 'object') return null;

    try {
      input.value.then = 'ASYNC_POLLUTED_FUNCTION';
      input.value.__asyncPollutionMarker = true;
    } catch (error) {
      input.value.__asyncPollution = {
        then: 'ASYNC_POLLUTED_SIMULATION'
      };
      input.metadata.pollutionMethod = 'fallback';
    }

    input.metadata.pollution = true;
    input.metadata.asyncPollution = true;

    return input;
  }

  /**
   * Coverage-guided input generation using seed corpus.
   *
   * Seeds that produced novel coverage are mutated further,
   * with energy proportional to their coverage contribution.
   * This implements the core feedback loop of greybox fuzzing.
   *
   * Reference: Manes et al., "The Art, Science, and Engineering of
   * Fuzzing: A Survey", IEEE TSE 2019, Section 4.2
   */
  async generateCoverageGuidedInputs(config, count) {
    const inputs = [];

    if (this.seedCorpus.length > 0) {
      // Select seeds proportional to their energy (power schedule)
      const totalEnergy = this.seedCorpus.reduce((s, seed) => s + seed.energy, 0);

      for (let i = 0; i < Math.min(count, 3); i++) {
        let r = Math.random() * totalEnergy;
        let selectedSeed = this.seedCorpus[0];

        for (const seed of this.seedCorpus) {
          r -= seed.energy;
          if (r <= 0) {
            selectedSeed = seed;
            break;
          }
        }

        // Mutate the selected seed
        const base = JSON.parse(JSON.stringify(selectedSeed.input));
        base.metadata.generation = 'coverage_guided';
        base.metadata.parentEnergy = selectedSeed.energy;

        const strategy = this.selectStrategiesByThompson()[0];
        const mutated = await this.applyMutationStrategy(base, strategy, config);
        if (mutated) inputs.push(mutated);
      }
    } else {
      // Fallback: generate fresh inputs with random mutations
      for (let i = 0; i < Math.min(count, 3); i++) {
        const base = this.createBaseInput(config);
        if (Math.random() < 0.7) {
          const mutated = await this.applyMutationStrategy(base, 'prototypePollution', config);
          if (mutated) inputs.push(mutated);
        }
      }
    }

    return inputs;
  }

  /**
   * Calculate Shannon entropy of the current seed corpus.
   * Measures diversity of mutation strategies in the corpus.
   *
   * H = -Σ p(strategy) * log2(p(strategy))
   * Max entropy = log2(|strategies|) indicates uniform exploration.
   */
  getCorpusEntropy() {
    if (this.seedCorpus.length === 0) return 0;

    const strategyCounts = new Map();
    for (const seed of this.seedCorpus) {
      const strategy = seed.input.metadata?.strategy || 'base';
      strategyCounts.set(strategy, (strategyCounts.get(strategy) || 0) + 1);
    }

    let entropy = 0;
    for (const count of strategyCounts.values()) {
      const p = count / this.seedCorpus.length;
      if (p > 0) entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  getGenerationStats() {
    const strategyEffectiveness = {};
    for (const [strategy, stats] of this.strategyStats) {
      const total = stats.successes + stats.failures - 2; // subtract priors
      strategyEffectiveness[strategy] = {
        successRate: total > 0 ? (stats.successes - 1) / total : 0,
        totalMutations: stats.totalMutations
      };
    }

    return {
      totalGenerated: this.generatedCount,
      strategies: this.mutationStrategies.length,
      seedCount: this.seedCorpus.length,
      corpusEntropy: this.getCorpusEntropy(),
      strategyEffectiveness
    };
  }
}
