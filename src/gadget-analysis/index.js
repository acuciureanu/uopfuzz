import { logger } from '../utils/logger.js';

/**
 * Gadget-chain analysis.
 *
 * Turns observed pollution→sink traces into ranked candidate findings, assigns
 * a coarse severity by sink class, and builds the standalone PoC for a confirmed
 * finding.
 *
 * IMPORTANT: nothing in this file decides whether a finding is real. A
 * vulnerability is only ever reported after it is independently reproduced in
 * fresh child processes (src/verification/reproduce.js). The severity and
 * ranking scores here are for triage and ordering only — they never gate
 * reporting.
 *
 * The prototype-pollution gadget taxonomy follows Shcherbakov et al., "Silent
 * Spring" (USENIX Security 2023).
 */
// detectAndRestorePrototype() (prototype-monitor.js) reports polluted keys fully
// qualified, e.g. "Object.prototype.polluted" — fine for display, but the PoC
// builder below re-prepends "Object.prototype." itself in console labels and
// summary text, so bare it here first or the output ends up with
// `Object.prototype.Object.prototype.x` (and dot-access reads would break).
function bareProperty(prop) {
  return typeof prop === 'string' ? prop.replace(/^[A-Za-z_$][\w$]*\.prototype\./, '') : prop;
}

export class GadgetAnalysis {
  constructor(options) {
    this.options = options;
    this.knownChains = new Map();

    /**
     * Coarse severity (0-10) and impact class per dangerous sink. This is a
     * simple fixed heuristic for ranking and triage — NOT a computed CVSS score.
     * `cvssVector` is a representative vector for the impact class (e.g. a
     * network RCE), included for readers who want the standard notation; it is
     * not calculated per finding.
     */
    this.sinkSeverity = {
      eval:                 { baseScore: 10.0, impact: 'RCE',  cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      Function:             { baseScore: 10.0, impact: 'RCE',  cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      'child_process.exec': { baseScore: 10.0, impact: 'RCE',  cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' },
      setTimeout:           { baseScore: 7.0,  impact: 'ACE',  cvssVector: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
      setInterval:          { baseScore: 7.0,  impact: 'ACE',  cvssVector: 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N' },
      innerHTML:            { baseScore: 8.0,  impact: 'XSS',  cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
      outerHTML:            { baseScore: 8.0,  impact: 'XSS',  cvssVector: 'AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N' },
      // Sink names emitted by the sandbox/repro worker hooks (record-then-delegate).
      'http.request':       { baseScore: 9.1,  impact: 'SSRF', cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'http.get':           { baseScore: 9.1,  impact: 'SSRF', cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'https.request':      { baseScore: 9.1,  impact: 'SSRF', cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'https.get':          { baseScore: 9.1,  impact: 'SSRF', cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N' },
      'fs.readFileSync':    { baseScore: 7.5,  impact: 'LFI',  cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
      'fs.readFile':        { baseScore: 7.5,  impact: 'LFI',  cvssVector: 'AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N' },
    };

    // Flat sink -> severity map (kept for callers that only need the number).
    this.riskScoring = {};
    for (const [sink, meta] of Object.entries(this.sinkSeverity)) {
      this.riskScoring[sink] = meta.baseScore;
    }
  }

  async analyzeTraces(traces, config) {
    try {
      logger.debug(`Analyzing ${traces.length} traces for gadget chains`);

      const potentialChains = [];

      for (const trace of traces) {
        if (!trace.success && !this.options.analyzeErrors) {
          continue;
        }

        const chains = await this.analyzeTrace(trace, config);
        potentialChains.push(...chains);
      }

      logger.debug(`Found ${potentialChains.length} potential chains`);
      return potentialChains;

    } catch (error) {
      throw new Error(`Gadget analysis failed: ${error.message}`);
    }
  }

  /**
   * Analyze a differential oracle result to create a confirmed gadget chain.
   *
   * Unlike analyzeTraces (which uses timestamp correlation and produces
   * unconfirmed candidates), this method uses causal evidence from the
   * differential oracle: the pollution actually changed behavior.
   *
   * @param {object} diffResult - Result from executeDifferential()
   * @param {object} input - The fuzzer input that triggered this
   * @param {object} config - Target configuration
   * @returns {object|null} A confirmed gadget chain, or null
   */
  analyzeDifferentialResult(diffResult, input, config) {
    if (!diffResult?.diff?.isConfirmedGadget) return null;

    const diff = diffResult.diff;
    const sinkName = diff.newSinkAccesses.length > 0
      ? diff.newSinkAccesses[0].sink
      : (diff.details.payloadReachedOutput ? 'output_injection' : 'behavioral_change');

    const sinkMeta = this.sinkSeverity[sinkName] || {
      baseScore: diff.details.payloadReachedOutput ? 8.0 : (diff.prototypePolluted ? 7.5 : 5.0),
      impact: diff.prototypePolluted ? 'Prototype Pollution' : (diff.details.payloadReachedOutput ? 'Injection' : 'Behavioral'),
      cvssVector: diff.prototypePolluted
        ? 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H'
        : 'AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N'
    };

    const chain = {
      id: `confirmed_${diff.property}_${sinkName}_${Date.now()}`,
      type: 'differential_confirmed',
      riskLevel: Math.min(sinkMeta.baseScore + (diff.pollutionWasRead ? 0.5 : 0), 10),
      confidence: diff.confidence,
      confirmed: true,
      description: this.buildDifferentialDescription(diff, sinkName),
      source: {
        type: 'Object.prototype',
        property: diff.property,
        payload: String(diff.payload).substring(0, 200)
      },
      sink: sinkName !== 'behavioral_change' ? {
        name: sinkName,
        arguments: diff.newSinkAccesses[0]?.arguments || [],
        confirmed: true
      } : 'behavioral_change',
      input: {
        entryPoint: input.entryPoint,
        type: input.type,
        polluted: true
      },
      differential: {
        outputChanged: diff.outputChanged,
        errorChanged: diff.errorChanged,
        pollutionWasRead: diff.pollutionWasRead,
        prototypePolluted: diff.prototypePolluted || false,
        pollutedProperties: diff.pollutedProperties || [],
        payloadReachedOutput: diff.details.payloadReachedOutput || false,
        cleanOutput: diff.details.cleanOutput,
        pollutedOutput: diff.details.pollutedOutput,
        cleanError: diff.details.cleanError,
        pollutedError: diff.details.pollutedError,
        exploitURL: diff.details.exploitURL || null,
        payloadType: diff.details.payloadType || null
      },
      metadata: {
        target: config.name,
        version: config.version,
        discoveredAt: new Date(),
        cvssVector: sinkMeta.cvssVector,
        impactType: sinkMeta.impact,
        verificationMethod: 'differential_oracle'
      },
      poc: this.buildPOC({
        source: { property: diff.property, payload: String(diff.payload).substring(0, 200) },
        differential: {
          exploitURL: diff.details.exploitURL || null,
          payloadType: diff.details.payloadType || null
        },
        input: { entryPoint: input.entryPoint }
      }, config)
    };

    // Store in known chains for deduplication
    const sig = `${diff.property}_${sinkName}`;
    if (!this.knownChains.has(sig)) {
      this.knownChains.set(sig, chain);
    }

    return chain;
  }

  buildDifferentialDescription(diff, sinkName) {
    const parts = [];

    if (diff.prototypePolluted) {
      const props = diff.pollutedProperties?.length > 0
        ? diff.pollutedProperties.map(bareProperty).join(', ')
        : bareProperty(diff.property);
      if (diff.details.exploitURL) {
        parts.push(`CONFIRMED URL GADGET: Object.prototype.${props} polluted via URL query string → ${diff.details.payloadType}`);
      } else {
        parts.push(`CONFIRMED PROTOTYPE POLLUTION: Object.prototype.${props} was modified`);
      }
    } else {
      parts.push(`CONFIRMED: Object.prototype.${bareProperty(diff.property)} pollution`);
    }

    if (diff.newSinkAccesses.length > 0) {
      parts.push(`triggers ${sinkName} sink`);
    } else if (diff.details.payloadReachedOutput) {
      parts.push(`payload reaches output (injection)`);
    } else if (diff.outputChanged) {
      parts.push(`changes execution output`);
    } else if (diff.errorChanged) {
      parts.push(`changes error behavior`);
    }

    if (diff.pollutionWasRead) {
      parts.push(`(property read via prototype chain)`);
    }

    return parts.join(' — ');
  }

  buildPOC(chain, config) {
    const target = config?.name || 'unknown';
    const version = config?.version || '';
    const ep = chain.input?.entryPoint || 'unknown';
    const prop = bareProperty(chain.source?.property || 'unknown');
    const val = chain.source?.payload || '';
    const exploitURL = chain.differential?.exploitURL;
    const payloadType = chain.differential?.payloadType || '';

    // Build the pollution payload as a JSON string and JSON.parse it in the
    // generated code: a plain object literal with a `__proto__` key sets the
    // prototype instead of creating an own property, so it would not pollute.
    // String concat with JSON.stringify quoting keeps prop/val safe even when
    // they contain quotes. constructor.prototype is used when the finding was
    // confirmed that way (targets that guard plain __proto__); __proto__ is
    // the default when payloadType is unknown.
    const isConstructor = payloadType.includes('constructor');
    const payloadInner = JSON.stringify(prop) + ':' + JSON.stringify(val);
    const payloadJson = isConstructor
      ? '{"constructor":{"prototype":{' + payloadInner + '}}}'
      : '{"__proto__":{' + payloadInner + '}}';
    const payloadJsonLiteral = JSON.stringify(payloadJson);

    const consoleLabel = JSON.stringify(`Object.prototype.${prop} =`);

    // Line comments can't contain line terminators — U+2028/U+2029 survive
    // JSON.stringify, so sanitize anything interpolated into a `//` comment
    // (applied after JSON.stringify for the expected-output line).
    const commentSafe = (s) => String(s).replace(/[\r\n\u2028\u2029]/g, ' ');
    const pocHeader = `// POC: ${commentSafe(`${target}@${version}`)} prototype pollution via ${commentSafe(ep)}()`;
    const expectedOutput = `// Expected output: ${commentSafe(JSON.stringify(val))}`;

    // Entry-point resolution mirrors targetRef() in verification/reproduce.js:
    // bare-function modules (module.exports = fn) record entryPoint === package
    // name and must call the required module directly — reducing
    // target['merge-deep'] would resolve to undefined.
    const fnResolution = ep === target
      ? 'const fn = target;'
      : `const fn = ${JSON.stringify(ep)}.split('.').reduce((o, k) => o?.[k], target);`;
    const fnGuard = `if (typeof fn !== 'function') throw new Error('entry point not found: ' + ${JSON.stringify(ep)});`;

    // Pollution-key explanation for the generated comment — matches the payload above.
    const keyComment = isConstructor
      ? '// The pollution key is constructor.prototype — the target guards plain __proto__.'
      : '// The pollution key is __proto__ — a plain property merge does NOT pollute the prototype.';

    if (exploitURL) {
      return {
        type: 'url_gadget',
        summary: `Prototype pollution via URL query parameter in ${target}@${version}`,
        attackerInput: {
          url: exploitURL,
          description: 'Attacker-controlled URL query string'
        },
        vulnerablePattern: {
          library: `${target}@${version}`,
          function: ep,
          description: `Attacker sends URL with malicious query string → ${target} parses it → ${target}.${ep}() merges attacker data into Object.prototype`
        },
        exploit: {
          language: 'javascript',
          code: `${pocHeader}
// Attacker sends: ${commentSafe(exploitURL)}

// Simulating what the server does:
const target = require(${JSON.stringify(target)});

// Attacker-controlled data from URL query string. Parsed via JSON.parse so a
// __proto__ key becomes an own property (a plain object literal would just
// set the payload's prototype and never pollute).
const maliciousPayload = JSON.parse(${payloadJsonLiteral});

// Vulnerable: attacker data merged into config (or any object)
const config = {};
${fnResolution}
${fnGuard}
fn(config, maliciousPayload);

// RESULT: Object.prototype is now polluted
console.log(${consoleLabel}, Object.prototype[${JSON.stringify(prop)}]);
${expectedOutput}

${isConstructor ? `// Note: Uses 'constructor.prototype' pattern to bypass __proto__ guards` : ''}`
        }
      };
    }

    return {
      type: 'prototype_pollution',
      summary: `Prototype pollution in ${target}@${version}`,
      vulnerablePattern: {
        library: `${target}@${version}`,
        function: ep
      },
      exploit: {
        language: 'javascript',
        code: `${pocHeader}
const target = require(${JSON.stringify(target)});

${keyComment}
const payload = JSON.parse(${payloadJsonLiteral});

${fnResolution}
${fnGuard}
fn({}, payload);

console.log(${consoleLabel}, Object.prototype[${JSON.stringify(prop)}]);
${expectedOutput}`
      }
    };
  }

  async analyzeTrace(trace, config) {
    const chains = [];

    const directChains = this.findDirectChains(trace, config);
    chains.push(...directChains);

    const multiStepChains = this.findMultiStepChains(trace, config);
    chains.push(...multiStepChains);

    const asyncChains = this.findAsyncChains(trace, config);
    chains.push(...asyncChains);

    const coercionChains = this.findCoercionChains(trace, config);
    chains.push(...coercionChains);

    return chains;
  }

  findDirectChains(trace, config) {
    const chains = [];

    if (trace.prototypeChanges.length > 0 && trace.sinkAccesses.length > 0) {
      // Pre-sort sinks by timestamp to skip early entries faster
      const sortedSinks = [...trace.sinkAccesses].sort((a, b) => a.timestamp - b.timestamp);

      for (const pollution of trace.prototypeChanges) {
        for (const sinkAccess of sortedSinks) {
          if (sinkAccess.timestamp <= pollution.timestamp) continue;

          const chain = this.createChain({
            type: 'direct',
            pollution,
            sink: sinkAccess,
            trace,
            config,
            steps: [pollution, sinkAccess]
          });

          chains.push(chain);
        }
      }
    }

    return chains;
  }

  findMultiStepChains(trace, config) {
    const chains = [];

    if (trace.prototypeChanges.length > 0 &&
        trace.propertyAccesses.length > 0 &&
        trace.sinkAccesses.length > 0) {

      // Pre-sort sinks by timestamp to enable binary-search-style skipping
      const sortedSinks = [...trace.sinkAccesses].sort((a, b) => a.timestamp - b.timestamp);

      for (const pollution of trace.prototypeChanges) {
        // Avoid .filter() — iterate once, skip non-qualifying accesses inline
        for (const access of trace.propertyAccesses) {
          if (access.timestamp <= pollution.timestamp) continue;
          if (!this.isRelevantPropertyAccess(access, pollution, config)) continue;

          // Use pre-sorted sinks: find first sink after access.timestamp
          for (const sink of sortedSinks) {
            if (sink.timestamp <= access.timestamp) continue;

            chains.push(this.createChain({
              type: 'multi-step',
              pollution,
              propertyAccess: access,
              sink,
              trace,
              config,
              steps: [pollution, access, sink]
            }));
          }
        }
      }
    }

    return chains;
  }

  findAsyncChains(trace, config) {
    const chains = [];

    const asyncIndicators = trace.functionCalls.filter(call =>
      call.function.includes('async') ||
      call.function.includes('Promise') ||
      call.function.includes('then') ||
      call.function.includes('await')
    );

    if (trace.prototypeChanges.length > 0 && asyncIndicators.length > 0) {
      for (const pollution of trace.prototypeChanges) {
        for (const asyncOp of asyncIndicators) {
          if (asyncOp.timestamp > pollution.timestamp) {
            const chain = this.createChain({
              type: 'async',
              pollution,
              asyncOperation: asyncOp,
              trace,
              config,
              steps: [pollution, asyncOp]
            });

            chains.push(chain);
          }
        }
      }
    }

    return chains;
  }

  findCoercionChains(trace, config) {
    const chains = [];

    if (trace.input.metadata?.coercionType) {
      const coercionChain = this.createChain({
        type: 'coercion',
        coercionType: trace.input.metadata.coercionType,
        trace,
        config,
        steps: [{ type: 'type_coercion', input: trace.input }]
      });

      chains.push(coercionChain);
    }

    return chains;
  }

  /**
   * Taint-aware property access relevance check.
   *
   * Determines if a property access is part of a taint flow from
   * the pollution source to a sink. Uses three heuristics:
   *
   * 1. Direct taint: property name matches pollution target
   * 2. Implicit flow: property is in the set of known dangerous props
   * 3. UOP pattern: property resolves to undefined (an attacker-controllable
   *    prototype-chain read)
   */
  isRelevantPropertyAccess(access, pollution, _config) {
    if (pollution.property && access.property === pollution.property) {
      return true;
    }

    const dangerousProperties = [
      'template', 'eval', 'exec', 'innerHTML', 'outerHTML',
      'isAdmin', 'isDebug', 'trusted', 'safe'
    ];

    if (dangerousProperties.includes(access.property)) {
      return true;
    }

    if (access.result === undefined) {
      return true;
    }

    return false;
  }

  createChain(data) {
    const { type, pollution, sink, trace, config, steps } = data;

    const chain = {
      id: this.generateChainId(data),
      type,
      riskLevel: this.calculateRiskLevel(data),
      confidence: this.calculateConfidence(data),
      description: this.generateDescription(data),
      source: this.identifySource(pollution, trace),
      sink: this.identifySink(sink, trace),
      steps: steps.map(step => this.serializeStep(step)),
      input: {
        entryPoint: trace.input.entryPoint,
        type: trace.input.type,
        polluted: trace.input.metadata?.pollution || false
      },
      timing: {
        startTime: steps[0]?.timestamp || trace.startTime,
        endTime: steps[steps.length - 1]?.timestamp || trace.endTime,
        duration: (steps[steps.length - 1]?.timestamp || trace.endTime) -
                 (steps[0]?.timestamp || trace.startTime)
      },
      metadata: {
        target: config.name,
        version: config.version,
        discoveredAt: new Date(),
        traceId: trace.id || 'unknown',
        cvssVector: this.getCVSSVector(data),
        impactType: this.getImpactType(data)
      }
    };

    return chain;
  }

  generateChainId(data) {
    const { type, pollution, sink } = data;
    const source = pollution?.property || 'unknown';
    const target = sink?.sink || 'unknown';
    return `${type}_${source}_${target}_${Date.now()}`;
  }

  /**
   * Coarse severity (0-10) for a candidate chain: the sink's base severity,
   * reduced for chain shapes that are harder to trigger (multi-step/async/
   * coercion), with a small bump for a direct Object.prototype write. A ranking
   * heuristic for triage — not a computed CVSS score, and it never gates
   * reporting (reproduction does).
   */
  calculateRiskLevel(data) {
    const { sink, pollution, type } = data;

    let score = 1;
    if (sink && this.sinkSeverity[sink.sink]) {
      score = this.sinkSeverity[sink.sink].baseScore;
    }

    // Harder-to-reach chain shapes score lower.
    const complexityModifiers = {
      'direct': 0,
      'multi-step': -0.5,
      'async': -1.5,
      'coercion': -2.0
    };
    score += (complexityModifiers[type] || 0);

    if (pollution?.type === 'setPrototypeOf' || pollution?.property === '__proto__') {
      score += 0.5;
    }

    return Math.min(Math.max(Math.round(score * 10) / 10, 0), 10);
  }

  /**
   * Coarse ranking score (0-1) for an UNCONFIRMED candidate chain, used only to
   * order leads for triage. It is NOT a probability and does not gate reporting
   * — the only thing that confirms a finding is independent reproduction.
   */
  calculateConfidence(data) {
    const { trace, steps, type } = data;
    let score = 0.1;
    if (trace?.success) score += 0.2;
    if (type === 'direct' || type === 'multi-step') score += 0.3;
    if (data.pollution && data.sink) score += 0.3;
    if (steps && steps.length > 1) score += 0.1;
    return Math.min(score, 1);
  }

  /**
   * Representative CVSS vector for the chain's impact class (by sink). Not a
   * per-finding calculation — see the sinkSeverity table.
   */
  getCVSSVector(data) {
    const { sink } = data;
    if (sink && this.sinkSeverity[sink.sink]) {
      return this.sinkSeverity[sink.sink].cvssVector;
    }
    return 'AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N';
  }

  /**
   * Get impact classification.
   */
  getImpactType(data) {
    const { sink } = data;
    if (sink && this.sinkSeverity[sink.sink]) {
      return this.sinkSeverity[sink.sink].impact;
    }
    return 'Unknown';
  }

  generateDescription(data) {
    const { type, pollution, sink, propertyAccess } = data;

    let description = '';

    switch (type) {
      case 'direct':
        description = `Direct prototype pollution chain: ${pollution?.property || 'unknown'} -> ${sink?.sink || 'unknown sink'}`;
        break;

      case 'multi-step':
        description = `Multi-step gadget chain: pollution -> ${propertyAccess?.property || 'property access'} -> ${sink?.sink || 'sink'}`;
        break;

      case 'async':
        description = `Async pollution chain affecting async operations`;
        break;

      case 'coercion':
        description = `Type coercion chain exploiting JavaScript type conversion`;
        break;

      default:
        description = `Unknown chain type: ${type}`;
    }

    return description;
  }

  identifySource(pollution, _trace) {
    if (!pollution) return 'unknown';

    return {
      type: pollution.type || 'unknown',
      property: pollution.property || 'unknown',
      target: pollution.target || 'unknown',
      timestamp: pollution.timestamp
    };
  }

  identifySink(sink, _trace) {
    if (!sink) return 'unknown';

    return {
      name: sink.sink || 'unknown',
      arguments: sink.arguments || [],
      timestamp: sink.timestamp,
      callStack: sink.callStack ? sink.callStack.split('\n').slice(0, 3) : []
    };
  }

  serializeStep(step) {
    return {
      type: step.type || 'unknown',
      timestamp: step.timestamp || Date.now(),
      description: this.getStepDescription(step),
      data: this.sanitizeStepData(step)
    };
  }

  getStepDescription(step) {
    if (step.type === 'setPrototypeOf') {
      return `Prototype modification: ${step.target} -> ${step.prototype}`;
    }

    if (step.type === 'hasOwnProperty') {
      return `Property access: ${step.object}.${step.property}`;
    }

    if (step.sink) {
      return `Sink access: ${step.sink}`;
    }

    return step.type || 'Unknown step';
  }

  sanitizeStepData(step) {
    const sanitized = { ...step };

    delete sanitized.callStack;

    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'string' && sanitized[key].length > 200) {
        sanitized[key] = sanitized[key].substring(0, 200) + '...';
      }
    });

    return sanitized;
  }

  /**
   * Deduplicate chains using structural similarity.
   *
   * Two chains are considered duplicates if they share the same
   * type, source property, and sink name (signature-based).
   */
  deduplicateChains(chains) {
    const seen = new Set();
    const unique = [];

    for (const chain of chains) {
      const signature = this.getChainSignature(chain);

      if (!seen.has(signature)) {
        seen.add(signature);
        unique.push(chain);
      }
    }

    logger.debug(`Deduplicated ${chains.length} chains to ${unique.length} unique chains`);
    return unique;
  }

  getChainSignature(chain) {
    return `${chain.type}_${chain.source?.property}_${chain.sink?.name}`;
  }

  /** Order candidate chains for triage: highest severity first, then ranking score. */
  rankChains(chains) {
    return chains.sort((a, b) => {
      if (a.riskLevel !== b.riskLevel) {
        return b.riskLevel - a.riskLevel;
      }
      return b.confidence - a.confidence;
    });
  }

  getAnalysisStats() {
    return {
      knownChains: this.knownChains.size,
      riskLevels: Object.keys(this.riskScoring).length,
      sinkTypes: Object.keys(this.sinkSeverity).length,
    };
  }
}
