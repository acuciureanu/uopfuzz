import { logger } from '../utils/logger.js';

export class GadgetAnalysis {
  constructor(options) {
    this.options = options;
    this.knownChains = new Map();
    this.riskScoring = {
      eval: 10,
      Function: 10,
      'child_process.exec': 10,
      setTimeout: 7,
      setInterval: 7,
      innerHTML: 8,
      outerHTML: 8
    };
  }

  async analyzeTraces(traces, config) {
    try {
      logger.debug(`Analyzing ${traces.length} traces for gadget chains`);
      
      const potentialChains = [];
      
      for (const trace of traces) {
        if (!trace.success && !this.options.analyzeErrors) {
          continue;
        }
        
        // Analyze each trace for potential gadget chains
        const chains = await this.analyzeTrace(trace, config);
        potentialChains.push(...chains);
      }
      
      logger.debug(`Found ${potentialChains.length} potential chains`);
      return potentialChains;
      
    } catch (error) {
      throw new Error(`Gadget analysis failed: ${error.message}`);
    }
  }

  async analyzeTrace(trace, config) {
    const chains = [];
    
    // Check for direct pollution-to-sink chains
    const directChains = this.findDirectChains(trace, config);
    chains.push(...directChains);
    
    // Check for multi-step gadget chains
    const multiStepChains = this.findMultiStepChains(trace, config);
    chains.push(...multiStepChains);
    
    // Check for async pollution chains
    const asyncChains = this.findAsyncChains(trace, config);
    chains.push(...asyncChains);
    
    // Check for type coercion chains
    const coercionChains = this.findCoercionChains(trace, config);
    chains.push(...coercionChains);
    
    return chains;
  }

  findDirectChains(trace, config) {
    const chains = [];
    
    // Look for traces where prototype pollution leads directly to sink access
    if (trace.prototypeChanges.length > 0 && trace.sinkAccesses.length > 0) {
      for (const pollution of trace.prototypeChanges) {
        for (const sinkAccess of trace.sinkAccesses) {
          // Check temporal relationship
          if (sinkAccess.timestamp > pollution.timestamp) {
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
    }
    
    return chains;
  }

  findMultiStepChains(trace, config) {
    const chains = [];
    
    // Look for chains: pollution -> property access -> sink
    if (trace.prototypeChanges.length > 0 && 
        trace.propertyAccesses.length > 0 && 
        trace.sinkAccesses.length > 0) {
      
      for (const pollution of trace.prototypeChanges) {
        // Find property accesses after pollution
        const relevantAccesses = trace.propertyAccesses.filter(
          access => access.timestamp > pollution.timestamp &&
                   this.isRelevantPropertyAccess(access, pollution, config)
        );
        
        for (const access of relevantAccesses) {
          // Find sink accesses after property access
          const relevantSinks = trace.sinkAccesses.filter(
            sink => sink.timestamp > access.timestamp
          );
          
          for (const sink of relevantSinks) {
            const chain = this.createChain({
              type: 'multi-step',
              pollution,
              propertyAccess: access,
              sink,
              trace,
              config,
              steps: [pollution, access, sink]
            });
            
            chains.push(chain);
          }
        }
      }
    }
    
    return chains;
  }

  findAsyncChains(trace, config) {
    const chains = [];
    
    // Look for pollution that might affect async operations
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
    
    // Look for type coercion that might enable gadget chains
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

  isRelevantPropertyAccess(access, pollution, config) {
    // Check if property access might be related to the pollution
    if (pollution.property && access.property === pollution.property) {
      return true;
    }
    
    // Check if accessing properties that commonly lead to sinks
    const dangerousProperties = [
      'template', 'eval', 'exec', 'innerHTML', 'outerHTML',
      'isAdmin', 'isDebug', 'trusted', 'safe'
    ];
    
    if (dangerousProperties.includes(access.property)) {
      return true;
    }
    
    // Check if accessing undefined properties (UOP pattern)
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
        traceId: trace.id || 'unknown'
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

  calculateRiskLevel(data) {
    const { sink, pollution, type } = data;
    
    let baseRisk = 1;
    
    // Risk based on sink type
    if (sink && this.riskScoring[sink.sink]) {
      baseRisk = this.riskScoring[sink.sink];
    }
    
    // Increase risk for direct chains
    if (type === 'direct') {
      baseRisk += 2;
    }
    
    // Increase risk for multi-step chains (they're more exploitable)
    if (type === 'multi-step') {
      baseRisk += 3;
    }
    
    // Increase risk for prototype pollution
    if (pollution?.type === 'setPrototypeOf' || pollution?.property === '__proto__') {
      baseRisk += 2;
    }
    
    // Cap at 10
    return Math.min(baseRisk, 10);
  }

  calculateConfidence(data) {
    const { trace, steps, type } = data;
    
    let confidence = 0.5; // Base confidence
    
    // Higher confidence for successful traces
    if (trace.success) {
      confidence += 0.2;
    }
    
    // Higher confidence for chains with clear temporal ordering
    if (steps.length > 1) {
      const properlyOrdered = steps.every((step, index) => {
        if (index === 0) return true;
        return step.timestamp >= steps[index - 1].timestamp;
      });
      
      if (properlyOrdered) {
        confidence += 0.2;
      }
    }
    
    // Higher confidence for known dangerous patterns
    if (type === 'direct' || type === 'multi-step') {
      confidence += 0.1;
    }
    
    return Math.min(confidence, 1.0);
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

  identifySource(pollution, trace) {
    if (!pollution) return 'unknown';
    
    return {
      type: pollution.type || 'unknown',
      property: pollution.property || 'unknown',
      target: pollution.target || 'unknown',
      timestamp: pollution.timestamp
    };
  }

  identifySink(sink, trace) {
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
    // Remove potentially sensitive data and limit size
    const sanitized = { ...step };
    
    // Remove call stacks to reduce size
    delete sanitized.callStack;
    
    // Truncate long strings
    Object.keys(sanitized).forEach(key => {
      if (typeof sanitized[key] === 'string' && sanitized[key].length > 200) {
        sanitized[key] = sanitized[key].substring(0, 200) + '...';
      }
    });
    
    return sanitized;
  }

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

  rankChains(chains) {
    // Sort by risk level (descending) then confidence (descending)
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
      riskLevels: Object.keys(this.riskScoring).length
    };
  }
}