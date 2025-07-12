import { logger } from '../utils/logger.js';

export class InputGeneration {
  constructor(options) {
    this.options = options;
    this.seedInputs = [];
    this.mutationStrategies = [
      'prototypePollution',
      'constructorPollution', 
      'verticalChaining',
      'horizontalChaining',
      'typeCoercion',
      'asyncPollution'
    ];
    this.generatedCount = 0;
  }

  async generateInputs(config, iteration) {
    try {
      const inputs = [];
      const inputsPerIteration = this.calculateInputsPerIteration(iteration);
      
      logger.debug(`Generating ${inputsPerIteration} inputs for iteration ${iteration}`);
      
      // Generate base inputs
      const baseInputs = await this.generateBaseInputs(config, inputsPerIteration);
      inputs.push(...baseInputs);
      
      // Apply UOP-specific mutations
      const mutatedInputs = await this.applyUOPMutations(baseInputs, config);
      inputs.push(...mutatedInputs);
      
      // Generate coverage-guided variations
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

  calculateInputsPerIteration(iteration) {
    // Start with more inputs, then reduce as we find patterns
    const baseCount = 10;
    const reductionFactor = Math.min(iteration / 100, 0.5);
    return Math.max(baseCount - Math.floor(baseCount * reductionFactor), 3);
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
    const entryPoint = this.selectRandomEntryPoint(config.entryPoints);
    const inputType = entryPoint.inputType || 'object';
    
    switch (inputType) {
      case 'string':
        return {
          entryPoint: entryPoint.name,
          type: 'string',
          value: this.generateStringInput(),
          metadata: { 
            pollution: false,
            generation: 'base'
          }
        };
        
      case 'object':
        return {
          entryPoint: entryPoint.name,
          type: 'object',
          value: this.generateObjectInput(),
          metadata: { 
            pollution: false,
            generation: 'base'
          }
        };
        
      case 'template':
        return {
          entryPoint: entryPoint.name,
          type: 'template',
          value: this.generateTemplateInput(),
          metadata: { 
            pollution: false,
            generation: 'base'
          }
        };
        
      default:
        return {
          entryPoint: entryPoint.name,
          type: 'mixed',
          value: this.generateMixedInput(),
          metadata: { 
            pollution: false,
            generation: 'base'
          }
        };
    }
  }

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
    // Generate inputs that could be strings or objects depending on context
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
      for (const strategy of this.mutationStrategies) {
        const mutated = await this.applyMutationStrategy(input, strategy, config);
        if (mutated) {
          mutatedInputs.push(mutated);
        }
      }
    }
    
    return mutatedInputs;
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

  applyPrototypePollution(input, config) {
    if (input.type !== 'object') return null;
    
    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'isDebug', 'template', 'eval'];
    const target = pollutionTargets[Math.floor(Math.random() * pollutionTargets.length)];
    
    try {
      input.value.__proto__ = input.value.__proto__ || {};
      input.value.__proto__[target] = 'POLLUTED';
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
    } catch (error) {
      // Fallback to safer pollution method if __proto__ modification fails
      input.value.__protoPollution = { [target]: 'POLLUTED' };
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
      input.metadata.pollutionMethod = 'fallback';
    }
    
    return input;
  }

  applyConstructorPollution(input, config) {
    if (input.type !== 'object') return null;
    
    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'template'];
    const target = pollutionTargets[Math.floor(Math.random() * pollutionTargets.length)];
    
    try {
      // Create a new constructor object to avoid modifying native prototypes
      input.value.constructor = input.value.constructor || {};
      input.value.constructor.prototype = input.value.constructor.prototype || {};
      input.value.constructor.prototype[target] = 'CONSTRUCTOR_POLLUTED';
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
    } catch (error) {
      // Fallback to safer pollution method if direct modification fails
      input.value.__constructorPollution = { [target]: 'CONSTRUCTOR_POLLUTED' };
      input.metadata.pollution = true;
      input.metadata.pollutionTarget = target;
      input.metadata.pollutionMethod = 'fallback';
    }
    
    return input;
  }

  applyVerticalChaining(input, config) {
    if (input.type !== 'object') return null;
    
    try {
      // Create nested __proto__ chain
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
      // Fallback to simulation
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
    
    return input;
  }

  applyHorizontalChaining(input, config) {
    if (input.type !== 'object') return null;
    
    const pollutionTargets = config.pollutionPoints || ['isAdmin', 'isDebug', 'template'];
    
    try {
      // Pollute multiple properties at the same level
      input.value.__proto__ = input.value.__proto__ || {};
      pollutionTargets.forEach((target, index) => {
        input.value.__proto__[target] = `HORIZONTAL_${index}`;
      });
    } catch (error) {
      // Fallback to simulation
      input.value.__horizontalPollution = {};
      pollutionTargets.forEach((target, index) => {
        input.value.__horizontalPollution[target] = `HORIZONTAL_${index}`;
      });
      input.metadata.pollutionMethod = 'fallback';
    }
    
    input.metadata.pollution = true;
    input.metadata.chainingType = 'horizontal';
    
    return input;
  }

  applyTypeCoercion(input, config) {
    // Apply mutations that exploit JavaScript type coercion
    const coercions = [
      () => ({ toString: () => 'COERCED_STRING' }),
      () => ({ valueOf: () => 42 }),
      () => ({ [Symbol.toPrimitive]: () => 'SYMBOL_COERCED' }),
      () => ({ toJSON: () => ({ polluted: true }) })
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

  applyAsyncPollution(input, config) {
    if (input.type !== 'object') return null;
    
    try {
      // Create pollution that might affect async operations
      input.value.then = function(callback) {
        // Simulate async pollution without actually polluting Object.prototype
        if (callback) callback(this);
        return this;
      };
    } catch (error) {
      // Fallback to simulation
      input.value.__asyncPollution = {
        then: 'ASYNC_POLLUTED_SIMULATION'
      };
      input.metadata.pollutionMethod = 'fallback';
    }
    
    input.metadata.pollution = true;
    input.metadata.asyncPollution = true;
    
    return input;
  }

  async generateCoverageGuidedInputs(config, count) {
    // In a real implementation, this would use coverage feedback
    // For now, generate variations based on previous successful patterns
    const inputs = [];
    
    for (let i = 0; i < Math.min(count, 3); i++) {
      const base = this.createBaseInput(config);
      
      // Apply successful patterns from previous iterations
      if (Math.random() < 0.7) {
        const mutated = await this.applyMutationStrategy(base, 'prototypePollution', config);
        if (mutated) inputs.push(mutated);
      }
    }
    
    return inputs;
  }

  getGenerationStats() {
    return {
      totalGenerated: this.generatedCount,
      strategies: this.mutationStrategies.length,
      seedCount: this.seedInputs.length
    };
  }
}