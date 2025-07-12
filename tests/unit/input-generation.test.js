import { test, describe } from 'node:test';
import assert from 'node:assert';
import { InputGeneration } from '../../src/input-generation/index.js';

describe('InputGeneration', () => {
  test('should generate base inputs', async () => {
    const inputGen = new InputGeneration({ dryRun: true });
    const config = {
      entryPoints: [
        { name: 'compile', inputType: 'template' },
        { name: 'render', inputType: 'object' }
      ],
      pollutionPoints: ['template', 'cache']
    };

    const inputs = await inputGen.generateInputs(config, 0);
    
    assert(Array.isArray(inputs));
    assert(inputs.length > 0);
    
    // Check that we have different types of inputs
    const types = inputs.map(input => input.type);
    assert(types.includes('template') || types.includes('object'));
  });

  test('should apply prototype pollution mutations', async () => {
    const inputGen = new InputGeneration({ dryRun: true });
    const config = {
      pollutionPoints: ['isAdmin', 'template']
    };
    
    const baseInput = {
      entryPoint: 'test',
      type: 'object',
      value: { test: 'data' },
      metadata: { pollution: false, generation: 'base' }
    };

    const mutated = await inputGen.applyMutationStrategy(baseInput, 'prototypePollution', config);
    
    assert(mutated);
    assert.strictEqual(mutated.metadata.pollution, true);
    assert.strictEqual(mutated.metadata.strategy, 'prototypePollution');
    assert(mutated.value.__proto__);
  });

  test('should generate different input types', () => {
    const inputGen = new InputGeneration({ dryRun: true });
    
    const stringInput = inputGen.generateStringInput();
    const objectInput = inputGen.generateObjectInput();
    const templateInput = inputGen.generateTemplateInput();
    
    assert(typeof stringInput === 'string');
    assert(typeof objectInput === 'object');
    assert(typeof templateInput === 'string');
  });

  test('should track generation statistics', async () => {
    const inputGen = new InputGeneration({ dryRun: true });
    const config = {
      entryPoints: [{ name: 'test', inputType: 'object' }],
      pollutionPoints: ['test']
    };

    await inputGen.generateInputs(config, 0);
    
    const stats = inputGen.getGenerationStats();
    assert(typeof stats.totalGenerated === 'number');
    assert(stats.totalGenerated > 0);
  });
});