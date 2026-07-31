import { test, describe } from 'node:test';
import assert from 'node:assert';
import { Orchestrator } from '../../src/orchestrator/index.js';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs/promises';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('Orchestrator Integration', () => {
  test('should run complete fuzzing workflow in dry-run mode', async () => {
    const configPath = path.join(__dirname, '../../config/targets/pug.yaml');
    const outputDir = path.join(__dirname, '../../test-results');
    
    const orchestrator = new Orchestrator({
      configPath,
      outputDir,
      timeout: 5,
      dryRun: true,
      maxIterations: 3,
      parallelWorkers: 1,
      verbose: false
    });

    const results = await orchestrator.run();
    
    // Verify results structure
    assert(results.startTime);
    assert(results.endTime);
    assert.strictEqual(results.iterationsCompleted, 3);
    assert(results.inputsGenerated > 0);
    assert(Array.isArray(results.potentialChains));
    assert(Array.isArray(results.errors));
    
    // Verify files were created
    const files = await fs.readdir(outputDir);
    const jsonFiles = files.filter(f => f.endsWith('.json'));
    const mdFiles = files.filter(f => f.endsWith('.md'));
    
    assert(jsonFiles.length > 0, 'Should create JSON results file');
    assert(mdFiles.length > 0, 'Should create Markdown report file');
    
    // Cleanup
    await fs.rm(outputDir, { recursive: true, force: true });
  });

  test('should handle configuration loading errors gracefully', async () => {
    const orchestrator = new Orchestrator({
      configPath: '/nonexistent/path.yaml',
      outputDir: './test-output',
      dryRun: true,
      maxIterations: 1
    });

    await assert.rejects(
      orchestrator.run(),
      /Failed to load configuration/
    );
  });

  test('should generate meaningful reports', async () => {
    const configPath = path.join(__dirname, '../../config/targets/squirrelly.yaml');
    
    const orchestrator = new Orchestrator({
      configPath,
      outputDir: './test-results-2',
      timeout: 5,
      dryRun: true,
      maxIterations: 2,
      verbose: false
    });

    await orchestrator.run();
    const report = orchestrator.generateReport();
    
    assert(report.includes('UoPFuzz Report'));
    assert(report.includes('squirrelly'));
    assert(report.includes('Iterations:'));
    
    // Cleanup
    await fs.rm('./test-results-2', { recursive: true, force: true });
  });

  test('should execute fuzzing with parallel workers', async () => {
    const configPath = path.join(__dirname, '../../config/targets/pug.yaml');
    const outputDir = path.join(__dirname, '../../test-results-parallel');
    
    const orchestrator = new Orchestrator({
      configPath,
      outputDir,
      timeout: 5,
      dryRun: true,
      maxIterations: 6,
      parallelWorkers: 2,
      verbose: false
    });

    const results = await orchestrator.run();
    
    // Verify results structure
    assert(results.startTime);
    assert(results.endTime);
    assert.strictEqual(results.iterationsCompleted, 6);
    assert(results.inputsGenerated > 0);
    assert(Array.isArray(results.potentialChains));
    assert(Array.isArray(results.errors));
    
    // Verify files were created
    const files = await fs.readdir(outputDir);
    const jsonFiles = files.filter(f => f.endsWith('.json'));
    const mdFiles = files.filter(f => f.endsWith('.md'));
    
    assert(jsonFiles.length > 0, 'Should create JSON results file');
    assert(mdFiles.length > 0, 'Should create Markdown report file');
    
    // Cleanup
    await fs.rm(outputDir, { recursive: true, force: true });
  });

  test('should handle more workers than iterations gracefully', async () => {
    const configPath = path.join(__dirname, '../../config/targets/pug.yaml');
    const outputDir = path.join(__dirname, '../../test-results-many-workers');
    
    const orchestrator = new Orchestrator({
      configPath,
      outputDir,
      timeout: 5,
      dryRun: true,
      maxIterations: 2,
      parallelWorkers: 5, // More workers than iterations
      verbose: false
    });

    const results = await orchestrator.run();
    
    // Should still complete all iterations
    assert.strictEqual(results.iterationsCompleted, 2);
    assert(results.inputsGenerated > 0);
    
    // Cleanup
    await fs.rm(outputDir, { recursive: true, force: true });
  });
});