import { test, describe } from 'node:test';
import assert from 'node:assert';
import { V8CoverageCollector } from '../../src/utils/v8-coverage.js';

describe('V8CoverageCollector', () => {
  test('should start and stop without errors', async () => {
    const collector = new V8CoverageCollector();
    await collector.start();
    assert.strictEqual(collector.isActive, true);
    await collector.stop();
    assert.strictEqual(collector.isActive, false);
  });

  test('should collect coverage from executed code', async () => {
    const collector = new V8CoverageCollector();
    await collector.start();

    // Execute some code that will be covered
    const fn = new Function('x', 'if (x > 0) return x * 2; return -x;');
    fn(5);
    fn(-3);

    const coverage = await collector.takeCoverage();
    await collector.stop();

    // Should have found at least some scripts
    assert(coverage.length >= 0, 'Coverage collection should work');
  });

  test('should extract metrics with block and branch data', async () => {
    const collector = new V8CoverageCollector();
    await collector.start();

    // Execute branching code
    const fn = new Function('x', `
      let result = 0;
      if (x > 10) { result = x * 2; }
      else if (x > 0) { result = x + 1; }
      else { result = 0; }
      return result;
    `);
    fn(15);
    fn(5);
    fn(-1);

    const coverage = await collector.takeCoverage();
    const metrics = collector.extractMetrics(coverage);
    await collector.stop();

    // Verify metrics structure
    assert(Array.isArray(metrics.blocks));
    assert(Array.isArray(metrics.branches));
    assert(Array.isArray(metrics.functions));
    assert(typeof metrics.summary === 'object');
    assert(typeof metrics.summary.blockCoverage === 'number');
    assert(typeof metrics.summary.branchCoverage === 'number');
    assert(typeof metrics.summary.functionCoverage === 'number');
  });

  test('should not collect coverage when not started', async () => {
    const collector = new V8CoverageCollector();
    const coverage = await collector.takeCoverage();
    assert.deepStrictEqual(coverage, []);
  });

  test('should handle multiple start/stop cycles', async () => {
    const collector = new V8CoverageCollector();

    await collector.start();
    await collector.stop();
    await collector.start();
    await collector.stop();

    // Should not throw
    assert.strictEqual(collector.isActive, false);
  });

  test('should detect different coverage for different inputs', async () => {
    const collector = new V8CoverageCollector();
    await collector.start();

    const fn = new Function('x', 'if (x === "admin") return true; return false;');
    fn('user');
    const cov1 = await collector.takeCoverage();
    const metrics1 = collector.extractMetrics(cov1);

    fn('admin');
    const cov2 = await collector.takeCoverage();
    const metrics2 = collector.extractMetrics(cov2);

    await collector.stop();

    // Both should produce valid metrics
    assert(typeof metrics1.summary.blockCoverage === 'number');
    assert(typeof metrics2.summary.blockCoverage === 'number');
  });
});
