import { test, describe } from 'node:test';
import assert from 'node:assert';
import { CoverageTracker } from '../../src/utils/coverage.js';

describe('CoverageTracker', () => {
  test('should record edges and detect novelty', () => {
    const tracker = new CoverageTracker();
    const bitmap = tracker.createLocalBitmap();

    // Record some edges
    tracker.recordEdge(bitmap, 0, 100);
    tracker.recordEdge(bitmap, 100, 200);
    tracker.recordEdge(bitmap, 200, 300);

    // First merge should find novel edges
    const result = tracker.mergeAndCheckNovelty(bitmap);
    assert.strictEqual(result.isNovel, true);
    assert(result.newEdges > 0);
    assert(result.totalEdges > 0);
  });

  test('should not report novelty for duplicate coverage', () => {
    const tracker = new CoverageTracker();

    const bitmap1 = tracker.createLocalBitmap();
    tracker.recordEdge(bitmap1, 0, 100);
    tracker.mergeAndCheckNovelty(bitmap1);

    // Same edge again - should not be novel
    const bitmap2 = tracker.createLocalBitmap();
    tracker.recordEdge(bitmap2, 0, 100);
    const result = tracker.mergeAndCheckNovelty(bitmap2);
    assert.strictEqual(result.isNovel, false);
    assert.strictEqual(result.newEdges, 0);
  });

  test('should detect novelty from new hit count buckets', () => {
    const tracker = new CoverageTracker();

    // Hit edge once
    const bitmap1 = tracker.createLocalBitmap();
    tracker.recordEdge(bitmap1, 0, 100);
    tracker.mergeAndCheckNovelty(bitmap1);

    // Hit same edge 4 times - new bucket (1 -> 4)
    const bitmap2 = tracker.createLocalBitmap();
    for (let i = 0; i < 4; i++) tracker.recordEdge(bitmap2, 0, 100);
    const result = tracker.mergeAndCheckNovelty(bitmap2);
    assert.strictEqual(result.isNovel, true);
  });

  test('should track saturation rate', () => {
    const tracker = new CoverageTracker();

    // Not enough data for saturation
    assert.strictEqual(tracker.getSaturationRate(), 0);

    // Generate many inputs, some with new edges
    for (let i = 0; i < 150; i++) {
      const bitmap = tracker.createLocalBitmap();
      if (i < 20) {
        // First 20 discover new edges
        tracker.recordEdge(bitmap, i * 7, (i + 1) * 7);
      }
      tracker.mergeAndCheckNovelty(bitmap);
    }

    // Should be saturated since last 100 inputs found few new edges
    const saturation = tracker.getSaturationRate();
    assert(saturation > 0.5, `Saturation should be high, got ${saturation}`);
  });

  test('should produce meaningful stats', () => {
    const tracker = new CoverageTracker();
    const bitmap = tracker.createLocalBitmap();
    tracker.recordEdge(bitmap, 0, 42);
    tracker.mergeAndCheckNovelty(bitmap);

    const stats = tracker.getStats();
    assert(stats.coveredEdges > 0);
    assert.strictEqual(stats.bitmapSize, 65536);
    assert(stats.bitmapDensity > 0);
    assert.strictEqual(stats.totalInputsProcessed, 1);
  });

  test('should hash locations deterministically', () => {
    const tracker = new CoverageTracker();
    const h1 = tracker.hashLocation('prop', 'template', 'Object');
    const h2 = tracker.hashLocation('prop', 'template', 'Object');
    const h3 = tracker.hashLocation('prop', 'eval', 'Object');

    assert.strictEqual(h1, h2, 'Same inputs should produce same hash');
    assert.notStrictEqual(h1, h3, 'Different inputs should produce different hashes');
  });
});
