import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { selectVersions, compareVersions, sortVersionsDesc, resolveInstallable } from '../../src/sources/version-scanner.js';

// ─── compareVersions ──────────────────────────────────────────────────────────

describe('compareVersions', () => {
  test('newer version returns positive', () => {
    assert.ok(compareVersions('4.17.21', '4.17.20') > 0);
  });

  test('older version returns negative', () => {
    assert.ok(compareVersions('3.0.0', '4.0.0') < 0);
  });

  test('equal versions return 0', () => {
    assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
  });

  test('handles version without patch segment', () => {
    assert.ok(compareVersions('2.0', '1.9.9') > 0);
  });

  test('strips leading v prefix', () => {
    assert.equal(compareVersions('v1.0.0', '1.0.0'), 0);
  });
});

// ─── sortVersionsDesc ─────────────────────────────────────────────────────────

describe('sortVersionsDesc', () => {
  test('sorts newest first', () => {
    const versions = ['1.0.0', '3.0.0', '2.5.0'];
    const sorted = sortVersionsDesc(versions);
    assert.equal(sorted[0], '3.0.0');
    assert.equal(sorted[1], '2.5.0');
    assert.equal(sorted[2], '1.0.0');
  });

  test('does not mutate input array', () => {
    const versions = ['1.0.0', '3.0.0'];
    const original = [...versions];
    sortVersionsDesc(versions);
    assert.deepEqual(versions, original);
  });
});

// ─── selectVersions ───────────────────────────────────────────────────────────

const ALL_VERSIONS = ['4.17.21', '4.17.20', '4.16.0', '3.10.0', '3.0.0', '2.0.0'];

describe('selectVersions — mode: all', () => {
  test('returns all versions', () => {
    const result = selectVersions(ALL_VERSIONS, { mode: 'all' });
    assert.equal(result.length, ALL_VERSIONS.length);
  });

  test('returns all versions when strategy is omitted', () => {
    const result = selectVersions(ALL_VERSIONS);
    assert.equal(result.length, ALL_VERSIONS.length);
  });
});

describe('selectVersions — mode: last', () => {
  test('returns the N newest versions', () => {
    const result = selectVersions(ALL_VERSIONS, { mode: 'last', count: 3 });
    assert.equal(result.length, 3);
    assert.equal(result[0], '4.17.21');
    assert.equal(result[1], '4.17.20');
    assert.equal(result[2], '4.16.0');
  });

  test('clamps to available versions when count exceeds total', () => {
    const result = selectVersions(['1.0.0', '2.0.0'], { mode: 'last', count: 100 });
    assert.equal(result.length, 2);
  });

  test('defaults to 1 when count is omitted', () => {
    const result = selectVersions(ALL_VERSIONS, { mode: 'last' });
    assert.equal(result.length, 1);
    assert.equal(result[0], '4.17.21');
  });
});

describe('selectVersions — mode: range', () => {
  test('returns versions between from and to (inclusive)', () => {
    // from='4.17.20' (newer boundary), to='3.10.0' (older boundary)
    const result = selectVersions(ALL_VERSIONS, { mode: 'range', from: '4.17.20', to: '3.10.0' });
    assert.ok(result.includes('4.17.20'));
    assert.ok(result.includes('4.16.0'));
    assert.ok(result.includes('3.10.0'));
    assert.ok(!result.includes('4.17.21'));
    assert.ok(!result.includes('3.0.0'));
  });

  test('returns nothing when range has no matches', () => {
    const result = selectVersions(ALL_VERSIONS, { mode: 'range', from: '4.17.21', to: '4.17.21' });
    assert.equal(result.length, 1);
    assert.equal(result[0], '4.17.21');
  });
});

// ─── resolveInstallable ───────────────────────────────────────────────────────

describe('resolveInstallable', () => {
  test('constructs correct installSpec', () => {
    const result = resolveInstallable('lodash.js', 'lodash', '4.17.21');
    assert.equal(result.installSpec, 'lodash@4.17.21');
    assert.equal(result.cdnjsName, 'lodash.js');
    assert.equal(result.npmPackage, 'lodash');
    assert.equal(result.version, '4.17.21');
  });
});
