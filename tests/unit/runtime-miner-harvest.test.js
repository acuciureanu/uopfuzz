import { test, describe } from 'node:test';
import assert from 'node:assert';

import { harvestCandidates, harvestLiteralSuspects, harvestClass, harvestAll, API_CLASSES } from '../../src/runtime-miner/harvest.js';

describe('runtime-miner harvest — harvestCandidates (pure)', () => {
  test('member reads on options/opts/config are harvested', () => {
    const src = `
      const a = options.foo;
      const b = opts?.bar;
      const c = config.baz_qux;
      const d = other.notHarvested;
      const e = myoptions.alsoNot;      // binding must be exact
    `;
    assert.deepEqual(harvestCandidates(src), ['bar', 'baz_qux', 'foo']);
  });

  test('destructuring of an options-ish binding yields the keys', () => {
    const src = `
      const { alpha, beta = 1, gamma: renamed } = options;
      function f({ delta, epsilon: { nested } } = {}) {}
      const { zeta } = config;
    `;
    const got = harvestCandidates(src);
    for (const want of ['alpha', 'beta', 'gamma', 'zeta']) assert.ok(got.includes(want), want);
  });

  test('denylist and global noise names are excluded', () => {
    const src = `
      options.constructor; options.__proto__; options.prototype;
      options.then; options.toString; options.hasOwnProperty('x');
      options.keepMe; options.classKey;
    `;
    const got = harvestCandidates(src, new Set(['classKey']));
    assert.deepEqual(got, ['keepMe']);
  });

  test('extraBindings extend the harvested binding names (undici init)', () => {
    const src = `init.method; init?.signal; options.classic;`;
    assert.deepEqual(harvestCandidates(src), ['classic']);
    assert.deepEqual(harvestCandidates(src, new Set(), ['init']), ['classic', 'method', 'signal']);
  });

  test('empty/garbage input yields nothing', () => {
    assert.deepEqual(harvestCandidates(''), []);
    assert.deepEqual(harvestCandidates(null), []);
    assert.deepEqual(harvestCandidates('no options here at all'), []);
  });

  test('process.env.FOO reads are harvested (env fall-through gadgets)', () => {
    const src = `
      const v = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
      const w = process.env?.NODE_OPTIONS;
      const x = process.env.PATH;         // too short to matter but valid
      const y = env.NOT_HARVESTED;        // binding must be process.env
    `;
    const got = harvestCandidates(src);
    assert.ok(got.includes('NODE_TLS_REJECT_UNAUTHORIZED'), 'tls env name');
    assert.ok(got.includes('NODE_OPTIONS'), 'node options');
    assert.ok(!got.includes('NOT_HARVESTED'), 'bare env binding ignored');
  });

  test('literal suspects catch computed-read names, skip noise', () => {
    const src = `
      switch (kind) { case 'writable': break; case 'ERR_BAD': break; }
      if (mode === 'transform') run();
      if (x !== 'utf-8') nope();          // dashed: not a property name
      if (typeof y === 'object') nope();  // typeof noise
      if (k === 'constructor') nope();    // denylisted
    `;
    assert.deepEqual(harvestLiteralSuspects(src), ['transform', 'writable']);
  });
});

describe('runtime-miner harvest — class harvesting on the real runtime', () => {
  test('every configured class harvests at least one candidate', () => {
    const all = harvestAll();
    assert.equal(all.size, Object.keys(API_CLASSES).length);
    for (const [id, { driver, properties }] of all) {
      assert.ok(typeof driver === 'string' && driver, `${id}: driver`);
      assert.ok(properties.length > 0, `${id}: harvested nothing — check sources list`);
    }
  });

  test('known GHunter gadget properties are within the harvested sets', () => {
    // Regression anchors: if a Node refactor renames internals these may move —
    // the point is that the harvester covers the reads the corpus relies on.
    const cases = [
      ['worker_threads.Worker', ['env', 'eval', 'argv', 'execArgv']],
      ['stream.Readable', ['highWaterMark', 'signal', 'encoding']],
      ['http.request', ['method', 'headers', 'hostname']],
      ['tls.connect', ['rejectUnauthorized']],
      ['fetch', ['method', 'body', 'signal']],
    ];
    for (const [cls, props] of cases) {
      const { properties } = harvestClass(cls);
      for (const p of props) assert.ok(properties.includes(p), `${cls}: ${p} harvested`);
    }
  });

  test('baseline keys the driver always sets are excluded', () => {
    const { properties } = harvestClass('http.request');
    for (const k of API_CLASSES['http.request'].baselineKeys) {
      assert.ok(!properties.includes(k), `${k} excluded`);
    }
  });
});
