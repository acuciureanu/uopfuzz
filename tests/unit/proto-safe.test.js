import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert';

import { callAndAwaitReal, structuralSerialize } from '../../src/utils/proto-safe.js';

// These primitives exist so the harness can touch a target's return value while
// Object.prototype is deliberately polluted, WITHOUT routing through an inherited
// engine-invoked member (then/toString/valueOf/toJSON/Symbol.toPrimitive). Every
// such route is a way for the harness to trigger itself and manufacture a false
// positive — the class the jQuery Event/`then` bug belonged to.

function cleanupProto(...props) {
  for (const p of props) { try { delete Object.prototype[p]; } catch { /* sealed */ } }
}

describe('structuralSerialize is invariant to prototype pollution', () => {
  afterEach(() => cleanupProto('toString', 'valueOf', 'toJSON', 'then'));

  test('does not invoke inherited coercion hooks and yields a stable result', () => {
    let toStringCalls = 0, valueOfCalls = 0, toJSONCalls = 0;
    const clean = structuralSerialize({ a: 1, b: 'x' });

    Object.prototype.toString = function () { toStringCalls++; return 'PWN'; };
    Object.prototype.valueOf = function () { valueOfCalls++; return 'PWN'; };
    Object.prototype.toJSON = function () { toJSONCalls++; return 'PWN'; };

    const polluted = structuralSerialize({ a: 1, b: 'x' });

    assert.equal(polluted, clean, 'serialization must not change when the prototype is polluted');
    assert.equal(toStringCalls, 0, 'must not invoke inherited toString');
    assert.equal(valueOfCalls, 0, 'must not invoke inherited valueOf');
    assert.equal(toJSONCalls, 0, 'must not invoke inherited toJSON');
  });

  test('still reflects the object\'s own structure and values', () => {
    const a = structuralSerialize({ greeting: 'hello' });
    const b = structuralSerialize({ greeting: 'world' });
    assert.notEqual(a, b, 'different own values must serialize differently');
    assert.ok(a.includes('hello'), 'own string values must appear in the serialization');
  });

  test('handles primitives, arrays, null/undefined, and cycles without throwing', () => {
    assert.equal(typeof structuralSerialize(42), 'string');
    assert.equal(typeof structuralSerialize('s'), 'string');
    assert.equal(typeof structuralSerialize(null), 'string');
    assert.equal(typeof structuralSerialize(undefined), 'string');
    assert.ok(structuralSerialize([1, 2, 3]).includes('2'));
    const cyclic = { x: 1 }; cyclic.self = cyclic;
    assert.doesNotThrow(() => structuralSerialize(cyclic));
  });
});

describe('callAndAwaitReal never adopts a polluted `then`', () => {
  afterEach(() => cleanupProto('then'));

  test('a plain-object return does not fire a callable Object.prototype.then', async () => {
    let fired = false;
    Object.prototype.then = function (res) { fired = true; if (res) res(); };

    const box = await callAndAwaitReal(() => ({ ok: true }), [], 1000);

    assert.equal(fired, false, 'harness must not invoke the polluted then during adoption');
    assert.equal(box.value.ok, true, 'the plain return value is passed through in the box');
  });

  test('a genuine async result is still awaited', async () => {
    const box = await callAndAwaitReal(async () => 'async-value', [], 1000);
    assert.equal(box.value, 'async-value', 'a real Promise return must be awaited');
  });
});
