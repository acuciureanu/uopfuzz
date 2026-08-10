import { test, describe } from 'node:test';
import assert from 'node:assert';
import { sourceCallArgs, renderSourceCalls } from '../../src/verification/source-call.js';

describe('sourceCallArgs — building the call that drives a PP source', () => {
  test('proto-json packs every property into one __proto__ payload (own key)', () => {
    const calls = sourceCallArgs('proto-json', 'fn(target, payload)', { command: 'X', isAdmin: true });
    assert.equal(calls.length, 1);
    const [target, payload] = calls[0];
    assert.deepEqual(target, {}); // fn(target, payload) convention
    // The payload carries a REAL own-property named __proto__ (as JSON.parse of an
    // attacker body would), not a set prototype.
    const desc = Object.getOwnPropertyDescriptor(payload, '__proto__');
    assert.ok(desc, 'payload has an own __proto__ key');
    assert.equal(desc.value.command, 'X');
    assert.equal(desc.value.isAdmin, true);
  });

  test('convention controls argument shape', () => {
    assert.deepEqual(sourceCallArgs('proto-json', 'fn(payload)', { a: 1 })[0].length, 1);
    assert.deepEqual(sourceCallArgs('proto-json', 'fn(true, {}, payload)', { a: 1 })[0].slice(0, 2), [true, {}]);
  });

  test('ctor-object uses the constructor.prototype form', () => {
    const [[, payload]] = sourceCallArgs('ctor-object', 'fn(target, payload)', { command: 'X' });
    assert.equal(payload.constructor.prototype.command, 'X');
  });

  test('proto-path emits one set-style call per property', () => {
    const calls = sourceCallArgs('proto-path', "fn({}, 'path', value)", { command: 'X', gate: true });
    assert.deepEqual(calls, [
      [{}, '__proto__.command', 'X'],
      [{}, '__proto__.gate', true],
    ]);
  });

  test('ctor-path uses the constructor.prototype path prefix', () => {
    const calls = sourceCallArgs('ctor-path', "fn({}, 'path', value)", { command: 'X' });
    assert.deepEqual(calls, [[{}, 'constructor.prototype.command', 'X']]);
  });
});

describe('renderSourceCalls — the PoC text must match sourceCallArgs', () => {
  test('proto-json renders a JSON.parse(__proto__) call', () => {
    const js = renderSourceCalls('source', 'proto-json', 'fn(target, payload)', { command: '"<attacker code>"', gate: 'true' });
    assert.match(js, /source\(\{\},/);
    assert.match(js, /JSON\.parse/);
    assert.match(js, /__proto__/);
    assert.match(js, /"<attacker code>"/);
  });

  test('proto-path renders one set call per property', () => {
    const js = renderSourceCalls('source', 'proto-path', "fn({}, 'path', value)", { command: '"<attacker code>"' });
    assert.match(js, /source\(\{\}, "__proto__\.command", "<attacker code>"\);/);
  });

  test('bare-function source is called directly (no dotted method)', () => {
    const js = renderSourceCalls('source', 'proto-json', 'fn(target, payload)', { a: '1' });
    assert.match(js, /^source\(/);
  });
});
