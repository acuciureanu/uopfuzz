import { test, describe } from 'node:test';
import assert from 'node:assert';

import { collectSinkStrings } from '../../src/utils/sink-record.js';

describe('collectSinkStrings — options-aware sink argument traversal', () => {
  test('records a plain string arg', () => {
    assert.deepEqual(collectSinkStrings('http://evil.example'), ['http://evil.example']);
  });

  test('records strings from nested options objects and arrays', () => {
    const args = ['cmd', { env: { AAA: 'BBB' }, cwd: '/tmp' }];
    const found = collectSinkStrings(args);
    assert.ok(found.includes('cmd'));
    assert.ok(found.includes('BBB'));
    assert.ok(found.includes('/tmp'));
  });

  test('captures a polluted prototype value through an options object (the GHunter env gadget)', () => {
    // Simulates Object.prototype.NODE_OPTIONS = token: the env object passed to
    // exec() inherits it, and Node's spawn normalization reads it.
    const token = '--inspect-brk=127.0.0.1:0';
    Object.defineProperty(Object.prototype, 'NODE_OPTIONS', {
      get() { return token; },
      configurable: true,
      enumerable: false,
    });
    try {
      const found = collectSinkStrings([{ env: { AAA: 'BBB' } }]);
      assert.ok(found.includes(token), `expected inherited NODE_OPTIONS in ${JSON.stringify(found)}`);
    } finally {
      delete Object.prototype.NODE_OPTIONS;
    }
  });

  test('reads a URL-ish href', () => {
    const found = collectSinkStrings([new URL('http://example.com/x')]);
    assert.ok(found.includes('http://example.com/x'));
  });

  test('never coerces non-strings (a polluted toString must not fire)', () => {
    let coercionFired = false;
    const origToString = Object.prototype.toString;
    Object.defineProperty(Object.prototype, 'toString', {
      value() { coercionFired = true; return 'x'; },
      configurable: true,
      writable: true,
    });
    try {
      collectSinkStrings([{ a: 1, b: true, c: null }]);
      assert.equal(coercionFired, false);
    } finally {
      // Restore — delete would lose the built-in for the rest of this process.
      Object.defineProperty(Object.prototype, 'toString', {
        value: origToString, configurable: true, writable: true,
      });
    }
  });

  test('never invokes an own accessor; a throwing own getter loses only that value', () => {
    let getterFired = false;
    const evil = {};
    Object.defineProperty(evil, 'pwn', {
      get() { getterFired = true; throw new Error('boom'); },
      enumerable: true,
    });
    evil.safe = 'ok';
    const found = collectSinkStrings([evil]);
    assert.equal(getterFired, false);
    assert.ok(found.includes('ok'));
  });

  test('a throwing INHERITED getter loses one value, not the rest', () => {
    const proto = {};
    Object.defineProperty(proto, 'bad', { get() { throw new Error('nope'); } });
    Object.defineProperty(proto, 'good', { get() { return 'inherited-ok'; } });
    const obj = Object.create(proto);
    obj.own = 'own-ok';
    const found = collectSinkStrings([obj]);
    assert.ok(found.includes('own-ok'));
    assert.ok(found.includes('inherited-ok'));
  });

  test('survives cyclic structures within the caps', () => {
    const a = { s: 'loop' };
    a.self = a;
    const found = collectSinkStrings([a]);
    assert.deepEqual(found, ['loop']);
  });

  test('respects the string-count cap', () => {
    const big = {};
    for (let i = 0; i < 200; i++) big['k' + i] = 'v' + i;
    const found = collectSinkStrings([big]);
    assert.ok(found.length <= 50);
  });

  test('truncates long strings to 200 chars', () => {
    const long = 'x'.repeat(500);
    const [found] = collectSinkStrings(long);
    assert.equal(found.length, 200);
  });
});
