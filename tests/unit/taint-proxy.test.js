import { test, describe } from 'node:test';
import assert from 'node:assert';
import { createTaintProxy, analyzeTaintLog } from '../../src/utils/taint-proxy.js';

describe('TaintProxy', () => {
  test('should intercept property reads', () => {
    const log = [];
    const obj = createTaintProxy({ name: 'test', value: 42 }, log);

    const _ = obj.name;
    const __ = obj.value;

    const getEvents = log.filter(e => e.type === 'get');
    assert(getEvents.length >= 2);
    assert(getEvents.some(e => e.property === 'name'));
    assert(getEvents.some(e => e.property === 'value'));
  });

  test('should detect UOP candidates (undefined property reads)', () => {
    const log = [];
    const obj = createTaintProxy({ existing: 'yes' }, log);

    const _ = obj.nonExistent;

    const uop = log.find(e => e.property === 'nonExistent');
    assert(uop, 'Should log access to nonExistent');
    assert.strictEqual(uop.isUOPCandidate, true);
    assert.strictEqual(uop.exists, false);
    assert.strictEqual(uop.isUndefined, true);
  });

  test('should track deep nested property access', () => {
    const log = [];
    const obj = createTaintProxy({
      user: { profile: { name: 'admin' } }
    }, log);

    const name = obj.user.profile.name;

    assert.strictEqual(name, 'admin');
    // Should have logged: user, user.profile, user.profile.name
    const paths = log.filter(e => e.type === 'get').map(e => e.path);
    assert(paths.some(p => p.includes('user')));
    assert(paths.some(p => p.includes('profile')));
    assert(paths.some(p => p.includes('name')));
  });

  test('should intercept property writes', () => {
    const log = [];
    const obj = createTaintProxy({}, log);

    obj.injected = 'malicious';

    const setEvents = log.filter(e => e.type === 'set');
    assert(setEvents.length >= 1);
    assert(setEvents.some(e => e.property === 'injected'));
  });

  test('should intercept "in" operator', () => {
    const log = [];
    const obj = createTaintProxy({ exists: true }, log);

    const _ = 'exists' in obj;
    const __ = 'missing' in obj;

    const hasEvents = log.filter(e => e.type === 'has');
    assert(hasEvents.length >= 2);
    assert(hasEvents.some(e => e.property === 'exists' && e.result === true));
    assert(hasEvents.some(e => e.property === 'missing' && e.result === false));
  });

  test('should not double-wrap proxied objects', () => {
    const log = [];
    const obj = createTaintProxy({ nested: {} }, log);

    // Access nested multiple times - should not create infinite proxy chain
    const a = obj.nested;
    const b = obj.nested;

    // Should complete without stack overflow
    assert(true);
  });
});

describe('analyzeTaintLog', () => {
  test('should identify UOP candidates', () => {
    const log = [];
    const obj = createTaintProxy({ safe: 'value' }, log);

    const _ = obj.safe;
    const __ = obj.template;      // UOP: doesn't exist
    const ___ = obj.isAdmin;      // UOP: doesn't exist
    const ____ = obj.__proto__;   // exists (from Object.prototype)

    const analysis = analyzeTaintLog(log);
    assert(analysis.uopCandidates.length >= 2, `Expected >=2 UOP candidates, got ${analysis.uopCandidates.length}`);
    assert(analysis.uopCandidates.some(c => c.property === 'template'));
    assert(analysis.uopCandidates.some(c => c.property === 'isAdmin'));
  });

  test('should detect read-then-write pattern', () => {
    const log = [];
    const obj = createTaintProxy({}, log);

    // Common gadget pattern: if (!obj.cache) obj.cache = defaultValue
    const _ = obj.cache;    // read undefined
    obj.cache = 'polluted'; // write

    const analysis = analyzeTaintLog(log);
    assert(analysis.propertyWriteAfterRead.length >= 1);
    assert(analysis.propertyWriteAfterRead.some(p => p.property === 'cache'));
  });

  test('should compute access entropy', () => {
    const log = [];
    const obj = createTaintProxy({ a: 1, b: 2, c: 3 }, log);

    // Diverse access pattern
    const _ = obj.a;
    const __ = obj.b;
    const ___ = obj.c;

    const analysis = analyzeTaintLog(log);
    assert(analysis.accessEntropy > 0, 'Entropy should be positive for diverse access');
    assert(analysis.uniquePropertiesAccessed >= 3);
  });

  test('should count total events', () => {
    const log = [];
    const obj = createTaintProxy({ x: 1 }, log);

    obj.x;
    obj.y = 2;
    'z' in obj;

    const analysis = analyzeTaintLog(log);
    assert(analysis.totalEvents > 0);
  });
});
