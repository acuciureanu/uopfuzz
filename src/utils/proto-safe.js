/**
 * Prototype-pollution-safe harness primitives.
 *
 * The fuzzer deliberately pollutes prototypes and then runs a target and
 * inspects what it returns. The danger is that the harness's OWN handling of the
 * return value can route through an inherited, engine-invoked member and trigger
 * itself — manufacturing a false positive that the target never caused:
 *
 *   - `Promise.resolve(x)` / `await x` read `x.then` and, if callable, INVOKE it
 *     (thenable adoption). A polluted callable `then` then "runs" from the
 *     harness's plumbing — the jQuery Event()/`then` false positive.
 *   - `JSON.stringify(x)` reads `x.toJSON`; `String(x)` / `` `${x}` `` read
 *     `x.toString` / `x.valueOf` / `x[Symbol.toPrimitive]`. A polluted one of
 *     those changes the serialized output, faking an "output changed" /
 *     "pollution was read" signal the target never produced.
 *
 * These helpers touch a target value without going through any inherited member,
 * so both oracles (discovery + reproduction) can pollute engine-invoked
 * properties safely. Shared, single source of truth, exactly like
 * prototype-monitor.js — the two paths must not drift.
 */

// Real timers, captured from node:timers rather than the global: sink tracing
// replaces global.setTimeout with a logging stub that returns a sentinel
// string, and the timeout race in callAndAwaitReal needs a genuine timer.
import { setTimeout as realSetTimeout, clearTimeout as realClearTimeout } from 'node:timers';

// Captured once at module load, before any pollution, so the serializer's own
// property enumeration cannot be redirected by a polluted prototype.
const ownKeys = Object.keys;
const isArray = Array.isArray;

/**
 * Serialize a value to a string that depends ONLY on its own structure, never on
 * an inherited member. Own getters (the target's own behaviour) are honoured;
 * inherited toString/valueOf/toJSON/Symbol.toPrimitive are never invoked. Used
 * for clean-vs-polluted output diffing, so the diff reflects the target, not the
 * harness's view through a polluted prototype.
 *
 * @param {*} value
 * @returns {string}
 */
export function structuralSerialize(value) {
  return walk(value, new WeakSet());
}

function walk(value, seen) {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'undefined') return 'undefined';
  if (t === 'string') return JSON.stringify(value); // quotes/escapes; no prototype access
  if (t === 'number' || t === 'boolean' || t === 'bigint') return t[0] + ':' + numish(value);
  if (t === 'symbol') return 'symbol';
  if (t === 'function') return '[function]';

  // Objects and arrays: own properties only.
  if (seen.has(value)) return '[cycle]';
  seen.add(value);

  if (isArray(value)) {
    const parts = [];
    for (let i = 0; i < value.length; i++) parts.push(walk(getOwn(value, i), seen));
    return '[' + parts.join(',') + ']';
  }

  let keys;
  try { keys = ownKeys(value); }
  catch { return '[unenumerable]'; } // exotic/proxy that throws on ownKeys
  keys.sort(); // stable regardless of insertion order
  const parts = [];
  for (const k of keys) parts.push(JSON.stringify(k) + ':' + walk(getOwn(value, k), seen));
  return '{' + parts.join(',') + '}';
}

// Read an own property value. Honours the target's own getter (its behaviour),
// but an absent own key never falls through to the (possibly polluted)
// prototype — we only ever call walk() on keys ownKeys() returned.
function getOwn(obj, key) {
  try { return obj[key]; } catch { return '[throws]'; }
}

// Render a number/boolean/bigint without String()/toString (which could route
// through a polluted prototype once non-Object prototypes are attacked too).
function numish(value) {
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  // Number/BigInt to string via the JSON grammar for numbers; NaN/Infinity are
  // not valid JSON, so name them explicitly.
  if (typeof value === 'bigint') return value.toString(10) + 'n';
  if (Number.isFinite(value)) return '' + value; // '' + number uses ToString on a primitive, no object hook
  return Number.isNaN(value) ? 'NaN' : (value > 0 ? 'Infinity' : '-Infinity');
}

/**
 * Invoke `fn(...args)` and await the result ONLY if it is a genuine Promise,
 * returning the resolved value inside a NULL-PROTOTYPE box: `{ value }`.
 *
 * Why a box: returning a plain object from an async function (or resolving a
 * promise with it) adopts it as a thenable — the engine reads `.then` and, if a
 * polluted prototype made it callable, invokes it. There is no way to pass a
 * plain-object-with-inherited-`then` back through a promise without that
 * adoption. A null-prototype box has no inherited `then`, so awaiting it is safe;
 * callers read `.value`. A native promise return is awaited normally (the engine
 * does not read `.then` on real promises); the timeout applies only to it.
 *
 * @param {Function} fn
 * @param {Array} args
 * @param {number} timeoutMs
 * @returns {Promise<{ value: * }>} null-prototype box holding the target's result
 */
export async function callAndAwaitReal(fn, args, timeoutMs) {
  const ret = fn(...args);
  let resolved;
  if (ret instanceof Promise) {
    let timer;
    try {
      resolved = await Promise.race([
        ret,
        new Promise((_, reject) => { timer = realSetTimeout(() => reject(new Error('timeout')), timeoutMs); }),
      ]);
    } finally {
      realClearTimeout(timer);
    }
  } else {
    resolved = ret;
  }
  const box = Object.create(null);
  box.value = resolved;
  return box;
}
