// Hermetic fixture: a function that EXPLICITLY invokes a method on its argument
// by a name that is NOT an engine-coercion hook (split / replace / …). With no
// own property of that name, the call falls through to Object.prototype — so a
// live *function* polluted there is invoked, firing the execution canary.
//
// This mirrors the real-world false positives the earlier engine-coercion-only
// guard did NOT cover: 6to5@3.6.5 `_util.list` (split), marked@16.3.0 `lexer`
// (replace) and immutable@5.1.9 `Map` (@@iterator). The library method-
// dispatches to the polluted prototype, but a prototype-pollution attacker can
// only inject DATA via JSON (`{"__proto__":{"split":…}}` carries a string,
// never a callable), so the `function_call` proof is unrealizable here exactly
// as it is for toString/valueOf. The reproduction gate must REJECT it — the
// only realizable proofs are the string ones (eval_string / sink_reach), and a
// string on `.split` just throws "split is not a function", never executes.
function tokenize(opts) {
  if (typeof opts.split === 'function') return opts.split(',');
  if (typeof opts.replace === 'function') return opts.replace('a', 'b');
  return 'no-op';
}

module.exports = { tokenize };
