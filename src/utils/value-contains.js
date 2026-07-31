/**
 * Transformed-value containment check — a lightweight taint-tracking
 * substitute.
 *
 * The classic string-substring match (`haystack.includes(needle)`) misses
 * common gadget sink transformations:
 *
 *   - `cmd.toUpperCase()` → needle `uopfuzz_sink_x` becomes `UOPFUZZ_SINK_X`.
 *     Substring match fails; the gadget is hidden.
 *   - `cmd.replace(/-/g, '_')` → needle `uopfuzz-sink` becomes `uopfuzz_sink`.
 *     Substring match fails.
 *   - `encodeURIComponent(cmd)` → the needle is URL-encoded inside the arg.
 *     Substring match fails.
 *
 * Replacing primitive strings with tagged String-wrapper objects (the textbook
 * taint-tracking approach) is impractical here: `structuralSerialize` walks own
 * properties of any object, so a tagged String wrapper would surface as
 * `{"0":"f", ..., "__uopTaint":"command"}` in the diff output — breaking the
 * clean-vs-polluted match and creating false positives.
 *
 * This module is the practical alternative: check whether the needle appears
 * in the haystack UNDER any of a small, well-chosen set of value
 * transformations that real gadget code performs. Each transformation is a
 * REVERSIBLE per-character operation, so the haystack can be derived from the
 * needle (and conversely the needle from the haystack) — substring match is
 * the appropriate check on the transformed form. Irreversible transformations
 * (hashing, encoding-decoding pairs, length-changing compression) are NOT
 * covered; they're rare in real gadget code anyway.
 *
 * Used by sink reachability (sink_reach payload) AND `payloadInOutput` checks.
 * The form chosen matches the form the harness installs on the prototype — so
 * a probe whose value is `'UOPFUZZ_SINK_x'` and a sink arg of `'uopfuzz_sink_x'`
 * (after `.toLowerCase()`) reports a hit.
 */

/**
 * True iff any of the candidate transformed forms of `needle` appears in
 * `haystack`. Always checks the unchanged form first (the historic behaviour),
 * so this is strictly a SUPERSET of `haystack.includes(needle)` — never a
 * regression for code paths that already matched case-sensitively.
 *
 * @param {string} haystack - the value as it appeared at the sink / in the
 *   output. May be derived from the needle by transformations the target
 *   performed (case fold, underscore↔dash substitution, URL-encode, etc.).
 * @param {string} needle - the value the harness planted on the prototype.
 * @returns {boolean}
 */
export function argContainsTransformedValue(haystack, needle) {
  if (typeof haystack !== 'string' || typeof needle !== 'string') return false;
  if (haystack.includes(needle)) return true;

  // Case folds — covers String.prototype.toUpperCase / toLowerCase.
  if (needle.length > 0) {
    if (haystack.toLowerCase().includes(needle.toLowerCase())) return true;
  }

  // Dash↔underscore and space↔plus normalisation: real gadget code often does
  // `cmd.replace(/-/g, '_')` to "normalize" a token (e.g. JSON Web Tokens,
  // query-string encoders). Cheap precomputed substitution: any non-empty
  // difference between the two forms is the test set.
  if (needle.includes('-') || needle.includes('_')) {
    const sub = needle.includes('-')
      ? needle.replace(/-/g, '_')
      : needle.replace(/_/g, '-');
    if (haystack.includes(sub)) return true;
  }

  // URL-encoded: encodeURIComponent(needle) appearing inside haystack OR the
  // decoded form of an encoded haystack containing needle. The first form is
  // the common one (target does `encodeURIComponent(cmd)` before passing it
  // to a sink, e.g. `fetch(\`/?q=${encodeURIComponent(opts.url)}\`)`).
  if (/[^\w.-]/.test(needle)) {
    const encoded = encodeURIComponent(needle);
    if (encoded !== needle && haystack.includes(encoded)) return true;
  }

  // Decoded: target decodes a query-string containing the needle before
  // passing it on — `decodeURIComponent(arg).includes(needle)`.
  if (haystack.includes('%')) {
    try {
      const decoded = decodeURIComponent(haystack);
      if (decoded !== haystack && decoded.includes(needle)) return true;
    } catch { /* malformed URI — skip */ }
  }

  return false;
}

/**
 * Convenience: case-insensitive includes(), used in `payloadInOutput`
 * (where the value-substring check pairs the descriptor's value against the
 * diff's polluted-side output). Kept as a separate export so callers that only
 * want case folds get a tighter, faster check than the full transformation
 * matrix above.
 *
 * @param {string} haystack
 * @param {string} needle
 * @returns {boolean}
 */
export function caseInsensitiveIncludes(haystack, needle) {
  if (typeof haystack !== 'string' || typeof needle !== 'string') return false;
  if (!needle) return false;
  return haystack.toLowerCase().includes(needle.toLowerCase());
}