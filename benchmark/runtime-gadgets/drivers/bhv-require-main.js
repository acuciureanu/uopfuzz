// Behavioral probe: directory require must resolve the REAL package entry
// (sub/package.json → sub/index.js, exports 1). The require-main gadget
// (polluted Object.prototype.main redirecting resolution, fixed in Node
// 18.19.0) would instead resolve sub/evil.js, which exports 2 — the
// fingerprint flips to main=2 and the corpus run fails with DETECTED-ANYWAY.
// Also serves the require + NODE_OPTIONS entry: polluted NODE_OPTIONS has no
// effect on require, so the fingerprint must stay main=1. Run via
// behavioral-harness.js (plain process).
exports.run = () => {
  const mod = require('./sub');
  return `main=${mod}`;
};
