// Behavioral probe: dynamic import must load the REAL module. The import-source
// gadget (polluted Object.prototype.source redirecting the ESM loader) is dead
// on Node 24, so clean and polluted fingerprints must be identical. The
// polluted value is a data: URL exporting a different value: if the gadget ever
// becomes live again the fingerprint flips to imported=666 and the corpus run
// fails with DETECTED-ANYWAY. Run via behavioral-harness.js (plain process).
exports.run = async () => {
  const mod = await import('./plain.mjs');
  return `imported=${mod.default}`;
};
