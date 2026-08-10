// Behavioral harness — runs a behavioral probe in a PLAIN child process (stock
// runtime, loopback allowed), clean vs polluted, and prints a one-line
// fingerprint on stdout. The corpus runner compares the two fingerprints: a
// difference proves the polluted value changed real runtime behavior end to
// end — used for gadgets whose effect only materializes in a live handshake
// (e.g. TLS certificate verification), which neither the sandbox (network
// blocked) nor the sink recorder (option never passed as an argument) can see.
//
// Env: UOPF_BHV_PROBE (probe name in index.js), UOPF_BHV_PROP / UOPF_BHV_VALUE
// (pollution to install before loading the probe).
const prop = process.env.UOPF_BHV_PROP;
if (prop) {
  let value = process.env.UOPF_BHV_VALUE;
  if (process.env.UOPF_BHV_TYPE === 'json') { try { value = JSON.parse(value); } catch { /* keep string */ } }
  Object.prototype[prop] = value;
}

const probe = require(`./${process.env.UOPF_BHV_PROBE}.js`);
Promise.resolve()
  .then(() => probe.run())
  .then(
    (fp) => { process.stdout.write(`FP:${fp}\n`, () => process.exit(0)); },
    (e) => { process.stdout.write(`FP:ERROR:${(e && (e.code || e.name)) || e}\n`, () => process.exit(0)); },
  );
require('node:timers').setTimeout(() => { process.stdout.write('FP:TIMEOUT\n', () => process.exit(0)); }, 8000).unref();
