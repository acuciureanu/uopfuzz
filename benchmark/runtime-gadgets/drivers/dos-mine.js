// Generic DoS driver for the runtime gadget miner: run the named mining probe
// in a PLAIN process (pollution already installed by dos-harness.js via
// UOPF_DOS_PROP/UOPF_DOS_VALUE) and exit 0 when it settles. A polluted-only
// non-zero exit is the miner's DoS signal (GHunter §4.3 methodology).
const probes = require('./index.js');
const probe = probes[process.env.UOPF_DOS_PROBE];
if (typeof probe !== 'function') process.exit(0);
Promise.resolve()
  .then(() => probe())
  .then(() => process.exit(0), () => process.exit(0));
