// Self-signed certificate for loopback-only behavioral probes (CN=localhost),
// generated in memory at require time. It exists so the
// NODE_TLS_REJECT_UNAUTHORIZED gadget probe has a server certificate that MUST
// fail validation when verification is on. It protects nothing: each process
// mints a fresh throwaway key, so no key material is ever committed to the
// repository (which would also trip secret-scanning push protection).
//
// This module is required by probes AFTER the behavioral harness has polluted
// Object.prototype. The ASN.1 serializer inside `selfsigned` iterates
// inherited enumerable properties and crashes on them, so generation runs
// with a temporarily pristine Object.prototype; the pollution is restored
// before the probe's TLS server ever sees a connection.
const polluted = Object.keys(Object.prototype).map((k) => [k, Object.prototype[k]]);
for (const [k] of polluted) delete Object.prototype[k];

let pems;
try {
  // Required lazily, after the prototype is pristine: merely loading the
  // dependency chain runs the crashing serializer at module scope.
  const selfsigned = require('selfsigned');
  pems = selfsigned.generate([{ name: 'commonName', value: 'localhost' }], {
    keySize: 2048,
    algorithm: 'sha256',
    days: 36500,
  });
} finally {
  for (const [k, v] of polluted) Object.prototype[k] = v;
}

module.exports = { cert: pems.cert, key: pems.private };
