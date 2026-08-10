// Behavioral probe: TLS certificate verification against a loopback server
// with a throwaway self-signed cert (selfsigned.js). Clean run: the handshake
// MUST fail (DEPTH_ZERO_SELF_SIGNED_CERT). If pollution of
// NODE_TLS_REJECT_UNAUTHORIZED disables verification, the handshake succeeds —
// the fingerprint flips. Run via behavioral-harness.js (plain process).
const tls = require('tls');
const { cert, key } = require('./selfsigned.js');

exports.run = () => new Promise((resolve) => {
  const srv = tls.createServer({ cert, key }, (s) => s.end());
  srv.listen(0, '127.0.0.1', () => {
    const sock = tls.connect({ host: '127.0.0.1', port: srv.address().port });
    sock.on('secureConnect', () => { srv.close(); resolve('HANDSHAKE-OK'); });
    sock.on('error', (e) => { srv.close(); resolve(String(e.code || e.name || e).slice(0, 60)); });
  });
});
