// DoS driver: tls.connect with options fall-through (GHunter
// nodejs/https/tls.connect.PoC.js — polluted `session` of the wrong type).
// Loopback port 1 (connection refused), error absorbed — a clean run exits 0.
const tls = require('tls');
const sock = tls.connect({ host: '127.0.0.1', port: 1 });
sock.on('error', () => {});
