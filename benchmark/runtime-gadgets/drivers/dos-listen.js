// DoS driver: http.Server.listen with options fall-through (GHunter
// nodejs/http/listen.host.PoC.js — polluted backlog/host causes a native
// uncaught exception). Loopback-only, ephemeral port — no external effect.
const http = require('http');
const server = http.createServer(() => {});
server.listen(0, '127.0.0.1', () => server.close());
