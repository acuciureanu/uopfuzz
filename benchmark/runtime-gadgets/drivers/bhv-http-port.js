// Behavioral probe: is a polluted `port` honored? The server listens on the
// FIXED port; the request targets port 1 (dead). Clean run: ECONNREFUSED.
// If polluted port=FIXED_PORT were honored (GHunter's Node v21 result), the
// request would reach the server and the fingerprint would flip to "hit".
const http = require('http');
const FIXED_PORT = 45932;

exports.run = () => new Promise((resolve) => {
  const srv = http.createServer((req, res) => {
    res.end();
    srv.close();
    resolve('hit');
  });
  srv.on('error', (e) => resolve('SRV:' + (e.code || e.name)));
  srv.listen(FIXED_PORT, '127.0.0.1', () => {
    const req = http.request({ host: '127.0.0.1', port: 1, path: '/' }, (res) => res.resume());
    req.on('error', (e) => { srv.close(); resolve('nohit:' + (e.code || e.name)); });
    req.end();
  });
});
