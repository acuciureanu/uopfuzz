// Behavioral probe: do polluted hostname/headers reach the wire? A loopback
// server on a fixed port receives the request and fingerprints the Host header
// and the x-polluted header. Clean run: host is 127.0.0.1 and no x-polluted.
// If pollution were live (GHunter's Node v21 result), either would change.
// Fixed port: the port-gadget variant needs a stable value to pollute with.
const http = require('http');
const FIXED_PORT = 45931;

exports.run = () => new Promise((resolve) => {
  const srv = http.createServer((req, res) => {
    res.end();
    srv.close();
    resolve(`host=${req.headers.host}|x=${req.headers['x-polluted'] || 'none'}`);
  });
  srv.on('error', (e) => resolve('SRV:' + (e.code || e.name)));
  srv.listen(FIXED_PORT, '127.0.0.1', () => {
    const req = http.request({ host: '127.0.0.1', port: FIXED_PORT, path: '/' }, (res) => res.resume());
    req.on('error', (e) => { srv.close(); resolve('ERR:' + (e.code || e.name)); });
    req.end();
  });
});
