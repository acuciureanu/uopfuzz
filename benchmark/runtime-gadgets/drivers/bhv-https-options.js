// https variant of bhv-http-options: same fingerprint over a TLS loopback
// (rejectUnauthorized:false is passed as an OWN option — the gadget under test
// is hostname/headers fall-through, not certificate verification).
const https = require('https');
const { cert, key } = require('./selfsigned.js');
const FIXED_PORT = 45933;

exports.run = () => new Promise((resolve) => {
  const srv = https.createServer({ cert, key }, (req, res) => {
    res.end();
    srv.close();
    resolve(`host=${req.headers.host}|x=${req.headers['x-polluted'] || 'none'}`);
  });
  srv.on('error', (e) => resolve('SRV:' + (e.code || e.name)));
  srv.listen(FIXED_PORT, '127.0.0.1', () => {
    const req = https.request({ host: '127.0.0.1', port: FIXED_PORT, path: '/', rejectUnauthorized: false }, (res) => res.resume());
    req.on('error', (e) => { srv.close(); resolve('ERR:' + (e.code || e.name)); });
    req.end();
  });
});
