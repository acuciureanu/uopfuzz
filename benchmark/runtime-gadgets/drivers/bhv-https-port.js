// https variant of bhv-http-port: is a polluted `port` honored over TLS?
const https = require('https');
const { cert, key } = require('./selfsigned.js');
const FIXED_PORT = 45934;

exports.run = () => new Promise((resolve) => {
  const srv = https.createServer({ cert, key }, (req, res) => {
    res.end();
    srv.close();
    resolve('hit');
  });
  srv.on('error', (e) => resolve('SRV:' + (e.code || e.name)));
  srv.listen(FIXED_PORT, '127.0.0.1', () => {
    const req = https.request({ host: '127.0.0.1', port: 1, path: '/', rejectUnauthorized: false }, (res) => res.resume());
    req.on('error', (e) => { srv.close(); resolve('nohit:' + (e.code || e.name)); });
    req.end();
  });
});
