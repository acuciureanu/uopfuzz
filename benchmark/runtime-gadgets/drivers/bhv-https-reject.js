// Same gadget through https.request (GHunter lists it for https.get and
// https.request separately — the env var governs the shared TLS layer).
const https = require('https');
const { cert, key } = require('./selfsigned.js');
const tls = require('tls');

exports.run = () => new Promise((resolve) => {
  const srv = tls.createServer({ cert, key }, (s) => s.end());
  srv.listen(0, '127.0.0.1', () => {
    const req = https.request({ host: '127.0.0.1', port: srv.address().port }, (res) => {
      res.resume();
      srv.close();
      resolve('HANDSHAKE-OK');
    });
    req.on('error', (e) => { srv.close(); resolve(String(e.code || e.name || e).slice(0, 60)); });
    req.end();
  });
});
