// Hermetic fixture: a prototype-pollution -> SSRF gadget. The function reads an
// option off the prototype chain and feeds it to http.request as the URL. With
// Object.prototype.endpoint polluted, calling fetch({}) issues an HTTP request
// to the attacker-controlled URL. Worker-hardening blocks the underlying socket
// so no packet ever leaves the worker, but the URL still reaches the http.request
// sink argument — which the sandbox worker records and reproduction's sink_reach
// proof confirms.
//
// Mirrors real-world SSRF gadgets (got/method, axios/url, request/uri) where a
// polluted property flows into an HTTP client's URL option.

const http = require('http');

function fetch(opts) {
  const options = opts || {};
  // Reads `endpoint` — falls through to Object.prototype.endpoint when polluted.
  if (options.endpoint) {
    return http.request(options.endpoint);
  }
  return null;
}

module.exports = { fetch };
