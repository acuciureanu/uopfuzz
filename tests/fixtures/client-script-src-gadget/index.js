// Hermetic CLIENT-SIDE prototype-pollution gadget, in the style of the
// BlackFan/client-side-prototype-pollution catalog: a browser library reads an
// option off the prototype chain and assigns it to a <script> element's `src`,
// a script-injection sink. With Object.prototype.scriptSrc polluted, loading the
// widget injects an attacker-controlled script URL into the page.
//
// It touches `document` at load time, so it only loads under jsdom (browserEnv)
// — exactly the path used for jQuery/Backbone-style browser-only targets.

if (typeof globalThis.document === 'undefined') {
  throw new Error('client-script-src-gadget requires a DOM (browser-only)');
}

function loadWidget(opts) {
  const options = opts || {};
  const doc = globalThis.document;
  const s = doc.createElement('script');
  // Reads `scriptSrc` — falls through to Object.prototype.scriptSrc when polluted.
  if (options.scriptSrc) {
    s.src = options.scriptSrc; // script.src sink (hooked by installDomSinkHooks)
  }
  doc.body.appendChild(s);
  return s.getAttribute('src');
}

module.exports = { loadWidget };
