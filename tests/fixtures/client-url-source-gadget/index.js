// Hermetic SELF-CONTAINED client-side gadget: this library is BOTH the URL
// prototype-pollution *source* (a naive nested query-string parser that doesn't
// guard __proto__) AND the *sink* (it reads a polluted option and assigns it to
// innerHTML). It models a router/parser library, where the whole chain — URL →
// pollution → DOM XSS — lives in one package, so the tool can verify it
// end-to-end without assuming an external source.
//
// Browser-only: touches `document`, so it loads under jsdom (browserEnv).

if (typeof globalThis.document === 'undefined') {
  throw new Error('client-url-source-gadget requires a DOM (browser-only)');
}

// Naive nested parser: `a[b][c]=v` -> obj.a.b.c = v, with NO __proto__ guard, so
// `__proto__[x]=v` (and chained forms) pollute Object.prototype.
function parseQuery(qs) {
  const obj = {};
  const s = String(qs).replace(/^\?/, '');
  if (!s) return obj;
  for (const pair of s.split('&')) {
    const eq = pair.indexOf('=');
    const rawKey = eq >= 0 ? pair.slice(0, eq) : pair;
    const val = eq >= 0 ? decodeURIComponent(pair.slice(eq + 1)) : '';
    const keys = rawKey.replace(/\]/g, '').split('[');
    let cur = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      const k = keys[i];
      if (cur[k] === undefined || cur[k] === null) cur[k] = {};
      cur = cur[k]; // for '__proto__', this walks onto Object.prototype
    }
    cur[keys[keys.length - 1]] = val; // pollutes when `cur` is Object.prototype
  }
  return obj;
}

function render(query) {
  parseQuery(query); // vulnerable parse — turns the URL query into pollution
  const doc = globalThis.document;
  const el = doc.createElement('div');
  doc.body.appendChild(el);
  const html = ({}).template; // reads Object.prototype.template when polluted
  if (typeof html === 'string') el.innerHTML = html; // DOM-XSS sink
  return el.outerHTML;
}

module.exports = { render };
