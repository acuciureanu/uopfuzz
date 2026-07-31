/**
 * Browser-environment support for browser-only packages (jQuery, Backbone, …).
 *
 * These libraries require `window`/`document` at load time and export a factory
 * rather than a ready object. To fuzz them we stand up a jsdom DOM and load the
 * module against it. This is the SINGLE SOURCE OF TRUTH for (a) which packages
 * are browser-only and (b) how to build the DOM + load the module, shared by the
 * in-process loader (target-integration) and the sandbox worker so they cannot
 * drift on either (invariant #4).
 *
 * Running a browser-only package in the SANDBOX child (rather than in-process)
 * matters for safety: its fuzzed Object.prototype pollution stays in the child,
 * where network is blocked, instead of leaking into the fuzzer's own Node
 * internals (e.g. undici's HTTP parser) and crashing the fuzzer.
 */

/** Packages that need a DOM at load time. Matched against the bare package name. */
export const BROWSER_ONLY_PACKAGES = new Set([
  'jquery', 'jquery-ui', 'backbone', 'underscore',
]);

/**
 * Extra wall-clock a sandbox child gets to stand up jsdom before its operation
 * timeout applies. jsdom cold-start is heavy (a couple seconds on a fast disk,
 * much more on a slow/networked filesystem), and the per-operation diff timeout
 * is tight (~1.5s), so without this allowance every browser-only call would time
 * out during startup. It is a ceiling, not a cost: a child that boots quickly and
 * finishes exits immediately and never uses the headroom.
 */
export const JSDOM_STARTUP_ALLOWANCE_MS = 20000;

/**
 * @param {string} pkgBase - Bare package name (no version/scope path).
 * @returns {boolean}
 */
export function isBrowserOnly(pkgBase) {
  return BROWSER_ONLY_PACKAGES.has(pkgBase);
}

/**
 * Stand up a jsdom DOM and install window/document/navigator as globals.
 * Idempotent-ish: safe to call once at the top of a worker before loading a
 * browser-only target. Returns the JSDOM instance (its `.window` is the factory
 * argument for jQuery-style modules).
 *
 * @returns {Promise<object>} the JSDOM instance
 */
export async function setupJsdomGlobals() {
  const { JSDOM, VirtualConsole } = await import('jsdom');
  // Swallow jsdom's internal resource errors (ECONNREFUSED, blocked sockets in
  // the sandbox, invalid protocols) — they are noise, not target behavior.
  const virtualConsole = new VirtualConsole();
  virtualConsole.on('error', () => {});
  const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
    url: 'http://localhost',
    virtualConsole,
  });
  global.window = dom.window;
  global.document = dom.window.document;
  try {
    Object.defineProperty(global, 'navigator', {
      value: dom.window.navigator,
      writable: true,
      configurable: true,
    });
  } catch { /* navigator may be a non-configurable getter on newer Node */ }
  return dom;
}

/**
 * Install DOM-XSS / script-injection sink hooks on a jsdom window, invoking
 * `record(sinkName, value)` for every string value that reaches a sink. Shared
 * by the discovery worker (sandbox-worker.js) and the reproduction worker
 * (repro-worker.js) so their DOM sink coverage cannot drift. Record-then-
 * delegate: the real DOM operation still runs.
 *
 * Covers the sink classes client-side prototype-pollution gadgets funnel into —
 * cf. the BlackFan/client-side-prototype-pollution catalog (jQuery, etc.):
 * innerHTML, outerHTML, insertAdjacentHTML, document.write(ln), dangerous
 * setAttribute targets (src/href/srcdoc/on*), and the `src` property of
 * script/iframe/img elements. jsdom does not execute scripts here, so this
 * proves REACHABILITY of a polluted value to a DOM-XSS sink, not execution.
 */
export function installDomSinkHooks(dom, record) {
  const win = dom?.window;
  if (!win) return;
  const rec = (sink, v) => { if (typeof v === 'string') { try { record(sink, v); } catch { /* ignore */ } } };

  const hookSetter = (proto, name, label) => {
    if (!proto) return;
    const desc = Object.getOwnPropertyDescriptor(proto, name);
    if (desc?.set && desc.configurable !== false) {
      const origSet = desc.set;
      Object.defineProperty(proto, name, { ...desc, set(v) { rec(label || name, v); return origSet.call(this, v); } });
    }
  };
  const hookMethod = (obj, name, pick) => {
    if (!obj || typeof obj[name] !== 'function') return;
    const orig = obj[name];
    obj[name] = function (...args) { rec(name, pick(args)); return orig.apply(this, args); };
  };

  const el = win.Element?.prototype;
  hookSetter(el, 'innerHTML');
  hookSetter(el, 'outerHTML');
  hookMethod(el, 'insertAdjacentHTML', a => a[1]);

  if (el && typeof el.setAttribute === 'function') {
    const orig = el.setAttribute;
    const DANGER = new Set(['src', 'href', 'xlink:href', 'srcdoc', 'formaction', 'action', 'data', 'onerror', 'onload', 'onclick']);
    el.setAttribute = function (name, value) {
      if (typeof name === 'string' && DANGER.has(name.toLowerCase())) rec('setAttribute:' + name.toLowerCase(), value);
      return orig.call(this, name, value);
    };
  }

  const docProto = win.Document?.prototype;
  hookMethod(docProto, 'write', a => a[0]);
  hookMethod(docProto, 'writeln', a => a[0]);

  for (const [tag, label] of [['HTMLScriptElement', 'script.src'], ['HTMLIFrameElement', 'iframe.src'], ['HTMLImageElement', 'img.src']]) {
    hookSetter(win[tag]?.prototype, 'src', label);
  }
}

/**
 * Load a browser-only CommonJS module against a prepared DOM. Prefers a
 * `<name>/factory` entry point invoked with `window` (jQuery's documented way to
 * get a DOM-bound instance); falls back to a plain require, which works once
 * `global.window` is set because these libraries detect it.
 *
 * @param {NodeRequire} requireFn - the caller's createRequire(import.meta.url)
 * @param {string} name - package name
 * @param {object} dom - JSDOM instance from setupJsdomGlobals()
 * @returns {*} the loaded module (a ready, DOM-bound object)
 */
export function loadBrowserModule(requireFn, name, dom) {
  try {
    const factory = requireFn(`${name}/factory`);
    if (typeof factory === 'function') return factory(dom.window);
  } catch { /* no factory subpath — fall through */ }
  return requireFn(name);
}
