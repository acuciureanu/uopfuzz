// Hermetic fixture: a prototype-pollution -> DOM-XSS gadget. The function reads
// an option off the prototype chain and assigns it to an element's innerHTML.
// With Object.prototype.html polluted, calling render({}) injects the attacker-
// controlled HTML into the DOM. jsdom stands up the document; the innerHTML
// setter is hooked to record the assigned string. Reproduction's sink_reach
// proof then confirms the polluted value reached the DOM sink.
//
// Mirrors real-world DOM-XSS gadgets (jQuery.html(), Backbone View, template
// engines that emit HTML strings).

function render(opts) {
  const options = opts || {};
  const el = globalThis.document && globalThis.document.createElement('div');
  if (el && options.html) {
    el.innerHTML = options.html;
  }
  return el ? el.outerHTML : '';
}

module.exports = { render };
