// Hermetic fixture modelling the template-compilation injection gadget class
// (EJS CVE-2022-29078 / pug / hogan …): a template engine reads an option off
// the prototype chain and splices it into GENERATED function source at an
// identifier/declaration position, then compiles and runs it.
//
// With Object.prototype.outputFunctionName polluted, `render()` compiles a
// function whose source embeds the attacker value. A bare `globalThis[x]=y`
// payload is a *syntax error* in the `var <value> = …` slot, so this exercises
// the reproduction gate's `template_injection` payload specifically (a valid
// identifier + statement + re-supplied identifier).

function render(template, opts) {
  const options = opts || {};
  // Read from the prototype chain when polluted (an attacker-controllable option).
  const outName = options.outputFunctionName || '__out';
  // Compile step: the option name is spliced verbatim into generated source.
  const src = `var ${outName} = ""; ${outName} += ${JSON.stringify(String(template))}; return ${outName};`;
  // eslint-disable-next-line no-new-func
  const compiled = new Function(src);
  return compiled();
}

module.exports = { render };
