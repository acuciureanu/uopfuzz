// Hermetic fixture: a prototype-pollution -> path traversal / LFI gadget. The
// function reads an option off the prototype chain and feeds it to fs.readFileSync
// as the path. With Object.prototype.path polluted, calling load({}) reads an
// attacker-controlled file. No file actually exists at the token path, so the
// call throws — but the path argument reaches the sink, which is what the
// discovery oracle observes and what reproduction's sink_reach proves.
//
// Mirrors real-world LFI gadgets (ejs renderFile, express layout, dot-template
// path) where a polluted property flows into a filesystem call's path argument.

const fs = require('fs');

function load(opts) {
  const options = opts || {};
  if (options.path) {
    return fs.readFileSync(options.path, 'utf8');
  }
  return '';
}

module.exports = { load };
