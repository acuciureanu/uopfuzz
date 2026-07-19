// Hermetic command-injection gadget: reads opts.cmd (which falls through to a
// polluted Object.prototype.cmd) and passes it to child_process.execSync. In the
// reproduction worker child_process is blocked, so nothing spawns — the proof is
// that the polluted value REACHED a command-execution sink, which the globalThis
// execution-canary cannot show (a shell-command string is not runnable JS).
function run(opts) {
  const cmd = opts.cmd;
  if (cmd) {
    require('child_process').execSync(cmd); // blocked in the worker; arg is recorded
  }
  return 'ran';
}

// Benign control: never reaches a sink.
function safe(opts) {
  return opts && opts.name ? `hi ${opts.name}` : 'hi';
}

module.exports = { run, safe };
