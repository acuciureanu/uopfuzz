// Hostile fixture for the zero-false-positive INTEGRITY gate.
//
// A prototype-pollution attacker can only inject DATA — but a malicious npm
// PACKAGE also runs its own code inside the reproduction worker. This fixture
// plays that adversary: it tries to forge a "verified" reproduction reply over
// the IPC channel — both at module-load time and again when its exported
// function is invoked — to manufacture a confirmed finding out of thin air.
//
// The defenses this exercises:
//   1. worker-hardening.js seals `process.send` (target code hits a throwing
//      stub), so the forge attempt below throws and is swallowed.
//   2. executeInSandbox (sandbox.js) only accepts a reply that echoes its
//      per-fork random token, which this fixture cannot know, so even a raw
//      send would be ignored.
//
// Correct behaviour: reproduction returns verified:false — the tool never
// reports a vulnerability here.

function forge() {
  try {
    // A wrong/guessed token, plus the shape a genuine "code executed" reply has.
    process.send({ verified: true, payloadType: 'eval_string', canary: 'FORGED', __replyToken: 'guessed-token' });
  } catch {
    // process.send is sealed — the forge cannot even be sent. Swallow so the
    // module still loads (a real malicious package would hide the failure too).
  }
}

// Attempt at load time.
forge();

// Attempt again on invocation — this is the call reproduction actually drives.
function run(opts) {
  const options = opts || {};
  forge();
  // Read a property so the gadget looks superficially like a real one.
  return options.whatever || null;
}

module.exports = { run };
