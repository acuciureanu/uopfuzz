// Test double for the orchestrator subprocess. runOrchestratorIsolated() forks
// this and sends { type:'run', options }; we branch on options.__behavior to
// simulate each way a real per-target run can end, so the isolation helper can
// be tested without installing npm packages.
process.on('message', (msg) => {
  if (!msg || msg.type !== 'run') return;
  const behavior = msg.options?.__behavior;
  switch (behavior) {
    case 'ok':
      process.send({ type: 'success', results: { confirmedChains: [], candidateChains: [], marker: msg.options.__marker } });
      setImmediate(() => process.exit(0));
      break;
    case 'reported-error':
      process.send({ type: 'error', error: 'orchestrator reported failure' });
      setImmediate(() => process.exit(0));
      break;
    case 'throw':
      // Uncaught async exception — mimics the undici crash. No reply is sent;
      // the parent must detect the non-zero exit as a contained crash.
      setImmediate(() => { throw new Error('boom — uncaught in a callback'); });
      break;
    case 'exit':
      process.exit(3);
      break;
    case 'hang':
      // Never reply and keep the event loop alive → parent's wall-clock timeout fires.
      setInterval(() => {}, 1000);
      break;
    default:
      process.send({ type: 'error', error: `unknown behavior: ${behavior}` });
      setImmediate(() => process.exit(0));
  }
});
