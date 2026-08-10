/**
 * Sink → impact classification, derived from the sink a finding was PROVEN to
 * reach (repro-worker.js returns the sink name). This is the single place that
 * decides what a gadget's impact actually is, so "RCE" is never an umbrella:
 *
 *   - code execution (eval / Function / vm / template compilation) → RCE, and the
 *     canary genuinely executed, so it is *proven* code execution.
 *   - command injection (child_process.*) → RCE-class, but the polluted value
 *     only *reached* the exec argument (spawning is unsafe to actually run), so it
 *     is reachability, not proven execution.
 *   - SSRF (http/https), LFI (fs.read*), XSS (DOM sinks) are their own impacts —
 *     never labelled RCE.
 *
 * `isRce` is reserved for genuine code/command execution. Everything else carries
 * its own honest category.
 */

const DOM_SINKS = new Set([
  'innerHTML', 'outerHTML', 'insertAdjacentHTML', 'document.write', 'srcdoc',
  'script.src', 'iframe.src', 'img.src',
  'setAttribute:src', 'setAttribute:href', 'setAttribute:action', 'setAttribute:formaction',
]);

/**
 * @param {string|null} sink - the proven sink name (from repro-worker), e.g.
 *   'code-execution', 'child_process.execSync', 'http.request', 'fs.readFile',
 *   'innerHTML'. `null`/unknown yields a conservative 'sink' category.
 * @returns {{ category: string, label: string, isRce: boolean }}
 */
export function sinkImpact(sink) {
  if (!sink) return { category: 'sink', label: 'Sink reachability', isRce: false };

  if (sink === 'code-execution' || sink === 'eval' || sink === 'Function' || sink.startsWith('vm.')) {
    return { category: 'code-execution', label: 'Remote code execution', isRce: true };
  }
  if (sink.startsWith('child_process.')) {
    return { category: 'command-injection', label: 'Command injection', isRce: true };
  }
  if (sink.startsWith('http.') || sink.startsWith('https.')) {
    return { category: 'ssrf', label: 'Server-side request forgery', isRce: false };
  }
  if (sink.startsWith('tls.') || sink.startsWith('crypto.')) {
    return { category: 'crypto-downgrade', label: 'Cryptographic downgrade', isRce: false };
  }
  if (sink.startsWith('fs.')) {
    return { category: 'lfi', label: 'Local file read', isRce: false };
  }
  if (sink.startsWith('worker_threads.')) {
    return { category: 'privilege-escalation', label: 'Privilege escalation (worker options)', isRce: false };
  }
  if (DOM_SINKS.has(sink) || sink.startsWith('setAttribute')) {
    return { category: 'xss', label: 'DOM XSS / script injection', isRce: false };
  }
  return { category: 'sink', label: `Sink reachability (${sink})`, isRce: false };
}

/**
 * The impact of a confirmed finding, from its reproduction proof. A PP *source*
 * (proofType 'pp') has no sink — its impact is that it is a pollution primitive.
 * A gadget's impact is its proven sink; whether it is *proven* (canary fired) or
 * *reachability* (the value reached the sink as a string) is carried separately.
 *
 * @param {{ type?: string, payloadType?: string, sink?: string }} proof - chain.proof
 * @returns {{ category: string, label: string, isRce: boolean, proven: boolean }}
 */
export function impactFromProof(proof) {
  if (!proof) return { category: 'unknown', label: 'Unknown', isRce: false, proven: false };
  if (proof.type === 'prototype-pollution') {
    return { category: 'prototype-pollution', label: 'Prototype pollution (source)', isRce: false, proven: true };
  }
  const base = sinkImpact(proof.sink);
  // A fired canary (type 'code-execution') is proven execution; 'sink-reachability'
  // proves the value reached the sink as a string, not that it executed.
  const proven = proof.type === 'code-execution';
  return { ...base, proven };
}
