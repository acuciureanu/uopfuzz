/**
 * Shared differential-tier classifier — the single source of truth for turning
 * a set of observed differential FACTS into a reproduction-candidate verdict.
 *
 * WHY THIS MODULE EXISTS (invariant #4: "two oracles must not drift"):
 * The tier ladder was previously implemented twice — once in
 * `differential.js#diffResults` (the in-process oracle) and once, by hand, in
 * `instrumentation/index.js#_sandboxedDifferential` (the sandboxed child-process
 * oracle). The two had already drifted: the sandbox reconstruction hardcoded
 * `pollutionWasRead: true`, discarded the sink-access facts the sandbox worker
 * actually computed (so Tier 1 was unreachable there), and used a different PP
 * confidence. Both oracles now feed their real facts into this one function so a
 * divergence is impossible by construction.
 *
 * ZERO-FP CONTRACT: this function only PROPOSES reproduction candidates. It never
 * asserts a vulnerability. Only Tier 0 (a real prototype mutation observed
 * in-run) is a pre-confirmed *pollution* candidate; every other tier is a
 * code-execution candidate that MUST survive independent reproduction
 * (src/verification/reproduce.js) before it is ever reported. `confidence` is
 * retained for ranking / effort ordering only — it does not gate reporting.
 */

/**
 * Classify a differential observation into a reproduction-candidate verdict.
 *
 * @param {object} facts
 * @param {string}  facts.property           - The polluted property name.
 * @param {boolean} [facts.prototypePolluted] - The target added a key to a monitored prototype.
 * @param {boolean} [facts.pollutionWasRead]  - The polluted property was read during execution.
 * @param {Array}   [facts.newSinkAccesses]   - Code sinks that fired only in the polluted run.
 * @param {boolean} [facts.payloadInOutput]   - The payload value reached output (and not in the clean run).
 * @param {boolean} [facts.outputChanged]     - Output differed between clean and polluted runs.
 * @param {boolean} [facts.errorChanged]      - Error differed between clean and polluted runs.
 * @returns {{isConfirmedGadget: boolean, isCandidate: boolean, proofType: (string|null), reproducible: boolean, confidence: number}}
 */
export function classifyDiff(facts) {
  const {
    property,
    prototypePolluted = false,
    pollutionWasRead = false,
    newSinkAccesses = [],
    payloadInOutput = false,
    outputChanged = false,
    errorChanged = false,
  } = facts;

  const verdict = {
    isConfirmedGadget: false,
    isCandidate: false,
    proofType: null,
    reproducible: false,
    confidence: 0,
  };

  if (prototypePolluted) {
    // Tier 0: the target actually added a property to a monitored prototype.
    // A pollution candidate — still gated on reproduction, but pre-confirmed.
    verdict.isConfirmedGadget = true;
    verdict.proofType = 'pp';
    verdict.reproducible = true;
    verdict.confidence = 0.85;
  } else if (newSinkAccesses.length > 0 && pollutionWasRead) {
    // Tier 1: a code sink fired while the polluted property was read.
    verdict.isCandidate = true;
    verdict.proofType = 'rce';
    verdict.reproducible = true;
    verdict.confidence = 0.95;
  } else if (payloadInOutput && pollutionWasRead) {
    // Tier 2: the payload reached output (injection) — try code execution.
    verdict.isCandidate = true;
    verdict.proofType = 'rce';
    verdict.reproducible = true;
    verdict.confidence = 0.90;
  } else if (outputChanged && pollutionWasRead) {
    // Tier 3: output changed while the polluted property was read.
    verdict.isCandidate = true;
    verdict.proofType = 'rce';
    verdict.reproducible = true;
    verdict.confidence = 0.75;
  } else if (errorChanged && pollutionWasRead) {
    // Tier 4: error changed while the polluted property was read.
    verdict.isCandidate = true;
    verdict.proofType = 'rce';
    verdict.reproducible = true;
    verdict.confidence = 0.60;
  } else if (pollutionWasRead) {
    // Tier 5: the target read the polluted property but nothing else observably
    // changed. This used to gate reproduction on a hardcoded HIGH_RISK_PROPS name
    // list — a genuine read of an unlisted property was dropped to manual review,
    // exactly the vocabulary-dependence the tool is meant to avoid. Now that the
    // read signal is accurate (the harness no longer self-reads a polluted
    // property while serializing/awaiting — see proto-safe.js), every genuine
    // read is worth a reproduction attempt. Reproduction stays the real gate and
    // rejects non-gadgets; the orchestrator dedups failed attempts so an
    // unconfirmable read is tried once, not every iteration.
    verdict.isCandidate = true;
    verdict.proofType = 'rce';
    verdict.reproducible = true;
    verdict.confidence = 0.50;
  }

  return verdict;
}
