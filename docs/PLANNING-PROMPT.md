# UoPFuzz — Planning Seed Prompt

> Paste this as the opening brief for a future planning session on UoPFuzz.
> It captures the current state, the invariants that must not be broken, the
> honest measurement baseline, and a prioritized backlog. Update the
> "Current state" and "Baseline" sections as work lands so it stays true.

---

## Your task

You are picking up work on **UoPFuzz**, a prototype-pollution gadget fuzzer for
npm libraries. Produce an implementation plan for the next slice of work. Before
planning: read the invariants below and do not propose anything that violates
them; read "Current state" so you don't redo finished work; pick from (or
re-prioritize, with reasons) the backlog. Prefer one well-scoped, verifiable
change over a broad rewrite. Every plan must say how it will be **measured**, not
just implemented — this project has been burned by claims that outran evidence.

## What the tool is (one paragraph)

UoPFuzz hunts prototype-pollution **sources** (merge/clone/set functions that
write attacker keys onto a prototype) and **gadgets** (a polluted property read
into a dangerous sink → RCE) in real npm packages. It is coverage-guided, runs
target code to observe behavior, and reports a finding as a *vulnerability* only
after an independent second oracle reproduces it in fresh processes. It classifies
each finding as known-CVE / previously-discovered / undocumented and emits a
standalone runnable PoC. It files nothing externally — disclosure is a human call.

## Invariants — do NOT break these

1. **Zero-false-positive gate is sacred.** A finding becomes a reported
   vulnerability ONLY when `src/verification/reproduce.js` reproduces its
   ground-truth condition in **two independent fresh child processes** (2/2
   agreement) via `src/utils/repro-worker.js`, which shares no verdict logic with
   the discovery oracle and computes only booleans from facts (own-property added,
   or canary token on `globalThis`). Discovery may propose; only reproduction
   confirms. Never let a discovery-side signal self-confirm.
2. **The dev container is the real isolation boundary.** In-process/in-child
   monkey-patches (`src/utils/worker-hardening.js`) are best-effort speed bumps,
   not a sandbox. Never document them as more than that. `child_process` and
   `worker_threads` are always blocked in workers; network is `--allow-network`-gated.
3. **Honest claims only.** Target code IS executed (not simulated). Recall is
   partial (see baseline). "Undocumented" means "not in the sources checked," not
   "provably novel." Any user-facing or README claim must stay literally true.
4. **Two oracles must not drift.** `src/utils/prototype-monitor.js` (pollution
   detection) and `src/utils/worker-hardening.js` (capability blocks) are shared
   single-sources-of-truth for exactly this reason. Discovery tiers, however, are
   still duplicated (see backlog item O1).
5. **The tool files nothing externally on its own.** No auto-disclosure, no
   issue-filing. OSV lookups are the only outbound metadata call and are
   `--no-osv`-gated with an opsec note.

## Current state (as of commit 47a3dd0)

Recently landed (do not redo):
- `47a3dd0` — unified worker hardening; blocked the `worker_threads` escape;
  added HTTP/2 block; corrected false isolation claims in README/sandbox.js; test
  in `tests/unit/worker-hardening.test.js`.
- `3e5a929` — renamed the CVE-classification vocabulary `novelty` → `disclosure`
  (`chain.disclosure`, `src/gadget-analysis/disclosure.js`). The unrelated
  coverage-guided `mergeAndCheckNovelty` was intentionally left alone.
- `6f824df` — fixed an `ERR_INTERNAL_ASSERTION` crash: `Object.prototype`
  accumulated residual keys across in-process differential runs (ejs/handlebars/
  pug) and corrupted `fs.writeFile`. Orchestrator now restores the run-start
  prototype baseline before `saveResults()`. This is a *safety net*, not a root
  cause (see backlog item O2).
- `d62017a` — fixed CVE mislabeling: a package with multiple PP-source CVEs at
  overlapping version ranges (lodash) got the first array-order match; now filters
  by the entry point's function name.

Test suite: `node --test tests/**/*.test.js` → all green (179 at last count).

## Measured baseline — the honest numbers

A recall measurement against the 34-entry known-CVE corpus (`known-gadgets.js`),
29 resolvable to an installable version:
- **Detected: 8/29 (27.6% raw); 8/19 (42.1%) excluding 9 timeout-inconclusive.**
- 9 targets never finished in a 90s budget (jquery, hoek, pug×3, got, …).
- 11 clean misses, in two buckets: **calling-convention gaps** (minimist, qs,
  json5 — not `merge(target,payload)`-shaped, so the standard invocation never
  triggers the sink) and **genuine gadget misses** (squirrelly, handlebars,
  hogan.js, nunjucks — pollution happens but the probed property/sink doesn't line
  up with the library's real gadget).
- One undocumented-gadget candidate surfaced: **`flat@5.0.0` `flatten()` via
  `Object.prototype.transformKey`** — verified by hand and by an independent PoC;
  distinct from flat's only CVE (CVE-2020-36632, which is `unflatten()`). Not yet
  responsibly disclosed.

No false positive has been observed slipping through the reproduction gate. But
"no FP" and "works well" are different claims: recall is well under 50%.

## Backlog (prioritized; re-order with justification if you disagree)

**Correctness / architecture**
- **O1 — Unify the two discovery oracles.** `src/instrumentation/differential.js`
  (in-process) and `src/utils/sandbox-worker.js` (sandboxed) implement the same
  tier logic twice, reconciled by hand in `_sandboxedDifferential`. Extract one
  shared `classifyDiff()` so they can't diverge on what they surface. Highest
  correctness stakes of the non-security work. `docs/IDEA-ASSESSMENT-FABLE.md`
  flagged this drift risk.
- **O2 — Root-cause the in-process prototype leak (currently only netted).** Some
  in-process modes (forced-branch, multi-property co-pollution) leave library
  option-object keys on `Object.prototype`. `6f824df` sweeps them before save, but
  the leak still means real prototype-touching behavior in ejs/handlebars/pug goes
  unobserved by the oracle (a recall blind spot), and those modes run with the
  fuzzer's privileges. Options: give the in-process trap modes a live-trap-capable
  worker, or scope the trap install/restore so no key survives the call.
- **O3 — Decompose the orchestrator god object.** `src/orchestrator/index.js`
  owns config, install, the iteration loop, all five differential modes, the proof
  gate, disclosure classification, persistence, and reporting. Split concerns.

**Recall (measure every change against the baseline above)**
- **R1 — Calling-convention coverage.** Add invocation shapes for non-merge APIs
  (minimist/qs/json5 argv/query-string parsers). Should recover several clean
  misses cheaply.
- **R2 — Timeout-bound targets.** Re-run the 9 inconclusive targets (jquery, hoek,
  pug×3, got) with a larger budget to get a defensible recall number; then decide
  whether the timeout is a perf bug or a real cost.
- **R3 — Template-engine gadget misses.** squirrelly/handlebars/hogan.js/nunjucks
  need per-library investigation of the actual property→sink path the fuzzer isn't
  probing.

**Disclosure / ethics**
- **D1 — Decide on the `flat@5.0.0` `transformKey` finding**: confirm novelty
  against upstream, and either responsibly disclose or document why not.

## Definition of done for any item

Tests green (`node --test tests/**/*.test.js`); a live run demonstrates the change
(not just unit tests); recall items report the before/after number against the
corpus; no invariant above weakened; README/claims still literally true.
