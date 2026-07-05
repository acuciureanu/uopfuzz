# UoPFuzz — Idea Assessment & Security Research Plan

**Question asked:** *Is this a serious idea? Score it, and make a plan if it's relevant for security research.*

**Verdict:** Yes — this is a serious, technically grounded security-research idea, not a toy.
It is directly relevant to an active area of Node.js supply-chain security. A research
plan follows.

---

## 1. What the idea actually is

UoPFuzz is a **hybrid dynamic-analysis framework for discovering prototype-pollution (PP)
gadget chains in JavaScript libraries**. "Undefined-Oriented Programming (UOP)" is the
framing: an attacker who can pollute `Object.prototype.x` controls the value that a library
reads when it accesses a property `x` that would otherwise be `undefined`. The tool hunts for
those reads and proves they change behavior.

The core is a **differential execution oracle** (`src/instrumentation/differential.js`):

1. Run the target function clean.
2. Run it again with `Object.prototype[prop]` trapped via a `get`/`set` accessor.
3. Compare outputs, errors, new sink accesses, and payload-in-output.
4. Snapshot **four** prototypes (`Object`, `Function`, `Array`, `String`), detect any new
   own-properties the target itself introduces, and restore them.

This is the key design decision that separates it from naive tools: it distinguishes
**causation** ("this pollution *caused* this sink to fire") from **correlation** ("a sink
fired after a prototype change"), which kills the dominant false-positive class.

## 2. Grounding in the literature (verified in-code)

The implementation is explicitly built on the current PP research frontier, and the
techniques map to real papers:

| Technique in code | Source it maps to |
|---|---|
| PP gadget taxonomy, source→sink chains | Shcherbakov et al., *Silent Spring*, USENIX Security 2023 |
| Monitoring `Function`/`Array`/`String.prototype`, not just `Object` | *GHunter*, USENIX Security 2024 |
| Forced-branch execution (co-pollute gate props like `debug`/`cache` → `true`) | *Dasty*, WWW 2024 |
| Coverage-guided power schedules, seed energy | Böhme et al., *Greybox Fuzzing as Markov Chain*, CCS 2016 |
| Rareness-based seed scheduling | *Entropic*, Böhme et al. 2019 |
| Differential testing | McKeeman, 1998 |

Whether every citation is load-bearing is secondary; the point is the design reflects how
this problem is *actually* attacked in 2023–2025 research, not a naive `for-in` grep.

## 3. Engineering maturity (verified)

- **~9,750 LOC**, modular pipeline: target-integration → input-generation → instrumentation
  → gadget-analysis → orchestrator → reporting.
- **116/116 tests pass** after `npm install` (a `proof-of-capability` suite runs real
  instrumentation against miniature vulnerable libraries and asserts on detections).
- **Auto-discovery**: given just `--target pkg@version`, it deep-walks exports, probes
  signatures, and synthesizes a target config — no hand-written YAML required.
- **Scale path**: `mass` and `versions` subcommands fuzz the top cdnjs libraries and sweep a
  library across versions — the shape of a real 0-day hunting campaign.
- **Exploit verification**: `verifyExploit()` uses canary tokens to turn "behavior changed"
  into "attacker-controlled code executed."
- **Safety-conscious**: child-process sandbox (default on), install hardening
  (`--no allow-scripts`, integrity checks), dangerous sinks stubbed, timeouts.

## 4. Honest weaknesses

- **"UOP" is a framing, not a new primitive.** The underlying technique is dynamic PP
  gadget discovery. That's fine — but the novelty is in *engineering and integration*
  (differential oracle + forced branches + multi-prototype + auto-discovery + mass scale),
  not a fundamentally new attack class. Position it accordingly.
- **Getter-trap oracle ≠ real pollution semantics.** Trapping `Object.prototype[prop]` with
  an accessor is not identical to a real polluted data property (enumerability, `in`
  checks, `hasOwnProperty` guards, own-vs-inherited). This can both over- and under-report
  vs. a genuine attack. Needs a validation pass against ground-truth CVEs.
- **Confidence math is heuristic dressed as rigor.** The Bayesian/CVSS scoring uses invented
  priors and likelihood ratios. Useful for *ranking*, but the numbers should not be reported
  as calibrated probabilities without empirical fitting.
- **Sink coverage is shallow.** Real RCE usually needs a *second* gadget (a sink-reaching
  library like `pug`/`ejs`) after the PP source. End-to-end source→gadget→sink chaining
  across two libraries isn't the primary mode yet.
- **No published benchmark result.** The known-gadget DB exists for regression, but there's
  no reported detection-rate/false-positive-rate against a labelled corpus.

## 5. Score

Scored as a security-research tool (rubric 1–10, weighted):

| Dimension | Weight | Score | Notes |
|---|---:|---:|---|
| Problem relevance | 20% | 9 | Server-side PP → RCE is a live, high-impact npm threat. |
| Technical soundness | 20% | 8 | Differential causation oracle is the right core idea. |
| Novelty | 15% | 6 | Strong *integration* novelty; primitive is known. |
| Implementation maturity | 20% | 8 | 9.7k LOC, all tests green, runs, auto-discovers, scales. |
| Rigor / evaluation | 15% | 5 | No benchmark FP/FN numbers; scoring un-calibrated. |
| Impact potential | 10% | 8 | Plausible path to real disclosable 0-days at scale. |

**Weighted total ≈ 7.4 / 10 — "serious, promising, needs an empirical evaluation to prove it."**

One-line: *A credible, well-built PP gadget hunter whose engineering is ahead of its
evidence — the missing piece is a measured benchmark, not more features.*

---

## 6. Security research plan

Goal: turn a promising tool into **evidence + real disclosures**. Four phases.

### Phase 0 — Reproducibility & guardrails (days)
- Pin deps, add CI running the full suite; publish the `proof-of-capability` results.
- Document the threat model precisely: *attacker controls JSON/query merged by target*.
- Confirm sandbox isolation holds when scanning untrusted npm packages (network off,
  scripts off, resource caps).

### Phase 1 — Ground-truth validation (the critical phase)
- Build a **labelled benchmark**: 30–50 known PP CVEs (lodash, jquery, minimist, set-value,
  merge-deep, pug CVE-2021-21353, etc.) with known-vulnerable and patched versions.
- Run UoPFuzz across both; compute **true-positive rate** (detects known vuln in vulnerable
  version) and **false-positive rate** (stays silent on the patched version).
- **Validate the getter-trap oracle** against a handful of real polluted-data-property PoCs
  to quantify where the accessor model diverges from real pollution.
- Deliverable: a table of detection/FP rates. This is what makes the tool *citable*.

### Phase 2 — Calibrate the scoring
- Refit the Bayesian priors/likelihoods from Phase-1 outcomes (or replace with a simple
  logistic model over observed features). Report confidence as calibrated, or relabel it
  "heuristic rank score" and stop implying probability.

### Phase 3 — Source→gadget→sink chaining
- Add explicit two-library chaining: PP *source* (merge/set/extend) + PP *gadget* library
  that reaches `eval`/`Function`/`child_process`/`vm`. Reproduce at least one full
  documented RCE chain end-to-end as a capstone regression test.

### Phase 4 — Mass hunt & responsible disclosure
- Run `mass` over the top-N cdnjs/npm libraries and `versions` sweeps on high-value targets.
- Triage candidates: auto-verified (canary) → manual PoC → severity.
- For anything novel: **coordinated disclosure** (maintainer first, CVE via GHSA, 90-day
  window). No public payloads before a fix. Keep an audit log of what was tested and why.
- Deliverable: disclosure reports + a short paper/blog with the Phase-1 benchmark.

### Success criteria
- ≥90% TP and ≤10% FP on the labelled benchmark.
- At least one end-to-end RCE chain reproduced as a test.
- At least one responsibly disclosed, maintainer-confirmed finding from the mass hunt.

### Risks & ethics
- Only scan libraries you're authorized to test; treat every candidate as sensitive until
  disclosed. Keep the sandbox mandatory for untrusted packages. Never publish working RCE
  payloads against unpatched, in-the-wild libraries.
</content>
</invoke>
