# UoPFuzz

A framework for finding prototype-pollution gadgets in JavaScript libraries. It
takes the "undefined-oriented programming" (UOP) view — a library reads an
attacker-controllable property that resolves through a polluted prototype chain
— and searches for those reads reaching dangerous sinks.

## Overview

UoPFuzz combines coverage-guided fuzzing, a differential execution oracle
(clean vs. polluted runs), and Proxy-based taint tracking to detect prototype
pollution and pollution → sink gadgets in Node.js libraries, targeting sinks
like `eval`, `child_process.exec`, `innerHTML`, `http.request`, and
`fs.readFile`. It is a research tool, not a turnkey scanner.

### Reproduction-gated reporting

A finding is only reported as a **vulnerability** when it is *independently
reproduced in fresh, isolated child processes* (twice) by a second oracle that
computes ground-truth facts — either a **real prototype mutation** (an
own-property added to a builtin prototype) or **real code execution** (a canary
token reaching `globalThis` through a code sink). Behavioral heuristics
(output/error changed, a property merely read) never confirm a vulnerability on
their own; they are kept as clearly-labeled **unproven leads** for manual review.
On the project's [ground-truth benchmark](benchmark/RESULTS.md) this yields a
**0% false-positive rate** against patched versions — see the benchmark for the
full picture, including a known miss. This is a strong empirical result, not an
absolute guarantee. Every proven finding is cross-referenced against a built-in
CVE database, live OSV.dev advisories, and this tool's own discovery store, and
labeled **KNOWN CVE**, **PREVIOUSLY DISCOVERED**, or **UNDOCUMENTED
VULNERABILITY** — and ships with a standalone, runnable PoC. See
`src/verification/reproduce.js` and `tests/integration/zero-fp-validation.test.js`.

> "Undocumented vulnerability" means *not present in the built-in advisory database or OSV.dev* — a candidate that still requires human verification against public advisories before disclosure. "Previously discovered" means this tool found the same bug on an earlier run, before any public advisory existed for it. The tool files nothing externally on its own.

## Features

- **Configuration-driven**: YAML target definitions, or point `--target` at an npm `package@version` for auto-discovery
- **Differential oracle**: confirms causation (this pollution caused this behaviour), not just correlation
- **Coverage-guided fuzzing**: AFL-style edge bitmap plus V8 precise coverage steer input generation
- **Parallel discovery**: `--parallel N` runs Phase-B probes across a pool of sandbox workers
- **Isolation-aware**: target code IS executed — in a forked child for discovery,
  and in fresh child processes for reproduction. It is not merely simulated; see
  the **Safety model** below for what that means and how to run it responsibly.
- **Real-world focus**: known-vulnerable libraries (e.g. pug 3.0.2, Squirrelly, hogan.js) and a ground-truth benchmark

## Quick Start

```bash
npm install
# Auto-discovery: point it at a package@version — installs it, finds and verifies gadgets
node src/cli.js --target lodash@4.17.4
# Config-driven: use a YAML target spec
node src/cli.js --config config/targets/pug.yaml --output results/
# Multi-threaded execution for better performance
node src/cli.js --config config/targets/pug.yaml --parallel 4 --output results/
```

`--target` installs the package from npm and executes its code — run untrusted
targets inside the dev container (see the **Safety model** below). Full flag
reference and the container invocation are in [`docs/usage.md`](docs/usage.md).

## Architecture

- **Target Integration**: Dynamic library loading and configuration management
- **Input Generation**: Coverage-guided fuzzing with UOP-specific mutations
- **Instrumentation**: Dynamic tracing — coverage bitmap + Proxy taint tracking
- **Gadget Analysis**: Taint tracking and exploit chain identification
- **Orchestrator**: Main workflow coordination and result aggregation

## Safety model

Read this before pointing UoPFuzz at a package you do not control.

**Target code is executed, not simulated.** To find gadgets the fuzzer must run
the library — repeatedly, with attacker-shaped inputs — and reproduction
deliberately lets a canary payload actually execute to prove code execution. This
is inherent to dynamic gadget hunting; treat every target as untrusted code that
will run on your machine.

**What isolates it — and what does not:**

- The **real isolation boundary is the container** (`run-sandboxed.sh`, backed by
  `.devcontainer/`): it drops all Linux capabilities (`--cap-drop=ALL`), applies a
  seccomp profile and `no-new-privileges`, runs as a non-root user, caps memory
  and PIDs, and carries no host secrets in its environment. **Run untrusted
  targets inside it.** Two honest caveats about what it does *not* do: network
  egress is **open** — the container must reach npm to install targets and, unless
  `--no-osv`, OSV.dev — so add an external egress policy if you need network
  containment; and the filesystem is not fully ephemeral — the workspace is
  mounted read-only, but `node_modules` is a **persistent named volume shared
  across runs** and `results/` is written to a host bind mount. Rely on this layer
  for capability/privilege containment, not for network or filesystem confinement.
- Inside that boundary, every discovery mode that *calls* target code — the
  single-property, forced-branch, and multi-property differentials, the merge-PP
  and URL-gadget probes, and UOP-property discovery — plus reproduction, run in
  **forked child processes** with best-effort in-process hardening
  (`src/utils/worker-hardening.js`): outbound network (opt-in via
  `--allow-network`), `child_process`, and `worker_threads` are monkey-patched
  off, and known secret-bearing environment variables are stripped from the
  child. These are speed bumps against low-effort/accidental bad behavior — **not
  a sandbox** against a targeted exploit, which shares the process uid,
  filesystem, and network namespace. Browser-only libraries (jQuery, Backbone, …)
  load under a jsdom DOM *inside* that child too, so their fuzzed pollution — and
  any network their DOM attempts (blocked here) — stays contained rather than
  corrupting the fuzzer's own Node internals.
- Two caveats keep this honest. First, the fuzzer's own process still runs some
  target code unsandboxed: the target module is **`import()`ed there** to
  auto-generate its config and entry points (so *module-load-time* code runs),
  and auto-discovery then **invokes** the target's exported functions and
  constructors, while the Phase-A coverage pass calls the entry point in-process
  too — another reason the container is the boundary that matters. Second,
  `--no-sandbox` runs *everything* (module load and every call) in-process. Only
  fuzz code you trust outside the container.

**Flags that lower the guardrails** (`--no-sandbox`, `--allow-scripts`,
`--allow-suspicious`, `--allow-network`) are opt-in and print a warning. The
supply-chain check (`src/utils/package-safety.js`) is a tripwire on lifecycle
scripts and obvious obfuscation, not a malware scanner.

**Use it ethically.** Only analyze packages you are authorized to test. Live
network lookups (OSV.dev) telegraph the analyzed `package@version` to a third
party — `--no-osv` opts out when hunting an unpublished bug. Generated PoCs under
`results/` are **real, working exploits**: handle them as sensitive, and the tool
files nothing externally on your behalf — disclosure is a human decision.

## Documentation

See the `docs/` directory for detailed documentation on:
- Architecture overview
- Configuration format
- Adding new target libraries
- Interpreting results