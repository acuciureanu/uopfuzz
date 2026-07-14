# UoPFuzz

A plug-and-play framework for Undefined-Oriented Programming (UOP) in prototype pollution gadget hunting.

## Overview

UoPFuzz is a hybrid security research framework that combines fuzzing with concolic execution to detect and chain prototype pollution gadgets in JavaScript libraries. It focuses on Node.js environments to identify vulnerabilities leading to dangerous sinks like `eval` or `exec`.

### Zero-false-positive reporting

A finding is only reported as a **vulnerability** when it is *independently reproduced in fresh, isolated child processes* (twice) by a second oracle that computes ground-truth facts — either a **real prototype mutation** (an own-property added to a builtin prototype) or **real code execution** (a canary token reaching `globalThis` through a code sink). Behavioral heuristics (output/error changed, a property merely read) never confirm a vulnerability on their own; they are kept as clearly-labeled **unproven leads** for manual review. Every proven finding is cross-referenced against a built-in CVE database, live OSV.dev advisories, and this tool's own durable discovery store, and labeled **KNOWN CVE**, **PREVIOUSLY DISCOVERED**, or **UNDOCUMENTED VULNERABILITY** — and ships with a standalone, runnable PoC. See `src/verification/reproduce.js` and `tests/integration/zero-fp-validation.test.js`.

> "Undocumented vulnerability" means *not present in the built-in advisory database or OSV.dev* — a candidate that still requires human verification against public advisories before disclosure. "Previously discovered" means this tool found the same bug on an earlier run, before any public advisory existed for it. The tool files nothing externally on its own.

## Features

- **Configuration-driven**: YAML-based target library definitions for plug-and-play usage
- **Hybrid approach**: Combines coverage-guided fuzzing with concolic execution
- **Parallel processing**: Utilize multiple CPU cores with configurable worker threads
- **Modular architecture**: Easy to extend and customize for specific research needs
- **Isolation-aware**: target code IS executed — in a forked child for discovery,
  and in fresh child processes for reproduction. It is not merely simulated; see
  the **Safety model** below for what that means and how to run it responsibly.
- **Real-world focus**: Targets known vulnerable libraries like pug v3.0.2, SquirrellyJS, hogan.js

## Quick Start

```bash
npm install
# Single-threaded execution
node src/cli.js --config config/targets/pug.yaml --output results/
# Multi-threaded execution for better performance
node src/cli.js --config config/targets/pug.yaml --parallel 4 --output results/
```

## Architecture

- **Target Integration**: Dynamic library loading and configuration management
- **Input Generation**: Coverage-guided fuzzing with UOP-specific mutations
- **Instrumentation**: Dynamic tracing and symbolic path exploration  
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

- The **real isolation boundary is the dev container** (`.devcontainer/`): no
  secrets in its environment, egress governed by the network policy, ephemeral
  filesystem. **Run untrusted targets inside it.** This is the layer you should
  rely on.
- Inside that boundary, every discovery mode that *calls* target code — the
  single-property, forced-branch, and multi-property differentials, the merge-PP
  and URL-gadget probes, and UOP-property discovery — plus reproduction, run in
  **forked child processes** with best-effort in-process hardening
  (`src/utils/worker-hardening.js`): outbound network (opt-in via
  `--allow-network`), `child_process`, and `worker_threads` are monkey-patched
  off, and known secret-bearing environment variables are stripped from the
  child. These are speed bumps against low-effort/accidental bad behavior — **not
  a sandbox** against a targeted exploit, which shares the process uid,
  filesystem, and network namespace.
- Two caveats keep this honest. First, the target module is still
  **`import()`ed in the fuzzer's own process** to auto-generate its config and
  entry points, so a package's *module-load-time* code runs unsandboxed — another
  reason the container is the boundary that matters. Second, `--no-sandbox` runs
  *everything* (module load and every call) in-process. Only fuzz code you trust
  outside the container.

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