# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Runtime gadget miner** (`npm run mine:runtime-gadgets`): harvests candidate
  gadget properties from the Node.js runtime's own source, then verifies them
  differentially (behavior change or crash, never sink-reach alone) with
  two-value severity grading.
- **Runtime gadget corpus** (`npm run benchmark:runtime-gadgets`): a curated,
  machine-checked corpus of published runtime gadgets with verdicts
  (`DETECTED` / `FIXED-UPSTREAM` / `MITIGATED-UPSTREAM` / `NOT-DETECTED`) and a
  behavioral oracle for effects that only materialize in live TLS/HTTP
  handshakes.
- **GHunter comparison harness** (`npm run compare:ghunter`): replays the
  published GHunter4Node gadget table against the current runtime and compares
  recall.
- Options-aware sink recording (`src/utils/sink-record.js`), crypto-downgrade
  sink detection, and sink-impact classification.
- Chain-synthesis verification and a source-call registry for tracing gadget
  sources.
- Community health files: Code of Conduct, issue templates, PR template.

### Changed

- The behavioral TLS probes now generate their throwaway self-signed
  certificate in memory at runtime instead of shipping a committed private key.
- Dependency audit: all `npm audit` findings resolved (0 vulnerabilities).

## [0.1.0]

Initial public release: differential fuzzing for prototype-pollution gadgets in
JavaScript libraries, with reproduction-gated reporting, sandboxed execution
(container/devcontainer isolation), client-side gadget coverage, template
injection detection, and a ground-truth benchmark suite.
