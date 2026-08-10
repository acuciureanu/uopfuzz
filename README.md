# UoPFuzz

A CLI that finds prototype-pollution gadgets in JavaScript libraries — and only reports the ones it can reproduce. It fuzzes a target library, pollutes `Object.prototype`, and checks whether an attacker-controlled property reaches a dangerous sink. A candidate becomes a reported finding only after an independent oracle reproduces it in fresh child processes; everything else is labelled a lead, not a vulnerability.

The name comes from the mechanic it hunts: a library reads a property that is *undefined* on the object, so the read resolves up the prototype chain to whatever an attacker planted there. (The literature also uses "UOPF" for a template-engine gadget-chaining framework; that is separate, prior work.)

<img src="assets/demo.gif" alt="UoPFuzz detecting and reproducing a prototype-pollution gadget" width="820">

### Key features

- **Reproduction-gated reporting.** Every finding is re-proven in two fresh Node processes by a second oracle that shares no verdict logic with discovery. On the project's [ground-truth benchmark](benchmark/RESULTS.md) this produced no false positives against patched versions — a measured result on that benchmark, not a guarantee.
- **Behavioural auto-discovery.** `--target pkg@version` needs no config. Entry points are found by probing the library, which can cover code paths a package's own test suite never exercises.
- **Runnable PoCs.** Confirmed findings ship a standalone script. Impact (RCE / SSRF / LFI / XSS) comes from the sink actually reached, not from a heuristic. When one library is both the pollution source and the gadget, the result is a self-contained exploit and is flagged as such.
- **Server-side and client-side.** Code execution, template-compilation injection (e.g. EJS `outputFunctionName`), SSRF and LFI on the server; browser libraries load under jsdom with DOM-XSS sinks hooked (`innerHTML`, `document.write`, script `src`, …). jsdom does not execute scripts, so client-side findings prove sink reachability.
- **Runtime gadget mining.** Mines the Node.js runtime itself for gadget properties (`NODE_OPTIONS`, `shell`, TLS verification, …), with a replay of GHunter's published gadget table for comparison — see [Runtime gadgets](#runtime-gadgets).
- **Novelty triage.** Findings are cross-referenced against a built-in advisory DB, OSV.dev, and the GitHub Advisory DB.

### Requirements

- Node.js 20 or newer
- Docker (or a devcontainer-capable editor) to run untrusted targets safely — see [Security](#security)

### Getting started

```bash
git clone https://github.com/acuciureanu/uopfuzz.git
cd uopfuzz
npm install

# Audit an npm package@version — installs it, finds and verifies gadgets
node src/cli.js --target lodash@4.17.4

# Or use a curated YAML target spec
node src/cli.js --config config/targets/ejs.yaml --output results/
```

Confirmed findings and their PoCs are written under `results/`. The full flag reference is in [docs/usage.md](docs/usage.md).

The demo target `lodash@4.17.4` is deliberately old: its prototype pollution is long patched and publicly disclosed (CVE-2019-10744, CVE-2020-8203). It demonstrates the workflow on a known finding — it is not a new lodash vulnerability.

`--target` installs a package from npm and **executes its code**. Outside the container the command refuses to run unless you pass `--i-understand-untrusted-code`.

### How it works

| Stage | What it does |
|-------|--------------|
| Target integration | Installs / loads the library and auto-generates entry points |
| Input generation | Coverage-guided fuzzing with UOP-specific mutations (Thompson-sampled strategies) |
| Instrumentation | AFL-style edge coverage + V8 precise coverage + Proxy taint tracking |
| Gadget analysis | Turns pollution → sink traces into ranked candidates |
| Verification | Reproduces each candidate in fresh child processes — the only thing that confirms a finding |

The pipeline is: discover entry points → coverage-guided fuzzing → differential oracle (clean vs. polluted run; only behaviour the pollution *caused* counts) → reproduction gate → cross-reference against advisory DBs. See [docs/architecture.md](docs/architecture.md) for details.

A gadget only matters if a prototype-pollution *source* can reach it. Pollution is a global effect, so any function that merges attacker input into an object is an interchangeable source — once a gadget is confirmed, UoPFuzz pairs it with a real, currently-shipping source and reproduces a runnable `attacker-input → source → gadget → sink` PoC:

```javascript
// Prototype-pollution RCE in ejs@3.1.6 via render(), reproduced in 2 fresh
// processes. The source pollutes Object.prototype; the gadget then reaches its
// code-execution sink.
//
// Source: assign-deep@1.0.0 (CVE-2019-10747) — interchangeable; any PP source works
const source = require('assign-deep');
const target = require('ejs');
source({}, JSON.parse('{"__proto__": ' + JSON.stringify({ "outputFunctionName": "<attacker code>" }) + '}'));
target.render(/* attacker-influenced input */);
// The polluted property reaches a code-execution sink and runs attacker code.
```

Chaining is on by default; `--no-chain` disables it.

### Runtime gadgets

Beyond npm packages, UoPFuzz hunts gadgets in the Node.js runtime itself — the properties that turn any prototype pollution into code execution:

```bash
npm run benchmark:runtime-gadgets   # curated corpus of published runtime gadgets
npm run mine:runtime-gadgets        # mine the installed runtime for new gadgets
npm run ab:ghunter                  # replay GHunter's published table, compare
```

The miner harvests candidate properties from the runtime source and verifies each one differentially in clean-vs-polluted child processes. A finding requires an observed behaviour change or crash, never sink-reach alone. Effects that only materialize in a live handshake (e.g. disabling TLS certificate verification) are proven by a behavioural oracle against a loopback server.

How the comparison was made, so the numbers can be read fairly: GHunter's research artifact requires a patched Node v21 build and does not run on a current runtime, so its side of the comparison is its own published, manually-validated table — this is a replay, not a live head-to-head. On Node 24.17, 33 of GHunter's 50 published gadget properties are still observable; UoPFuzz confirms 32 of them (the remaining one, `fetch.referrer`, shows only weak evidence). The other 17 are fixed or mitigated upstream and are reported as such, with the evidence inline. The miner additionally reports 145 gadget properties absent from GHunter's table — verified by this tool's differential harness on this Node version, not independently audited. For effort: GHunter's authors report 31 person-hours of manual validation, while the replay and the miner run unattended. Full tables: [benchmark/runtime-gadgets/RESULTS.md](benchmark/runtime-gadgets/RESULTS.md) and [results/runtime-miner/AB-RESULTS.md](results/runtime-miner/AB-RESULTS.md).

### Output

A run produces two kinds of result:

- **Confirmed findings** (`confirmedChains`) — reproduced in fresh processes; each ships a standalone PoC.
- **Unproven leads** (`candidateChains`) — a behavioural signal that did not reproduce. Kept for manual review, never counted as a vulnerability.

Every confirmed finding is labelled against the advisory sources:

| Label | Meaning |
|-------|---------|
| KNOWN CVE | Matches a published advisory (built-in DB, OSV.dev, or GitHub Advisory DB) |
| PREVIOUSLY DISCOVERED | This tool reproduced the same bug on an earlier run |
| UNDOCUMENTED VULNERABILITY | In no advisory source — a candidate that still needs human verification and responsible disclosure, not a confirmed 0-day |

The proof is one of: **prototype pollution** (a real own-property added to a builtin prototype), **code execution** (a canary actually ran), or **sink reachability** (a polluted value reached a code/command sink argument — flow proven, execution not).

### Related work

The reference points for server-side gadget hunting are Silent Spring (USENIX '23, static taint), Dasty and GHunter (USENIX '24, driven by the target's own test suite), and Bullseye (NDSS '26). UoPFuzz is not a new detection algorithm; it is an operationalized, reproduction-gated take on dynamic gadget hunting, with behavioural auto-discovery instead of test-suite-driven analysis.

Limits worth knowing: the discovery sweep is deliberately relevance-filtered to a few dozen freshly-published packages a day (see [scripts/discovery](scripts/discovery)), not a whole-registry corpus scan. And the reproduction gate trades recall for precision — a gadget that only fires under conditions the harness can't recreate is reported as an unproven lead, not a finding.

### Security

**This tool executes untrusted code and generates real, working exploits.** Only analyze packages you are authorized to test.

The real isolation boundary is the container (`run-sandboxed.sh`, backed by `.devcontainer/`): dropped capabilities, seccomp, `no-new-privileges`, non-root user, memory/PID caps, no host secrets. Run untrusted targets there. The in-process hardening on forked children (network off by default, `child_process`/`worker_threads` patched off, secret-bearing env vars stripped) is a speed bump, not a sandbox. Flags that lower the guardrails (`--no-sandbox`, `--allow-scripts`, `--allow-suspicious`, `--allow-network`) are opt-in and print a warning.

Generated PoCs under `results/` are real exploits — handle them as sensitive and disclose responsibly. Live OSV.dev lookups reveal the analyzed `package@version` to a third party (`--no-osv` opts out). The tool files nothing externally; every disclosure decision is yours. To report a vulnerability in UoPFuzz itself, see [SECURITY.md](SECURITY.md).

### Documentation

- [docs/architecture.md](docs/architecture.md) — pipeline and components
- [docs/configuration.md](docs/configuration.md) — YAML target format
- [docs/usage.md](docs/usage.md) — full CLI reference and the container workflow
- [benchmark/RESULTS.md](benchmark/RESULTS.md) — ground-truth benchmark
- [benchmark/runtime-gadgets/RESULTS.md](benchmark/runtime-gadgets/RESULTS.md) — runtime-gadget corpus verdicts
- [results/runtime-miner/AB-RESULTS.md](results/runtime-miner/AB-RESULTS.md) — UoPFuzz vs GHunter A/B

### Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

### License

[MIT](LICENSE) © Alexandru Cuciureanu
