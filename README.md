# UoPFuzz

UoPFuzz hunts for prototype-pollution gadgets in JavaScript libraries — and only tells you about the ones it can actually reproduce.

It fuzzes a library, pollutes `Object.prototype`, and watches whether an attacker-controlled property flows into a dangerous sink. That alone isn't enough to call something a vulnerability, so nothing gets reported until a second, independent oracle re-proves it in fresh Node processes. If it can't be reproduced, it stays labelled a *lead* — never a finding.

The name points at the bug class it chases: a library reads a property that's *undefined* on an object, so the read walks up the prototype chain and picks up whatever an attacker planted there — a **U**se **O**f **P**olluted property. (The acronym "UOPF" also appears in the literature for a template-engine gadget-chaining framework — that's separate, earlier work.)

<img src="assets/demo.gif" alt="UoPFuzz detecting and reproducing a prototype-pollution gadget" width="820">

## What makes it different

- **Reproduction-gated reporting.** Every finding is re-proven in two fresh Node processes by an oracle that shares no verdict logic with discovery. On the project's [ground-truth benchmark](benchmark/RESULTS.md) this produced zero false positives against patched versions — a measured result on that corpus, not a promise about every package.
- **No config needed.** `--target pkg@version` is enough. It probes the library to find entry points itself, which can reach code paths the package's own test suite never touches.
- **Findings come with a working PoC.** Each confirmed finding ships a standalone script. The impact label (RCE / SSRF / LFI / XSS) comes from the sink that was actually reached, not a guess. When a single library is both the pollution source and the gadget, you get a self-contained exploit — and it says so.
- **Server-side and client-side.** On the server: code execution, template-compilation injection (e.g. EJS `outputFunctionName`), SSRF, LFI. Browser libraries load under jsdom with DOM-XSS sinks hooked (`innerHTML`, `document.write`, script `src`, …). jsdom doesn't run scripts, so client-side findings prove the sink is reachable rather than firing it.
- **It also mines the Node runtime.** Beyond npm packages, it looks for gadget properties inside Node itself (`NODE_OPTIONS`, `shell`, TLS verification, …), and can replay GHunter's published gadget table side by side — see [Runtime gadgets](#runtime-gadgets).
- **Every finding is checked against known advisories.** Findings are cross-referenced against a built-in advisory DB, OSV.dev, and the GitHub Advisory DB, so each one is labelled as a known CVE, a prior finding, or something not in any advisory source.

## Requirements

- Node.js 20 or newer
- Docker — needed to run untrusted targets safely (see [Running it safely](#running-it-safely))

## Quick start

```bash
git clone https://github.com/acuciureanu/uopfuzz.git
cd uopfuzz
npm install

# Audit an npm package@version — installs it, finds and verifies gadgets
node src/cli.js --target lodash@4.17.4

# Or drive it from a curated YAML target spec
node src/cli.js --config config/targets/ejs.yaml --output results/
```

Confirmed findings and their PoCs land in `results/`. The full flag reference lives in [docs/usage.md](docs/usage.md).

The demo target `lodash@4.17.4` is deliberately ancient: its prototype pollution was patched and publicly disclosed years ago (CVE-2019-10744, CVE-2020-8203). It's here to show the workflow on a *known* finding — not a new lodash bug.

Note before your first run: **`--target` installs a package from npm and executes its code.** Outside a container the command refuses to run unless you pass `--i-understand-untrusted-code` — see the next section.

## Running it safely

You're deliberately downloading and running code you don't trust. Do that inside the hardened container — it's the real isolation boundary. There are two ways in.

### The sandbox scripts (recommended for scans)

`run-sandboxed.sh` (Linux / macOS / WSL) and `run-sandboxed.ps1` (Windows) wrap the whole thing up for you. They build the container image on first use, install the fuzzer's own dependencies into a persistent volume, and then run the CLI with the guardrails on: `cap-drop=ALL`, a seccomp profile, `no-new-privileges`, memory and PID caps, and a **read-only** mount of the source tree.

```bash
# Anything you'd pass to the CLI, you can pass here
./run-sandboxed.sh --target lodash@4.17.20

# Scan the latest release of the top-100 cdnjs libraries (by GitHub stars)
./run-sandboxed.sh mass --top 100

# Walk one library's version history to bisect when a bug appeared/was fixed
./run-sandboxed.sh versions --library handlebars.js --last 5
```

Windows is the same, via PowerShell:

```powershell
.\run-sandboxed.ps1 --target lodash@4.17.20
.\run-sandboxed.ps1 mass --top 20
```

A few things worth knowing:

- **Results come back to the host.** They're written to `./results` so you can read them after the container exits. Send them elsewhere with `UOPFUZZ_RESULTS_DIR=/some/path`.
- **The scripts set `UOPFUZZ_CONTAINER=1`.** That's the flag that satisfies the host-safety gate, so you never need `--i-understand-untrusted-code`.
- **`mass` and `versions` refuse to run on a bare host.** They install and execute arbitrary packages, so they only run inside the sandbox (or an environment where you've set `UOPFUZZ_CONTAINER=1` yourself).
- **Don't `sudo` the script.** The container runs as an unprivileged user; running the wrapper as root just leaves you with root-owned results you can't read. If Docker complains about permissions, the script prints the actual fix (usually adding your user to the `docker` group).
- **First run is slower** — it builds the image and populates the dependency volume once. After that it's warm.

The PowerShell version has an extra `-Init` switch to force that dependency install by hand (`.\run-sandboxed.ps1 -Init`), handy after you change `package.json`.

### The dev container (recommended for development)

If you're working *on* UoPFuzz — or just want an editor that runs everything inside the same hardened environment — the repo ships a `.devcontainer/`. Open the folder in VS Code (or any devcontainer-capable editor) and let it build, or drive it from the CLI:

```bash
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . node src/cli.js --target <pkg@version>
```

It runs as a non-root `node` user on a read-only root filesystem, with the same dropped capabilities, `no-new-privileges`, and memory/CPU/PID caps as the scan scripts. `/tmp` and the npm cache are writable `noexec` tmpfs mounts; your findings persist in a `uopfuzz-results` volume.

One caveat: **the container contains capabilities, not the network.** Egress stays on by design — the tool needs it to install the fuzzer's dependencies, pull each target from npm, and query OSV.dev. If you also want to lock down the network, add your own egress policy on top. See [Security](#security) for the full picture.

## How it works

| Stage | What it does |
|-------|--------------|
| Target integration | Installs / loads the library and auto-generates entry points |
| Input generation | Coverage-guided fuzzing with UOP-specific mutations (Thompson-sampled strategies) |
| Instrumentation | AFL-style edge coverage + V8 precise coverage + Proxy taint tracking |
| Gadget analysis | Turns pollution → sink traces into ranked candidates |
| Verification | Reproduces each candidate in fresh child processes — the only thing that confirms a finding |

Read left to right, the pipeline is: discover entry points → coverage-guided fuzzing → a differential oracle (compare a clean run against a polluted one, and count only the behaviour the pollution *caused*) → the reproduction gate → cross-reference against advisory DBs. [docs/architecture.md](docs/architecture.md) has the details.

The built-in property and payload lists are *seeds*, not the detection logic. Candidate properties are discovered per target by watching which absent properties the library actually reads, and no verdict ever depends on a list lookup — see "Seeds vs. mechanism" in the architecture doc and the proof test `tests/integration/novel-property-detection.test.js`.

### Chaining a gadget to a real source

A gadget only matters if some prototype-pollution *source* can reach it. Pollution is a global effect, so any function that merges attacker input into an object is an interchangeable source. Once a gadget is confirmed, UoPFuzz pairs it with a real, currently-shipping source and reproduces a runnable `attacker-input → source → gadget → sink` PoC:

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

Chaining is on by default; `--no-chain` turns it off.

## Runtime gadgets

Beyond npm packages, UoPFuzz hunts gadgets in the Node.js runtime itself — the properties that turn *any* prototype pollution into code execution:

```bash
npm run benchmark:runtime-gadgets   # curated corpus of published runtime gadgets
npm run mine:runtime-gadgets        # mine the installed runtime for new gadgets
npm run compare:ghunter             # replay GHunter's published table, compare
```

The miner harvests candidate properties from the runtime source and verifies each one differentially in clean-vs-polluted child processes. A finding needs an observed behaviour change or crash — never sink-reach alone. Effects that only show up in a live handshake (say, disabling TLS certificate verification) are proven by a behavioural oracle against a loopback server.

How the comparison works: GHunter's research artifact needs a patched Node v21 build and won't run on a current runtime, so its side of the comparison is its own published, manually-validated table — this is a replay, not a live head-to-head. On Node 24.17, 33 of GHunter's 50 published gadget properties are still observable; UoPFuzz confirms 32 of them (the odd one out, `fetch.referrer`, shows only weak evidence). The other 17 are fixed or mitigated upstream and reported as such, with the evidence inline. The miner also surfaces 145 gadget properties absent from GHunter's table — verified by this tool's differential harness on this Node version, not independently audited. On effort: GHunter's authors report 31 person-hours of manual validation; the replay and the miner run unattended. Full tables: [benchmark/runtime-gadgets/RESULTS.md](benchmark/runtime-gadgets/RESULTS.md) and [results/runtime-miner/COMPARISON.md](results/runtime-miner/COMPARISON.md).

## Reading the output

A run produces two kinds of result:

- **Confirmed findings** (`confirmedChains`) — reproduced in fresh processes; each ships a standalone PoC.
- **Unproven leads** (`candidateChains`) — a behavioural signal that didn't reproduce. Kept for manual review, never counted as a vulnerability.

Every confirmed finding is labelled against the advisory sources:

| Label | Meaning |
|-------|---------|
| KNOWN CVE | Matches a published advisory (built-in DB, OSV.dev, or GitHub Advisory DB) |
| PREVIOUSLY DISCOVERED | This tool reproduced the same bug on an earlier run |
| UNDOCUMENTED VULNERABILITY | In no advisory source — a candidate that still needs human verification and responsible disclosure, not a confirmed 0-day |

The proof behind a finding is one of: **prototype pollution** (a real own-property added to a builtin prototype), **code execution** (a canary actually ran), or **sink reachability** (a polluted value reached a code/command sink argument — flow proven, execution not).

## Related work

The reference points for server-side gadget hunting are Silent Spring (USENIX '23, static taint), Dasty and GHunter (USENIX '24, driven by the target's own test suite), and Bullseye (NDSS '26). UoPFuzz isn't a new detection algorithm; it's an operationalized, reproduction-gated take on dynamic gadget hunting, with behavioural auto-discovery in place of test-suite-driven analysis.

Two limits worth knowing up front. The discovery sweep is deliberately relevance-filtered to a few dozen freshly-published packages a day (see [scripts/discovery](scripts/discovery)), not a whole-registry corpus scan. And the reproduction gate trades recall for precision — a gadget that only fires under conditions the harness can't recreate is reported as an unproven lead, not a finding.

## Security

**This tool executes untrusted code and generates real, working exploits.** Only analyze packages you're authorized to test.

The real isolation boundary is the container (`run-sandboxed.sh` / `run-sandboxed.ps1`, backed by `.devcontainer/`): dropped capabilities, seccomp, `no-new-privileges`, non-root user, memory/PID caps, no host secrets. Run untrusted targets there. The in-process hardening on forked children (network off by default, `child_process`/`worker_threads` patched off, secret-bearing env vars stripped) is a speed bump, not a sandbox. The flags that lower the guardrails (`--no-sandbox`, `--allow-scripts`, `--allow-suspicious`, `--allow-network`) are opt-in and print a warning.

Generated PoCs under `results/` are real exploits — treat them as sensitive and disclose responsibly. Live OSV.dev lookups reveal the analyzed `package@version` to a third party (`--no-osv` opts out). The tool files nothing externally; every disclosure decision is yours. To report a vulnerability in UoPFuzz itself, see [SECURITY.md](SECURITY.md).

## npm scripts

Every script defined in `package.json`:

| Command | What it does |
|---------|--------------|
| `npm start -- <args>` | Run the CLI (`node src/cli.js`) |
| `npm run dev -- <args>` | Run the CLI with `--watch`, restarting on source changes |
| `npm test` | Run the unit and integration test suite |
| `npm run test:ci` | The same suite, single-concurrency (for CI) |
| `npm run lint` | ESLint over `src/` and `tests/` |
| `npm run benchmark` | Full ground-truth benchmark — installs real vulnerable/patched packages and reports true/false-positive rates |
| `npm run benchmark:self-test` | Offline check of the benchmark scoring logic (installs nothing) |
| `npm run benchmark:runtime-gadgets` | Verify the curated corpus of published Node runtime gadgets (no installs) |
| `npm run mine:runtime-gadgets` | Mine the installed Node runtime for new gadget properties |
| `npm run compare:ghunter` | Replay GHunter's published gadget table and compare recall |
| `npm run demo` | Regenerate `assets/demo.gif` (needs [`agg`](https://github.com/asciinema/agg) on your PATH) |

Pass CLI flags through `npm start`/`npm run dev` after a `--`, e.g. `npm start -- --target lodash@4.17.4`.

## Documentation

- [docs/usage.md](docs/usage.md) — full CLI reference, the sandbox workflow, and mass scanning
- [docs/architecture.md](docs/architecture.md) — pipeline and components
- [docs/configuration.md](docs/configuration.md) — YAML target format
- [benchmark/RESULTS.md](benchmark/RESULTS.md) — ground-truth benchmark
- [benchmark/runtime-gadgets/RESULTS.md](benchmark/runtime-gadgets/RESULTS.md) — runtime-gadget corpus verdicts
- [results/runtime-miner/COMPARISON.md](results/runtime-miner/COMPARISON.md) — UoPFuzz vs GHunter comparison

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Alexandru Cuciureanu
