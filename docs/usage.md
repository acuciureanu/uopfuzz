# UoPFuzz Usage

## Running the CLI

From a clone of this repo, run the CLI directly with Node:

```bash
npm install                       # once, to install dependencies
node src/cli.js --target pug@3.0.2
```

The `uopfuzz` command shown in some examples below only exists after you install
the package globally or link it:

```bash
npm link            # makes `uopfuzz` available on your PATH (dev convenience)
uopfuzz --target pug@3.0.2
# equivalently, without linking:
node src/cli.js --target pug@3.0.2
npm start -- --target pug@3.0.2   # `--` forwards args through npm
```

You must pass **either** `--target <package@version>` **or** `--config <path>`;
with neither, the CLI prints usage help and exits.

> **This installs the target from npm and executes its code.** `--target` needs
> network + npm access, and third-party code runs during discovery. Fuzz
> untrusted packages **inside the dev container** — the real isolation boundary
> (see the Security section in `README.md`).

## Two ways to choose a target

### 1. Auto-discovery (recommended): `--target`

Point it at a package and version; it installs the package, auto-generates a
target config (entry points, sequences), hunts sources and gadgets, and verifies
every finding in fresh processes.

```bash
node src/cli.js --target pug@3.0.2
node src/cli.js --target squirrelly@8.0.8 --max-iterations 500
node src/cli.js --target lodash@4.17.4 --max-iterations 50   # known PP source
```

### 2. Config-driven: `--config`

Use a hand-written YAML target spec (see `config/targets/*.yaml` and
`examples/target-template.yaml`).

```bash
node src/cli.js --config config/targets/pug.yaml --max-iterations 100
node src/cli.js --config config/targets/squirrelly.yaml --output ./my-results
```

## Running in the dev container (recommended for untrusted targets)

The dev container (`.devcontainer/`) is the actual isolation boundary: no secrets
in its environment, egress governed by the network policy, ephemeral filesystem.

```bash
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . node src/cli.js --target <pkg@version>
```

## Mass scanning in the sandbox

To hunt across many libraries — installing and running **untrusted** third‑party
code — use the hardened container via `run-sandboxed.sh` (Linux/macOS/WSL) or
`run-sandboxed.ps1` (Windows). It runs the CLI with `cap-drop=ALL`, seccomp,
`no-new-privileges`, memory/pid caps, a read‑only workspace mount, and sets
`UOPFUZZ_CONTAINER=1` so the host‑safety gate passes.

> The `mass` and `versions` commands **refuse to run on a non‑sandboxed host**
> (they install and execute arbitrary packages). Run them through
> `run-sandboxed.sh`, or from your own isolated environment with
> `UOPFUZZ_CONTAINER=1` set. `--i-understand-untrusted-code` is an explicit,
> loud opt‑out — use it only if you accept running untrusted code on the host.

```bash
# Scan the latest release of the top-100 cdnjs libraries (by GitHub stars)
./run-sandboxed.sh mass --top 100
```

`mass` tests the **latest** version of each library. Scale coverage with:

- `--top <N>` — how many libraries to scan (after star‑ranking)
- `--limit <M>` — how many to pull from cdnjs before ranking (`M ≥ N`)
- **resume is on by default** — already‑scanned libraries are skipped, so you can
  stop/restart or grow `--top` over multiple runs without redoing work. Pass
  `--no-resume` to force a full re‑scan.
- `--concurrency <n>` — scan several libraries at once
- `--max-iterations <n>` / `--timeout <s>` — depth/time budget per library
- `--no-osv` — don't reveal `package@version` to OSV.dev (labels use the built‑in DB only)

```bash
# A broad, restartable sweep
./run-sandboxed.sh mass --top 300 --limit 800 --concurrency 2

# Track when a bug was introduced/fixed across one library's versions
./run-sandboxed.sh versions --library lodash.js --last 10
```

**Results are written to the host** at `./results` (override with
`UOPFUZZ_RESULTS_DIR=/path`), so you can review them after the container exits:

- `results/mass-report-<timestamp>.md` — the summary; read this first.
- `results/mass-<lib>-<version>.json` — per‑library detail with runnable PoCs.

The report counts libraries with a reproduction‑proven finding. Recall the label
distinction: **KNOWN CVE** is a rediscovery of a published bug (expected on old
versions), while **UNDOCUMENTED VULNERABILITY** is the candidate 0‑day worth your
attention — grep the JSON for `UNDOCUMENTED`. A candidate still needs human
verification against public advisories before disclosure; the tool files nothing
externally on its own.

> **Requirement:** Docker installed and running. A truly broad sweep is
> long‑running (each library has a 15‑minute wall‑clock cap), so start small
> (`--top 20 --max-iterations 40`) to confirm the pipeline, then scale with
> resume.

### Validating detection quality (benchmark)

Before trusting a mass hunt, confirm the oracle actually detects known bugs and
stays silent on patched versions. The benchmark runs the full pipeline against a
labelled corpus of real vulnerable/patched npm pairs and reports true‑positive /
false‑positive rates (see `benchmark/`):

```bash
./run-sandboxed.sh   # (or set UOPFUZZ_CONTAINER=1 in an isolated env)
npm run benchmark            # real installs; PASS iff TP ≥ 90% and FP ≤ 10%
npm run benchmark:self-test  # offline check of the scoring logic (no installs)
```

### Runtime-gadget benchmark (UoPFuzz vs GHunter)

A second, offline benchmark runs GHunter's published Node.js universal-gadget
corpus (runtime gadgets like polluted `NODE_OPTIONS` → `child_process.exec`)
through UoPFuzz's own oracles — no installs, no network:

```bash
npm run benchmark:runtime-gadgets   # per-gadget verdicts; exit 1 on a capability gap
```

Entries documented as fixed upstream (e.g. the `require` gadget, fixed in Node
18.19.0) or verified as incidentally mitigated on the running Node must come
back unobservable — a regression there fails the run. Results are committed at
`benchmark/runtime-gadgets/RESULTS.md` (regenerate with `--write`).

### Mining for NEW runtime gadgets (beyond GHunter)

The runtime gadget miner does GHunter's candidate enumeration on a **stock**
runtime with **zero manual validation**: it harvests option-property reads from
the Node source exposed via `process.binding('natives')`, then validates every
candidate with the value-differential oracle (clean vs polluted behavior), the
exit-code oracle (polluted-only fatal exit = DoS), and the 2× fresh-process
sink reproduction for impact classification:

```bash
npm run mine:runtime-gadgets                                   # all 17 API classes
node benchmark/runtime-gadgets/mine.js --classes tls.connect   # one class
node benchmark/runtime-gadgets/mine.js --write                 # + FINDINGS.md
```

Findings land in `results/runtime-miner/`. Because nothing is patched, the
miner re-runs on every new Node release as a continuous discovery/regression
gate. Verdicts never rest on sink recording alone — only an observable
behavior change or an exit-code difference counts as LIVE/DoS.

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `-c, --config <path>` | — | Target configuration file (YAML) |
| `--target <pkg@version>` | — | Target package; auto-discovers everything |
| `-o, --output <dir>` | `./results` | Output directory for results |
| `-t, --timeout <seconds>` | `60` | Timeout per iteration |
| `--max-iterations <num>` | `1000` | Maximum fuzzing iterations |
| `--parallel <num>` | `1` | Concurrent sandbox workers for Phase-B differential probes (pool-backed; same confirmed findings as sequential) |
| `-v, --verbose` | off | Debug logging |
| `--dry-run` | off | Validate config/plumbing without executing target code |
| `--sandbox` / `--no-sandbox` | `--sandbox` | Run each target-executing discovery call in an isolated child process (default on) |
| `--no-isolate` | isolate on | Run the whole session in this process instead of a crash-isolated child. By default a single-target run is forked so a target that corrupts Node's own internals (e.g. a browser-only package whose in-process pollution poisons undici's HTTP parser) dies as a reported failure instead of taking the fuzzer down; opt out only to debug a crash in-process |
| `--allow-network` | off | Permit outbound network from target code |
| `--allow-scripts` | off | Allow npm lifecycle scripts during install (**DANGEROUS**) |
| `--allow-suspicious` | off | Install packages with suspicious install scripts (**DANGEROUS**) |
| `--skip-integrity-check` | off | Skip package integrity verification |
| `--no-osv` | OSV on | Disable live OSV.dev lookups (an OSV query reveals the analyzed `package@version` to a third party) |
| `--no-chain` | chain on | Disable end-to-end chain synthesis (pairing a proven gadget with a proven PP source and reproducing the full attacker-input → source → gadget → sink exploit); findings are then reported gadget-half only |

The guardrail-lowering flags (`--no-sandbox`, `--allow-scripts`,
`--allow-suspicious`, `--allow-network`) are opt-in and print a warning.

## Interpreting results

A run writes a JSON results file and a human-readable report to `--output`.

### What "confirmed" means

A finding is reported as a **proven vulnerability** only after the independent
reproduction oracle reproduces it in **two fresh child processes** — a real
prototype mutation, or real code execution via a canary token. Everything else is
kept as a clearly-labeled **unproven lead** for manual review, never as a
vulnerability. Each proven finding is labeled **KNOWN CVE**, **PREVIOUSLY
DISCOVERED**, or **UNDOCUMENTED VULNERABILITY** and ships with a standalone,
runnable PoC. See `src/verification/reproduce.js`.

### Console summary

At the end of a run the CLI prints, in red, the count of proven vulnerabilities
(broken down as undocumented / previously discovered / known CVE) and, separately,
the count of unproven leads. Proven findings include their disclosure label and,
where available, the CVE id and whether it was matched via the built-in DB or
OSV.dev.

## Batch testing

```bash
# Every YAML target config in sequence
for config in config/targets/*.yaml; do
  echo "Testing $(basename "$config")"
  node src/cli.js --config "$config" --max-iterations 100 \
    --output "results/$(basename "$config" .yaml)"
done
```

## Performance tips

1. **Start small**: `--max-iterations 10` for a first pass on a new target.
2. **Dry run first**: `--dry-run --verbose` validates config without executing code.
3. **Timeout tuning**: raise `--timeout` for heavy targets (template compilers).
4. **Parallelism**: `--parallel $(nproc)` to use all cores.

```bash
node src/cli.js --config config/targets/pug.yaml \
  --parallel "$(nproc)" --max-iterations 5000 --timeout 30 --output ./results
```

## Troubleshooting

- **Cannot install / resolve target**: the `package@version` must be installable
  from your npm registry; check network and that the version exists.
- **Everything times out**: raise `--timeout`, or lower `--max-iterations`.
- **Nothing found on a known-vulnerable package**: recall is partial; confirm the
  entry point/calling convention matches how the gadget actually fires, or try
  `--config` with an explicit target spec.
- **Debugging a config**: `node src/cli.js --config your-target.yaml --dry-run --verbose`.

## Requirements

Node.js ≥ 20 (`package.json` `engines`). Target packages are installed via npm at
run time, so npm and network access are required for `--target`.
