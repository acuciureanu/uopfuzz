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
> (see the Safety model in `README.md`).

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

## Options

| Flag | Default | Meaning |
|------|---------|---------|
| `-c, --config <path>` | — | Target configuration file (YAML) |
| `--target <pkg@version>` | — | Target package; auto-discovers everything |
| `-o, --output <dir>` | `./results` | Output directory for results |
| `-t, --timeout <seconds>` | `60` | Timeout per iteration |
| `--max-iterations <num>` | `1000` | Maximum fuzzing iterations |
| `--parallel <num>` | `1` | Number of parallel workers |
| `-v, --verbose` | off | Debug logging |
| `--dry-run` | off | Validate config/plumbing without executing target code |
| `--sandbox` / `--no-sandbox` | `--sandbox` | Run each target-executing discovery call in an isolated child process (default on) |
| `--no-isolate` | isolate on | Run the whole session in this process instead of a crash-isolated child. By default a single-target run is forked so a target that corrupts Node's own internals (e.g. a browser-only package whose in-process pollution poisons undici's HTTP parser) dies as a reported failure instead of taking the fuzzer down; opt out only to debug a crash in-process |
| `--allow-network` | off | Permit outbound network from target code |
| `--allow-scripts` | off | Allow npm lifecycle scripts during install (**DANGEROUS**) |
| `--allow-suspicious` | off | Install packages with suspicious install scripts (**DANGEROUS**) |
| `--skip-integrity-check` | off | Skip package integrity verification |
| `--no-osv` | OSV on | Disable live OSV.dev lookups (an OSV query reveals the analyzed `package@version` to a third party) |

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

Node.js ≥ 18 (`package.json` `engines`). Target packages are installed via npm at
run time, so npm and network access are required for `--target`.
