# UoPFuzz Architecture Overview

## Core Components

### 1. Target Integration (`src/target-integration/`)
- **Purpose**: Manages dynamic loading and configuration of target libraries
- **Key Features**:
  - YAML-based configuration parsing
  - Dynamic package installation via npm
  - Entry point validation
  - Module caching for performance

### 2. Input Generation (`src/input-generation/`)
- **Purpose**: Generates test inputs with UOP-specific mutations
- **Key Features**:
  - Coverage-guided fuzzing strategies
  - Prototype pollution mutations (vertical/horizontal chaining)
  - Type coercion exploits
  - Async pollution patterns

### Seeds vs. mechanism

The static lists in this repo are fuzzer **seeds**, not detection logic:

| Artifact | File | Role |
|---|---|---|
| `GENERIC_POLLUTION_PROPS`, `PAYLOADS` | `src/input-generation/index.js` | Seed dictionary of property names and payload values (AFL-style; shapes known to be useful across library categories) |
| Known-gadget/CVE DB | `src/gadget-analysis/known-gadgets.js` | Seed priority for known-CVE properties, novelty triage labels, benchmark ground truth |
| `GATE_PROPERTIES` | `src/instrumentation/gate-properties.js` | Dasty-style forced-branch co-pollution |
| Runtime corpus | `benchmark/runtime-gadgets/corpus.js` | Benchmark questions; verdicts are computed by executing every entry |

No verdict depends on these lists. Candidate properties are discovered
target-first: `discoverUOPProperties` (`src/instrumentation/differential.js`)
observes which *absent* properties the library actually reads, and those feed
back into the fuzzer above every static list. Detection is behavioral
(differential oracle + sink-token capture), and confirmation is the
reproduction gate in fresh processes. Executable proof:
`tests/integration/novel-property-detection.test.js` detects and confirms a
gadget whose property appears in no list. The static lists only bias the
search order toward known shapes — a target whose gadget property matches
nothing static is still found whenever its reads are observable.

### 3. Instrumentation (`src/instrumentation/`)
- **Purpose**: Executes inputs with comprehensive tracing
- **Key Features**:
  - Property access monitoring
  - Prototype modification tracking
  - Sink function instrumentation
  - Safe execution with timeouts

### 4. Gadget Analysis (`src/gadget-analysis/`)
- **Purpose**: Identifies potential exploit chains from traces
- **Key Features**:
  - Multi-step chain detection
  - Risk level assessment
  - Temporal relationship analysis
  - Chain deduplication and ranking

### 5. Orchestrator (`src/orchestrator/`)
- **Purpose**: Coordinates the entire fuzzing workflow
- **Key Features**:
  - Component lifecycle management
  - Result aggregation and reporting
  - Performance optimization
  - Error handling and recovery

### 6. Verification (`src/verification/`)
- **Purpose**: The zero-false-positive gate — a finding is reported only after
  independent reproduction in fresh child processes
- **Key Features**:
  - Ground-truth oracles (real prototype mutation, executed canary, named sink reach)
  - End-to-end chain synthesis: a proven gadget is paired with a proven
    prototype-pollution *source* (`source-registry.js`) and the full
    `attacker-input → source → gadget → sink` exploit is reproduced
    (`reproduce.js` `reproduceChain`, on by default; `--no-chain` disables)
  - Reproduction-derived impact classification (RCE / command injection / SSRF /
    LFI / XSS / crypto-downgrade) from the proven sink
    (`gadget-analysis/sink-impact.js`); the reproduction worker records the
    string arguments of code/command, network, filesystem, TLS/crypto, and
    `worker_threads.Worker` sinks — including values reached through an options
    object's prototype chain (`utils/sink-record.js`)
  - Standalone runnable PoC generation per confirmed finding

### 7. Runtime Gadget Miner (`src/runtime-miner/`)
- **Purpose**: Discovers *unknown* universal gadgets in the Node runtime itself
  (GHunter-style enumeration) on a stock runtime, with no manual validation
- **Key Features**:
  - Candidate harvest from the runtime's own source (`process.binding('natives')`)
    — option-property reads per API class (`harvest.js`)
  - Automatic validation: value-differential oracle (behavior change = LIVE),
    exit-code oracle (polluted-only fatal exit = DoS), 2× fresh-process sink
    reproduction for impact classification (`mine.js`)
  - CLI: `benchmark/runtime-gadgets/mine.js`; findings in `results/runtime-miner/`

## Data Flow

1. **Configuration Loading**: Target YAML files define entry points, sinks, and pollution vectors
2. **Input Generation**: Creates base inputs and applies UOP-specific mutations
3. **Instrumented Execution**: Runs inputs against target with comprehensive tracing
4. **Chain Analysis**: Identifies temporal relationships between pollution and sinks
5. **Verification**: Reproduces every candidate in fresh child processes (twice) against ground-truth oracles; confirmed gadgets are chained with a proven pollution source into an end-to-end exploit and classified by proven impact
6. **Result Reporting**: Generates human-readable reports and detailed JSON data

## Security Considerations

- **Target code IS executed, not stubbed**: to find gadgets the fuzzer must run
  the library with attacker-shaped inputs, and reproduction deliberately lets a
  canary payload execute to *prove* code execution. The real isolation boundary
  is therefore the dev container, not in-process stubbing — see the **Safety
  model** in `README.md`. (Sink functions are wrapped as logging monitors during
  discovery, and `child_process` stays hardened off, so "proof of execution"
  means a controlled global write, never a spawned shell.)
- **Isolation**: run untrusted targets inside the dev container
  (`.devcontainer/`, `run-sandboxed.sh`). The untrusted-package modes (`mass`,
  cdnjs `versions`) hard-refuse on a non-sandboxed host — see
  `src/utils/sandbox-guard.js`.
- **Timeouts**: Prevent infinite loops and resource exhaustion
- **Data Sanitization**: Removes sensitive information from traces