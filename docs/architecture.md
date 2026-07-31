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

## Data Flow

1. **Configuration Loading**: Target YAML files define entry points, sinks, and pollution vectors
2. **Input Generation**: Creates base inputs and applies UOP-specific mutations
3. **Instrumented Execution**: Runs inputs against target with comprehensive tracing
4. **Chain Analysis**: Identifies temporal relationships between pollution and sinks
5. **Result Reporting**: Generates human-readable reports and detailed JSON data

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