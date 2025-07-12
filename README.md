# UoPFuzz

A plug-and-play framework for Undefined-Oriented Programming (UOP) in prototype pollution gadget hunting.

## Overview

UoPFuzz is a hybrid security research framework that combines fuzzing with concolic execution to detect and chain prototype pollution gadgets in JavaScript libraries. It focuses on Node.js environments to identify vulnerabilities leading to dangerous sinks like `eval` or `exec`.

## Features

- **Configuration-driven**: YAML-based target library definitions for plug-and-play usage
- **Hybrid approach**: Combines coverage-guided fuzzing with concolic execution
- **Parallel processing**: Utilize multiple CPU cores with configurable worker threads
- **Modular architecture**: Easy to extend and customize for specific research needs
- **Safety-first**: Simulates exploits without executing dangerous code
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

## Documentation

See the `docs/` directory for detailed documentation on:
- Architecture overview
- Configuration format
- Adding new target libraries
- Interpreting results