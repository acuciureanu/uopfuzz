# UoPFuzz

A plug-and-play framework for Undefined-Oriented Programming (UOP) in prototype pollution gadget hunting.

## ⚠️ Important: False Positives

**This tool has a 60-80% false positive rate in real execution, 90-95% in dry-run mode.**

- ✅ Good for: Mass scanning, discovery, casting a wide net
- ❌ Bad for: Automated vulnerability reporting without verification
- 🔍 **Manual verification REQUIRED** for all findings
- 🧠 **ML-enhanced filtering reduces FP to ~33%** (see FILTER_COMPARISON.md)
- 📖 See `HONEST_ASSESSMENT.md` for realistic expectations

## Overview

UoPFuzz is a hybrid security research framework that combines fuzzing with concolic execution to detect and chain prototype pollution gadgets in JavaScript libraries. It focuses on Node.js environments to identify vulnerabilities leading to dangerous sinks like `eval` or `exec`.

**Think of it as:** A force multiplier for security researchers, not a magic vulnerability detector.

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

# Scan any package (auto-detects entry points)
node src/auto-scanner.js pug --max-iterations 1000

# Filter results with ML-enhanced filtering (reduces FP by 50%)
node src/simple-ml-filter.js results/pug/results-*.json

# Or use config-based scanning
node src/cli.js --config config/targets/pug.yaml --output results/
```

## ML-Enhanced Filtering

UoPFuzz includes a lightweight ML filter using TF-IDF and semantic similarity:

- **Zero complex dependencies**: Pure JavaScript implementation
- **50% FP reduction**: From 60-80% down to ~33%
- **CVE matching**: Pre-loaded with 5 known vulnerability patterns
- **Fast**: ~10ms per chain

```bash
# After scanning, apply ML filter
node src/simple-ml-filter.js results/package/results-*.json

# Review high confidence findings (best similarity to known CVEs)
cat results/package/*-simple-ml-filtered.json | jq '.highConfidence'

# Review medium confidence findings
cat results/package/*-simple-ml-filtered.json | jq '.mediumConfidence'
```

See `FILTER_COMPARISON.md` for detailed comparison with rule-based filtering.

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