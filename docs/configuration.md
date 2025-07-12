# UoPFuzz Configuration Guide

## Target Configuration Format

UoPFuzz uses YAML files to define target libraries. Each configuration file should include:

### Required Fields

```yaml
name: "target-name"              # Unique identifier
package: "npm-package-name"      # NPM package name
version: "1.0.0"                 # Specific version to test
entryPoints: []                  # Array of function entry points
sinks: []                        # Array of dangerous functions
pollutionPoints: []              # Array of pollution target properties
```

### Entry Points

Define functions that accept user input:

```yaml
entryPoints:
  - name: "compile"              # Function name
    inputType: "template"        # Input type: string, object, template, mixed
    description: "Template compilation function"
  - name: "render"
    inputType: "object"
    description: "Data rendering function"
```

### Sinks

List dangerous functions that could lead to RCE/XSS:

```yaml
sinks:
  - "eval"
  - "Function"
  - "child_process.exec"
  - "vm.runInThisContext"
  - "innerHTML"
```

### Pollution Points

Properties commonly targeted in prototype pollution:

```yaml
pollutionPoints:
  - "isAdmin"
  - "template"
  - "cache"
  - "debug"
  - "trusted"
```

### Optional Fields

```yaml
description: "Human-readable description"
knownPatterns:                   # Known vulnerability patterns
  - description: "Pattern description"
    pattern: "__proto__.template"
    sink: "eval"
    reference: "Research paper or CVE"

testConfig:                      # Testing parameters
  timeout: 30                    # Timeout in seconds
  maxDepth: 3                    # Maximum pollution depth
  enableAsyncTesting: true       # Enable async pattern testing
```

## Example Configurations

See `config/targets/` for complete examples:
- `pug.yaml` - Template engine with eval sinks
- `squirrelly.yaml` - Lightweight template engine
- `hogan.yaml` - Mustache template engine

## Adding New Targets

1. Create a new YAML file in `config/targets/`
2. Define all required fields
3. Test with dry-run mode: `uopfuzz --config your-target.yaml --dry-run`
4. Validate configuration with real package installation