# UoPFuzz Usage Examples

## Basic Usage

### Quick Start
```bash
# Test pug template engine with 100 iterations
uopfuzz --config config/targets/pug.yaml --max-iterations 100

# Dry run to test configuration
uopfuzz --config config/targets/pug.yaml --dry-run --verbose

# Save results to specific directory
uopfuzz --config config/targets/squirrelly.yaml --output ./my-results
```

### Advanced Options
```bash
# Long-running fuzzing session with custom timeout
uopfuzz --config config/targets/pug.yaml \
        --max-iterations 10000 \
        --timeout 120 \
        --output ./pug-analysis \
        --verbose

# Quick validation with minimal iterations
uopfuzz --config config/targets/hogan.yaml \
        --max-iterations 50 \
        --timeout 30
```

## Interpreting Results

### Report File
Each run generates a human-readable report:
```
UoPFuzz Analysis Report
======================

Target: pug
Duration: 45s
Iterations: 1000
Inputs Generated: 5000
Potential Chains: 3
Errors: 2

Potential Gadget Chains:
------------------------
1. Direct prototype pollution chain: template -> eval
   Risk Level: 9
   Source: __proto__.template
   Sink: eval

2. Multi-step gadget chain: pollution -> cache -> Function
   Risk Level: 7
   Source: constructor.prototype.cache
   Sink: Function
```

### JSON Results
Detailed technical data includes:
- Complete input/output traces
- Temporal chain analysis
- Property access patterns
- Function call sequences

### Risk Levels
- **9-10**: Critical - Direct path to RCE
- **7-8**: High - Multi-step exploitation possible
- **5-6**: Medium - Requires additional conditions
- **1-4**: Low - Theoretical or limited impact

## Common Patterns

### Template Engine Testing
Template engines are prime targets for UOP attacks:
```bash
# Test major template engines
uopfuzz --config config/targets/pug.yaml --max-iterations 1000
uopfuzz --config config/targets/squirrelly.yaml --max-iterations 500
uopfuzz --config config/targets/hogan.yaml --max-iterations 500
```

### Batch Testing
Test multiple targets in sequence:
```bash
#!/bin/bash
for config in config/targets/*.yaml; do
    echo "Testing $(basename $config)"
    uopfuzz --config $config --max-iterations 100 --output results/$(basename $config .yaml)
done
```

## Docker Usage

Run UoPFuzz in an isolated container:
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "src/cli.js"]
```

```bash
# Build and run
docker build -t uopfuzz .
docker run -v $(pwd)/results:/app/results uopfuzz \
    --config config/targets/pug.yaml --max-iterations 100
```

## Performance Tips

1. **Start Small**: Use `--max-iterations 10` for initial testing
2. **Use Dry Run**: Test configurations with `--dry-run` first
3. **Monitor Resources**: Large iteration counts may consume significant memory
4. **Timeout Tuning**: Adjust `--timeout` based on target complexity
5. **Parallel Processing**: Future versions will support `--parallel` option

## Troubleshooting

### Common Issues
- **Module Not Found**: Ensure target package can be installed via npm
- **Permission Errors**: Run with appropriate npm permissions
- **Memory Issues**: Reduce `--max-iterations` or increase system memory
- **Timeout Errors**: Increase `--timeout` for complex targets

### Debug Mode
```bash
# Enable verbose logging for debugging
uopfuzz --config your-target.yaml --verbose --dry-run
```