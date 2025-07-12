#!/bin/bash

# UoPFuzz Quick Start Examples
# This script demonstrates various ways to use UoPFuzz

echo "🔍 UoPFuzz - Prototype Pollution Gadget Hunter"
echo "=============================================="

# Example 1: Quick validation with dry run
echo ""
echo "1. Quick validation with dry run:"
echo "node src/cli.js --config config/targets/pug.yaml --dry-run --max-iterations 10"
node src/cli.js --config config/targets/pug.yaml --dry-run --max-iterations 10

echo ""
echo "----------------------------------------"

# Example 2: Test multiple targets
echo ""
echo "2. Testing multiple targets:"
for config in config/targets/*.yaml; do
    target_name=$(basename "$config" .yaml)
    echo "Testing $target_name..."
    node src/cli.js --config "$config" --dry-run --max-iterations 5 --output "results/$target_name"
done

echo ""
echo "----------------------------------------"

# Example 3: Verbose debugging
echo ""
echo "3. Verbose debugging mode:"
echo "node src/cli.js --config config/targets/squirrelly.yaml --dry-run --verbose --max-iterations 3"
node src/cli.js --config config/targets/squirrelly.yaml --dry-run --verbose --max-iterations 3

echo ""
echo "🎉 Examples completed! Check the results/ directory for output files."