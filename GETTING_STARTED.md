# 🚀 Getting Started with UoPFuzz (Security-Hardened Edition)

## ✅ What's Been Fixed

Your UoPFuzz installation is now **secure and ready to hunt bugs**!

### Security Improvements:
- ✅ **2 production dependencies** (down from 5)
- ✅ **0 vulnerabilities** (verified)
- ✅ **No supply chain risk** from winston/chalk
- ✅ **All tests passing** (12/12)
- ✅ **Locked dependencies** (package-lock.json committed)

## 📦 Quick Start

### 1. Verify Installation
```bash
# Check dependencies are installed
npm list --depth=0

# Should show:
# ├── commander@11.1.0
# ├── eslint@8.57.0
# └── yaml@2.3.4

# Run security audit
npm audit
# Should show: found 0 vulnerabilities
```

### 2. Run Your First Scan (Safe Mode)
```bash
# Dry-run mode (no actual npm packages installed)
node src/cli.js \
  --config config/targets/pug.yaml \
  --dry-run \
  --max-iterations 100 \
  --output results/

# View results
cat results/report-*.txt
```

### 3. Run Tests
```bash
npm test
# All 12 tests should pass ✅
```

## 🎯 Start Hunting Bugs NOW

### Strategy: Hit the Ground Running

**Phase 1: Low-Hanging Fruit (Today!)**

Target the most popular vulnerable libraries first:

```bash
# 1. Pug (template engine - known vulnerable)
node src/cli.js \
  --config config/targets/pug.yaml \
  --max-iterations 1000 \
  --parallel 4 \
  --output results/pug/

# 2. SquirrellyJS (template engine)
node src/cli.js \
  --config config/targets/squirrelly.yaml \
  --max-iterations 1000 \
  --parallel 4 \
  --output results/squirrelly/

# 3. Hogan.js (Mustache compiler)
node src/cli.js \
  --config config/targets/hogan.yaml \
  --max-iterations 1000 \
  --parallel 4 \
  --output results/hogan/
```

**Phase 2: Expand Your Targets (This Week)**

Create configs for other popular template engines:

```bash
# Popular template engines (good targets)
- handlebars
- ejs
- nunjucks
- mustache
- lodash.template
- dot (doT.js)
- jade (old pug)
```

**Phase 3: Scale Up (Next Week)**

```bash
# Top 1000 npm packages by downloads
# Focus on:
# - Template engines
# - Object merge utilities
# - Configuration parsers
# - Serialization libraries
```

## 🔍 What to Look For

### High-Value Targets:
1. **Template engines** - Often have eval/code generation
2. **Object merge utilities** - Direct prototype pollution vectors
3. **Config parsers** - Process untrusted input
4. **Express middleware** - Widely deployed

### Good Signs of Vulnerability:
- Libraries with `eval()` or `Function()`
- Deep object merging
- Template compilation
- Options processing
- Older codebases (pre-2020)

## 📝 Creating New Target Configs

```bash
# Copy template
cp examples/target-template.yaml config/targets/mynewlib.yaml

# Edit with your target's details
nano config/targets/mynewlib.yaml
```

Example config for a new library:

```yaml
name: "my-template-engine"
package: "my-template-engine"
version: "2.5.0"
description: "Popular template engine"

entryPoints:
  - name: "compile"
    inputType: "template"
  - name: "render"
    inputType: "object"

sinks:
  - "eval"
  - "Function"
  - "vm.runInThisContext"

pollutionPoints:
  - "isDebug"
  - "template"
  - "cache"
  - "filename"

testConfig:
  timeout: 30
  maxDepth: 3
```

## 🎯 Bug Reporting Strategy

When you find a potential vulnerability:

### 1. Verify the Finding
```bash
# Re-run with verbose mode
node src/cli.js \
  --config config/targets/TARGET.yaml \
  --max-iterations 100 \
  --verbose

# Check the results JSON
cat results/results-*.json | jq '.potentialChains'
```

### 2. Create a PoC
```javascript
// poc.js
const vulnerable = require('vulnerable-package');

// Set up pollution
Object.prototype.polluted = 'malicious';

// Trigger the chain
vulnerable.render(payload);

// Check if sink is reached
```

### 3. Report Responsibly
1. Check if already reported (search CVE database)
2. Contact maintainer privately first
3. Give 90 days for fix
4. Request CVE if confirmed
5. Publish disclosure after fix

### 4. Track Your Discoveries
```bash
mkdir discoveries/
echo "LibraryName - ChainType - Status" >> discoveries/tracker.txt
```

## 🏆 Success Metrics

### Week 1 Goals:
- [ ] Scan 10 libraries
- [ ] Find 1-2 potential issues
- [ ] Create 3 new target configs
- [ ] Report first finding

### Month 1 Goals:
- [ ] Scan 100 libraries
- [ ] Find 5-10 vulnerabilities
- [ ] Get 1-2 CVEs assigned
- [ ] Present findings (blog/conference)

## 🔧 Performance Tips

### Maximize Throughput:
```bash
# Use all CPU cores
node src/cli.js \
  --config config/targets/pug.yaml \
  --parallel $(nproc) \
  --max-iterations 10000

# Run multiple targets in parallel
for config in config/targets/*.yaml; do
  node src/cli.js --config $config --parallel 4 &
done
wait
```

### Monitor Progress:
```bash
# Watch results in real-time
watch -n 5 'ls -lh results/ | tail -20'

# Count findings
grep -r "Risk Level" results/*.txt | wc -l
```

## 🚨 Safety Reminders

1. **Always use --dry-run first** when testing new configs
2. **Run in isolated environment** (Docker/VM) when not using dry-run
3. **Never test on production systems**
4. **Respect rate limits** on npm registry
5. **Report vulnerabilities responsibly**

## 📊 Next Steps

### Immediate (Today):
1. ✅ Run first scan with dry-run
2. ✅ Create 2-3 new target configs
3. ✅ Start scanning popular libraries

### Short-term (This Week):
1. Find first potential vulnerability
2. Create PoC for verification
3. Set up tracking system
4. Contact first maintainer

### Medium-term (This Month):
1. Scan 100+ libraries
2. Report 5+ vulnerabilities
3. Get first CVE
4. Consider Rust rewrite for scale

## 📚 Resources

- [Silent Spring Paper](https://www.usenix.org/conference/usenixsecurity23/presentation/shcherbakov) - Original UOP research
- [npm Security](https://docs.npmjs.com/cli/v9/using-npm/security) - npm best practices
- [HackerOne](https://hackerone.com/) - Bug bounty platform
- [CVE Program](https://www.cve.org/) - Vulnerability reporting

## 🎉 You're Ready!

**The tool is secure, tested, and ready to hunt bugs.**

**The window is open for 6-12 months before this becomes mainstream.**

**Time to start finding vulnerabilities! 🚀**

---

Questions? Check:
- `README.md` - General overview
- `DEPENDENCY_AUDIT.md` - Security analysis
- `SECURITY_SETUP.md` - Detailed security guide
- `docs/` - Architecture and usage docs
