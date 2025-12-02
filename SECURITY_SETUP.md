# 🔒 Security Setup Guide for UoPFuzz

## ✅ Security Hardening Complete

UoPFuzz has been hardened against supply chain attacks with the following measures:

### 🛡️ Implemented Security Features

1. **Minimal Dependencies** (Only 2 production deps!)
   - `yaml@2.3.4` - YAML config parser (0 transitive deps)
   - `commander@11.1.0` - CLI args (0 transitive deps)
   - **REMOVED**: winston (15+ deps) → Simple built-in logger
   - **REMOVED**: chalk (optional) → ANSI codes directly

2. **Dependency Pinning**
   - All versions are exact (no `^` or `~` ranges)
   - `package-lock.json` is committed
   - Ensures reproducible builds

3. **Installation Security**
   - `.npmrc` configured with `ignore-scripts=true`
   - Prevents malicious postinstall scripts
   - Audit level set to `moderate`

4. **Zero Vulnerabilities**
   ```bash
   $ npm audit
   found 0 vulnerabilities
   ```

5. **Minimal Attack Surface**
   - Only 102 packages total (including dev deps)
   - No dynamic code loading from npm during runtime
   - Target packages installed only when needed

## 📋 Security Audit Summary

| Dependency | Version | Downloads/week | Maintainers | Risk | Status |
|------------|---------|----------------|-------------|------|--------|
| yaml | 2.3.4 | ~6M | 1 (trusted) | LOW | ✅ Safe |
| commander | 11.1.0 | ~100M | Team | LOW | ✅ Safe |
| eslint | 8.57.0 | ~40M | Team | LOW | ✅ Safe (dev only) |

**Total Production Dependencies**: 2
**Known Vulnerabilities**: 0
**Supply Chain Incidents**: None

## 🚀 Quick Start (Secure)

### First Time Setup

```bash
# 1. Verify dependencies are locked
cat package-lock.json | head -20

# 2. Install with security checks
npm ci  # Uses lockfile, verifies integrity

# 3. Audit for vulnerabilities
npm audit

# 4. Run tests
npm test

# 5. Try dry-run
node src/cli.js --config config/targets/pug.yaml --dry-run
```

### Regular Usage

```bash
# Before each scan, check security
npm audit --audit-level=moderate

# Run fuzzer (dry-run mode is safe)
node src/cli.js --config config/targets/pug.yaml --dry-run --max-iterations 100
```

## 🔐 Security Best Practices

### 1. Keep Dependencies Updated (Carefully)

```bash
# Check for outdated packages
npm outdated

# Update only patch versions (safest)
npm update --save-exact

# Re-run audit after updates
npm audit
```

### 2. Review Package Changes

Before updating any dependency:
1. Check GitHub for security advisories
2. Review CHANGELOG for breaking changes
3. Check npm page for maintainer changes
4. Run `npm audit` after update

### 3. Monitor for Supply Chain Attacks

Tools to use:
- `npm audit` (built-in)
- [Socket.dev](https://socket.dev) - Free supply chain monitoring
- [Snyk](https://snyk.io) - Vulnerability scanning
- GitHub Dependabot - Automated alerts

### 4. Sandboxing Target Packages

When testing actual npm packages (not dry-run):

```bash
# Use Docker for isolation
docker run --rm -v $(pwd):/app node:18 \
  node /app/src/cli.js --config /app/config/targets/pug.yaml

# Or use VM/dedicated machine
# NEVER run on production systems
```

### 5. Verify Package Integrity

```bash
# Check package signatures (if available)
npm view yaml

# Verify checksums match lockfile
npm ci --dry-run

# Check for unexpected file changes
git status
```

## ⚠️ Warning Signs of Compromise

Watch for these indicators:

1. **Unexpected postinstall scripts**
   ```bash
   npm ls --all | grep "postinstall"
   ```

2. **New transitive dependencies**
   ```bash
   npm ls --depth=5
   ```

3. **Size anomalies**
   ```bash
   du -sh node_modules/*
   ```

4. **Unexpected network activity**
   - Monitor during `npm install`
   - Use `--offline` flag when possible

## 🔧 Security Configuration Files

### `.npmrc` (Project Root)
```
ignore-scripts=true      # Disable postinstall
audit-level=moderate     # Fail on moderate+ vulns
save-exact=true         # Pin exact versions
```

### `package.json` Security Fields
```json
{
  "scripts": {
    "preinstall": "npm audit",
    "audit": "npm audit --audit-level=moderate"
  }
}
```

## 🎯 Incident Response Plan

If you suspect a compromised dependency:

1. **Isolate immediately**
   ```bash
   # Stop all running processes
   killall node

   # Move to clean environment
   cd /tmp && git clone [repo]
   ```

2. **Investigate**
   ```bash
   # Check recent installs
   npm ls --depth=0

   # Review package-lock.json changes
   git diff HEAD package-lock.json

   # Check for suspicious files
   find node_modules -name "*.sh" -o -name "*.py"
   ```

3. **Report**
   - npm: security@npmjs.com
   - GitHub: Use security advisory
   - Maintainers: Open issue

4. **Recover**
   ```bash
   # Clean install from lockfile
   rm -rf node_modules
   npm ci

   # Verify integrity
   npm audit
   ```

## 📊 Ongoing Monitoring

### Daily
```bash
# Quick security check
npm audit
```

### Weekly
```bash
# Check for updates
npm outdated

# Review dependencies
npm ls --depth=1
```

### Monthly
```bash
# Deep dependency review
npm ls --all > deps-$(date +%Y%m).txt

# Compare with previous month
diff deps-202411.txt deps-202412.txt
```

## 🏆 Security Scorecard

✅ **Current Status: SECURE**

- [x] Minimal dependencies (2 prod, 1 dev)
- [x] Zero known vulnerabilities
- [x] Exact version pinning
- [x] Lockfile committed
- [x] Scripts disabled by default
- [x] No unsafe code execution
- [x] Regular audit checks
- [x] Documented security practices

## 📚 Additional Resources

- [npm Security Best Practices](https://docs.npmjs.com/cli/v9/using-npm/security)
- [OWASP Dependency Check](https://owasp.org/www-project-dependency-check/)
- [Socket.dev Blog](https://socket.dev/blog)
- [Snyk Advisor](https://snyk.io/advisor/)

## 🔄 Version History

- **2024-12-02**: Initial security hardening
  - Removed winston and chalk
  - Reduced to 2 production dependencies
  - Added security documentation
  - Zero vulnerabilities confirmed

---

**Remember**: Security is a process, not a state. Stay vigilant! 🛡️
