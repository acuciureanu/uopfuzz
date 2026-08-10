---
name: Bug report
about: Something in UoPFuzz is broken or misbehaving
title: ""
labels: bug
assignees: ""
---

**Describe the bug**
A clear description of what went wrong.

**To reproduce**
The exact command you ran (e.g. `node src/cli.js ...`, `npm test`) and, if
applicable, the target package/config involved.

**Expected behavior**
What you expected to happen.

**Actual behavior**
What actually happened. Paste the relevant output/stack trace.

**Environment**

- OS: <!-- e.g. Ubuntu 24.04, Windows 11 + WSL2 -->
- Node.js version: <!-- `node --version`; must be >= 20 -->
- UoPFuzz commit or version:
- Running inside the container (`run-sandboxed.sh` / devcontainer)? yes/no

**Security note**
If the bug is a security issue in UoPFuzz itself (e.g. an isolation escape), do
NOT file it here — see [SECURITY.md](../SECURITY.md) for private reporting.
