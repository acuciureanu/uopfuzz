# Security Policy

UoPFuzz is a security research tool: it **executes untrusted target code** and
generates **real, working proof-of-concept exploits**. Please read the "Safety
model" section of the [README](README.md) before running it.

## Reporting a vulnerability in UoPFuzz itself

If you find a security issue in this tool — for example, a way for a malicious
target package to escape the intended isolation, or a flaw that could cause the
tool to mislead an operator — please report it privately:

- Email: **alexandru.cuciureanu@gmail.com** with a subject beginning `[uopfuzz-security]`
- Or open a GitHub [private security advisory](https://github.com/acuciureanu/uopfuzz/security/advisories/new)

Please do not open a public issue for a security report. I aim to acknowledge
reports within a few days. There is no bug-bounty program; this is a personal
open-source project.

## Findings produced by the tool

UoPFuzz can surface gadgets in third-party libraries, some labelled
`UNDOCUMENTED VULNERABILITY` (meaning: not found in the tool's built-in advisory
database or OSV.dev — **not** a verified novel 0-day). The tool **files nothing
externally on your behalf**. If you believe you have found a genuine, previously
unknown vulnerability in a third-party package:

- Verify it independently and against public advisories first.
- Disclose it **responsibly and privately** to that package's maintainers.
- Do not publish a working exploit before the maintainers have had a reasonable
  opportunity to respond.

You are responsible for using this tool ethically and only against code you are
authorized to test.

## Supported versions

This project is pre-1.0 and provided as-is. Only the latest `main` receives
fixes.
