# Discovery sweep

Tooling to hunt for **undocumented prototype-pollution gadgets** in current npm
libraries — especially freshly published ones, which are the least audited.

The pipeline is three composable steps:

```
scan-recent.mjs  →  targets.txt  →  sweep.sh  →  results/hunt/  →  triage.mjs
   (discover)                        (fuzz in                        (classify +
                                      the sandbox)                    surface candidates)
```

Nothing here weakens the tool's core guarantee: every reported gadget is
**reproduced twice in fresh processes**, and a finding is only called
*undocumented* when the static DB, **OSV.dev**, **and** the **GitHub Advisory
Database** all have no advisory for it.

## 1. Discover recently-updated candidates

```bash
# PP-prone packages published today (UTC), ranked by weekly downloads:
node scripts/discovery/scan-recent.mjs --max 40 --out targets-today.txt

# a wider window / custom cutoff:
node scripts/discovery/scan-recent.mjs --since 2026-07-24 --max 40 --out targets.txt
```

Flags: `--since <ISO>` (default: today 00:00 UTC), `--max <n>`,
`--min-downloads <n>` (default 50), `--keywords a,b,c`, `--no-name-filter`
(scan every keyword hit, not just packages whose *name* looks PP-prone),
`--out <file>`.

Relevance is intentionally filtered to packages that expose a fuzzable surface
(merge / clone / deep-set / defaults / object-path / parse). Coverage it does
**not** provide — brand-new packages outside a keyword's top results — is logged,
never silently dropped. You can always hand-write a `targets.txt`.

## 2. Sweep them through the sandbox

Requires Docker (see the repo README "Safety model"). Reuses `./run-sandboxed.sh`,
so every target runs with `cap-drop=ALL`, seccomp, `no-new-privileges`, non-root,
read-only rootfs, and pid/memory caps.

```bash
scripts/discovery/sweep.sh targets-today.txt 30 15   # <file> [max-iters] [timeout-s]
```

Per-target logs and machine-readable results land under `results/hunt/<pkg>/`
(git-ignored).

## 3. Triage

```bash
node scripts/discovery/triage.mjs results/hunt --json summary.json
```

Prints a per-target verdict table and dumps the standalone PoC for every
reproduced **undocumented** candidate. Exit code `2` when at least one candidate
needs human eyes (so a scheduler can gate on it), `0` otherwise.

## Responsible disclosure

A surviving candidate is a *lead*, not a published advisory. **This tool is the
finder, never the disclosure vehicle.** Confirm it by hand, then report it
privately to the package maintainer (or via the GitHub Security Advisory flow on
their repo). Do not open a public issue with a working exploit.

## Scheduling

`.github/workflows/recent-scan.yml` runs this pipeline on a daily schedule (and
on demand via *workflow_dispatch*). It uploads the sweep artifact and opens a
tracking issue **only** when a reproduced undocumented candidate survives triage.
It is informational and never gates other CI.
