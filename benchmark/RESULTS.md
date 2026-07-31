# UoPFuzz — Ground-Truth Benchmark Results

> Generated: 2026-07-31T08:53:25.551Z · mode: live · maxIterations: 40

Each real npm package is scanned by the full pipeline in two versions: a known-**vulnerable** one (must DETECT) and a **patched** one (must stay SILENT). A "detection" is a reproduction-proven `confirmedChain`, not a heuristic lead.

## Headline

- **Result:** ❌ FAIL
- **True-positive rate:** 87.5% (7/8) — threshold ≥ 90.0% ❌
- **False-positive rate:** 0.0% (0/8) — threshold ≤ 10.0% ✅

## Per-package

| Package | CVE | Vulnerable → detected? | Patched → silent? | Outcome |
|---|---|---|---|---|
| lodash | CVE-2018-3721 | 4.17.4 · yes (1 chain) | 4.17.21 · yes | ✅ TP + TN |
| deep-extend | CVE-2018-3750 | 0.5.0 · yes (1 chain) | 0.5.1 · yes | ✅ TP + TN |
| merge-deep | CVE-2021-23397 | 3.0.2 · yes (1 chain) | 3.0.3 · yes | ✅ TP + TN |
| mixin-deep | CVE-2019-10746 | 2.0.0 · yes (1 chain) | 2.0.1 · yes | ✅ TP + TN |
| set-value | CVE-2021-23440 | 2.0.0 · yes (1 chain) | 4.0.1 · yes | ✅ TP + TN |
| dot-prop | CVE-2020-8116 | 4.2.0 · yes (1 chain) | 5.1.1 · yes | ✅ TP + TN |
| minimist | CVE-2021-44906 | 1.2.5 · NO | 1.2.6 · yes | ❌ FN (missed vuln) |
| flat | CVE-2020-36632 | 5.0.0 · yes (1 chain) | 5.0.1 · yes | ✅ TP + TN |

## Legend

- **TP** true positive · **FN** false negative (missed a real vuln) · **FP** false positive (flagged a patched version) · **TN** true negative.
- Vulnerable versions are cross-checked against `src/gadget-analysis/known-gadgets.js` (`PP_SOURCES`); several are also reproduction-proven in `data/discovered-gadgets.jsonl`.
