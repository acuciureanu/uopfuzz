/**
 * Ground-truth benchmark corpus.
 *
 * A labelled set of REAL npm packages, each pairing a known-VULNERABLE version
 * (the oracle must DETECT) with a PATCHED version (the oracle must stay SILENT).
 * This is the evidence the project's own assessment docs call "the critical
 * phase": a measured true-positive / false-positive result on real code, not on
 * synthetic fixtures.
 *
 * Every entry is derived from — and kept consistent with — the CVE database in
 * `src/gadget-analysis/known-gadgets.js` (`PP_SOURCES`):
 *   - `vulnerableVersion` falls INSIDE the CVE's affected range.
 *   - `patchedVersion`   falls OUTSIDE every affected range for that package.
 * Several `vulnerableVersion`s are already reproduction-proven in
 * `data/discovered-gadgets.jsonl`, so their "detect" side is known-good.
 *
 * These are all prototype-pollution SOURCES (merge/extend/set-family), so the
 * expected proof is a real prototype mutation (`proofType: 'pp'`). They are
 * small, well-known, pure-JS packages — the low-risk tier that is still only run
 * inside the container / the ephemeral CI VM, never ad hoc on a host.
 *
 * To expand: add a pair, confirm the vulnerable version is inside the matching
 * `PP_SOURCES` range and the patched version is outside all of them, then run
 * the benchmark to confirm it lands TP on the vulnerable side and TN on the
 * patched side before trusting it as ground truth.
 */

/**
 * @typedef {object} CorpusEntry
 * @property {string}  package           - npm package name.
 * @property {string}  cve               - primary CVE/advisory id (for the report).
 * @property {string}  entryPoint        - the vulnerable function (informational; 'default' = bare export).
 * @property {'pp'|'rce'} proofType       - the ground-truth proof the oracle must produce.
 * @property {string}  vulnerableVersion - a version INSIDE the affected range (expect DETECT).
 * @property {string}  patchedVersion    - a version OUTSIDE all affected ranges (expect SILENT).
 * @property {string}  [note]            - human context.
 */

/** @type {CorpusEntry[]} */
export const BENCHMARK_CORPUS = [
  {
    package: 'lodash',
    cve: 'CVE-2018-3721',
    entryPoint: 'merge',
    proofType: 'pp',
    vulnerableVersion: '4.17.4',
    patchedVersion: '4.17.21',
    note: 'The canonical PP source. merge() pollutes Object.prototype; fixed by 4.17.5+ guards.',
  },
  {
    package: 'deep-extend',
    cve: 'CVE-2018-3750',
    entryPoint: 'default',
    proofType: 'pp',
    vulnerableVersion: '0.5.0',
    patchedVersion: '0.5.1',
    note: 'Unguarded recursive extend; patched in 0.5.1.',
  },
  {
    package: 'merge-deep',
    cve: 'CVE-2021-23397',
    entryPoint: 'default',
    proofType: 'pp',
    vulnerableVersion: '3.0.2',
    patchedVersion: '3.0.3',
    note: 'Deep merge PP; patched in 3.0.3.',
  },
  // defaults-deep (CVE-2019-10793) was intentionally removed from the corpus.
  // Its "patched" 0.2.4 — the LATEST published release — is NOT actually fixed:
  // it still pollutes via the realistic `{"constructor":{"prototype":{…}}}` JSON
  // vector (only the `__proto__` path was guarded). Verified by direct
  // reproduction: `defaultsDeep({}, {constructor:{prototype:{polluted:1}}})`
  // adds Object.prototype.polluted. Since no non-vulnerable release exists, it
  // cannot serve as a vuln/patched pair — the tool CORRECTLY flags 0.2.4, so
  // scoring that as a "false positive on a patched version" was a corpus error,
  // not a tool defect. (The tool's own zero-FP gate is what surfaced this.)
  {
    package: 'mixin-deep',
    cve: 'CVE-2019-10746',
    entryPoint: 'default',
    proofType: 'pp',
    vulnerableVersion: '2.0.0',
    patchedVersion: '2.0.1',
    note: 'Deep mixin PP; patched in 2.0.1.',
  },
  {
    package: 'set-value',
    cve: 'CVE-2021-23440',
    entryPoint: 'default',
    proofType: 'pp',
    vulnerableVersion: '2.0.0',
    patchedVersion: '4.0.1',
    note: 'Path-based set() PP; patched in 4.0.1.',
  },
  {
    package: 'dot-prop',
    cve: 'CVE-2020-8116',
    entryPoint: 'set',
    proofType: 'pp',
    vulnerableVersion: '4.2.0',
    patchedVersion: '5.1.1',
    note: 'Path-based set() PP; patched in 5.1.1.',
  },
  {
    package: 'minimist',
    cve: 'CVE-2021-44906',
    entryPoint: 'parse',
    proofType: 'pp',
    vulnerableVersion: '1.2.5',
    patchedVersion: '1.2.6',
    note: 'argv --__proto__.x parsing PP; patched in 1.2.6.',
  },
  {
    package: 'flat',
    cve: 'CVE-2020-36632',
    entryPoint: 'unflatten',
    proofType: 'pp',
    vulnerableVersion: '5.0.0',
    patchedVersion: '5.0.1',
    note: 'unflatten() PP; patched in 5.0.1.',
  },
];

/**
 * Success thresholds — the project's stated criteria (docs/IDEA-ASSESSMENT.md
 * "Success criteria"): the benchmark PASSES only when the oracle detects at
 * least this fraction of vulnerable versions AND false-alarms on at most this
 * fraction of patched versions.
 */
export const THRESHOLDS = {
  minTruePositiveRate: 0.90,
  maxFalsePositiveRate: 0.10,
};
