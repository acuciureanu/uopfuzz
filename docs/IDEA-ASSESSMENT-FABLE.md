# UoPFuzz — Re-Assessment (empirical pass)

*Companion to `IDEA-ASSESSMENT.md`. That pass read the code and scored the idea. This pass
**ran** the tool and probed its claims. The conclusions differ materially.*

**Headline:** The idea is still sound, but the tool's advanced detection oracle is **silently
broken at runtime** and — verified end-to-end — **fails to detect the single most famous
prototype-pollution vulnerability in existence**, which is listed in its own ground-truth
database. The "116/116 tests pass, world-class" framing is misleading: no test exercises the
detection core.

---

## 1. The finding that changes everything

`src/instrumentation/differential.js` — the module holding *every* advertised advanced
capability (GHunter-style multi-prototype monitoring, merge-PP source detection, URL-gadget
tests, forced-branch execution, multi-property co-pollution) — **throws on its own snapshot
function** the moment it runs:

```
snapshotPrototype()  →  proto[key]  where proto = Function.prototype, key = 'caller'
TypeError: 'caller', 'callee', and 'arguments' properties may not be accessed on strict mode functions
```

The "World-class PP gadget discovery … cross-prototype detection" commit added
`Function.prototype`, `Array.prototype`, `String.prototype` to `MONITORED_PROTOTYPES`
(a real, GHunter-motivated improvement) but reads every own-property value —
including the poisoned `caller`/`arguments`/`callee` accessors on `Function.prototype`, which
throw in strict mode. ES modules are always strict, so **the read always throws.**

Every call site swallows it:

```js
try { return await executeDifferential(...); }
catch (error) { logger.debug(...); return null; }   // instrumentation/index.js:335
```

So in `--no-sandbox` mode the differential phase returns `null` for **every input** and
reports nothing — a silent, total failure of the detection core.

### Verified, not theorized

```
GROUND TRUTH: lodash.merge polluted Object.prototype.grndtruth = YES
TOOL executeMergePPTest THREW: 'caller','callee','arguments' … strict mode
```

End-to-end run, default settings:

```
$ node src/cli.js --target lodash@4.17.4 --max-iterations 2
Analysis complete: 0 confirmed gadgets, 1 unconfirmed candidates
```

`lodash@4.17.4` is vulnerable to **CVE-2018-3721** (`merge`) and **CVE-2019-10744**
(`defaultsDeep`) — the textbook PP bugs, and both are entries in the tool's own
`PP_SOURCES` list. The tool detected **zero**. This is a false negative on the canonical case.

## 2. Two oracles, neither delivering the advertised behavior

There are **two divergent implementations** of the differential oracle:

- `src/instrumentation/differential.js` — the advanced 4-prototype version. **Crashes.**
- `src/utils/sandbox-worker.js` — a separate reimplementation that only snapshots
  `Object.prototype`. Runs (that's why the sandbox run above didn't crash) but **does not
  contain** the GHunter multi-prototype / forced-branch / merge-source logic.

Consequence: with `--sandbox` (the default) the flagship features don't execute as designed;
with `--no-sandbox` they execute and crash-to-null. There is **no configuration in which the
advertised oracle actually works.** Two copies of the same logic also means every future fix
must be made twice, and they will keep drifting.

## 3. The test suite creates false confidence

116/116 green — but I found **zero** tests importing or exercising `executeDifferential`,
`snapshotPrototype`, `executeMergePPTest`, `executeURLGadgetTest`, or
`executeForcedBranchDifferential`. The one test mentioning "differential" only checks
Markdown report formatting on canned data. The suite covers input generation, coverage
utilities, cdnjs parsing, and reporting — everything *except* detection. A fatal crash in the
core sailed through CI green. This is the most important gap: **the thing the tool exists to
do is the thing that isn't tested.**

## 4. Oracle-fidelity gap (independent of the crash)

Real pollution installs an **enumerable data property** on `Object.prototype`; the tool's
trap installs a **non-enumerable accessor**. Verified difference:

| Check | Real PP (data prop) | Tool's trap (accessor) |
|---|---|---|
| `'x' in obj` | true | true |
| `for-in` sees `x` | **true** | **false** |
| `obj.x` value | value | value |

Merge/extend/clone gadgets propagate pollution precisely by iterating with `for…in`. Because
the trap is invisible to `for…in`, an entire class of real gadgets is unobservable to the
oracle — a systematic false-negative source that a benchmark would surface, on top of the crash.

## 5. What's still genuinely good

The concept and most of the surrounding engineering are real and worth preserving:

- The **differential causation** insight (clean vs. polluted, compare) is the correct core.
- Auto-discovery works — it walked lodash's exports and found 20 entry points, 60 sequences,
  21 pollution candidates with no config file. That machinery is solid.
- The literature grounding (Silent Spring, GHunter, Dasty) is real and well-chosen.
- **The bug is a one-line fix.** Guarding the read (`try { v = proto[key] } catch {}`)
  restores the snapshot, and the merge-PP logic then correctly reports `Object.polluted`
  from real lodash — I verified this. The underlying detection logic is sound once it runs.

## 6. Revised scoring — split the idea from the artifact

The first pass conflated these and landed at 7.4. They must be separated.

| | Score | Basis |
|---|---:|---|
| **The idea** (differential PP gadget hunting at scale) | **7.5 / 10** | Relevant, sound, well-read. Unchanged. |
| **The current artifact's real capability** | **3 / 10** | Flagship oracle crashes; misses the canonical CVE; detection core untested; duplicated implementations. |

The gap between these two numbers *is* the assessment. The previous "engineering is ahead of
its evidence" was too kind — read-only review credited features that do not run. Corrected:
**the evidence, once gathered, shows the flagship engineering does not currently work; but the
failure is shallow and recoverable, not architectural.**

## 7. Revised plan — verification before ambition

Reorder the earlier plan. Do **not** launch a mass 0-day hunt on top of a broken, untested
oracle; it would produce confident silence and be mistaken for "the libraries are safe."

1. **Fix the crash** (1 line): guard `proto[key]` in `snapshotPrototype`, or drop
   `caller`/`arguments`/`callee` from the walk.
2. **Unify the two oracles.** One implementation, imported by both the in-process and sandbox
   paths. Delete the `sandbox-worker.js` fork or make it a thin wrapper.
3. **Regression-test the core against ground truth.** For every entry in `PP_SOURCES`
   (lodash, jquery, minimist, set-value…), assert the oracle confirms the known-vulnerable
   version and stays silent on the patched one. This is the test that was missing. Wire it
   into CI so a core crash can never be green again.
4. **Address the fidelity gap:** add a data-property (enumerable) oracle mode and compare its
   detections against the accessor mode; keep whichever the benchmark shows is more faithful.
5. **Only then** proceed to calibration, source→gadget→sink chaining, and the mass hunt from
   the original plan — now on a foundation that provably detects what it claims to.

### Bottom line
A good idea with sound bones, currently undermined by a trivial-but-fatal bug that the test
suite was structured not to catch. It is one line and one missing regression test away from
being real. Prove it on the CVEs it already knows about before pointing it at the unknown.
</content>
