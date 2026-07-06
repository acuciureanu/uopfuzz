# Persisting discovered 0-days across runs

## Problem

Every UoPFuzz run is fully independent. A finding classified `novel-0day` today
produces a one-off `results/*.json`/`.md` report and nothing else — nothing is
written back to `known-gadgets.js` or any other durable store, and past results
are never read back in. Run N+1 against the same package has no memory of what
run N found: it re-derives everything from scratch, and there is no growing
inventory of 0-days this tool has found over time.

Separately, the existing `novel-0day` label is informal ("0day" slang) and
imprecise once persistence exists — it needs to distinguish "we've never seen
this and nobody's documented it" from "we found this before, and still nobody's
documented it."

## Goals

1. Give confirmed findings a durable, cross-run home: a full audit trail of
   every vulnerability this tool has confirmed (`undocumented-vulnerability`,
   `known-cve`, `regression-suspect`), so "what has this tool ever found" is an
   answerable question.
2. Recognize a rediscovery of the same bug on a later run, and label it
   distinctly from a first sighting.
3. Rename `novel-0day` → `undocumented-vulnerability` for precision.

## Non-goals

- No changes to how findings are *discovered* or *reproduced* — this is purely
  a post-confirmation classification/persistence layer, same boundary
  `known-gadgets.js`/OSV.dev already occupy.
- No UI/query tool for the store in this iteration — it's a JSONL file,
  greppable/parseable directly. A query CLI can be a later addition if needed.
- No de-duplication or garbage collection of the store. It only grows.

## Design

### Storage

New file `data/discovered-gadgets.jsonl`, one JSON object per line, **append-only**
— no line is ever rewritten. Tracked in git: the point is durable, shared
memory of what this tool has found, not a per-machine cache.

Append-only means "has this been seen before" is answered by scanning for any
*earlier* line with a matching identity key — never a read-modify-write. This
also makes concurrent appends safe: each append is one `write()` syscall
(atomic on POSIX for writes below the pipe buffer size, which every record
here is), so parallel orchestrator instances (`MassRunner`/`VersionRunner`,
`--parallel N`) can't interleave or corrupt each other's lines.

**Identity key**: `package + entryPoint + property` (version-agnostic) — same
model `known-gadgets.js` already uses (a bug is tied to a function/property,
valid across a version range until patched), so a later run on a nearby or
newer version of the same package still recognizes it.

**Record schema**:
```json
{
  "discoveredAt": "2026-07-06T12:00:00.000Z",
  "package": "ejs",
  "version": "3.1.6",
  "entryPoint": "compile",
  "property": "escapeFunction",
  "proofType": "rce",
  "label": "undocumented-vulnerability",
  "description": "CONFIRMED CODE-EXECUTION: ...",
  "cvssVector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N",
  "riskLevel": 5.5,
  "standalonePoC": "// PoC ..."
}
```

### Renaming `novel-0day` → `undocumented-vulnerability`

Mechanical, no behavior change:
- `src/gadget-analysis/novelty.js` — the label string itself, everywhere it's
  assigned or compared.
- `src/reporting/markdown-report.js` — display text and any `label ===
  'novel-0day'` branches.
- `src/orchestrator/index.js` — the plain-text report's equivalent branches.
- `tests/integration/zero-fp-validation.test.js` — assertions that currently
  check `c.label === 'novel-0day'`.
- Any other occurrence turned up by `grep -rn "novel-0day"` across `src/` and
  `tests/`.

### Classification integration

New module `src/gadget-analysis/discovery-store.js`:
- `loadDiscoveries(filePath)` — reads and parses the JSONL file into an array.
  Never throws: missing file, unreadable file, or a malformed line all degrade
  to `[]` (a malformed line is skipped, not fatal to the whole read), mirroring
  the defensive contract `src/sources/osv.js` already uses for OSV.dev lookups.
- `appendDiscovery(filePath, record)` — serializes one record and appends it.
  Never throws: a persistence failure is logged at debug level and otherwise
  swallowed — it must not abort a scan.
- `findPriorSighting(discoveries, { package, entryPoint, property })` — returns
  the earliest matching record, or `null`.

`classifyFinding(finding, context)` (in `novelty.js`) gains an optional
`context.priorDiscoveries` array, defaulting to `[]` (same backward-compatible
pattern `osvVulns` already uses — passing nothing is identical to today).
Precedence, in order:

1. Static DB match → `known-cve` (unchanged — an actual CVE always wins,
   even over our own prior sighting of the same bug).
2. Regression-suspect condition → `regression-suspect` (unchanged).
3. `findPriorSighting(priorDiscoveries, ...)` finds an earlier record for this
   `package + entryPoint + property` → **`previously-discovered`** (new),
   carrying that record's `discoveredAt`/`version` for the report line.
4. Otherwise → `undocumented-vulnerability` (first sighting).

`classifyFinding` itself stays pure and synchronous — the orchestrator loads
`discovered-gadgets.jsonl` once per run (same timing as the existing per-run
OSV fetch) and passes the array in; no I/O happens inside the classifier
itself, keeping it trivially unit-testable with synthetic arrays exactly like
the existing `osvVulns` tests in `zero-fp-validation.test.js`.

### Write path

In `src/orchestrator/index.js`'s `proveAndRecord`, once `chain.novelty` is
assigned and the chain is pushed onto `results.confirmedChains`, call
`appendDiscovery(...)` for it — unconditionally, for all three labels. This is
the "full audit trail" behavior: every confirmed finding this session becomes
one more line in the store, whether or not it was already documented.

### Reporting

`markdown-report.js` and the orchestrator's plain-text report gain a rendering
branch for `previously-discovered`, alongside the existing
`regressionSuspect`/`osvNote` branches:

> ℹ Previously discovered by this tool on `<discoveredAt>` at
> `<package>@<version>` — no public CVE.

## Testing

Hermetic tests (no real writes under `data/` — use a temp file path per test):

- First sighting of a `(package, entryPoint, property)` → classified
  `undocumented-vulnerability`, and a matching record is appended to the store.
- A second run with a matching prior record → classified
  `previously-discovered`, carrying the first record's date/version.
- A finding that also matches the static DB or OSV still classifies
  `known-cve` even when a prior "previously-discovered" record exists for the
  same key (static/OSV precedence is unchanged).
- `loadDiscoveries` on a missing file, an unreadable file, and a file with one
  malformed line (plus otherwise-valid lines) all degrade gracefully — `[]` or
  the valid subset, never a thrown error.
- Existing `novel-0day` assertions across the test suite updated to
  `undocumented-vulnerability`; full suite still green.

## Open questions / risks

- POSIX atomic-append guarantees assume a POSIX-ish filesystem underneath.
  This repo runs under WSL (`/mnt/c/Users/...`), where the backing store is an
  NTFS mount through the 9P/DrvFs layer — small-write atomicity is a weaker
  guarantee there than on native ext4. Acceptable for a research tool; would
  need real file locking if this ever ran on heavily concurrent native
  Windows or networked filesystems.
- The store only grows; no compaction/rotation is in scope now. Fine at
  research-tool scale (dozens to low thousands of records); would need
  revisiting well before that becomes a performance concern.
