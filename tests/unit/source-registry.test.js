import { test, describe, afterEach } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  loadSources, appendSourceIfNew, sourceFromPpProof, REFERENCE_SOURCE,
} from '../../src/verification/source-registry.js';

function tmpFile() {
  return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'uopfuzz-src-')), 'proven-sources.jsonl');
}

describe('source-registry', () => {
  const created = [];
  afterEach(() => { for (const f of created.splice(0)) fs.rmSync(path.dirname(f), { recursive: true, force: true }); });

  test('loadSources returns [] for a missing file (never throws)', () => {
    assert.deepEqual(loadSources(path.join(os.tmpdir(), 'does-not-exist-xyz.jsonl')), []);
  });

  test('append then load round-trips; malformed lines are skipped', () => {
    const f = tmpFile(); created.push(f);
    const entry = { package: 'assign-deep', version: '1.0.0', entryPoint: 'assign-deep', callConvention: 'fn(target, payload)', payloadKind: 'proto-json' };
    assert.equal(appendSourceIfNew(entry, f), true);
    fs.appendFileSync(f, 'not json\n');
    const loaded = loadSources(f);
    assert.equal(loaded.length, 1);
    assert.equal(loaded[0].package, 'assign-deep');
  });

  test('appendSourceIfNew dedups by package+entryPoint+convention+payloadKind', () => {
    const f = tmpFile(); created.push(f);
    const entry = { package: 'p', entryPoint: 'p', callConvention: 'fn(payload)', payloadKind: 'proto-json' };
    assert.equal(appendSourceIfNew(entry, f), true);
    assert.equal(appendSourceIfNew({ ...entry }, f), false); // same identity → not written again
    assert.equal(appendSourceIfNew({ ...entry, payloadKind: 'proto-path' }, f), true); // different payload kind → new
    assert.equal(loadSources(f).length, 2);
  });

  test('sourceFromPpProof builds an entry only when the proof is chainable', () => {
    const ctx = { package: 'merge-thing', version: '2.0.0', entryPoint: 'merge-thing' };
    const good = sourceFromPpProof({ callConvention: 'fn(target, payload)', payloadKind: 'proto-json' }, ctx);
    assert.equal(good.package, 'merge-thing');
    assert.equal(good.payloadKind, 'proto-json');
    // A proof missing the payload kind/convention is not a usable source.
    assert.equal(sourceFromPpProof({ callConvention: 'fn(payload)' }, ctx), null);
    assert.equal(sourceFromPpProof({}, ctx), null);
    assert.equal(sourceFromPpProof({ payloadKind: 'proto-json', callConvention: 'fn(payload)' }, { package: '' }), null);
  });

  test('REFERENCE_SOURCE points at the hermetic vuln-merge fixture', () => {
    assert.ok(REFERENCE_SOURCE.fixture);
    assert.ok(fs.existsSync(path.join(REFERENCE_SOURCE.package, 'package.json')), 'vuln-merge fixture exists');
    assert.equal(REFERENCE_SOURCE.entryPoint, 'merge');
    assert.equal(REFERENCE_SOURCE.payloadKind, 'proto-json');
  });
});
