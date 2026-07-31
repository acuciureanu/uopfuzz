import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';

import {
  fetchNpmAdvisories,
  npmAdvisoryToOsvVuln,
  _clearNpmAdvisoryCache,
} from '../../src/sources/npm-advisories.js';
import { isPrototypePollution, isVersionAffected, preferredVulnId, osvKnownCve } from '../../src/sources/osv.js';

// Shaped like a real npm bulk-advisory-endpoint entry.
const DEEP_SET_ADV = {
  id: 1097165,
  url: 'https://github.com/advisories/GHSA-wgxm-rg53-h2c6',
  title: "Prototype pollution vulnerability in 'deep-set'",
  severity: 'critical',
  vulnerable_versions: '>=1.0.0 <=1.0.1',
  cwe: ['CWE-1321'],
  cvss: { score: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
};

describe('fetchNpmAdvisories (mocked fetch)', () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; _clearNpmAdvisoryCache(); });
  afterEach(() => { globalThis.fetch = originalFetch; });

  test('sends {pkg:[version]} and returns the advisories for that key', async () => {
    let sentBody = null;
    globalThis.fetch = async (_url, opts) => {
      sentBody = JSON.parse(opts.body);
      return { ok: true, status: 200, json: async () => ({ 'deep-set': [DEEP_SET_ADV] }) };
    };
    const r = await fetchNpmAdvisories('deep-set', '1.0.1');
    assert.equal(r.ok, true);
    assert.equal(r.advisories.length, 1);
    assert.deepEqual(sentBody, { 'deep-set': ['1.0.1'] });
  });

  test('a package with no advisories yields an empty list, not an error', async () => {
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({}) });
    const r = await fetchNpmAdvisories('deepmerge', '4.3.1');
    assert.equal(r.ok, true);
    assert.deepEqual(r.advisories, []);
  });

  test('NEVER throws — a network failure resolves to {ok:false, advisories:[]}', async () => {
    globalThis.fetch = async () => { throw new Error('ECONNREFUSED'); };
    const r = await fetchNpmAdvisories('deep-set', '1.0.1');
    assert.equal(r.ok, false);
    assert.deepEqual(r.advisories, []);
    assert.match(r.error, /ECONNREFUSED/);
  });

  test('a 4xx (non-ok) response resolves to {ok:false}, never throws', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 400, json: async () => ({}) });
    const r = await fetchNpmAdvisories('deep-set', '1.0.1');
    assert.equal(r.ok, false);
  });
});

describe('npmAdvisoryToOsvVuln adapter', () => {
  test('produces a shape the OSV classifier consumes as a known PP CVE', () => {
    const vuln = npmAdvisoryToOsvVuln(DEEP_SET_ADV, '1.0.1');
    // Recognised as prototype-pollution (via CWE-1321) and affecting the version.
    assert.equal(isPrototypePollution(vuln), true);
    assert.equal(isVersionAffected(vuln, '1.0.1'), true);
    // The GHSA id is extracted from the url and used as the reporting id.
    assert.equal(preferredVulnId(vuln), 'GHSA-wgxm-rg53-h2c6');
    // Provenance marker so the disclosure classifier can credit GHSA, not OSV.
    assert.equal(vuln._source, 'ghsa');
  });

  test('osvKnownCve matches a GHSA-adapted advisory (the OSV blind-spot fix)', () => {
    // Simulates the exact bug this module fixes: OSV returns nothing, but the
    // GitHub Advisory DB has the CVE. Merged, the classifier must see known-cve.
    const merged = [npmAdvisoryToOsvVuln(DEEP_SET_ADV, '1.0.1')];
    const hit = osvKnownCve(merged, '1.0.1');
    assert.ok(hit, 'a GHSA-only advisory must be recognised as a known CVE');
    assert.equal(hit.cve, 'GHSA-wgxm-rg53-h2c6');
  });

  test('prefers a CVE alias over the GHSA id when present', () => {
    const withCve = { ...DEEP_SET_ADV, cves: ['CVE-2021-25944'] };
    const vuln = npmAdvisoryToOsvVuln(withCve, '1.0.1');
    assert.equal(preferredVulnId(vuln), 'CVE-2021-25944');
  });

  test('an advisory whose title (no CWE) says prototype pollution is still recognised', () => {
    const noCwe = { url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc',
      title: 'Prototype Pollution in thing', cwe: [] };
    const vuln = npmAdvisoryToOsvVuln(noCwe, '2.0.0');
    assert.equal(isPrototypePollution(vuln), true);   // keyword fallback
    assert.equal(preferredVulnId(vuln), 'GHSA-aaaa-bbbb-cccc');
  });
});
