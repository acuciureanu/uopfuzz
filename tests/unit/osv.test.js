import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert';

import {
  fetchOsvVulns,
  _clearOsvCache,
  isVersionAffected,
  isPrototypePollution,
  preferredVulnId,
  describeMatchedRange,
  osvKnownCve,
  osvOtherAdvisories,
} from '../../src/sources/osv.js';

// Fixtures shaped like real OSV /v1/query responses.
const PP_VULN = {
  id: 'GHSA-jf85-cpcp-j695',
  summary: 'Prototype Pollution in lodash',
  aliases: ['CVE-2019-10744'],
  database_specific: { cwe_ids: ['CWE-1321'] },
  affected: [{
    package: { name: 'lodash', ecosystem: 'npm' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.12' }] }],
    versions: ['4.17.4', '4.17.11'],
  }],
};

const CMDINJ_VULN = {
  id: 'GHSA-35jh-r3h4-6jhm',
  summary: 'Command Injection in lodash',
  aliases: ['CVE-2021-23337'],
  database_specific: { cwe_ids: ['CWE-77', 'CWE-94'] },
  affected: [{
    package: { name: 'lodash', ecosystem: 'npm' },
    ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '4.17.21' }] }],
  }],
};

// ─── Network client (mocked fetch, cdnjs.test.js convention) ─────────────────
describe('fetchOsvVulns (mocked fetch)', () => {
  let originalFetch;
  beforeEach(() => { originalFetch = globalThis.fetch; _clearOsvCache(); });
  afterEach(() => { globalThis.fetch = originalFetch; });

  test('returns {ok:true, vulns} and sends the correct query body', async () => {
    let sentBody = null;
    globalThis.fetch = async (url, opts) => {
      sentBody = JSON.parse(opts.body);
      return { ok: true, status: 200, json: async () => ({ vulns: [PP_VULN] }) };
    };
    const r = await fetchOsvVulns('lodash', '4.17.4');
    assert.equal(r.ok, true);
    assert.equal(r.vulns.length, 1);
    assert.equal(sentBody.version, '4.17.4');
    assert.equal(sentBody.package.name, 'lodash');
    assert.equal(sentBody.package.ecosystem, 'npm');
  });

  test('retries up to 3 times on 5xx then succeeds', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      if (calls < 3) return { ok: false, status: 503, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ vulns: [] }) };
    };
    const r = await fetchOsvVulns('x', '1.0.0');
    assert.equal(calls, 3);
    assert.equal(r.ok, true);
  });

  test('NEVER throws on persistent 5xx — resolves {ok:false} (unlike cdnjs)', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 500, json: async () => ({}) });
    let r;
    await assert.doesNotReject(async () => { r = await fetchOsvVulns('x', '1.0.0'); });
    assert.equal(r.ok, false);
    assert.match(r.error, /500/);
  });

  test('NEVER throws on network error (e.g. --network=none) — {ok:false, vulns:[]}', async () => {
    globalThis.fetch = async () => { throw new TypeError('fetch failed'); };
    let r;
    await assert.doesNotReject(async () => { r = await fetchOsvVulns('x', '1.0.0'); });
    assert.equal(r.ok, false);
    assert.deepEqual(r.vulns, []);
  });

  test('NEVER throws on malformed JSON — {ok:false}', async () => {
    globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => { throw new Error('bad json'); } });
    const r = await fetchOsvVulns('x', '1.0.0');
    assert.equal(r.ok, false);
  });

  test('bounded by timeout — resolves even when fetch never settles', async () => {
    globalThis.fetch = async (url, opts) => new Promise((_, reject) => {
      opts.signal.addEventListener('abort', () => reject(new Error('aborted')));
    });
    let r;
    await assert.doesNotReject(async () => { r = await fetchOsvVulns('x', '1.0.0', { timeoutMs: 50 }); });
    assert.equal(r.ok, false);
  });

  test('caches identical (pkg, version) lookups', async () => {
    let calls = 0;
    globalThis.fetch = async () => { calls++; return { ok: true, status: 200, json: async () => ({ vulns: [] }) }; };
    await fetchOsvVulns('dup', '1.2.3');
    await fetchOsvVulns('dup', '1.2.3');
    assert.equal(calls, 1);
  });
});

// ─── Pure helpers (no network) ───────────────────────────────────────────────
describe('OSV pure helpers', () => {
  test('isVersionAffected: introduced/fixed interval', () => {
    assert.equal(isVersionAffected(PP_VULN, '4.17.4'), true);
    assert.equal(isVersionAffected(PP_VULN, '4.17.12'), false); // fixed is exclusive
    assert.equal(isVersionAffected(PP_VULN, '4.17.21'), false);
  });

  test('isVersionAffected: explicit versions[] membership', () => {
    const v = { affected: [{ versions: ['1.0.0', '1.0.1'] }] };
    assert.equal(isVersionAffected(v, '1.0.1'), true);
    assert.equal(isVersionAffected(v, '1.0.2'), false);
  });

  test('isVersionAffected: unbounded introduced (no fixed)', () => {
    const v = { affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '2.0.0' }] }] }] };
    assert.equal(isVersionAffected(v, '2.5.0'), true);
    assert.equal(isVersionAffected(v, '1.9.0'), false);
  });

  test('isVersionAffected: last_affected is inclusive', () => {
    const v = { affected: [{ ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { last_affected: '3.0.0' }] }] }] };
    assert.equal(isVersionAffected(v, '3.0.0'), true);
    assert.equal(isVersionAffected(v, '3.0.1'), false);
  });

  test('isVersionAffected: disjoint introduced/fixed pairs', () => {
    const v = { affected: [{ ranges: [{ type: 'SEMVER', events: [
      { introduced: '1.0.0' }, { fixed: '1.5.0' }, { introduced: '2.0.0' }, { fixed: '2.5.0' },
    ] }] }] };
    assert.equal(isVersionAffected(v, '1.2.0'), true);
    assert.equal(isVersionAffected(v, '1.7.0'), false); // patched interval
    assert.equal(isVersionAffected(v, '2.2.0'), true);
  });

  test('isVersionAffected: non-SEMVER/ECOSYSTEM ranges are ignored', () => {
    const v = { affected: [{ ranges: [{ type: 'GIT', events: [{ introduced: '0' }] }] }] };
    assert.equal(isVersionAffected(v, '1.0.0'), false);
  });

  test('isPrototypePollution: CWE-1321 vs command injection', () => {
    assert.equal(isPrototypePollution(PP_VULN), true);
    assert.equal(isPrototypePollution(CMDINJ_VULN), false);
  });

  test('isPrototypePollution: keyword fallback when no CWE tagged', () => {
    assert.equal(isPrototypePollution({ summary: 'Prototype Pollution in foo' }), true);
    assert.equal(isPrototypePollution({ details: 'attacker can set __proto__' }), true);
    assert.equal(isPrototypePollution({ summary: 'Denial of Service' }), false);
  });

  test('preferredVulnId prefers a CVE alias, else the id', () => {
    assert.equal(preferredVulnId(PP_VULN), 'CVE-2019-10744');
    assert.equal(preferredVulnId({ id: 'GHSA-xxxx', aliases: ['GHSA-yyyy'] }), 'GHSA-xxxx');
  });

  test('describeMatchedRange reconstructs a range string', () => {
    assert.equal(describeMatchedRange(PP_VULN, '4.17.4'), '<4.17.12');
  });

  test('osvKnownCve returns only PP-class matches; skips unrelated CVEs', () => {
    // A version covered ONLY by a command-injection advisory must NOT be "known".
    assert.equal(osvKnownCve([CMDINJ_VULN], '4.17.20'), null);
    const hit = osvKnownCve([CMDINJ_VULN, PP_VULN], '4.17.4');
    assert.ok(hit);
    assert.equal(hit.cve, 'CVE-2019-10744');
  });

  test('osvOtherAdvisories lists non-PP advisories covering the version', () => {
    const others = osvOtherAdvisories([CMDINJ_VULN, PP_VULN], '4.17.4');
    assert.deepEqual(others, ['CVE-2021-23337']);
  });
});
