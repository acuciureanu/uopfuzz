import { test, describe, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  fetchLibraries,
  fetchLibrary,
  resolveNpmPackage,
  filterJSLibraries,
  rankByStars,
  _clearCdnjsCache
} from '../../src/sources/cdnjs.js';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeFetch(responses) {
  let idx = 0;
  return async function mockFetch(_url, _opts) {
    const resp = responses[idx++ % responses.length];
    return {
      ok: true,
      status: 200,
      json: async () => resp
    };
  };
}

let originalFetch;

beforeEach(() => {
  originalFetch = globalThis.fetch;
  // The on-disk cache tier persists across cases; clear it so mocked responses
  // aren't served from a previous test's write (keeps these tests hermetic).
  _clearCdnjsCache();
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  _clearCdnjsCache();
});

// ─── fetchLibraries ────────────────────────────────────────────────────────────

describe('fetchLibraries', () => {
  test('returns results array from API response', async () => {
    globalThis.fetch = makeFetch([{ results: [{ name: 'lodash.js', version: '4.17.21' }] }]);
    const libs = await fetchLibraries({ search: 'lodash', limit: 1 });
    assert.equal(libs.length, 1);
    assert.equal(libs[0].name, 'lodash.js');
  });

  test('returns empty array when results is missing', async () => {
    globalThis.fetch = makeFetch([{}]);
    const libs = await fetchLibraries();
    assert.deepEqual(libs, []);
  });

  test('includes search param in URL', async () => {
    let capturedUrl = '';
    globalThis.fetch = async (url) => {
      capturedUrl = url;
      return { ok: true, status: 200, json: async () => ({ results: [] }) };
    };
    await fetchLibraries({ search: 'react' });
    assert.ok(capturedUrl.includes('search=react'), `URL should include search param: ${capturedUrl}`);
  });
});

// ─── resolveNpmPackage ────────────────────────────────────────────────────────

describe('resolveNpmPackage', () => {
  test('uses autoupdate.target when source is npm', () => {
    const lib = { name: 'lodash.js', autoupdate: { source: 'npm', target: 'lodash' } };
    assert.equal(resolveNpmPackage(lib), 'lodash');
  });

  test('falls back to library name when autoupdate is absent', () => {
    const lib = { name: 'my-lib' };
    assert.equal(resolveNpmPackage(lib), 'my-lib');
  });

  test('falls back to library name when source is not npm', () => {
    const lib = { name: 'my-lib', autoupdate: { source: 'git', target: 'something' } };
    assert.equal(resolveNpmPackage(lib), 'my-lib');
  });
});

// ─── filterJSLibraries ────────────────────────────────────────────────────────

describe('filterJSLibraries', () => {
  test('keeps libraries with fileType js', () => {
    const libs = [
      { name: 'a', fileType: 'js' },
      { name: 'b', fileType: 'css' },
      { name: 'c', fileType: 'js' }
    ];
    const result = filterJSLibraries(libs);
    assert.equal(result.length, 2);
    assert.equal(result[0].name, 'a');
    assert.equal(result[1].name, 'c');
  });

  test('keeps libraries whose latest file ends with .js when fileType is absent', () => {
    const libs = [
      { name: 'a', latest: 'https://cdn/a.min.js' },
      { name: 'b', latest: 'https://cdn/b.css' }
    ];
    const result = filterJSLibraries(libs);
    assert.equal(result.length, 1);
    assert.equal(result[0].name, 'a');
  });

  test('excludes non-js libraries', () => {
    const libs = [{ name: 'font-awesome', fileType: 'css' }];
    assert.equal(filterJSLibraries(libs).length, 0);
  });
});

// ─── rankByStars ──────────────────────────────────────────────────────────────

describe('rankByStars', () => {
  const libs = [
    { name: 'a', github: { stargazers_count: 1000 } },
    { name: 'b', github: { stargazers_count: 50000 } },
    { name: 'c' },  // no github data
    { name: 'd', github: { stargazers_count: 5000 } }
  ];

  test('sorts by star count descending', () => {
    const result = rankByStars(libs, 0);
    assert.equal(result[0].name, 'b');
    assert.equal(result[1].name, 'd');
    assert.equal(result[2].name, 'a');
  });

  test('places libraries without star data last', () => {
    const result = rankByStars(libs, 0);
    assert.equal(result[result.length - 1].name, 'c');
  });

  test('limits to topN when specified', () => {
    const result = rankByStars(libs, 2);
    assert.equal(result.length, 2);
    assert.equal(result[0].name, 'b');
    assert.equal(result[1].name, 'd');
  });

  test('returns all when topN is 0', () => {
    assert.equal(rankByStars(libs, 0).length, 4);
  });

  test('does not mutate the original array', () => {
    const original = [...libs];
    rankByStars(libs, 2);
    assert.deepEqual(libs, original);
  });
});

// ─── retry logic ──────────────────────────────────────────────────────────────

describe('retry on 5xx', () => {
  test('retries up to 3 times on server error then succeeds', async () => {
    let calls = 0;
    globalThis.fetch = async () => {
      calls++;
      if (calls < 3) return { ok: false, status: 503, json: async () => ({}) };
      return { ok: true, status: 200, json: async () => ({ results: [{ name: 'ok' }] }) };
    };
    const libs = await fetchLibraries();
    assert.equal(libs.length, 1);
    assert.equal(calls, 3);
  });

  test('throws after 3 consecutive failures', async () => {
    globalThis.fetch = async () => ({ ok: false, status: 500, json: async () => ({}) });
    await assert.rejects(() => fetchLibraries(), /500/);
  });
});
