import { test, describe } from 'node:test';
import assert from 'node:assert';

import { discoverTarget } from '../../src/target-integration/discovery.js';

// Regression for a real-world miss: @feathersjs/commons (and lodash, underscore,
// and every library following that convention) exports its entire public API
// under a namespace object literally named `_`. Discovery's private-member
// filter skipped any export whose name starts with `_`, which is meant to hide
// internal helpers like `_privateHelper` — but a bare `_` is a PUBLIC namespace,
// not a private member. Skipping it discarded `_.merge`, the one function that
// carries CVE-2026-54335, before it was ever probed.
//
// The convention here is general: descend into a namespace object regardless of
// whether its container name looks private; keep filtering genuinely-private
// leaf members inside it. No package name or method name is hardcoded.
describe('discovery descends into underscore-named public namespaces', () => {
  test('finds a merge function exported under a `_` namespace', async () => {
    // Lodash/underscore/feathers-commons shape: public utilities under `_`.
    const mod = {
      _: {
        merge(target, source) { return Object.assign(target, source); },
        extend(target, source) { return Object.assign(target, source); },
      },
      stripSlashes(s) { return s; },
    };

    const config = await discoverTarget(mod, 'ns-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    const mergeEp = names.find((n) => n === '_.merge' || n.split('.').pop() === 'merge');
    assert.ok(
      mergeEp,
      `expected a merge entry point under the _ namespace; got: ${names.join(', ')}`,
    );
  });

  // Merge-likeness must mean DEEP merge (the prototype-pollution-capable kind
  // that recurses into a nested target), not "a source key became observable".
  // jQuery's Event/data/makeArray shallow-copy props, so the loose test flagged
  // them as merges; they then tied with the real deep merge and, being
  // shorter-named, pushed it below the probe/differential cap — which is exactly
  // why jQuery 3.1.1's `extend` prototype pollution (CVE-2019-11358) went unfound.
  test('a deep merge outranks shallow prop-copy decoys', async () => {
    const shallowCopy = (a, b) => Object.assign({}, a, b); // observable, but NOT PP-capable
    const mod = {};
    for (let i = 0; i < 6; i++) mod[`aaCopy${i}`] = shallowCopy; // short names, would win a tie
    mod.zzDeepMerge = function m(t, s) {
      for (const k in s) {
        if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; m(t[k], s[k]); }
        else { t[k] = s[k]; }
      }
      return t;
    };

    const cfg = await discoverTarget(mod, 'rank-lib', '1.0.0', {});
    const names = cfg.entryPoints.map((ep) => ep.name);
    assert.ok(
      names.indexOf('zzDeepMerge') < names.indexOf('aaCopy0'),
      `the deep merge must outrank shallow copies; order: ${names.join(', ')}`,
    );
  });

  // Discovery probes only the top-N ranked exports. Ranking was purely
  // name-based: a hardcoded DANGEROUS_MERGE_METHODS list, then an
  // INTERESTING_METHODS list, then "prefer shorter names". A merge function
  // whose name is in neither list AND is longer than its benign siblings sorts
  // last and falls off the cap — so a genuinely vulnerable deep-merge is never
  // probed and the tool reports nothing. That makes detection depend on
  // guessing the author's vocabulary.
  //
  // Merge-likeness is detectable by BEHAVIOUR, not name: fn({}, {k: v}) makes
  // k observable. Rank on that instead, so an unheard-of name is still probed.
  test('ranks a merge-like function ahead of benign ones despite an unknown, long name', async () => {
    const mod = {};
    // 40 short, top-level, benign names — these win every name-based tie-break.
    for (let i = 0; i < 40; i++) mod[`fn${String(i).padStart(2, '0')}`] = (a) => String(a).length;
    // The vulnerable one: in no hardcoded list, and longer than every sibling.
    mod.reconcileConfigurationTree = function (target, source) {
      for (const key in source) {
        if (source[key] && typeof source[key] === 'object') {
          if (!target[key]) target[key] = {};
          mod.reconcileConfigurationTree(target[key], source[key]);
        } else { target[key] = source[key]; }
      }
      return target;
    };

    const config = await discoverTarget(mod, 'hidden-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    assert.ok(
      names.includes('reconcileConfigurationTree'),
      `a behaviourally merge-like export must survive the probe cap; got: ${names.join(', ')}`,
    );
  });

  // Same failure mode as the merge case, for the other gadget class. Multi-step
  // chains (compile -> render, CVE-2022-29078-style) were reached by ranking on
  // an INTERESTING_METHODS name list — 'compile', 'render', 'parse', … A
  // template compiler named something outside that vocabulary sorted below 40
  // benign siblings and fell off the probe cap, so its returned function was
  // never discovered and no call sequence was ever built for it.
  //
  // The behavioural signal: calling it hands back more callable surface (a
  // function, or an object carrying methods) rather than a plain value.
  test('ranks a factory-like function ahead of benign ones despite an unknown name', async () => {
    const mod = {};
    for (let i = 0; i < 40; i++) mod[`fn${String(i).padStart(2, '0')}`] = (a) => String(a).length;
    // Compile->render shape, with a name in no list and longer than its siblings.
    mod.assembleTemplateProcessor = (tpl) => (locals) => `${tpl}:${JSON.stringify(locals)}`;

    const config = await discoverTarget(mod, 'factory-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    assert.ok(
      names.includes('assembleTemplateProcessor'),
      `a behaviourally factory-like export must survive the probe cap; got: ${names.join(', ')}`,
    );
  });

  // Descending into namespace objects must NOT descend into module-plumbing
  // keys (`default`, `module`, `exports`). Those are aliases of the same
  // functions, and the reproduction/sandbox worker loads the package via
  // require() — where no such wrapper key exists — so `default._.merge` and
  // `module.exports._.merge` never resolve.
  //
  // They are not merely wasteful: the differential phase bails after 3
  // consecutive un-callable entry points, so a cluster of dead aliases sorted
  // ahead of a real one starves it. That is exactly how the @feathersjs/commons
  // CVE went undetected — three `_.extend` aliases burned the budget before
  // `_.merge` was ever tested.
  test('does not emit unresolvable module-plumbing aliases', async () => {
    const utils = {
      merge(target, source) { return Object.assign(target, source); },
    };
    // The shape an ESM/CJS interop wrapper presents: the same namespace reachable
    // as `_`, as `default._`, and as `module.exports._`.
    const mod = { _: utils };
    mod.default = mod;
    mod.module = { exports: mod };

    const config = await discoverTarget(mod, 'alias-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    const aliases = names.filter((n) => /(^|\.)(default|module|exports)\./.test(n));
    assert.deepEqual(aliases, [],
      `module-plumbing aliases must not become entry points; got: ${aliases.join(', ')}`);
    assert.ok(names.includes('_.merge'), `the real entry point must survive; got: ${names.join(', ')}`);
  });

  // Names must never decide what gets TESTED — only what order it is tried in.
  // shouldSkipExport dropped exports matching React vocabulary (`create`,
  // `memo`, `lazy`, `forward`, `/^use[A-Z]/`, …). Those are ordinary names in
  // non-React libraries, so a vulnerable `create` was invisible to the tool.
  //
  // The stated reason — React hooks cannot run outside a render context — is
  // already handled by behaviour: a hook throws when probed, so it is not
  // merge-like, and it sorts to the bottom on its own. The list bought nothing
  // and cost real coverage.
  test('discovers a vulnerable function whose name matches framework vocabulary', async () => {
    const vulnMerge = (t, s) => {
      for (const k in s) {
        if (s[k] && typeof s[k] === 'object') { if (!t[k]) t[k] = {}; vulnMerge(t[k], s[k]); }
        else { t[k] = s[k]; }
      }
      return t;
    };
    const mod = { create: vulnMerge, useConfig: vulnMerge, memo: vulnMerge, harmless: (a) => a };

    const config = await discoverTarget(mod, 'framework-named', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    for (const expected of ['create', 'useConfig', 'memo']) {
      assert.ok(names.includes(expected),
        `'${expected}' is behaviourally a merge and must be probed; got: ${names.join(', ')}`);
    }
  });

  // The probe cap must truncate only the uninteresting tail. If it can drop a
  // function the behavioural probe already flagged as merge-like, then rank
  // position — not evidence — decides what gets tested.
  test('the probe cap never drops a behaviourally merge-like export', async () => {
    const vulnMerge = (t, s) => Object.assign(t, s);
    const mod = {};
    for (let i = 0; i < 25; i++) mod[`combineVariant${String(i).padStart(2, '0')}`] = vulnMerge;
    for (let i = 0; i < 15; i++) mod[`plain${i}`] = (a) => String(a).length;

    const config = await discoverTarget(mod, 'many-merges', '1.0.0', {});
    const names = new Set(config.entryPoints.map((ep) => ep.name));

    const missing = Object.keys(mod).filter(k => k.startsWith('combineVariant') && !names.has(k));
    assert.deepEqual(missing, [],
      `every merge-like export must survive the cap; missing: ${missing.join(', ')}`);
  });

  // A `_` prefix is a convention, not a guarantee — plenty of libraries expose
  // reachable internals that way, and an attacker does not honour the
  // convention. So it must not exclude either: a vulnerable `_applyDefaults`
  // is still a vulnerability. Ordering may demote it; inclusion may not.
  test('a private-looking member is still probed when it behaves like a merge', async () => {
    const vulnMerge = (t, s) => Object.assign(t, s);
    const mod = {
      publicFn(x) { return x; },
      _applyDefaults: vulnMerge, // conventionally private, genuinely dangerous
    };

    const config = await discoverTarget(mod, 'priv-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    assert.ok(names.includes('publicFn'), `public fn should be discovered; got: ${names.join(', ')}`);
    assert.ok(
      names.includes('_applyDefaults'),
      `a private-looking but merge-like export must still be probed; got: ${names.join(', ')}`,
    );
  });
});
