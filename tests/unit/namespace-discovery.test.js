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

  test('still skips genuinely-private leaf members (_internalHelper)', async () => {
    const mod = {
      publicFn(x) { return x; },
      _internalHelper(x) { return x; }, // conventionally private — should stay skipped
    };

    const config = await discoverTarget(mod, 'priv-lib', '1.0.0', {});
    const names = config.entryPoints.map((ep) => ep.name);

    assert.ok(names.includes('publicFn'), `public fn should be discovered; got: ${names.join(', ')}`);
    assert.ok(
      !names.some((n) => n.split('.').pop() === '_internalHelper'),
      `private _-prefixed leaf must stay skipped; got: ${names.join(', ')}`,
    );
  });
});
