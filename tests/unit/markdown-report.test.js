import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { generateSingleReport, generateMassReport, generateVersionReport } from '../../src/reporting/markdown-report.js';

// ─── Fixtures ─────────────────────────────────────────────────────────────────

const BASE_CONFIG = {
  name: 'test-lib',
  version: '1.2.3',
  entryPoints: [
    { name: 'render', inputType: 'string' },
    { name: 'compile', inputType: 'string' }
  ],
  sinks: ['eval', 'innerHTML']
};

const EMPTY_RESULTS = {
  startTime: new Date('2024-01-01T00:00:00Z'),
  endTime: new Date('2024-01-01T00:01:00Z'),
  iterationsCompleted: 100,
  inputsGenerated: 200,
  confirmedChains: [],
  potentialChains: [],
  errors: [],
  coverageStats: {
    coveredEdges: 42,
    bitmapDensity: 0.00064,
    saturationRate: 0.55,
    totalInputsProcessed: 200,
    v8CoverageEnabled: false
  },
  strategyEffectiveness: {
    seedCount: 10,
    corpusEntropy: 3.14,
    discoveredUOPProperties: ['toString', 'valueOf'],
    strategyEffectiveness: {
      mutation: { successRate: 0.25, totalMutations: 80 },
      generation: { successRate: 0.10, totalMutations: 120 }
    }
  }
};

const GADGET_CHAIN = {
  riskLevel: '8.1',
  confidence: 0.95,
  input: { entryPoint: 'render' },
  source: { property: 'outputFunctionName', payload: 'x=1;process.exit(0)//' },
  metadata: { cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N' },
  poc: {
    type: 'direct',
    exploit: { code: 'Object.prototype.outputFunctionName = "x=1;process.exit(0)//";\nrender(template);' }
  },
  differential: { pollutedProperties: ['outputFunctionName'] }
};

const RESULTS_WITH_GADGET = {
  ...EMPTY_RESULTS,
  confirmedChains: [GADGET_CHAIN],
  potentialChains: [
    { description: 'Unconfirmed candidate', riskLevel: '3.5', confidence: 0.4 }
  ]
};

// ─── generateSingleReport ─────────────────────────────────────────────────────

describe('generateSingleReport', () => {
  test('returns a string', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.equal(typeof md, 'string');
  });

  test('includes library name and version in heading', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('test-lib@1.2.3'), 'should include library@version');
  });

  test('includes CLEAN status when no gadgets found', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('CLEAN'), 'should indicate clean result');
  });

  test('includes VULNERABLE status when gadgets found', () => {
    const md = generateSingleReport(RESULTS_WITH_GADGET, BASE_CONFIG);
    assert.ok(md.includes('VULNERABLE'), 'should indicate vulnerable');
  });

  test('includes gadget property name in confirmed section', () => {
    const md = generateSingleReport(RESULTS_WITH_GADGET, BASE_CONFIG);
    assert.ok(md.includes('outputFunctionName'), 'should include polluted property');
  });

  test('includes PoC code block', () => {
    const md = generateSingleReport(RESULTS_WITH_GADGET, BASE_CONFIG);
    assert.ok(md.includes('Proof of Concept'), 'should include PoC heading');
    assert.ok(md.includes('```javascript'), 'should include fenced code block');
  });

  test('includes coverage section', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('Coverage Analysis'), 'should include coverage section');
    assert.ok(md.includes('42'), 'should include edge count');
  });

  test('includes methodology section', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('Methodology'), 'should include methodology section');
    assert.ok(md.includes('Differential oracle'), 'should include differential oracle description');
  });

  test('includes collapsible raw JSON section', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('<details>'), 'should include collapsible details');
    assert.ok(md.includes('```json'), 'should include JSON code block');
  });

  test('includes entry points in attack surface', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('render'), 'should include entry point names');
    assert.ok(md.includes('compile'), 'should include entry point names');
  });

  test('includes UOP properties when discovered', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('toString'), 'should list UOP properties');
    assert.ok(md.includes('valueOf'), 'should list UOP properties');
  });

  test('includes mutation strategy stats', () => {
    const md = generateSingleReport(EMPTY_RESULTS, BASE_CONFIG);
    assert.ok(md.includes('Thompson Sampling'), 'should reference Thompson Sampling');
    assert.ok(md.includes('mutation'), 'should include strategy name');
  });

  test('handles missing config gracefully', () => {
    const md = generateSingleReport(EMPTY_RESULTS, null);
    assert.equal(typeof md, 'string');
    assert.ok(md.includes('Unknown@?'));
  });

  test('includes CVSS vector when present', () => {
    const md = generateSingleReport(RESULTS_WITH_GADGET, BASE_CONFIG);
    assert.ok(md.includes('CVSS:3.1'), 'should include CVSS vector');
  });

  test('URL gadget type shows URL heading', () => {
    const urlResults = {
      ...EMPTY_RESULTS,
      confirmedChains: [{
        ...GADGET_CHAIN,
        poc: {
          type: 'url_gadget',
          attackerInput: { url: 'https://example.com/?__proto__[x]=1' },
          exploit: { code: '// exploit' },
          vulnerablePattern: { description: 'URL query string leads to prototype pollution' }
        }
      }]
    };
    const md = generateSingleReport(urlResults, BASE_CONFIG);
    assert.ok(md.includes('Attacker-Controlled Input'), 'should show attacker input section');
    assert.ok(md.includes('https://example.com/?__proto__[x]=1'), 'should show exploit URL');
  });
});

// ─── generateMassReport ───────────────────────────────────────────────────────

describe('generateMassReport', () => {
  const massResults = [
    { library: 'pug', version: '3.0.2', stars: 21000, results: RESULTS_WITH_GADGET, config: BASE_CONFIG },
    { library: 'squirrelly', version: '8.0.8', stars: 500, results: EMPTY_RESULTS, config: BASE_CONFIG },
    { library: 'broken-lib', version: '1.0.0', stars: 100, results: null, error: 'install failed' }
  ];

  test('returns a string', () => {
    assert.equal(typeof generateMassReport(massResults), 'string');
  });

  test('includes summary heading', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('Mass Scan Report'), 'should include mass scan heading');
  });

  test('includes all library names in summary table', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('pug'), 'should list pug');
    assert.ok(md.includes('squirrelly'), 'should list squirrelly');
    assert.ok(md.includes('broken-lib'), 'should list broken-lib');
  });

  test('marks vulnerable library as VULNERABLE', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('VULNERABLE'), 'should mark vulnerable library');
  });

  test('marks failed library as FAILED', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('FAILED'), 'should mark failed library');
  });

  test('shows failed libraries section', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('Failed Scans'), 'should include failed scans section');
    assert.ok(md.includes('install failed'), 'should show error message');
  });

  test('includes statistics section', () => {
    const md = generateMassReport(massResults);
    assert.ok(md.includes('Scan Statistics'), 'should include statistics section');
  });

  test('handles empty results array', () => {
    const md = generateMassReport([]);
    assert.equal(typeof md, 'string');
    assert.ok(md.includes('0'));
  });
});

// ─── generateVersionReport ────────────────────────────────────────────────────

describe('generateVersionReport', () => {
  const versionResults = [
    { version: '3.0.2', results: RESULTS_WITH_GADGET, config: BASE_CONFIG },
    { version: '3.0.1', results: EMPTY_RESULTS, config: BASE_CONFIG },
    { version: '2.9.0', results: EMPTY_RESULTS, config: BASE_CONFIG },
    { version: '2.8.0', results: null, error: 'timeout' }
  ];

  test('returns a string', () => {
    assert.equal(typeof generateVersionReport(versionResults, 'pug'), 'string');
  });

  test('includes library name in heading', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('pug'), 'should include library name');
  });

  test('includes version timeline table with all versions', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('3.0.2'), 'should list version 3.0.2');
    assert.ok(md.includes('3.0.1'), 'should list version 3.0.1');
    assert.ok(md.includes('2.9.0'), 'should list version 2.9.0');
  });

  test('marks vulnerable version as VULNERABLE', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('VULNERABLE'), 'should mark vulnerable version');
  });

  test('marks error version as FAILED', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('FAILED'), 'should mark failed version');
  });

  test('includes regression analysis section', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('Regression Analysis'), 'should include regression analysis');
  });

  test('lists vulnerable properties in regression analysis', () => {
    const md = generateVersionReport(versionResults, 'pug');
    assert.ok(md.includes('outputFunctionName'), 'should list vulnerable property');
  });

  test('handles all-clean case', () => {
    const cleanResults = [
      { version: '1.0.0', results: EMPTY_RESULTS, config: BASE_CONFIG }
    ];
    const md = generateVersionReport(cleanResults, 'safe-lib');
    assert.ok(md.includes('No vulnerabilities found'), 'should say clean');
  });
});
