/**
 * ESLint flat config (ESLint 9/10).
 *
 * Deliberately dependency-free: every rule below is an ESLint CORE rule, so
 * `npm run lint` works from a plain `npm install` without pulling in @eslint/js
 * or globals. That also lets the rule set stay curated — the goal is catching
 * real defects (typos, dead code, accidental globals) in a mature codebase, not
 * imposing a style regime on 12k existing lines.
 *
 * Three environments live in this repo:
 *   - src            Node ESM (the fuzzer itself, plus its worker scripts)
 *   - tests          Node ESM (node:test)
 *   - tests/fixtures CommonJS — deliberately vulnerable target stand-ins
 */

// Node host globals. ESLint supplies the ECMAScript builtins (Atomics,
// SharedArrayBuffer, globalThis, …) from ecmaVersion; these are the runtime's.
const nodeGlobals = {
  process: 'readonly',
  console: 'readonly',
  Buffer: 'readonly',
  global: 'readonly',
  URL: 'readonly',
  URLSearchParams: 'readonly',
  TextEncoder: 'readonly',
  TextDecoder: 'readonly',
  setTimeout: 'readonly',
  clearTimeout: 'readonly',
  setInterval: 'readonly',
  clearInterval: 'readonly',
  setImmediate: 'readonly',
  clearImmediate: 'readonly',
  queueMicrotask: 'readonly',
  structuredClone: 'readonly',
  fetch: 'readonly',
  AbortController: 'readonly',
  AbortSignal: 'readonly',
  performance: 'readonly',
  Event: 'readonly',
  EventTarget: 'readonly',
  MessageChannel: 'readonly',
  MessagePort: 'readonly',
};

// Correctness rules only — each one flags code that is a bug or dead weight.
const correctnessRules = {
  // Accidental globals / typo'd identifiers. The single highest-value rule here.
  'no-undef': 'error',

  // Dead or duplicated code.
  'no-unreachable': 'error',
  'no-dupe-keys': 'error',
  'no-dupe-args': 'error',
  'no-dupe-else-if': 'error',
  'no-duplicate-case': 'error',
  'no-func-assign': 'error',
  'no-import-assign': 'error',
  'no-self-assign': 'error',
  'no-self-compare': 'error',
  'no-unmodified-loop-condition': 'error',

  // Common footguns.
  'no-cond-assign': ['error', 'always'],
  'no-constant-condition': ['error', { checkLoops: false }],
  'no-compare-neg-zero': 'error',
  'no-unsafe-negation': 'error',
  'no-unsafe-finally': 'error',
  'no-unsafe-optional-chaining': 'error',
  'no-async-promise-executor': 'error',
  // Off by design: the codebase uses the standard sleep idiom
  // `await new Promise(r => setTimeout(r, ms))`, where the arrow implicitly
  // returns the timer id and the Promise machinery ignores it. That is correct
  // and intentional in ~14 places; the rule only catches a mistake people make
  // with an explicit `return resolve(x)`, which does not occur here.
  'no-promise-executor-return': 'off',
  'require-atomic-updates': 'off', // too many false positives on this async codebase
  'no-fallthrough': 'error',
  'no-irregular-whitespace': 'error',
  'no-sparse-arrays': 'error',
  'use-isnan': 'error',
  'valid-typeof': 'error',
  'no-obj-calls': 'error',
  'no-redeclare': 'error',
  'no-octal': 'error',
  'no-delete-var': 'error',
  'no-global-assign': 'error',
  'no-invalid-regexp': 'error',
  'no-control-regex': 'off', // fuzzer payloads legitimately embed control chars
  'no-useless-escape': 'warn',
  'no-empty': ['error', { allowEmptyCatch: true }],
  'no-empty-pattern': 'error',
  'no-ex-assign': 'error',
  'no-case-declarations': 'error',
  'no-prototype-builtins': 'off', // this tool intentionally pokes at Object.prototype

  // Unused code. Warn, not error: useful signal, but shouldn't fail a build over
  // an intentionally-unused catch binding or a placeholder parameter.
  'no-unused-vars': ['warn', {
    args: 'after-used',
    argsIgnorePattern: '^_',
    varsIgnorePattern: '^_',
    caughtErrors: 'none',
    ignoreRestSiblings: true,
  }],
};

export default [
  {
    // Build output, deps, and generated result files are not ours to lint.
    ignores: ['node_modules/**', 'results/**', 'data/**', 'coverage/**', '.claude/**'],
  },
  {
    // src/ and tests/ — Node ESM.
    files: ['src/**/*.js', 'tests/**/*.js', 'tests/**/*.mjs'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'module',
      globals: nodeGlobals,
    },
    // The few existing `eslint-disable no-eval` / `no-new` comments sit in
    // fixtures and document deliberate intent. This rule set does not enable
    // those rules, so reporting the directives as "unused" would only pressure
    // someone into deleting useful intent markers.
    linterOptions: { reportUnusedDisableDirectives: 'off' },
    rules: correctnessRules,
  },
  {
    // Test fixtures are CommonJS packages (each has "type": "commonjs") and are
    // intentionally vulnerable — they exist to be exploited by the fuzzer, so
    // they get the CJS globals and nothing stricter.
    files: ['tests/fixtures/**/*.js'],
    languageOptions: {
      ecmaVersion: 2024,
      sourceType: 'commonjs',
      globals: {
        ...nodeGlobals,
        require: 'readonly',
        module: 'writable',
        exports: 'writable',
        __dirname: 'readonly',
        __filename: 'readonly',
      },
    },
    rules: correctnessRules,
  },
];
