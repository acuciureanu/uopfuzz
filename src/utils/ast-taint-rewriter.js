/**
 * AST Taint Rewriter — NodeProf/GraalVM-style instrumentation for Node.js
 *
 * Parses library source code with acorn and rewrites every MemberExpression
 * into a call to a tracking helper. This provides taint tracking through
 * primitive operations that ES6 Proxy cannot intercept.
 *
 * Why Proxy is insufficient for primitive taint:
 *   A Proxy must wrap an *object*. When tainted data becomes a primitive
 *   (e.g. a string from obj.toString(), a number from obj.count), subsequent
 *   property accesses on that primitive (e.g. str.length, str.split(','))
 *   auto-box the primitive into a temporary wrapper — the Proxy is gone.
 *   AST rewriting captures these by injecting tracking calls directly into
 *   the source, so the tracker sees every .prop access regardless of whether
 *   the receiver is an object or a boxed primitive.
 *
 * Technique (NodeProf/GraalVM reference):
 *   NodeProf (Bao et al., ASE 2021) instruments GraalJS bytecodes to fire
 *   callbacks on every property read/write. We replicate the observable
 *   behaviour — tracking every MemberExpression — at the source level using
 *   acorn for parsing and a recursive code generator for output.
 *
 * Three runtime helpers injected into the instrumented scope:
 *   __tg(obj, prop, pos)           — property get  (obj.prop / obj[prop])
 *   __tc(obj, prop, pos, args)     — method call   (obj.method(...args))
 *   __ts(obj, prop, val, pos)      — property set  (obj.prop = val)
 *
 * __tc preserves the correct `this` binding via Function.prototype.apply,
 * which a naïve __tg(obj,'method',pos)(args) rewrite would lose.
 *
 * Reference:
 *   Bao et al., "NodeProf: Efficient and General Dynamic Analysis for Node.js",
 *   ASE 2021. https://dl.acm.org/doi/10.1145/3338906.3338963
 */

import { createRequire } from 'module';

const _require = createRequire(import.meta.url);

// Load acorn (available as transitive dep of eslint, already installed)
let acorn = null;
try {
  acorn = _require('acorn');
} catch {
  // acorn not available — rewriter will be a no-op
}

// ---------------------------------------------------------------------------
// Runtime helpers — injected as a preamble into every rewritten module
// ---------------------------------------------------------------------------

/**
 * Build the preamble source that defines __tg, __tc, __ts in the target scope.
 * The log array is closed over so all helpers share the same event stream.
 *
 * @param {string} logVar - Name of the log array variable in the outer scope
 * @returns {string} JS source for the three helpers
 */
export function buildHelperPreamble(logVar = '__astTaintLog') {
  return `
var __tg = function(obj, prop, pos) {
  var val;
  try { val = obj == null ? undefined : obj[prop]; } catch(e) { val = undefined; }
  ${logVar}.push({
    type: 'get', source: 'ast_rewrite', property: String(prop), pos: pos,
    receiverType: obj === null ? 'null' : typeof obj,
    valueType: val === null ? 'null' : typeof val,
    isUndefined: val === undefined,
    // Prototype chain lookup: value exists but not as own property
    isPrototypeChainLookup: val !== undefined && obj != null &&
      !Object.prototype.hasOwnProperty.call(Object(obj), prop),
    // Pure UOP: property doesn't exist anywhere
    isUOPCandidate: val === undefined,
    timestamp: Date.now()
  });
  return val;
};
var __tc = function(obj, prop, pos, args) {
  var fn;
  var __tc_isProto = false;
  try {
    fn = obj == null ? undefined : obj[prop];
    __tc_isProto = fn !== undefined && obj != null &&
      !Object.prototype.hasOwnProperty.call(Object(obj), prop);
  } catch(e) { fn = undefined; }
  ${logVar}.push({
    type: 'call', source: 'ast_rewrite', property: String(prop), pos: pos,
    receiverType: obj === null ? 'null' : typeof obj,
    isMissing: typeof fn !== 'function',
    // Method lives on prototype (e.g. String.prototype.toUpperCase for a string receiver)
    isPrototypeChainLookup: __tc_isProto,
    argsCount: args ? args.length : 0,
    timestamp: Date.now()
  });
  if (typeof fn !== 'function') return undefined;
  return fn.apply(obj, args || []);
};
var __ts = function(obj, prop, val, pos) {
  ${logVar}.push({
    type: 'set', source: 'ast_rewrite', property: String(prop), pos: pos,
    receiverType: obj === null ? 'null' : typeof obj,
    valueType: val === null ? 'null' : typeof val,
    timestamp: Date.now()
  });
  if (obj !== null && obj !== undefined) obj[prop] = val;
  return val;
};
`;
}

// ---------------------------------------------------------------------------
// Code generator — recursive AST → instrumented JS source
// ---------------------------------------------------------------------------

function escStr(s) {
  return s.replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, '\\n').replace(/\r/g, '\\r');
}

function genArgs(nodes, src) {
  return nodes.map(n => gen(n, src)).join(', ');
}

function genBody(node, src) {
  if (!node) return ';';
  if (node.type === 'BlockStatement') return gen(node, src);
  return `{ ${gen(node, src)} }`;
}

function genParams(params, src) {
  return params.map(p => gen(p, src)).join(', ');
}

function genFuncCore(node, src, isMethod = false) {
  const async_ = node.async ? 'async ' : '';
  const gen_ = node.generator ? '*' : '';
  const params = genParams(node.params, src);
  const body = gen(node.body, src);
  if (isMethod) return `${async_}${gen_}(${params}) ${body}`;
  return `${async_}function${gen_} (${params}) ${body}`;
}

function genTemplateLiteral(node, src) {
  let result = '`';
  for (let i = 0; i < node.quasis.length; i++) {
    result += node.quasis[i].value.raw;
    if (i < node.expressions.length) {
      result += '${' + gen(node.expressions[i], src) + '}';
    }
  }
  result += '`';
  return result;
}

function genClass(node, src) {
  const name = node.id ? ` ${node.id.name}` : '';
  const superClass = node.superClass ? ` extends ${gen(node.superClass, src)}` : '';
  const members = node.body.body.map(m => {
    if (m.type === 'StaticBlock') return `static ${gen(m, src)}`;
    const isStatic = m.static ? 'static ' : '';
    const acc = m.kind === 'get' ? 'get ' : m.kind === 'set' ? 'set ' : '';
    const key = m.computed ? `[${gen(m.key, src)}]` : gen(m.key, src);
    if (m.type === 'PropertyDefinition') {
      return `${isStatic}${key}${m.value ? ` = ${gen(m.value, src)}` : ''};`;
    }
    return `${isStatic}${acc}${key}${genFuncCore(m.value, src, true)}`;
  }).join('\n');
  return `class${name}${superClass} {\n${members}\n}`;
}

/**
 * Core recursive code generator.
 * Returns instrumented JS source for the given AST node.
 * Falls back to src.slice(node.start, node.end) for unrecognised node types.
 */
function gen(node, src) {
  if (!node) return '';

  switch (node.type) {

    // ---- Primitives ----
    case 'Identifier':
      return node.name;
    case 'Literal':
      return node.raw !== undefined ? node.raw : JSON.stringify(node.value);
    case 'TemplateLiteral':
      return genTemplateLiteral(node, src);
    case 'TaggedTemplateExpression': {
      // If tag is a MemberExpression this is a method-call-like tag: obj.tag`...`
      // Preserve as-is — rewriting would break the template tag protocol
      const tag = gen(node.tag, src);
      return `${tag}${genTemplateLiteral(node.quasi, src)}`;
    }
    case 'ThisExpression': return 'this';
    case 'Super': return 'super';
    case 'MetaProperty': return `${node.meta.name}.${node.property.name}`;

    // ---- Member / Call — the key instrumented nodes ----
    case 'MemberExpression': {
      if (node.optional) {
        // a?.b — fall back to original; optional chaining semantics are
        // hard to rewrite correctly without a temp variable in all positions
        return src.slice(node.start, node.end);
      }
      const obj = gen(node.object, src);
      if (node.computed) {
        const prop = gen(node.property, src);
        return `__tg(${obj}, ${prop}, ${node.start})`;
      }
      return `__tg(${obj}, '${escStr(node.property.name)}', ${node.start})`;
    }

    case 'CallExpression': {
      if (node.optional) return src.slice(node.start, node.end);
      // Method call: preserve `this` binding via __tc
      if (node.callee.type === 'MemberExpression' && !node.callee.optional) {
        const callee = node.callee;
        const obj = gen(callee.object, src);
        const propExpr = callee.computed
          ? gen(callee.property, src)
          : `'${escStr(callee.property.name)}'`;
        const args = genArgs(node.arguments, src);
        return `__tc(${obj}, ${propExpr}, ${callee.start}, [${args}])`;
      }
      const callee = gen(node.callee, src);
      const args = genArgs(node.arguments, src);
      return `${callee}(${args})`;
    }

    case 'NewExpression': {
      const callee = gen(node.callee, src);
      const args = genArgs(node.arguments, src);
      return `new ${callee}(${args})`;
    }

    case 'ChainExpression':
      // Optional chaining — fall back to original source to preserve semantics
      return src.slice(node.start, node.end);

    // ---- Assignment ----
    case 'AssignmentExpression': {
      // Simple assignment to a member: obj.prop = val → __ts(obj, 'prop', val, pos)
      if (node.left.type === 'MemberExpression' && node.operator === '=' && !node.left.optional) {
        const lhs = node.left;
        const obj = gen(lhs.object, src);
        const propExpr = lhs.computed
          ? gen(lhs.property, src)
          : `'${escStr(lhs.property.name)}'`;
        const val = gen(node.right, src);
        return `__ts(${obj}, ${propExpr}, ${val}, ${lhs.start})`;
      }
      // Compound assignment (+=, -=, etc.) or destructuring — preserve as-is
      return `${gen(node.left, src)} ${node.operator} ${gen(node.right, src)}`;
    }

    // ---- Expressions ----
    case 'BinaryExpression':
    case 'LogicalExpression': {
      const l = gen(node.left, src);
      const r = gen(node.right, src);
      return `(${l} ${node.operator} ${r})`;
    }
    case 'UnaryExpression': {
      const arg = gen(node.argument, src);
      const sp = /^[a-z]/.test(node.operator) ? ' ' : '';
      return node.prefix ? `${node.operator}${sp}${arg}` : `${arg}${node.operator}`;
    }
    case 'UpdateExpression': {
      const arg = gen(node.argument, src);
      return node.prefix ? `${node.operator}${arg}` : `${arg}${node.operator}`;
    }
    case 'ConditionalExpression': {
      const test = gen(node.test, src);
      const cons = gen(node.consequent, src);
      const alt = gen(node.alternate, src);
      return `(${test} ? ${cons} : ${alt})`;
    }
    case 'SequenceExpression':
      return `(${node.expressions.map(e => gen(e, src)).join(', ')})`;
    case 'SpreadElement':
    case 'RestElement':
      return `...${gen(node.argument, src)}`;
    case 'AwaitExpression':
      return `await ${gen(node.argument, src)}`;
    case 'YieldExpression':
      return node.delegate
        ? `yield* ${node.argument ? gen(node.argument, src) : ''}`
        : `yield${node.argument ? ` ${gen(node.argument, src)}` : ''}`;

    // ---- Object / Array literals ----
    case 'ObjectExpression': {
      const props = node.properties.map(p => gen(p, src)).join(', ');
      return `{ ${props} }`;
    }
    case 'Property': {
      if (node.shorthand) return gen(node.key, src);
      const key = node.computed ? `[${gen(node.key, src)}]` : gen(node.key, src);
      if (node.method) return `${key}${genFuncCore(node.value, src, true)}`;
      const acc = node.kind === 'get' ? 'get ' : node.kind === 'set' ? 'set ' : '';
      if (node.kind === 'get' || node.kind === 'set') {
        return `${acc}${key}${genFuncCore(node.value, src, true)}`;
      }
      return `${key}: ${gen(node.value, src)}`;
    }
    case 'ArrayExpression': {
      const els = node.elements.map(e => e ? gen(e, src) : '').join(', ');
      return `[${els}]`;
    }

    // ---- Functions ----
    case 'FunctionExpression':
      return `(${genFuncCore(node, src)})`;
    case 'ArrowFunctionExpression': {
      const async_ = node.async ? 'async ' : '';
      const params = genParams(node.params, src);
      const body = node.body.type === 'BlockStatement'
        ? gen(node.body, src)
        : gen(node.body, src);
      const needsParens = node.params.length !== 1 || node.params[0].type !== 'Identifier';
      const paramStr = needsParens ? `(${params})` : params;
      return `${async_}${paramStr} => ${body}`;
    }
    case 'FunctionDeclaration': {
      const id = node.id ? ` ${node.id.name}` : '';
      const async_ = node.async ? 'async ' : '';
      const gen_ = node.generator ? '*' : '';
      const params = genParams(node.params, src);
      const body = gen(node.body, src);
      return `${async_}function${gen_}${id}(${params}) ${body}`;
    }

    // ---- Patterns (destructuring) ----
    case 'ObjectPattern': {
      const props = node.properties.map(p => {
        if (p.type === 'RestElement') return `...${gen(p.argument, src)}`;
        if (p.shorthand) {
          return p.value.type === 'AssignmentPattern'
            ? `${gen(p.key, src)} = ${gen(p.value.right, src)}`
            : gen(p.key, src);
        }
        const key = p.computed ? `[${gen(p.key, src)}]` : gen(p.key, src);
        return `${key}: ${gen(p.value, src)}`;
      }).join(', ');
      return `{ ${props} }`;
    }
    case 'ArrayPattern': {
      const els = node.elements.map(e => e ? gen(e, src) : '').join(', ');
      return `[${els}]`;
    }
    case 'AssignmentPattern':
      return `${gen(node.left, src)} = ${gen(node.right, src)}`;

    // ---- Statements ----
    case 'Program':
      return node.body.map(s => gen(s, src)).join('\n');
    case 'BlockStatement':
      return `{\n${node.body.map(s => gen(s, src)).join('\n')}\n}`;
    case 'ExpressionStatement':
      return `${gen(node.expression, src)};`;
    case 'ReturnStatement':
      return node.argument ? `return ${gen(node.argument, src)};` : 'return;';
    case 'ThrowStatement':
      return `throw ${gen(node.argument, src)};`;
    case 'BreakStatement':
      return node.label ? `break ${node.label.name};` : 'break;';
    case 'ContinueStatement':
      return node.label ? `continue ${node.label.name};` : 'continue;';
    case 'EmptyStatement':
      return ';';
    case 'DebuggerStatement':
      return 'debugger;';
    case 'LabeledStatement':
      return `${node.label.name}: ${gen(node.body, src)}`;

    case 'IfStatement': {
      let code = `if (${gen(node.test, src)}) ${genBody(node.consequent, src)}`;
      if (node.alternate) code += ` else ${genBody(node.alternate, src)}`;
      return code;
    }
    case 'WhileStatement':
      return `while (${gen(node.test, src)}) ${genBody(node.body, src)}`;
    case 'DoWhileStatement':
      return `do ${genBody(node.body, src)} while (${gen(node.test, src)});`;

    case 'ForStatement': {
      const init = node.init ? gen(node.init, src).replace(/;\s*$/, '') : '';
      const test = node.test ? gen(node.test, src) : '';
      const update = node.update ? gen(node.update, src) : '';
      return `for (${init}; ${test}; ${update}) ${genBody(node.body, src)}`;
    }
    case 'ForInStatement': {
      const left = gen(node.left, src).replace(/;\s*$/, '');
      return `for (${left} in ${gen(node.right, src)}) ${genBody(node.body, src)}`;
    }
    case 'ForOfStatement': {
      const left = gen(node.left, src).replace(/;\s*$/, '');
      const aw = node.await ? 'await ' : '';
      return `for (${aw}${left} of ${gen(node.right, src)}) ${genBody(node.body, src)}`;
    }

    case 'VariableDeclaration': {
      const decls = node.declarations.map(d => {
        const id = gen(d.id, src);
        return d.init ? `${id} = ${gen(d.init, src)}` : id;
      }).join(', ');
      return `${node.kind} ${decls};`;
    }

    case 'TryStatement': {
      let code = `try ${gen(node.block, src)}`;
      if (node.handler) {
        const param = node.handler.param ? ` (${gen(node.handler.param, src)})` : '';
        code += ` catch${param} ${gen(node.handler.body, src)}`;
      }
      if (node.finalizer) code += ` finally ${gen(node.finalizer, src)}`;
      return code;
    }
    case 'SwitchStatement': {
      const cases = node.cases.map(c => {
        const test = c.test ? `case ${gen(c.test, src)}:` : 'default:';
        const body = c.consequent.map(s => gen(s, src)).join('\n');
        return `${test}\n${body}`;
      }).join('\n');
      return `switch (${gen(node.discriminant, src)}) {\n${cases}\n}`;
    }

    // ---- Classes ----
    case 'ClassDeclaration':
    case 'ClassExpression':
      return genClass(node, src);

    // ---- Modules — pass through (import/export semantics must be preserved) ----
    case 'ImportDeclaration':
    case 'ExportAllDeclaration':
      return src.slice(node.start, node.end);

    case 'ExportNamedDeclaration': {
      if (node.declaration) return `export ${gen(node.declaration, src)}`;
      const specs = node.specifiers.map(s => {
        const local = gen(s.local, src);
        const exported = gen(s.exported, src);
        return local === exported ? local : `${local} as ${exported}`;
      }).join(', ');
      const from = node.source ? ` from ${node.source.raw}` : '';
      return `export { ${specs} }${from};`;
    }
    case 'ExportDefaultDeclaration':
      return `export default ${gen(node.declaration, src)};`;

    // ---- Fallback: return original source slice ----
    default:
      return src.slice(node.start, node.end);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Rewrite JavaScript source code to inject property-access taint tracking.
 *
 * Parses the source with acorn, walks the AST, and generates an instrumented
 * copy where every obj.prop read calls __tg(...), every obj.method() call
 * calls __tc(...), and every obj.prop = val write calls __ts(...).
 *
 * @param {string} source - Original library source code
 * @param {object} [opts]
 * @param {string}  [opts.logVar='__astTaintLog'] - Name for the log array var
 * @param {string}  [opts.sourceType='script']    - 'script' or 'module'
 * @param {boolean} [opts.tolerant=true]          - Continue on parse errors
 * @returns {{ ok: boolean, instrumented: string|null, error: string|null }}
 */
export function rewriteSource(source, opts = {}) {
  if (!acorn) {
    return { ok: false, instrumented: null, error: 'acorn not available' };
  }

  const {
    logVar = '__astTaintLog',
    sourceType = 'script',
    tolerant = true
  } = opts;

  let ast;
  try {
    ast = acorn.parse(source, {
      ecmaVersion: 2022,
      sourceType,
      locations: false,
      allowReserved: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
  } catch (err) {
    if (!tolerant) return { ok: false, instrumented: null, error: err.message };
    // Partial fallback: return original source with just the preamble
    return {
      ok: false,
      instrumented: `${buildHelperPreamble(logVar)}\n${source}`,
      error: err.message
    };
  }

  let instrumented;
  try {
    instrumented = gen(ast, source);
  } catch (err) {
    return {
      ok: false,
      instrumented: `${buildHelperPreamble(logVar)}\n${source}`,
      error: `codegen failed: ${err.message}`
    };
  }

  return {
    ok: true,
    instrumented: `${buildHelperPreamble(logVar)}\n${instrumented}`,
    error: null
  };
}

/**
 * Analyse an AST taint log (events from __tg / __tc / __ts).
 *
 * @param {Array} log - Events collected during instrumented execution
 * @returns {object} Structured analysis compatible with analyzeTaintLog output
 */
export function analyzeASTTaintLog(log) {
  const uopCandidates = [];
  const prototypeChainLookups = [];
  const coercionFlows = [];
  const methodCallsMissing = [];
  const propertyWrites = [];
  const accessFrequency = new Map();
  let totalAccesses = 0;

  const COERCION_PROPS = new Set(['toString', 'valueOf', 'toJSON']);

  for (const event of log) {
    if (event.type === 'get') {
      totalAccesses++;
      const cnt = (accessFrequency.get(event.property) || 0) + 1;
      accessFrequency.set(event.property, cnt);

      if (event.isUOPCandidate) {
        uopCandidates.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
      if (event.isPrototypeChainLookup) {
        prototypeChainLookups.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
      if (COERCION_PROPS.has(event.property)) {
        coercionFlows.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
    }

    if (event.type === 'call') {
      // Count every method call in access frequency (calls ARE property reads)
      totalAccesses++;
      const cnt = (accessFrequency.get(event.property) || 0) + 1;
      accessFrequency.set(event.property, cnt);

      if (event.isMissing) {
        methodCallsMissing.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
      // Prototype-chain method calls: e.g. "str".toUpperCase() — String.prototype access
      if (event.isPrototypeChainLookup) {
        prototypeChainLookups.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
      if (COERCION_PROPS.has(event.property)) {
        coercionFlows.push({
          property: event.property,
          receiverType: event.receiverType,
          pos: event.pos,
          timestamp: event.timestamp
        });
      }
    }

    if (event.type === 'set') {
      propertyWrites.push({
        property: event.property,
        receiverType: event.receiverType,
        pos: event.pos,
        timestamp: event.timestamp
      });
    }
  }

  return {
    totalEvents: log.length,
    totalAccesses,
    uopCandidates,
    prototypeChainLookups,
    coercionFlows,
    methodCallsMissing,
    propertyWrites,
    uniqueProperties: accessFrequency.size,
    accessFrequency: Object.fromEntries(accessFrequency)
  };
}
