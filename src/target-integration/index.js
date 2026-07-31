import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);
import { createRequire } from 'module';
import YAML from 'yaml';
import { logger } from '../utils/logger.js';
import { discoverTarget } from './discovery.js';
import { verifyPackageIntegrity } from '../utils/package-safety.js';
import { BROWSER_ONLY_PACKAGES } from '../utils/browser-env.js';

const require = createRequire(import.meta.url);

export class TargetIntegration {
  constructor(options) {
    this.options = options;
    this.installedPackages = new Set();
    this.targetCache = new Map();
  }

  async loadConfig(configPath) {
    try {
      const configContent = await fs.readFile(configPath, 'utf8');
      const config = YAML.parse(configContent);
      
      this.validateConfig(config);
      return config;
      
    } catch (error) {
      throw new Error(`Failed to load configuration: ${error.message}`);
    }
  }

  validateConfig(config) {
    const required = ['name', 'package', 'version', 'entryPoints', 'sinks', 'pollutionPoints'];
    const missing = required.filter(field => !config[field]);
    
    if (missing.length > 0) {
      throw new Error(`Missing required config fields: ${missing.join(', ')}`);
    }

    if (!Array.isArray(config.entryPoints) || config.entryPoints.length === 0) {
      throw new Error('entryPoints must be a non-empty array');
    }

    if (!Array.isArray(config.sinks) || config.sinks.length === 0) {
      throw new Error('sinks must be a non-empty array');
    }

    if (!Array.isArray(config.pollutionPoints) || config.pollutionPoints.length === 0) {
      throw new Error('pollutionPoints must be a non-empty array');
    }
  }

  async setupTarget(config) {
    try {
      logger.info(`Setting up target: ${config.name} v${config.version}`);
      
      // Install target package if not already installed
      await this.installPackage(config.package, config.version);
      
      // Load and validate the target module
      const targetModule = await this.loadTargetModule(config);
      
      // Cache the target for reuse
      this.targetCache.set(config.name, {
        config,
        module: targetModule,
        setupTime: new Date()
      });
      
      logger.info(`Target ${config.name} setup completed successfully`);
      return targetModule;
      
    } catch (error) {
      throw new Error(`Failed to setup target ${config.name}: ${error.message}`);
    }
  }

  async installPackage(packageName, version) {
    const packageId = `${packageName}@${version}`;

    if (this.installedPackages.has(packageId)) {
      logger.debug(`Package ${packageId} already installed`);
      return;
    }

    try {
      // SECURITY: Validate package name/version BEFORE any use — including the
      // on-disk short-circuit below — to prevent command/code injection.
      // The version allowlist deliberately excludes space/|/* (shell metachars),
      // so compound range specs (">=1 <2", "^1 || ^2", "*") are rejected —
      // pass a concrete version or dist-tag instead.
      if (!/^(@[a-z0-9\-~][a-z0-9\-._~]*\/)?[a-z0-9\-~][a-z0-9\-._~]*$/.test(packageName)) {
        throw new Error(`Invalid package name: ${packageName}`);
      }
      if (version !== 'latest' && !/^[\w.\-^~<>=]+$/.test(version)) {
        throw new Error(`Invalid version specifier: ${version}`);
      }

      // Skip the npm round-trip when node_modules already has this exact
      // version. The default single-target run and every mass/version target
      // run in a FRESH forked subprocess, so `installedPackages` (in-memory) is
      // empty each time — without this on-disk check, a full `npm install`
      // re-ran for every target/version/invocation even when the package was
      // already present. Only short-circuits on a concrete exact-version match;
      // `latest` and semver ranges still go through npm so resolution stays
      // correct and deterministic.
      if (!this.options.dryRun && this._isInstalledAtVersion(packageName, version)) {
        logger.info(`Package ${packageId} already resolvable in node_modules — skipping install`);
        // Still verify integrity of what's on disk before trusting it.
        await verifyPackageIntegrity(packageName, version, this.options);
        this.installedPackages.add(packageId);
        return;
      }

      logger.info(`Installing package: ${packageId}`);

      if (this.options.dryRun) {
        logger.info(`Dry run - would install ${packageId}`);
        this.installedPackages.add(packageId);
        return;
      }

      // SECURITY: --ignore-scripts prevents postinstall/preinstall attacks.
      // Malicious packages commonly use lifecycle scripts for RCE.
      // If a package legitimately needs postinstall (e.g., native addons),
      // use --allow-scripts to opt in explicitly.
      // --no-package-lock avoids write conflicts during concurrent installs.
      // --prefer-offline uses the npm cache when a matching version is present,
      // avoiding a registry round-trip on repeat scans.
      // execFile: no shell parses these args, so packageId can never inject.
      const installArgs = ['install', packageId, '--no-save', '--silent', '--no-package-lock', '--prefer-offline'];
      if (!this.options.allowScripts) installArgs.push('--ignore-scripts');

      // Install timeout is configurable (--install-timeout, seconds) and retried
      // once — the previous hard 30 s with no override silently failed whole
      // targets on slow/proxied networks or large dependency trees.
      const installTimeoutMs = (this.options.installTimeout || 30) * 1000;
      // execFile does not resolve .cmd via PATHEXT, so npm is npm.cmd on Windows.
      const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
      logger.debug(`Running: ${npmBin} ${installArgs.join(' ')} (timeout ${installTimeoutMs}ms)`);
      try {
        await execFileAsync(npmBin, installArgs, { timeout: installTimeoutMs });
      } catch (firstErr) {
        logger.warn(`Install of ${packageId} failed (${firstErr.killed ? 'timeout' : firstErr.message.split('\n')[0]}); retrying once...`);
        await execFileAsync(npmBin, installArgs, { timeout: installTimeoutMs });
      }

      // SECURITY: Verify package integrity after install
      await verifyPackageIntegrity(packageName, version, this.options);

      this.installedPackages.add(packageId);
      logger.debug(`Successfully installed ${packageId}`);

    } catch (error) {
      throw new Error(`Failed to install ${packageId}: ${error.message}`);
    }
  }

  /**
   * True only when node_modules already contains this package at exactly the
   * requested concrete version. Reads node_modules/<pkg>/package.json directly
   * (rather than require.resolve) so it works even when a package's "exports"
   * field hides package.json. Conservative by design: `latest` and any semver
   * range return false so npm still performs resolution.
   */
  _isInstalledAtVersion(packageName, version) {
    if (!version || version === 'latest') return false;
    // Only treat a plain, exact semver-ish string as a short-circuit candidate;
    // ranges/operators (^ ~ > < * | x, spaces) must go through npm.
    if (!/^[0-9][\w.\-+]*$/.test(version)) return false;
    return this._installedVersion(packageName) === version;
  }

  /**
   * The CONCRETE version npm actually installed for this package, read from
   * node_modules/<pkg>/package.json, or null if unreadable. Used to reconcile a
   * dist-tag / range / 'latest' spec down to an exact version — without which the
   * reported version, the PoC, and (critically) the OSV/GitHub-Advisory-DB
   * lookups all carry the literal "latest", making every advisory query miss and
   * a known CVE masquerade as an undocumented finding.
   */
  _installedVersion(packageName) {
    try {
      const pkgJsonPath = path.join(process.cwd(), 'node_modules', packageName, 'package.json');
      if (!fsSync.existsSync(pkgJsonPath)) return null;
      return JSON.parse(fsSync.readFileSync(pkgJsonPath, 'utf8')).version || null;
    } catch {
      return null;
    }
  }

  async loadTargetModule(config) {
    try {
      // Attempt to require the target module
      const modulePath = config.package;
      logger.debug(`Loading module: ${modulePath}`);

      if (this.options.dryRun) {
        return {
          name: config.name,
          version: config.version,
          isDryRun: true,
          entryPoints: config.entryPoints
        };
      }

      // Clear CJS cache so a freshly-installed version is loaded (not a stale
      // cached one from a previous VersionRunner iteration).
      this._clearRequireCache(modulePath);

      // Dynamic import of the target package
      const targetModule = await import(modulePath);

      // Validate that required entry points exist
      this.validateEntryPoints(targetModule, config.entryPoints);

      return targetModule;

    } catch (error) {
      throw new Error(`Failed to load target module ${config.package}: ${error.message}`);
    }
  }

  validateEntryPoints(targetModule, entryPoints) {
    const availableExports = Object.keys(targetModule);
    const missingEntryPoints = [];

    for (const entryPoint of entryPoints) {
      const entryName = entryPoint.name || entryPoint;
      
      if (!this.hasEntryPoint(targetModule, entryName)) {
        missingEntryPoints.push(entryName);
      }
    }

    if (missingEntryPoints.length > 0) {
      logger.warn(`Missing entry points: ${missingEntryPoints.join(', ')}`);
      logger.debug(`Available exports: ${availableExports.join(', ')}`);
    }
  }

  hasEntryPoint(targetModule, entryName) {
    // Check direct export
    if (targetModule[entryName]) return true;
    
    // Check default export
    if (targetModule.default && targetModule.default[entryName]) return true;
    
    // Check nested paths (e.g., "compile.render")
    if (entryName.includes('.')) {
      const path = entryName.split('.');
      let current = targetModule;
      
      for (const segment of path) {
        if (current && current[segment]) {
          current = current[segment];
        } else {
          return false;
        }
      }
      return true;
    }
    
    return false;
  }

  getTargetModule(targetName) {
    const cached = this.targetCache.get(targetName);
    if (!cached) {
      throw new Error(`Target ${targetName} not found in cache. Call setupTarget() first.`);
    }
    return cached.module;
  }

  getTargetConfig(targetName) {
    const cached = this.targetCache.get(targetName);
    if (!cached) {
      throw new Error(`Target ${targetName} not found in cache. Call setupTarget() first.`);
    }
    return cached.config;
  }

  /**
   * Set up a target from just a package name and version — no YAML config needed.
   * Auto-discovers entry points, call sequences, and pollution candidates.
   *
   * @param {string} packageSpec - e.g., "pug@3.0.2" or "squirrelly@8.0.8"
   * @returns {{ config: object, module: object }} The auto-generated config and loaded module
   */
  async setupTargetFromPackage(packageSpec) {
    const { name, version: requestedVersion } = this.parsePackageSpec(packageSpec);
    let version = requestedVersion;

    logger.info(`Setting up target from package: ${name}@${version}`);

    // Install the package
    await this.installPackage(name, version);

    // Reconcile the requested spec ('latest', a dist-tag, or a semver range) to
    // the CONCRETE version npm installed. Everything downstream — the reported
    // version, the standalone PoC, and the OSV / GitHub-Advisory-DB lookups that
    // decide known-cve vs undocumented — must key on an exact version, or a known
    // CVE gets mislabelled as an undocumented 0-day (advisory queries for the
    // literal "latest" match nothing).
    if (!this.options.dryRun) {
      const installed = this._installedVersion(name);
      if (installed && installed !== version) {
        logger.info(`Resolved ${name}@${version} to installed version ${installed}`);
        version = installed;
      }
    }

    if (this.options.dryRun) {
      const config = {
        name, package: name, version,
        description: `Dry-run target: ${name}@${version}`,
        entryPoints: [{ name: 'compile', inputType: 'template' }],
        sinks: ['eval', 'Function', 'child_process.exec'],
        pollutionPoints: ['debug', 'template', 'cache'],
        _autoDiscovered: true
      };
      return { config, module: { name, version, isDryRun: true } };
    }

    // Load the main module — with DOM shim fallback for browser-only packages
    const targetModule = await this.importWithDOMFallback(name);
    const subModules = await this.loadSubPathModules(name);

    // Auto-discover everything (main module + sub-modules)
    const config = await discoverTarget(targetModule, name, version, subModules);

    // Record whether this target needed a DOM (loaded via jsdom). The
    // instrumentation uses this to route Phase A execution through the sandbox
    // child instead of running the browser lib in-process (where a synchronous
    // jsdom XHR would freeze the fuzzer's event loop). Covers both the known
    // browser-only packages and the runtime DOM-detection fallback.
    config.browserEnv = this._loadedViaJsdom === true;

    // Cache — merge sub-module exports into targetModule for execution
    const mergedModule = { ...targetModule };
    for (const [subPath, subMod] of Object.entries(subModules)) {
      const key = subPath.replace(`${name}/`, '').replace(/[/-]/g, '_');
      if (!mergedModule[key]) mergedModule[key] = subMod;
    }

    this.targetCache.set(name, {
      config,
      module: mergedModule,
      setupTime: new Date()
    });

    return { config, module: mergedModule };
  }

  /**
   * Import a module, falling back to a minimal DOM shim for browser-only packages
   * (jQuery, Backbone, etc.) that require window/document at load time.
   */
  async importWithDOMFallback(name) {
    // Clear CJS cache first — critical for VersionRunner which loads multiple
    // versions of the same package sequentially. Without this, require() returns
    // the first version's cached module instead of the newly-installed one.
    this._clearRequireCache(name);

    // Reset the per-load jsdom marker; _loadWithJsdom sets it when a DOM is used.
    this._loadedViaJsdom = false;

    // Known browser-only packages that export a factory requiring window/document.
    // These may import() successfully but return a useless factory without DOM globals.
    // Go straight to jsdom for these to get a fully-initialized module.
    const isLikelyBrowserOnly = [...BROWSER_ONLY_PACKAGES].some(pkg => name === pkg || name.startsWith(pkg + '@'));

    if (isLikelyBrowserOnly) {
      logger.info(`${name} is a known browser-only package — loading with jsdom`);
      return await this._loadWithJsdom(name);
    }

    try {
      // A clean import wins. We deliberately do NOT speculatively re-load a bare
      // `module.exports = fn` package under jsdom: that shape is the tool's most
      // common target (deep-extend, merge-deep, defaults-deep and every other
      // server-side merge/extend function), not a browser factory. Routing all of
      // them through jsdom marked them browserEnv and ran every discovery probe on
      // the slow jsdom path — enough to blow the per-target wall-clock budget in a
      // CPU-constrained container (observed as INCONCLUSIVE timeouts for
      // deep-extend/merge-deep in the benchmark). Genuine browser-only factories
      // are covered two other ways: the explicit BROWSER_ONLY_PACKAGES list above,
      // and the DOM-error catch below (a factory that actually touches
      // window/document at load throws, and we retry with jsdom then). An unlisted
      // browser factory that imports cleanly without touching the DOM is the only
      // gap; add it to BROWSER_ONLY_PACKAGES if one turns up.
      return await import(name);
    } catch (err) {
      const msg = err.message || '';
      const needsDom = /window|document|DOM|browser|navigator/i.test(msg);
      if (!needsDom) throw err;

      // Needs DOM shim
      logger.info(`${name} requires a DOM environment — loading with jsdom`);
      return await this._loadWithJsdom(name);
    }
  }

  /**
   * Load a module with full jsdom environment.
   * Uses CJS require with jsdom globals for proper jQuery-style initialization.
   */
  async _loadWithJsdom(name) {
    // Try minimal shim first
    this._installDOMShim();

    // Full jsdom for complete browser environment
    let jsdomErr;
    try {
      const { JSDOM, VirtualConsole } = await import('jsdom');
      const vc = new VirtualConsole();
      vc.on('error', () => {});
      const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', { url: 'http://localhost', virtualConsole: vc });
      global.window = dom.window;
      global.document = dom.window.document;
      try {
        Object.defineProperty(global, 'navigator', {
          value: dom.window.navigator,
          writable: true,
          configurable: true
        });
      } catch { /* ignore */ }
      logger.info(`Using jsdom for ${name}`);
      this._loadedViaJsdom = true;
      // Use CJS loader for fresh cache and proper DOM initialization
      return await this._importWithFreshCache(name);
    } catch (err_jsdom) {
      jsdomErr = err_jsdom;
    }
    throw new Error(
      `${name} requires a browser DOM. Install jsdom to enable browser package support: npm install jsdom\nJSDOM error: ${jsdomErr?.message}`
    );
  }

  /**
   * Import a module with fresh cache by loading via CommonJS.
   * Clears the CJS require cache for the package first, so that
   * a different version installed into node_modules is actually loaded.
   * This is critical for VersionRunner which installs multiple versions
   * of the same package sequentially.
   */
  async _importWithFreshCache(name) {
    // Clear CJS cache entries for this package so require() picks up the
    // newly-installed version instead of returning the cached old one.
    this._clearRequireCache(name);

    // Write the loader inside node_modules, not the workspace root. Under the
    // sandbox the workspace is mounted READ-ONLY (EROFS on any write to cwd),
    // but node_modules is a writable volume. Placing the loader here keeps
    // module resolution intact — require('jsdom') / require(name) still walk up
    // to <cwd>/node_modules — while writing to a path the sandbox permits.
    const tmpDir = path.join(process.cwd(), 'node_modules', '.uopfuzz-temp');
    const loaderPath = path.join(tmpDir, `loader-${Date.now()}-${Math.random().toString(36).slice(2)}.cjs`);

    const loaderCode = `
// Clear require cache for '${name}' inside the loader too — the parent
// process may have already cached a different version.
for (const key of Object.keys(require.cache)) {
  if (key.includes('/node_modules/${name}/') || key.includes('\\\\node_modules\\\\${name}\\\\')) {
    delete require.cache[key];
  }
}

const { JSDOM, VirtualConsole } = require('jsdom');
// Suppress jsdom internal errors (ERR_INVALID_PROTOCOL, ECONNREFUSED, etc.)
const virtualConsole = new VirtualConsole();
virtualConsole.on('error', () => {});
const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>', {
  url: 'http://localhost',
  virtualConsole
});
global.window = dom.window;
global.document = dom.window.document;
try {
  Object.defineProperty(global, 'navigator', {
    value: dom.window.navigator,
    writable: true,
    configurable: true
  });
} catch {}

// Try factory entry point first (for jquery and similar)
try {
  const factory = require('${name}/factory');
  module.exports = factory(dom.window);
} catch {
  // Fall back to regular require
  module.exports = require('${name}');
}
`;
    
    try {
      await fs.mkdir(tmpDir, { recursive: true });
      await fs.writeFile(loaderPath, loaderCode, 'utf8');
      const cjsModule = require(loaderPath);
      
      // Convert to ESM-like format with default and named exports
      if (cjsModule && typeof cjsModule === 'object') {
        return cjsModule;
      }
      // If it's a function (like jQuery), wrap it
      return { default: cjsModule, ...cjsModule };
    } finally {
      try { await fs.unlink(loaderPath); } catch { /* ignore */ }
    }
  }

  /**
   * Install a minimal global DOM shim for packages that check for window/document.
   * Installs only what's needed — avoids breaking Node.js builtins.
   */
  _installDOMShim() {
    if (global.window) return; // Already shimmed

    const noop = () => {};
    const noopEl = { style: {}, classList: { add: noop, remove: noop }, addEventListener: noop };

    // Use defineProperty for read-only globals — many Node.js globals (navigator,
    // location) have a getter but no setter, so direct assignment throws TypeError.
    const defineGlobal = (name, value) => {
      const desc = Object.getOwnPropertyDescriptor(global, name);
      if (desc && !desc.configurable) {
        if (desc.set) {
          try { global[name] = value; } catch { /* ignore */ }
        }
        return;
      }
      try {
        global[name] = value;
      } catch {
        try {
          Object.defineProperty(global, name, { value, writable: true, configurable: true });
        } catch { /* can't override, leave as-is */ }
      }
    };

    defineGlobal('window', global);
    defineGlobal('document', {
      createElement: () => ({ ...noopEl }),
      createElementNS: () => ({ ...noopEl }),
      createTextNode: () => ({}),
      getElementById: () => null,
      querySelector: () => null,
      querySelectorAll: () => [],
      getElementsByTagName: () => [],
      addEventListener: noop,
      removeEventListener: noop,
      body: { ...noopEl, appendChild: noop, removeChild: noop },
      head: { ...noopEl, appendChild: noop },
      documentElement: { ...noopEl },
      location: { href: 'http://localhost/', origin: 'http://localhost' },
      readyState: 'complete',
    });
    defineGlobal('navigator', { userAgent: 'Node.js/UoPFuzz', platform: 'node' });
    defineGlobal('location', { href: 'http://localhost/', origin: 'http://localhost' });
    defineGlobal('XMLHttpRequest', class XMLHttpRequest { open() {} send() {} addEventListener() {} });
    defineGlobal('Event', class Event { constructor(type) { this.type = type; } });
    defineGlobal('CustomEvent', class CustomEvent extends global.Event {});
    logger.debug('Minimal DOM shim installed for browser-only package');
  }

  /**
   * Load sub-path modules from a package using multiple strategies:
   * 1. Read package.json exports map for declared sub-paths
   * 2. Scan the installed package's dist directory for utility files
   * 3. Try common sub-path patterns
   * Uses both ESM import() and CJS require() as fallbacks.
   */
  async loadSubPathModules(packageName) {
    const subModules = {};
    const tried = new Set();

    // Strategy 1: Read package.json exports map via filesystem
    const subPathsFromExports = this.getExportsSubPaths(packageName);
    for (const sub of subPathsFromExports) {
      await this.tryLoadSubModule(packageName, sub, subModules, tried);
    }

    // Strategy 2: Scan for utility files in the installed package
    const utilityFiles = this.scanForUtilityFiles(packageName);
    for (const relPath of utilityFiles) {
      await this.tryLoadSubModule(packageName, relPath, subModules, tried);
    }

    // Strategy 3: Try common sub-path patterns
    const commonSubPaths = [
      'server', 'client', 'utils', 'helpers', 'lib', 'core',
      'router', 'middleware', 'config',
      'head', 'link', 'image', 'script', 'dynamic',
      'navigation', 'headers', 'cookies',
      'parser', 'compiler', 'renderer', 'transformer',
      'merge', 'clone', 'defaults', 'extend',
    ];
    for (const sub of commonSubPaths) {
      await this.tryLoadSubModule(packageName, sub, subModules, tried);
    }

    if (Object.keys(subModules).length > 0) {
      logger.info(`Loaded ${Object.keys(subModules).length} sub-modules: ${Object.keys(subModules).map(k => k.replace(`${packageName}/`, '')).join(', ')}`);
    } else {
      logger.debug(`No sub-modules loadable for ${packageName}`);
    }

    return subModules;
  }

  /**
   * Read the package.json exports field and extract importable sub-paths.
   */
  getExportsSubPaths(packageName) {
    const subPaths = [];
    try {
      const pkgJsonPath = require.resolve(`${packageName}/package.json`);
      const pkg = JSON.parse(fsSync.readFileSync(pkgJsonPath, 'utf8'));

      if (pkg.exports && typeof pkg.exports === 'object') {
        const extractPaths = (obj) => {
          for (const [key] of Object.entries(obj)) {
            if (key.startsWith('./') && key !== '.' && key !== './package.json') {
              // Remove ./ prefix and any wildcard
              const clean = key.slice(2).replace(/\/\*$/, '');
              if (clean && !clean.includes('*')) {
                subPaths.push(clean);
              }
            }
          }
        };
        extractPaths(pkg.exports);
      }

      logger.debug(`Found ${subPaths.length} sub-paths from exports map: ${subPaths.slice(0, 10).join(', ')}`);
    } catch (err) {
      logger.debug(`Could not read exports map for ${packageName}: ${err.message}`);
    }
    return subPaths;
  }

  /**
   * Scan the installed package directory for utility/shared files that
   * are likely to contain pure functions (merge, parse, config utils, etc.).
   */
  scanForUtilityFiles(packageName) {
    const files = [];
    try {
      const pkgJsonPath = require.resolve(`${packageName}/package.json`);
      const pkgDir = path.dirname(pkgJsonPath);

      // Directories likely to contain reusable utilities
      const scanDirs = [
        'dist/shared', 'dist/lib', 'dist/utils', 'dist/shared/lib',
        'lib', 'lib/utils', 'lib/shared',
        'utils', 'shared', 'helpers',
        'dist/compiled', 'dist/server/lib',
      ];

      const jsExtRe = /\.(js|mjs|cjs)$/;
      const interestingPatterns = /\b(util|helper|merge|config|parse|route|url|path|header|cookie|query|param|option|default|extend|assign|clone|deep|share|common)\b/i;

      for (const dir of scanDirs) {
        const fullDir = path.join(pkgDir, dir);
        try {
          if (!fsSync.existsSync(fullDir) || !fsSync.statSync(fullDir).isDirectory()) continue;

          const entries = fsSync.readdirSync(fullDir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isFile() && jsExtRe.test(entry.name) && interestingPatterns.test(entry.name)) {
              const relPath = path.join(dir, entry.name).replace(/\\/g, '/').replace(jsExtRe, '');
              files.push(relPath);
            }
          }
        } catch { /* directory not readable */ }
      }

      logger.debug(`Found ${files.length} utility files to probe: ${files.slice(0, 10).join(', ')}`);
    } catch (err) {
      logger.debug(`Could not scan package directory for ${packageName}: ${err.message}`);
    }
    return files;
  }

  /**
   * Try loading a sub-module using both ESM import() and CJS require().
   */
  async tryLoadSubModule(packageName, subPath, subModules, tried) {
    const fullPath = `${packageName}/${subPath}`;
    if (tried.has(fullPath)) return;
    tried.add(fullPath);

    // Try ESM import first
    try {
      const mod = await import(fullPath);
      if (mod && (typeof mod === 'object' || typeof mod === 'function')) {
        const exportCount = Object.keys(mod).filter(k => k !== '__esModule' && k !== 'default').length;
        if (exportCount > 0 || mod.default) {
          subModules[fullPath] = mod;
          logger.debug(`Loaded (ESM): ${fullPath} (${exportCount} exports)`);
          return;
        }
      }
    } catch { /* ESM import failed */ }

    // Try CJS require as fallback
    try {
      const mod = require(fullPath);
      if (mod && (typeof mod === 'object' || typeof mod === 'function')) {
        const exportCount = typeof mod === 'function' ? 1 : Object.keys(mod).filter(k => k !== '__esModule').length;
        if (exportCount > 0) {
          subModules[fullPath] = mod;
          logger.debug(`Loaded (CJS): ${fullPath} (${exportCount} exports)`);
          return;
        }
      }
    } catch { /* CJS require failed */ }
  }

  parsePackageSpec(spec) {
    // Handle "pug@3.0.2", "pug@^3.0.0", "pug" (latest)
    const atIdx = spec.lastIndexOf('@');
    if (atIdx > 0) {
      return { name: spec.substring(0, atIdx), version: spec.substring(atIdx + 1) };
    }
    return { name: spec, version: 'latest' };
  }

  /**
   * Clear the CJS require cache for a package and all its sub-modules.
   *
   * This is essential for VersionRunner: after `npm install pkg@v2` overwrites
   * `pkg@v1` in node_modules, `require('pkg')` still returns the cached v1
   * module unless we purge the cache entries first.
   *
   * Note: ESM import() cache cannot be cleared programmatically. For ESM-only
   * packages, the sandbox child process (which starts with a fresh cache) is
   * the correct path. For CJS packages loaded via _importWithFreshCache, this
   * method ensures the loader picks up the new version.
   *
   * @param {string} packageName - Package name (e.g., 'jquery')
   */
  _clearRequireCache(packageName) {
    // Build a pattern that matches node_modules/packageName/ entries
    // Handle both forward and backward slashes (Windows compat)
    const patterns = [
      `/node_modules/${packageName}/`,
      `\\node_modules\\${packageName}\\`,
    ];

    let cleared = 0;
    for (const key of Object.keys(require.cache)) {
      if (patterns.some(p => key.includes(p))) {
        delete require.cache[key];
        cleared++;
      }
    }

    if (cleared > 0) {
      logger.debug(`Cleared ${cleared} CJS cache entries for ${packageName}`);
    }
  }

  async cleanup() {
    // In a real implementation, this might clean up temporary installations
    // For now, we just clear our caches
    this.targetCache.clear();
    this.installedPackages.clear();
    logger.debug('Target integration cleanup completed');
  }
}