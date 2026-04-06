import fs from 'fs/promises';
import fsSync from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { createRequire } from 'module';
import YAML from 'yaml';
import { logger } from '../utils/logger.js';
import { discoverTarget } from './discovery.js';

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
      logger.info(`Installing package: ${packageId}`);
      
      if (this.options.dryRun) {
        logger.info(`🏃‍♂️ Dry run - would install ${packageId}`);
        this.installedPackages.add(packageId);
        return;
      }

      // Use npm to install the specific package version
      const installCommand = `npm install ${packageId} --no-save --silent`;
      execSync(installCommand, { 
        stdio: this.options.verbose ? 'inherit' : 'pipe',
        timeout: 30000 // 30 second timeout for package installation
      });
      
      this.installedPackages.add(packageId);
      logger.debug(`Successfully installed ${packageId}`);
      
    } catch (error) {
      throw new Error(`Failed to install ${packageId}: ${error.message}`);
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
    const { name, version } = this.parsePackageSpec(packageSpec);

    logger.info(`Setting up target from package: ${name}@${version}`);

    // Install the package
    await this.installPackage(name, version);

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

    logger.info(`Target ${name}@${version} auto-discovered and ready`);
    return { config, module: mergedModule };
  }

  /**
   * Import a module, falling back to a minimal DOM shim for browser-only packages
   * (jQuery, Backbone, etc.) that require window/document at load time.
   */
  async importWithDOMFallback(name) {
    // First attempt — most packages work fine
    try {
      return await import(name);
    } catch (err) {
      const msg = err.message || '';
      const needsDom = /window|document|DOM|browser|navigator/i.test(msg);
      if (!needsDom) throw err;

      logger.info(`${name} requires a DOM environment — installing minimal window/document shim`);
      this._installDOMShim();
      try {
        return await import(name);
      } catch (err2) {
        // Shim wasn't enough — try jsdom if available
        try {
          const { JSDOM } = await import('jsdom');
          const dom = new JSDOM('<!DOCTYPE html><html><body></body></html>');
          global.window = dom.window;
          global.document = dom.window.document;
          global.navigator = dom.window.navigator;
          logger.info(`Using jsdom for ${name}`);
          return await import(name);
        } catch {
          // jsdom not installed — re-throw original error with helpful message
          throw new Error(
            `${name} requires a browser DOM. Install jsdom to enable browser package support: npm install jsdom\nOriginal error: ${err2.message}`
          );
        }
      }
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
        const extractPaths = (obj, prefix = '') => {
          for (const [key, value] of Object.entries(obj)) {
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

      // Patterns in filenames that suggest interesting targets
      const interestingPatterns = /\b(util|helper|merge|config|parse|route|url|path|header|cookie|query|param|option|default|extend|assign|clone|deep|share|common)\b/i;

      for (const dir of scanDirs) {
        const fullDir = path.join(pkgDir, dir);
        try {
          if (!fsSync.existsSync(fullDir) || !fsSync.statSync(fullDir).isDirectory()) continue;

          const entries = fsSync.readdirSync(fullDir, { withFileTypes: true });
          for (const entry of entries) {
            if (entry.isFile() && /\.(js|mjs|cjs)$/.test(entry.name) && interestingPatterns.test(entry.name)) {
              // Convert filesystem path to a require-able path relative to package
              const relPath = path.join(dir, entry.name).replace(/\\/g, '/').replace(/\.(js|mjs|cjs)$/, '');
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

  async cleanup() {
    // In a real implementation, this might clean up temporary installations
    // For now, we just clear our caches
    this.targetCache.clear();
    this.installedPackages.clear();
    logger.debug('Target integration cleanup completed');
  }
}