import fs from 'fs/promises';
import path from 'path';
import { execSync } from 'child_process';
import YAML from 'yaml';
import { logger } from '../utils/logger.js';
import { discoverTarget } from './discovery.js';

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

    // Load the module
    const targetModule = await import(name);

    // Auto-discover everything
    const config = await discoverTarget(targetModule, name, version);

    // Cache
    this.targetCache.set(name, {
      config,
      module: targetModule,
      setupTime: new Date()
    });

    logger.info(`Target ${name}@${version} auto-discovered and ready`);
    return { config, module: targetModule };
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