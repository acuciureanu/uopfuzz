import { createRequire } from 'module';
import fsSync from 'fs';
import path from 'path';
import { logger } from './logger.js';

const require = createRequire(import.meta.url);

/**
 * Supply Chain Security: Package Integrity Verification
 *
 * Checks installed packages for known indicators of malicious content:
 * 1. Lifecycle scripts (postinstall, preinstall, install) that would have
 *    run if --ignore-scripts weren't set
 * 2. Suspicious patterns in package contents (eval of env vars, network
 *    calls in install hooks, obfuscated code)
 * 3. Abnormal package structure (binaries in unexpected places, hidden files)
 */

// Patterns in lifecycle scripts that are strong indicators of malicious intent
const SUSPICIOUS_SCRIPT_PATTERNS = [
  /curl\s+/i,
  /wget\s+/i,
  /powershell/i,
  /\bhttp:\/\//,
  /\bhttps:\/\/(?!registry\.npmjs\.org|github\.com)/,
  /eval\s*\(/,
  /child_process/,
  /\bexec\s*\(/,
  /\bexecSync\s*\(/,
  /\bspawn\s*\(/,
  /process\.env/,
  /Buffer\.from\s*\(\s*['"][A-Za-z0-9+/=]{20,}['"]/,  // Base64 encoded payloads
  /\\x[0-9a-f]{2}/i,  // Hex-encoded strings
];

// Files that should not exist in normal npm packages
const SUSPICIOUS_FILES = [
  '.env',
  '.npmrc',
  'postinstall.sh',
  'preinstall.sh',
  'setup.sh',
  'install.sh',
];

/**
 * Verify a package is safe after installation.
 * Called after `npm install --ignore-scripts`.
 *
 * @param {string} packageName
 * @param {string} version
 * @param {object} options - CLI options (skipIntegrityCheck to bypass)
 */
export async function verifyPackageIntegrity(packageName, version, options = {}) {
  if (options.skipIntegrityCheck) {
    logger.debug('Skipping package integrity check (--skip-integrity-check)');
    return;
  }

  const warnings = [];

  try {
    // Locate the installed package
    const pkgJsonPath = require.resolve(`${packageName}/package.json`);
    const pkgDir = path.dirname(pkgJsonPath);
    const pkg = JSON.parse(fsSync.readFileSync(pkgJsonPath, 'utf8'));

    // Check 1: Lifecycle scripts
    const lifecycleScripts = ['preinstall', 'install', 'postinstall', 'preuninstall', 'postuninstall'];
    for (const hook of lifecycleScripts) {
      if (pkg.scripts?.[hook]) {
        const script = pkg.scripts[hook];
        const isSuspicious = SUSPICIOUS_SCRIPT_PATTERNS.some(p => p.test(script));

        if (isSuspicious) {
          warnings.push(
            `BLOCKED lifecycle script "${hook}": "${script}" ` +
            `(contains suspicious pattern — would have run without --ignore-scripts)`
          );
        } else {
          warnings.push(
            `Package has "${hook}" script: "${script}" ` +
            `(blocked by --ignore-scripts; use --allow-scripts to permit)`
          );
        }
      }
    }

    // Check 2: Suspicious files in package root
    for (const file of SUSPICIOUS_FILES) {
      const filePath = path.join(pkgDir, file);
      if (fsSync.existsSync(filePath)) {
        warnings.push(`Suspicious file found: ${file}`);
      }
    }

    // Check 3: Binary/native files outside expected locations
    const bindingGyp = path.join(pkgDir, 'binding.gyp');
    if (fsSync.existsSync(bindingGyp)) {
      warnings.push(
        'Package contains native addon (binding.gyp). ' +
        'Native addons cannot compile with --ignore-scripts. ' +
        'If this package requires compilation, use --allow-scripts.'
      );
    }

    // Check 4: Look for obfuscated JS in top-level files
    const topFiles = fsSync.readdirSync(pkgDir).filter(f => f.endsWith('.js'));
    for (const file of topFiles.slice(0, 5)) {
      try {
        const content = fsSync.readFileSync(path.join(pkgDir, file), 'utf8');
        // Very long single lines with heavy hex/unicode escaping = obfuscated
        const lines = content.split('\n');
        for (const line of lines) {
          if (line.length > 5000) {
            const hexCount = (line.match(/\\x[0-9a-f]{2}/gi) || []).length;
            const unicodeCount = (line.match(/\\u[0-9a-f]{4}/gi) || []).length;
            if (hexCount + unicodeCount > 20) {
              warnings.push(`Potentially obfuscated code in ${file} (${hexCount} hex + ${unicodeCount} unicode escapes in a ${line.length}-char line)`);
              break;
            }
          }
        }
      } catch { /* unreadable file, skip */ }
    }

  } catch (error) {
    logger.debug(`Package integrity check failed for ${packageName}: ${error.message}`);
    // Don't block on check failure — the package may not resolve yet
    return;
  }

  // Report findings
  if (warnings.length > 0) {
    logger.warn(`Package safety check for ${packageName}@${version}:`);
    for (const warning of warnings) {
      logger.warn(`  ⚠ ${warning}`);
    }

    // If any lifecycle script had suspicious patterns, abort unless forced
    const hasSuspicious = warnings.some(w => w.startsWith('BLOCKED'));
    if (hasSuspicious && !options.allowSuspicious) {
      throw new Error(
        `Package ${packageName}@${version} has suspicious lifecycle scripts. ` +
        `Refusing to proceed. Use --allow-suspicious to override (NOT RECOMMENDED).`
      );
    }
  } else {
    logger.debug(`Package ${packageName}@${version} passed integrity checks`);
  }
}
