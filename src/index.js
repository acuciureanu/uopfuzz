import { Orchestrator } from './orchestrator/index.js';

export { Orchestrator };
export { TargetIntegration } from './target-integration/index.js';
export { discoverTarget } from './target-integration/discovery.js';
export { InputGeneration } from './input-generation/index.js';
export { Instrumentation } from './instrumentation/index.js';
export { GadgetAnalysis } from './gadget-analysis/index.js';
export { executeDifferential, discoverUOPProperties } from './instrumentation/differential.js';
export { logger } from './utils/logger.js';

// cdnjs sources
export { fetchLibraries, fetchLibrary, fetchLibraryVersion, resolveNpmPackage, filterJSLibraries, rankByStars } from './sources/cdnjs.js';
export { getVersions, selectVersions, resolveInstallable, compareVersions, sortVersionsDesc } from './sources/version-scanner.js';

// Runners
export { MassRunner, VersionRunner } from './orchestrator/mass-runner.js';

// Reporting
export { generateSingleReport, generateMassReport, generateVersionReport } from './reporting/markdown-report.js';