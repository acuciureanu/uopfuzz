import fs from 'fs';
import chalk from 'chalk';
import { logger } from './logger.js';

/**
 * Host-safety gate for the untrusted-package modes (`mass`, cdnjs `versions`).
 *
 * These modes install and EXECUTE arbitrary, attacker-influencable npm/cdnjs
 * packages. `--ignore-scripts` and the in-process worker hardening are speed
 * bumps, not a boundary — the only thing that actually contains a hostile
 * package is the dev container (`.devcontainer/`, `run-sandboxed.sh`). Running
 * these modes on a bare host means a supply-chain payload runs with your uid, on
 * your filesystem, on your network. So on a non-sandboxed host we refuse by
 * default rather than merely printing a tip.
 *
 * "Sandboxed" is detected, not asserted by us: the container sets
 * `UOPFUZZ_CONTAINER=1` (see run-sandboxed.sh) and Docker/Podman leave a
 * marker file at the fs root. Either is enough. This is best-effort detection —
 * it can be spoofed by setting the env var, which is exactly what the explicit
 * `--i-understand-untrusted-code` override is for (an honest, loud opt-out for
 * users who isolate another way).
 */

/** Marker files Docker/Podman drop into a container's filesystem root. */
const CONTAINER_MARKERS = ['/.dockerenv', '/run/.containerenv'];

/**
 * True when this process appears to be running inside a container sandbox.
 *
 * Detection sources (any one suffices):
 *   - `UOPFUZZ_CONTAINER` is set and non-empty (run-sandboxed.sh sets it).
 *   - a Docker (`/.dockerenv`) or Podman (`/run/.containerenv`) marker exists.
 *
 * @param {object} [env=process.env] - injectable for tests.
 * @param {(p: string) => boolean} [markerExists] - injectable fs check for tests.
 * @returns {boolean}
 */
export function isSandboxed(env = process.env, markerExists = (p) => fs.existsSync(p)) {
  if (env && typeof env.UOPFUZZ_CONTAINER === 'string' && env.UOPFUZZ_CONTAINER.trim() !== '') {
    return true;
  }
  return CONTAINER_MARKERS.some((p) => {
    try { return markerExists(p); } catch { return false; }
  });
}

/**
 * Pure decision function — no I/O, trivially unit-testable.
 *
 * @param {{ sandboxed: boolean, override: boolean }} state
 * @returns {{ allow: boolean, level: 'ok'|'warn'|'refuse', message: string }}
 *   - sandboxed              → allow, level 'ok'
 *   - not sandboxed, override → allow, level 'warn' (loud, proceed anyway)
 *   - not sandboxed, no override → refuse, level 'refuse'
 */
export function evaluateSandboxGate({ sandboxed, override }) {
  if (sandboxed) {
    return { allow: true, level: 'ok', message: 'Sandbox detected — running contained.' };
  }
  if (override) {
    return {
      allow: true,
      level: 'warn',
      message:
        '--i-understand-untrusted-code: running untrusted packages OUTSIDE a container. ' +
        'A supply-chain payload can now reach your host filesystem and network. ' +
        'You have accepted this risk.',
    };
  }
  return {
    allow: false,
    level: 'refuse',
    message:
      'Refusing to run untrusted packages on a non-sandboxed host.\n' +
      'This mode installs and EXECUTES arbitrary packages — run it inside the dev container:\n' +
      '    ./run-sandboxed.sh <same arguments>\n' +
      'or from an already-isolated environment (CI, your own sandbox) with UOPFUZZ_CONTAINER=1 set.\n' +
      'If you truly accept the risk of running on this host, pass --i-understand-untrusted-code.',
  };
}

/**
 * Enforce the gate for a mode that installs/executes untrusted packages.
 *
 * Logs the decision and, when refusing, exits the process with a non-zero code.
 * The `exit`/`log`/`sandboxedFn` hooks are injectable so the enforcement path
 * itself is unit-testable without spawning a process.
 *
 * @param {object} opts
 * @param {string} opts.mode - human label for the mode (e.g. 'mass', 'versions').
 * @param {boolean} [opts.override=false] - the --i-understand-untrusted-code flag.
 * @param {() => boolean} [opts.sandboxedFn=isSandboxed] - injectable detector.
 * @param {(code: number) => void} [opts.exit=process.exit] - injectable exit.
 * @param {object} [opts.log=logger] - injectable logger.
 * @returns {boolean} true when the caller may proceed (never returns on refuse
 *   unless a non-terminating `exit` hook is injected, in which case it returns false).
 */
export function assertSandboxedOrRefuse({
  mode,
  override = false,
  sandboxedFn = isSandboxed,
  exit = process.exit,
  log = logger,
} = {}) {
  const sandboxed = sandboxedFn();
  const decision = evaluateSandboxGate({ sandboxed, override });

  if (decision.level === 'ok') {
    log.info(chalk.green(`[sandbox] ${mode}: ${decision.message}`));
    return true;
  }
  if (decision.level === 'warn') {
    log.warn(chalk.red.bold(`[sandbox] ${mode}: ${decision.message}`));
    return true;
  }
  // refuse
  log.error(chalk.red.bold(`[sandbox] ${mode}: ${decision.message}`));
  exit(1);
  return false;
}
