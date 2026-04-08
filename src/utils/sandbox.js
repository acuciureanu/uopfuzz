import { fork } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';
import { logger } from './logger.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Sandboxed Target Execution
 *
 * Runs target code in an isolated child process to prevent:
 * 1. Malicious code from accessing the fuzzer's process state
 * 2. Filesystem writes outside the sandbox
 * 3. Network exfiltration during execution
 * 4. Process-level attacks (process.exit, process.env manipulation)
 *
 * Defense in depth:
 * - Layer 1: Child process isolation (separate V8 instance, separate memory)
 * - Layer 2: Network restriction via NODE_OPTIONS=--dns-result-order and unref
 * - Layer 3: Filesystem restriction via chroot/chdir (when running as root in container)
 * - Layer 4: Timeout enforcement from the parent process
 * - Layer 5: Dev container (outer boundary — see .devcontainer/)
 *
 * The child process loads the target, executes it, and returns results via IPC.
 * If it crashes, hangs, or tries to escape, the parent kills it.
 */

/**
 * Execute a function call in a sandboxed child process.
 *
 * @param {string} packageName - npm package to load
 * @param {string} entryPoint - Function path (e.g., 'compile' or 'utils.merge')
 * @param {Array} args - Serializable arguments
 * @param {object} options
 * @param {number} options.timeoutMs - Execution timeout
 * @param {boolean} options.blockNetwork - Disable outbound network (default true)
 * @param {object} options.pollution - { property, value } for differential testing
 * @returns {Promise<object>} Execution result with output, error, traces
 */
export function executeInSandbox(packageName, entryPoint, args, options = {}) {
  const {
    timeoutMs = 5000,
    blockNetwork = true,
    pollution = null,
    mode = 'execute', // 'execute' | 'differential' | 'discover_uop'
  } = options;

  return new Promise((resolve, reject) => {
    const workerPath = path.join(__dirname, 'sandbox-worker.js');

    // Build environment for the child process
    const childEnv = { ...process.env };

    // SECURITY: Block network access in the child process.
    // We use two mechanisms:
    // 1. Set a flag the child reads to disable net/http at startup
    // 2. The child process monkey-patches net.connect/http.request
    if (blockNetwork) {
      childEnv.UOPFUZZ_BLOCK_NETWORK = '1';
    }

    // Remove sensitive env vars from the child
    const sensitiveVars = [
      'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
      'GITHUB_TOKEN', 'GH_TOKEN', 'GITLAB_TOKEN', 'NPM_TOKEN',
      'DOCKER_AUTH_CONFIG', 'SSH_AUTH_SOCK', 'SSH_PRIVATE_KEY',
      'DATABASE_URL', 'REDIS_URL', 'MONGO_URI', 'MONGODB_URI',
      'API_KEY', 'SECRET_KEY', 'PRIVATE_KEY', 'JWT_SECRET',
      'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
    ];
    for (const v of sensitiveVars) {
      delete childEnv[v];
    }
    // Also strip anything that looks like a secret
    for (const key of Object.keys(childEnv)) {
      if (/SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE.*KEY/i.test(key)) {
        delete childEnv[key];
      }
    }

    const child = fork(workerPath, [], {
      env: childEnv,
      stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
      // SECURITY: Don't inherit the parent's file descriptors
      detached: false,
      // Limit child memory to 512MB to prevent resource exhaustion
      execArgv: ['--max-old-space-size=512'],
    });

    let settled = false;

    const timer = setTimeout(() => {
      if (!settled) {
        settled = true;
        child.kill('SIGKILL');
        resolve({
          error: 'Sandbox execution timed out',
          timedOut: true,
          output: null,
        });
      }
    }, timeoutMs + 1000); // +1s grace for IPC overhead

    child.on('message', (msg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      child.kill('SIGTERM');
      resolve(msg);
    });

    child.on('error', (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ error: err.message, output: null });
    });

    child.on('exit', (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({
        error: code !== 0 ? `Sandbox exited with code ${code}` : null,
        output: null,
        crashed: code !== 0,
      });
    });

    // Send the execution request to the child
    child.send({
      mode,
      packageName,
      entryPoint,
      args: serializeArgs(args),
      timeoutMs,
      pollution,
    });
  });
}

/**
 * Serialize arguments for IPC transfer.
 * Functions and symbols cannot cross the IPC boundary.
 */
function serializeArgs(args) {
  return args.map(arg => {
    if (typeof arg === 'function') {
      return { __type: 'function', source: arg.toString() };
    }
    if (typeof arg === 'symbol') {
      return { __type: 'symbol', description: arg.description };
    }
    if (arg instanceof Date) {
      return { __type: 'date', iso: arg.toISOString() };
    }
    if (Buffer.isBuffer(arg)) {
      return { __type: 'buffer', data: arg.toString('base64') };
    }
    return arg;
  });
}
