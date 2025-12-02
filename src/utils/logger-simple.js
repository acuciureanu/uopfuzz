/**
 * Simple, secure logger replacement for winston
 * Zero dependencies, no supply chain risk
 */

// ANSI color codes (replaces chalk)
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  dim: '\x1b[2m',

  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',

  bgRed: '\x1b[41m',
  bgGreen: '\x1b[42m',
  bgYellow: '\x1b[43m',
};

class SimpleLogger {
  constructor() {
    this.levels = {
      error: 0,
      warn: 1,
      info: 2,
      debug: 3
    };
    this.currentLevel = 'info';
  }

  set level(levelName) {
    if (this.levels[levelName] !== undefined) {
      this.currentLevel = levelName;
    }
  }

  get level() {
    return this.currentLevel;
  }

  shouldLog(level) {
    return this.levels[level] <= this.levels[this.currentLevel];
  }

  formatMessage(level, ...args) {
    const timestamp = new Date().toISOString();
    const levelStr = level.toUpperCase().padEnd(5);
    return `[${timestamp}] ${levelStr} ${args.map(arg =>
      typeof arg === 'object' ? JSON.stringify(arg) : String(arg)
    ).join(' ')}`;
  }

  error(...args) {
    if (this.shouldLog('error')) {
      const msg = this.formatMessage('error', ...args);
      console.error(`${colors.red}${msg}${colors.reset}`);
    }
  }

  warn(...args) {
    if (this.shouldLog('warn')) {
      const msg = this.formatMessage('warn', ...args);
      console.warn(`${colors.yellow}${msg}${colors.reset}`);
    }
  }

  info(...args) {
    if (this.shouldLog('info')) {
      const msg = this.formatMessage('info', ...args);
      console.log(`${colors.blue}${msg}${colors.reset}`);
    }
  }

  debug(...args) {
    if (this.shouldLog('debug')) {
      const msg = this.formatMessage('debug', ...args);
      console.log(`${colors.dim}${msg}${colors.reset}`);
    }
  }
}

// Export a singleton instance
export const logger = new SimpleLogger();

// Export colors for direct use (replaces chalk)
export { colors };
