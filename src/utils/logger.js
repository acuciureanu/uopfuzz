import winston from 'winston';

/**
 * This logger runs in the SAME process as the fuzzer, which deliberately
 * pollutes Object.prototype. Two pollution hazards produced "[Invalid Date]"
 * timestamps mid-run and must be designed out:
 *
 *   1. `winston.format.timestamp()` only sets `info.timestamp` when it is falsy
 *      (`if (!info.timestamp)`). A polluted `Object.prototype.timestamp`
 *      (a common UOP property name) is inherited as truthy, so winston skips
 *      setting a real one and the formatter reparses the polluted value.
 *   2. `new Date(x).toLocaleTimeString()` reparses a value and routes through
 *      Intl/locale resolution, both perturbable by a polluted prototype.
 *
 * So we ignore any inherited timestamp entirely and build HH:MM:SS from pristine
 * Date getters + String.prototype.padStart (own methods on Date/String
 * prototypes, unaffected by Object.prototype pollution), and guard the whole
 * formatter so a polluted prototype can never corrupt or crash a log line.
 */

const pad2 = (n) => String(n).padStart(2, '0');

function formatLine(info) {
  const d = new Date();
  const ts = `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;

  let metaStr = '';
  try {
    const meta = {};
    for (const k of Object.keys(info)) {
      if (k !== 'level' && k !== 'message' && k !== 'timestamp') meta[k] = info[k];
    }
    if (Object.keys(meta).length) metaStr = ' ' + JSON.stringify(meta);
  } catch {
    /* a polluted prototype (e.g. Object.prototype.toJSON) must not break logging */
  }

  return `[${ts}] ${info.level}: ${info.message}${metaStr}`;
}

export const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.colorize(),
    winston.format.printf((info) => {
      try {
        return formatLine(info);
      } catch {
        // Last-resort fallback — never let logging itself throw mid-scan.
        return `${info.level}: ${info.message}`;
      }
    })
  ),
  transports: [
    new winston.transports.Console()
  ]
});
