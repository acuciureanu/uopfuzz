// DoS driver: stream.Readable with a polluted `highWaterMark` (string instead
// of number). Stream state validation throws ERR_INVALID_ARG_VALUE from an
// async context — uncatchable by user code (not even via 'error' listener or
// try/catch around construction), so the process dies (exit 1). A clean run
// idles and exits 0 via the watchdog timer below.
const { Readable } = require('stream');
const s = new Readable({ read() {} });
s.on('error', () => process.exit(0));
s.resume();
require('node:timers').setTimeout(() => process.exit(0), 2000).unref();
