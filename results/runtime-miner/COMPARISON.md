# Comparison — UoPFuzz vs GHunter

Node 24.17.0 — 2026-08-10

Ground truth: union of GHunter's published, manually-validated Node gadget table and UoPFuzz's machine-verified findings (corpus + miner). GHunter itself cannot execute here (patched-Node v21 artifact); its answers are its own published table.

## Headline

- GHunter-published gadget properties: **50**
- still live on this Node: **33** (dead/fixed: 17)
- UoPFuzz recall on the live ones: **97%** (32/33 — not fully proven: fetch.referrer=WEAK)
- machine-verified UoPFuzz gadgets GHunter never published: **145**
- manual effort: GHunter 31 person-hours · UoPFuzz 0

## Full table

| API | Property | Published by | GHunter | UoPFuzz (this Node) |
|---|---|---|---|---|
| child_process.exec | NODE_OPTIONS | SS | published | DETECTED |
| child_process.execFile | NODE_OPTIONS | SS | published | DETECTED |
| child_process.execFileSync | shell | SS | published | DETECTED |
| child_process.execFileSync | NODE_OPTIONS | SS | published | DETECTED |
| child_process.execSync | NODE_OPTIONS | SS | published | DETECTED |
| child_process.execSync | shell | SS | published | DETECTED |
| child_process.execSync | env | SS | published | DETECTED |
| child_process.fork | NODE_OPTIONS | SS | published | DETECTED |
| child_process.spawn | shell | SS | published | DETECTED |
| child_process.spawn | env | SS | published | DETECTED |
| child_process.spawn | NODE_OPTIONS | SS | published | DETECTED |
| child_process.spawnSync | shell | SS | published | DETECTED |
| child_process.spawnSync | NODE_OPTIONS | SS | published | DETECTED |
| child_process.spawnSync | env | SS | published | DETECTED |
| fetch | method | G | published | DETECTED |
| fetch | body | G | published | DETECTED |
| fetch | referrer | G | published | WEAK |
| fetch | socketPath | G | published | MITIGATED-UPSTREAM |
| http.get | hostname | G | published | MITIGATED-UPSTREAM (via http.request) |
| http.get | headers | G | published | MITIGATED-UPSTREAM (via http.request) |
| http.get | method | G | published | DETECTED (via http.request) |
| http.get | path | G | published | DETECTED |
| http.get | port | G | published | MITIGATED-UPSTREAM (via http.request) |
| http.request | hostname | G | published | MITIGATED-UPSTREAM |
| http.request | headers | G | published | MITIGATED-UPSTREAM |
| http.request | method | G | published | DETECTED |
| http.request | path | G | published | DETECTED |
| http.request | port | G | published | MITIGATED-UPSTREAM |
| http.Server.listen | backlog | G | published | MITIGATED-UPSTREAM |
| https.get | hostname | G | published | MITIGATED-UPSTREAM (via https.request) |
| https.get | headers | G | published | MITIGATED-UPSTREAM (via https.request) |
| https.get | method | G | published | DETECTED (via https.request) |
| https.get | path | G | published | DETECTED |
| https.get | port | G | published | MITIGATED-UPSTREAM (via https.request) |
| https.get | NODE_TLS_REJECT_UNAUTHORIZED | G | published | DETECTED (via https.request) |
| https.request | hostname | G | published | MITIGATED-UPSTREAM |
| https.request | headers | G | published | MITIGATED-UPSTREAM |
| https.request | method | G | published | DETECTED |
| https.request | path | G | published | DETECTED |
| https.request | port | G | published | MITIGATED-UPSTREAM |
| https.request | NODE_TLS_REJECT_UNAUTHORIZED | G | published | DETECTED |
| import() | source | G | published | MITIGATED-UPSTREAM |
| tls.connect | path | G | published | DETECTED |
| tls.connect | port | G | published | DETECTED |
| tls.connect | NODE_TLS_REJECT_UNAUTHORIZED | G | published | DETECTED |
| require | main | G+SS | published | FIXED-UPSTREAM |
| require | NODE_OPTIONS | G+SS | published | MITIGATED-UPSTREAM |
| worker_threads.Worker | argv | G | published | DETECTED |
| worker_threads.Worker | env | G | published | DETECTED |
| worker_threads.Worker | eval | G | published | DETECTED |
| child_process.spawn | shell+NODE_OPTIONS | — | not published | DETECTED |
| child_process.exec | shell | — | not published | DETECTED |
| tls.connect | rejectUnauthorized | — | not published | DETECTED |
| fetch | signal | — | not published | DETECTED |
| stream.Readable | highWaterMark | — | not published | DETECTED |
| http.request | encoding | — | not published | DETECTED |
| http.request | highWaterMark | — | not published | DETECTED |
| http.request | signal | — | not published | DETECTED |
| http.request | timeout | — | not published | DETECTED |
| http.Server.listen | signal | — | not published | DETECTED |
| https.request | encoding | — | not published | DETECTED |
| https.request | maxVersion | — | not published | DETECTED |
| https.request | minVersion | — | not published | DETECTED |
| https.request | secureOptions | — | not published | DETECTED |
| https.request | secureProtocol | — | not published | DETECTED |
| https.request | sessionIdContext | — | not published | DETECTED |
| https.request | signal | — | not published | DETECTED |
| https.request | timeout | — | not published | DETECTED |
| net.connect | signal | — | not published | DETECTED |
| tls.connect | enableTrace | — | not published | DETECTED |
| tls.connect | highWaterMark | — | not published | DETECTED |
| tls.connect | keepAliveInitialDelay | — | not published | DETECTED |
| tls.connect | maxVersion | — | not published | DETECTED |
| tls.connect | minVersion | — | not published | DETECTED |
| tls.connect | pskCallback | — | not published | DETECTED |
| tls.connect | secureOptions | — | not published | DETECTED |
| tls.connect | secureProtocol | — | not published | DETECTED |
| tls.connect | sessionIdContext | — | not published | DETECTED |
| tls.connect | sessionTimeout | — | not published | DETECTED |
| tls.connect | signal | — | not published | DETECTED |
| tls.connect | timeout | — | not published | DETECTED |
| child_process.spawn | DEP0129 | — | not published | DETECTED |
| child_process.spawn | DEP0190 | — | not published | DETECTED |
| child_process.spawn | LIBPATH | — | not published | DETECTED |
| child_process.spawn | NODE_ | — | not published | DETECTED |
| child_process.spawn | NODE_HANDLE | — | not published | DETECTED |
| child_process.spawn | NODE_HANDLE_ACK | — | not published | DETECTED |
| child_process.spawn | NODE_HANDLE_NACK | — | not published | DETECTED |
| child_process.spawn | NODE_V8_COVERAGE | — | not published | DETECTED |
| child_process.spawn | SIGTERM | — | not published | DETECTED |
| child_process.spawn | STEPLIB | — | not published | DETECTED |
| child_process.spawn | android | — | not published | DETECTED |
| child_process.spawn | argv0 | — | not published | DETECTED |
| child_process.spawn | buffer | — | not published | DETECTED |
| child_process.spawn | callback | — | not published | DETECTED |
| child_process.spawn | cwd | — | not published | DETECTED |
| child_process.spawn | detached | — | not published | DETECTED |
| child_process.spawn | disconnect | — | not published | DETECTED |
| child_process.spawn | encoding | — | not published | DETECTED |
| child_process.spawn | envPairs | — | not published | DETECTED |
| child_process.spawn | execArgv | — | not published | DETECTED |
| child_process.spawn | execPath | — | not published | DETECTED |
| child_process.spawn | gid | — | not published | DETECTED |
| child_process.spawn | ignore | — | not published | DETECTED |
| child_process.spawn | inherit | — | not published | DETECTED |
| child_process.spawn | input | — | not published | DETECTED |
| child_process.spawn | ipc | — | not published | DETECTED |
| child_process.spawn | keepOpen | — | not published | DETECTED |
| child_process.spawn | killSignal | — | not published | DETECTED |
| child_process.spawn | maxBuffer | — | not published | DETECTED |
| child_process.spawn | message | — | not published | DETECTED |
| child_process.spawn | options | — | not published | DETECTED |
| child_process.spawn | os390 | — | not published | DETECTED |
| child_process.spawn | overlapped | — | not published | DETECTED |
| child_process.spawn | pipe | — | not published | DETECTED |
| child_process.spawn | send | — | not published | DETECTED |
| child_process.spawn | serialization | — | not published | DETECTED |
| child_process.spawn | signal | — | not published | DETECTED |
| child_process.spawn | silent | — | not published | DETECTED |
| child_process.spawn | stdio | — | not published | DETECTED |
| child_process.spawn | swallowErrors | — | not published | DETECTED |
| child_process.spawn | timeout | — | not published | DETECTED |
| child_process.spawn | uid | — | not published | DETECTED |
| child_process.spawn | win32 | — | not published | DETECTED |
| child_process.spawn | windowsHide | — | not published | DETECTED |
| child_process.spawn | windowsVerbatimArguments | — | not published | DETECTED |
| child_process.spawn | wrap | — | not published | DETECTED |
| child_process.execFile | DEP0129 | — | not published | DETECTED |
| child_process.execFile | DEP0190 | — | not published | DETECTED |
| child_process.execFile | LIBPATH | — | not published | DETECTED |
| child_process.execFile | NODE_ | — | not published | DETECTED |
| child_process.execFile | NODE_HANDLE | — | not published | DETECTED |
| child_process.execFile | NODE_HANDLE_ACK | — | not published | DETECTED |
| child_process.execFile | NODE_HANDLE_NACK | — | not published | DETECTED |
| child_process.execFile | NODE_V8_COVERAGE | — | not published | DETECTED |
| child_process.execFile | SIGTERM | — | not published | DETECTED |
| child_process.execFile | STEPLIB | — | not published | DETECTED |
| child_process.execFile | android | — | not published | DETECTED |
| child_process.execFile | argv0 | — | not published | DETECTED |
| child_process.execFile | buffer | — | not published | DETECTED |
| child_process.execFile | callback | — | not published | DETECTED |
| child_process.execFile | cwd | — | not published | DETECTED |
| child_process.execFile | detached | — | not published | DETECTED |
| child_process.execFile | disconnect | — | not published | DETECTED |
| child_process.execFile | encoding | — | not published | DETECTED |
| child_process.execFile | envPairs | — | not published | DETECTED |
| child_process.execFile | execArgv | — | not published | DETECTED |
| child_process.execFile | execPath | — | not published | DETECTED |
| child_process.execFile | gid | — | not published | DETECTED |
| child_process.execFile | ignore | — | not published | DETECTED |
| child_process.execFile | inherit | — | not published | DETECTED |
| child_process.execFile | input | — | not published | DETECTED |
| child_process.execFile | ipc | — | not published | DETECTED |
| child_process.execFile | keepOpen | — | not published | DETECTED |
| child_process.execFile | killSignal | — | not published | DETECTED |
| child_process.execFile | maxBuffer | — | not published | DETECTED |
| child_process.execFile | message | — | not published | DETECTED |
| child_process.execFile | options | — | not published | DETECTED |
| child_process.execFile | os390 | — | not published | DETECTED |
| child_process.execFile | overlapped | — | not published | DETECTED |
| child_process.execFile | pipe | — | not published | DETECTED |
| child_process.execFile | send | — | not published | DETECTED |
| child_process.execFile | serialization | — | not published | DETECTED |
| child_process.execFile | shell | — | not published | DETECTED |
| child_process.execFile | signal | — | not published | DETECTED |
| child_process.execFile | silent | — | not published | DETECTED |
| child_process.execFile | stdio | — | not published | DETECTED |
| child_process.execFile | swallowErrors | — | not published | DETECTED |
| child_process.execFile | timeout | — | not published | DETECTED |
| child_process.execFile | uid | — | not published | DETECTED |
| child_process.execFile | win32 | — | not published | DETECTED |
| child_process.execFile | windowsHide | — | not published | DETECTED |
| child_process.execFile | windowsVerbatimArguments | — | not published | DETECTED |
| child_process.execFile | wrap | — | not published | DETECTED |
| stream.Readable | encoding | — | not published | DETECTED |
| stream.Readable | signal | — | not published | DETECTED |
| stream.Writable | signal | — | not published | DETECTED |
| fs.readFile | encoding | — | not published | DETECTED |
| fs.readFile | signal | — | not published | DETECTED |
| fs.writeFile | signal | — | not published | DETECTED |
| zlib.createGzip | encoding | — | not published | DETECTED |
| worker_threads.Worker | DEP0132 | — | not published | DETECTED |
| worker_threads.Worker | WATCH_REPORT_DEPENDENCIES | — | not published | DETECTED |
| worker_threads.Worker | depth | — | not published | DETECTED |
| worker_threads.Worker | execArgv | — | not published | DETECTED |
| worker_threads.Worker | message | — | not published | DETECTED |
| worker_threads.Worker | messageerror | — | not published | DETECTED |
| worker_threads.Worker | resourceLimits | — | not published | DETECTED |
| worker_threads.Worker | stderr | — | not published | DETECTED |
| worker_threads.Worker | stdin | — | not published | DETECTED |
| worker_threads.Worker | stdout | — | not published | DETECTED |
| worker_threads.Worker | sunos | — | not published | DETECTED |
| worker_threads.Worker | trackUnmanagedFds | — | not published | DETECTED |
| worker_threads.Worker | transferList | — | not published | DETECTED |
| worker_threads.Worker | workerData | — | not published | DETECTED |

WEAK = behavior changed by definedness only (not counted as a full gadget). NOT-COVERED = no driver/class reaches that API yet.
