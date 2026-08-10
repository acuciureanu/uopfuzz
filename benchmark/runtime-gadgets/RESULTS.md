# Runtime-Gadget Benchmark — UoPFuzz vs GHunter

Corpus: GHunter's published Node.js universal-gadget PoCs (KTH-LangSec/server-side-prototype-pollution, nodejs/), property-level.

Node 24.17.0 — 2026-08-10

**34 detected · 12 confirmed fixed/mitigated upstream · 0 not detected** (46 entries)

| Verdict | Gadget | API | Property | Category | Observation |
|---|---|---|---|---|---|
| DETECTED | cp-exec-env | child_process.exec | NODE_OPTIONS | ACE | sink_reach @ child_process.exec (2x) |
| DETECTED | cp-execSync-env | child_process.execSync | NODE_OPTIONS | ACE | sink_reach @ child_process.execSync (2x) |
| DETECTED | cp-execFile-env | child_process.execFile | NODE_OPTIONS | ACE | sink_reach @ child_process.execFile (2x) |
| DETECTED | cp-execFileSync-env | child_process.execFileSync | NODE_OPTIONS | ACE | sink_reach @ child_process.execFileSync (2x) |
| DETECTED | cp-spawn-env | child_process.spawn | NODE_OPTIONS | ACE | sink_reach @ child_process.spawn (2x) |
| DETECTED | cp-spawnSync-env | child_process.spawnSync | NODE_OPTIONS | ACE | sink_reach @ child_process.spawnSync (2x) |
| DETECTED | cp-fork-env | child_process.fork | NODE_OPTIONS | ACE | sink_reach @ child_process.fork (2x) |
| DETECTED | cp-execSync-shell | child_process.execSync | shell | ACE | sink_reach @ child_process.execSync (2x) |
| DETECTED | cp-spawn-shell-env-combo | child_process.spawn | shell+NODE_OPTIONS | ACE | 2-property combo proved @ child_process.spawn |
| DETECTED | cp-exec-shell | child_process.exec | shell | ACE | sink_reach @ child_process.exec (2x) |
| DETECTED | cp-execSync-env | child_process.execSync | env | ACE | sink_reach @ child_process.execSync (2x) |
| DETECTED | cp-execFileSync-shell | child_process.execFileSync | shell | ACE | sink_reach @ child_process.execFileSync (2x) |
| DETECTED | cp-spawn-shell | child_process.spawn | shell | ACE | sink_reach @ child_process.spawn (2x) |
| DETECTED | cp-spawn-env | child_process.spawn | env | ACE | sink_reach @ child_process.spawn (2x) |
| DETECTED | cp-spawnSync-shell | child_process.spawnSync | shell | ACE | sink_reach @ child_process.spawnSync (2x) |
| DETECTED | cp-spawnSync-env | child_process.spawnSync | env | ACE | sink_reach @ child_process.spawnSync (2x) |
| DETECTED | http-request-path | http.request | path | EoP | sink_reach @ http.request (2x) |
| DETECTED | http-request-method | http.request | method | EoP | sink_reach @ http.request (2x) |
| DETECTED | http-get-path | http.get | path | EoP | sink_reach @ http.get (2x) |
| DETECTED | https-request-path | https.request | path | EoP | sink_reach @ https.request (2x) |
| DETECTED | https-get-path | https.get | path | EoP | sink_reach @ https.get (2x) |
| DETECTED | https-request-method | https.request | method | EoP | sink_reach @ https.request (2x) |
| MITIGATED-UPSTREAM | http-request-hostname | http.request | hostname | SSRF | clean "FP:host=127.0.0.1:45931|x=none", polluted "FP:host=127.0.0.1:45931|x=none" |
| MITIGATED-UPSTREAM | http-request-headers | http.request | headers | SSRF | clean "FP:host=127.0.0.1:45931|x=none", polluted "FP:host=127.0.0.1:45931|x=none" |
| MITIGATED-UPSTREAM | http-request-port | http.request | port | SSRF | clean "FP:nohit:ECONNREFUSED", polluted "FP:nohit:ECONNREFUSED" |
| MITIGATED-UPSTREAM | https-request-hostname | https.request | hostname | SSRF | clean "FP:host=127.0.0.1:45933|x=none", polluted "FP:host=127.0.0.1:45933|x=none" |
| MITIGATED-UPSTREAM | https-request-headers | https.request | headers | SSRF | clean "FP:host=127.0.0.1:45933|x=none", polluted "FP:host=127.0.0.1:45933|x=none" |
| MITIGATED-UPSTREAM | https-request-port | https.request | port | SSRF | clean "FP:nohit:ECONNREFUSED", polluted "FP:nohit:ECONNREFUSED" |
| MITIGATED-UPSTREAM | fetch-socketPath | fetch | socketPath | SSRF | no observable difference |
| DETECTED | fetch-method | fetch | method | EoP | trap-read+output-changed |
| DETECTED | fetch-body | fetch | body | EoP | trap-read+output-changed |
| DETECTED | tls-connect-rejectUnauthorized | tls.connect | rejectUnauthorized | crypto-downgrade | sink_reach @ tls.connect (2x) |
| DETECTED | tls-connect-path | tls.connect | path | crypto-downgrade | sink_reach @ tls.connect (2x) |
| DETECTED | tls-connect-port | tls.connect | port | second-order-SSRF | sink_reach @ tls.connect (2x) |
| DETECTED | tls-connect-tls-reject | tls.connect | NODE_TLS_REJECT_UNAUTHORIZED | crypto-downgrade | clean "FP:DEPTH_ZERO_SELF_SIGNED_CERT", polluted "FP:HANDSHAKE-OK" |
| DETECTED | https-request-tls-reject | https.request | NODE_TLS_REJECT_UNAUTHORIZED | crypto-downgrade | clean "FP:DEPTH_ZERO_SELF_SIGNED_CERT", polluted "FP:ECONNRESET" |
| MITIGATED-UPSTREAM | import-source | import() | source | ACE | not verified |
| FIXED-UPSTREAM | require-main | require | main | ACE | not verified |
| MITIGATED-UPSTREAM | require-node-options | require | NODE_OPTIONS | ACE | not verified |
| DETECTED | worker-ctor-env | worker_threads.Worker | env | EoP | sink_reach @ worker_threads.Worker (2x) |
| DETECTED | worker-ctor-eval | worker_threads.Worker | eval | ACE | sink_reach @ worker_threads.Worker (2x) |
| DETECTED | worker-ctor-argv | worker_threads.Worker | argv | EoP | sink_reach @ worker_threads.Worker (2x) |
| MITIGATED-UPSTREAM | dos-listen-backlog | http.Server.listen | backlog | DoS | clean exit 0, polluted exit 0 |
| MITIGATED-UPSTREAM | dos-tls-session | tls.connect | session | DoS | clean exit 0, polluted exit 0 |
| DETECTED | dos-fetch-signal | fetch | signal | DoS | clean exit 0, polluted exit 1 |
| DETECTED | dos-stream-hwm | stream.Readable | highWaterMark | DoS | clean exit 0, polluted exit 1 |

Verdicts: DETECTED = flow observed by UoPFuzz's oracles (2x fresh-process proof for sink flows); FIXED-UPSTREAM = no effect and the gadget is documented as fixed in this Node version; MITIGATED-UPSTREAM = no documented fix, but direct experiment on this Node shows the gadget is dead (reason in the corpus entry); NOT-DETECTED = capability gap.
