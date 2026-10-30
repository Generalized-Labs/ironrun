# Installation follow-up evidence

October 21, 2026. Parent commit: `87a53b9ec7661333fb86197ec8837e8d3005960c`.
This directory records the later npm startup-signal repair and installation
checks. [provenance.json](provenance.json) identifies the exact tested npm and
workflow files. The earlier Go/paper/source manifests retain their original
scope; they are not overwritten to imply that this later launcher was tested
in those earlier runs. No Go runtime or manuscript source changed here.

## Startup termination regression

The native process can run before `spawn` returns. Registering signal handlers
afterward left a window in which caller termination killed the launcher and
left the native child alive. The original caller-signal test could pass after
waiting for the synthetic child's 30-second lifetime because it did not check
prompt completion or child survival.

The repair registers handlers before spawn, queues signals until the child
handle is available, then forwards them after installing child error/exit
listeners. Cleanup restores normal signal handling before mirroring child exit.
The stronger tests check completion within two seconds and confirm that the
native PID is gone. They cover an actual OS signal during the spawn wrapper and
synchronous delivery before child assignment. Failed assertions kill their
fixture processes.

[signal-race-before.log](signal-race-before.log) records both new startup cases
failing against the parent launcher; its three failures include their parent
test. All cases pass with the repair. Independent review also checked that
synchronous spawn throws and asynchronous spawn errors restore signal listeners.

## Final local matrix

Run from `npm/`, with each named runtime:

```sh
node --test test/*.test.js
node test/proxy-audit.mjs
```

| Runtime | Launcher suite | Proxy fixture |
| --- | --- | --- |
| Node 20.20.2 | 19 pass, 0 skipped | 2 pass |
| Node 22.23.3 | 19 pass, 0 skipped | 9 pass |
| Node 24.19.0 | 19 pass, 0 skipped | 9 pass |

The adjacent `node*-unit.log` and `node*-proxy.log` files contain the fresh raw
outputs. Launcher tests include real non-root directory permissions: verified
warm read-only cache works offline; cold or corrupt read-only caches refuse
execution. This is not a test of every read-only mount implementation.

The proxy fixture keeps fetch, TLS verification, CONNECT tunneling, redirects,
archive/binary verification, extraction, and child execution real. It uses a
synthetic CA and loopback endpoints; outbound guards prevent external fallback.
Modern Node cases cover success, unavailable proxy with warm cache, missing
opt-in, npm-only proxy settings, `NO_PROXY`, corrupt archive, untrusted CA, and
proxy failure. Node 20 checks only that unsupported environment-proxy opt-in
fails safely. Counts include parent/subtests. OpenSSL and tar are test tools,
not new runtime dependencies. CI runs the same fixture on Node 20/22/24.

[NPM_RUNTIME_SUPPORT.md](../../../NPM_RUNTIME_SUPPORT.md) describes the support
boundary and workarounds. Node 20 retains direct-network support; this change
does not add a proxy implementation to that runtime.

## Published historical assets

[HISTORICAL_RELEASE_REVIEW.md](HISTORICAL_RELEASE_REVIEW.md) and
[historical-release-evidence.json](historical-release-evidence.json) record real
verification of the old public v0.5.0 assets: six signatures, nine authenticated
checksum entries, and wrong-tag/tampered-blob negative controls. No Ironrun
binary or installer was executed. Its valid signatures do not validate the
new source or a future release; all four old binaries report `vcs.modified=true`.

Public v0.5.1 release/tag and npm metadata returned 404 at the recorded time.
The npm manifest remains intentionally unprepared until matching real release
archives exist. No tag, package, tap update, or paper submission was published.
