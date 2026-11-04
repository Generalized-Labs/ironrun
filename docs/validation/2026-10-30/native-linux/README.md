# Actual Linux Secret Service integration

**Passed on runtime inputs matching merged commit
`6e03c06aebff3040563a3d8d147875824af9d366`.** The diagnostic binary was built
from local `07eb2c4`; all 182 Go/module input hashes were compared to the merged
commit and match. Before/after source identity is unchanged.

This uses the **real** libsecret `secret-tool` 0.21.7 and GNOME Keyring 48.0
Secret Service over a dedicated new DBus session. The native root-key adapter
is not substituted. No existing user collection, desktop session bus or
credential store was accessed. A new isolated HOME/XDG tree and nonempty
synthetic collection password were used; the password went through stdin,
not argv. The original project remains untouched.

## Observed flow

- Actual native store/lookup/clear smoke succeeded in an isolated test collection.
- Real Ironrun CLI `env init`, synthetic `env set --from-stdin --unsafe`, and
  metadata-only `doctor` passed. Root-key save/load uses native Secret Service.
- Actual stdio MCP initialized and discovered 12 tools. Its pending workspace
  call made no loopback request during a bounded 100 ms preapproval observation.
- Actual CLI trust grant resumed the call. The child received the correct
  synthetic value, authenticated to the loopback endpoint, and both direct and
  echoed stdout were filtered before return to MCP. No full test value appears
  in retained MCP or CLI output.
- Strict saved-command child actually started and emitted `DIAL_BLOCKED` with
  no loopback request. This is an attempted denied dial, not a setup failure.
- Actual CLI revoke followed by deny prevented another workspace request.
- Stopping GNOME Keyring removed its DBus service owner. A fresh daemon process
  unlocked the same newly created persisted collection, and a **new Ironrun CLI
  process** reopened/decrypted the vault and completed a second authenticated
  loopback request with filtered output. This exercises persisted root-key
  recovery across native-daemon process restart.
- Native `.keyring` and `.irvault` files are nonempty/owner-only and lack the
  full synthetic environment value. This byte observation is not a cryptographic
  security proof. Ciphertext files and all native-store state are excluded.

## Tool provenance

Only four official Debian trixie packages were downloaded/extracted under the
workspace, without system installation. `InRelease` was verified using the
existing system Debian archive keyring. Its SHA256 entry authenticates the
Packages.xz index, whose per-package SHA256 entries were verified before
extraction. Raw signature log, InRelease, selected metadata, URLs, package hashes,
actual executable hashes and `ldd` observations are retained. TLS/proxy trust was
preserved. No repository credentials were used.

Raw successful evidence lives under `final/`. The earlier root-level run
completed the behavior but failed its last driver assertion because the probe
looked for `.json` rather than the actual `.irvault` extension. Original driver
bytes/logs and `FIRST_PROBE_NOTE.md` retain that instrumentation failure. The
complete final run used a fresh home/project/collection and corrected only the
extension and output-directory selection. No product implementation was changed.

The race/namespace path ran outside the additional agent filesystem sandbox;
Ironrun containment remained enabled. The HTTP helper was invoked only in its
loopback `http` mode and was not named or used as `secret-tool`. No native daemon
or test HTTP server remains running after cleanup.

## Limits

This establishes one headless Debian/GNOME Secret Service path. It does not
establish desktop login/PAM unlock or prompting UX, KWallet/other Linux backends,
macOS Keychain, an actual model/agent-host decision, human approval usability,
external providers, signed installers/Homebrew/npm release behavior or sustained
daily use. CLI approval here is scripted. The result closes the earlier
*substitute key-store* limitation for this specific Linux probe; it does not
close all native/platform or launch gates.

The driver and tool paths are workspace-specific; adapt them for replay in a
fresh output directory. Never aim it at an existing home or collection.
`artifact-manifest.json` covers this compact selected evidence and excludes
itself. Diagnostic binaries, package downloads, caches, private DBus sockets,
keyring files and encrypted vault state remain external and unarchived.
