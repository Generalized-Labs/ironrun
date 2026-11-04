"""Real macOS Keychain -> encrypted vault -> child/filter integration.

Run only in a disposable macOS account or CI runner:
python3 tests/native_keychain_test.py --binary PATH --disposable-account

This temporarily changes the user's default keychain and search-list settings.
Ordinary completion, exceptions and subprocess timeouts attempt to restore them;
forced termination cannot guarantee restoration. Do not use a primary account.
The test deliberately fails on other platforms. It never substitutes security
or opens existing credential values. After isolation is verified, its new
temporary keychain is the only credential search target.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import subprocess
import sys
import tempfile


ENTRY = "IRONRUN_NATIVE_TEST_SECRET"
PROBE = '''import hashlib, os, sys
value = os.environ.get("IRONRUN_NATIVE_TEST_SECRET")
if value is None:
    print("NATIVE_MISSING")
    sys.exit(43)
if hashlib.sha256(value.encode()).hexdigest() != sys.argv[1]:
    print("NATIVE_WRONG_VALUE")
    sys.exit(44)
print("NATIVE_OK")
print(value)
print(value, file=sys.stderr)
'''


def parse_keychain_metadata(process, kind):
    """Parse password-free security metadata, preserving an absent default.

    Apple documents `default-keychain -s` without a path as the unset operation.
    A fresh HOME can therefore legitimately have no original default to restore.
    Treat only its exact diagnostic as absence; other failures remain failures.
    """
    if kind not in {"default", "search"}:
        raise ValueError("unknown keychain metadata kind")
    diagnostic = process.stderr.strip()
    if (
        kind == "default"
        and process.returncode == 1
        and not process.stdout.strip()
        and diagnostic == "security: SecKeychainCopyDomainDefault user: A default keychain could not be found."
    ):
        return []
    if process.returncode != 0 or diagnostic:
        # These queries have no password flag or input. Retain bounded metadata
        # stderr so an unfamiliar platform failure is diagnosable, not ignored.
        raise RuntimeError(
            f"{kind} metadata query failed: exit {process.returncode}; "
            f"stderr={json.dumps(diagnostic[:500])}"
        )
    try:
        paths = shlex.split(process.stdout)
    except ValueError:
        raise RuntimeError(f"{kind} metadata output is invalid") from None
    if kind == "default" and len(paths) > 1:
        raise RuntimeError("default metadata output is invalid")
    return paths


class NativeKeychainCheck:
    def __init__(self, binary, root):
        self.binary = binary
        self.root = root
        self.project = root / "project"
        home = root / "home"
        self.project.mkdir(mode=0o700)
        home.mkdir(mode=0o700)
        self.env = {
            **os.environ,
            "HOME": str(home),
            "IRONRUN_HOME": str(home / "application"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_STATE_HOME": str(home / "state"),
            "XDG_CACHE_HOME": str(home / "cache"),
            # Ironrun must resolve the real Apple CLI, not a test wrapper.
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "GITHUB_ACTIONS": "false",
            # Match the documented absence diagnostic deterministically.
            "LC_ALL": "C",
        }
        self.env.pop(ENTRY, None)
        self.keychain = root / "native-test.keychain-db"
        self.password = secrets.token_hex(32)
        self.value = "ironrun-native-fixture-" + secrets.token_hex(32)
        self.stage = "initialization"
        self.failure_stage = None
        self.primary_failure = None
        self.cleanup_failures = []
        self.cleanup_operations = []
        self.metadata_observations = []
        self.observed = []

    def run(self, label, argv, *, input_text=None, expect_success=True):
        self.stage = label
        process = subprocess.run(
            argv, cwd=self.project, env=self.env, input=input_text,
            capture_output=True, text=True, timeout=30,
        )
        if expect_success and process.returncode != 0:
            # Native error output can contain an echoed key-manager command.
            # Do not print it, even on failure. Stages and status identify the
            # failing boundary without exposing generated values or root keys.
            raise RuntimeError(f"{label}: exit {process.returncode}")
        return process

    def security(self, label, *args, **kwargs):
        return self.run(label, ["/usr/bin/security", *args], **kwargs)

    def cli(self, label, *args, **kwargs):
        process = self.run(label, [str(self.binary), *args], **kwargs)
        if self.value in process.stdout or self.value in process.stderr:
            raise RuntimeError(f"{label}: full synthetic credential in CLI output")
        return process

    def keychain_metadata(self, label, kind):
        command = "default-keychain" if kind == "default" else "list-keychains"
        process = self.security(label, command, "-d", "user", expect_success=False)
        # These two commands query paths/preferences only: never a password,
        # value or native key item. Keep their bounded output to diagnose CI
        # preference-domain differences without opening any credential store.
        record = {
            "stage": label, "kind": kind, "returncode": process.returncode,
            "stdout": process.stdout[:1000], "stderr": process.stderr[:500],
        }
        self.metadata_observations.append(record)
        paths = parse_keychain_metadata(process, kind)
        record.update({"paths": paths, "count": len(paths)})
        return paths

    def execute(self):
        original_default = self.keychain_metadata("read default keychain metadata", "default")
        original_search = self.keychain_metadata("read keychain search-list metadata", "search")
        self.observed.append("original keychain metadata captured; default " + ("present" if original_default else "absent"))
        keychain_attempted = False
        try:
            # create-keychain can itself add the item to the search list. From
            # this point restore both captured settings even if setup fails.
            keychain_attempted = True
            self.security("create isolated keychain", "create-keychain", "-p", self.password, str(self.keychain))
            self.security("configure isolated keychain", "set-keychain-settings", "-lut", "3600", str(self.keychain))
            self.security("unlock isolated keychain", "unlock-keychain", "-p", self.password, str(self.keychain))
            self.security("isolate search list", "list-keychains", "-d", "user", "-s", str(self.keychain))
            self.security("select isolated default", "default-keychain", "-d", "user", "-s", str(self.keychain))
            selected = self.keychain_metadata("verify isolated default", "default")
            search = self.keychain_metadata("verify isolated search list", "search")
            if len(selected) != 1 or Path(selected[0]).resolve() != self.keychain.resolve():
                raise RuntimeError("temporary keychain is not the default")
            if len(search) != 1 or Path(search[0]).resolve() != self.keychain.resolve():
                raise RuntimeError("credential search list is not isolated")
            self.observed.append("only new temporary keychain selected")

            missing = self.security("confirm root-key item initially absent", "find-generic-password", "-s", "ironrun/env/vault-keys", expect_success=False)
            if missing.returncode == 0:
                raise RuntimeError("new keychain unexpectedly already contained an Ironrun root-key item")
            probe = self.project / "probe.py"
            probe.write_text(PROBE)
            digest = hashlib.sha256(self.value.encode()).hexdigest()
            argv = json.dumps([sys.executable, str(probe), digest])
            policy = self.project / "ironrun.yml"
            policy.write_text(
                'version: "2"\ncommands:\n'
                '  - id: native-check\n'
                f'    argv: {argv}\n'
                f'    secrets: [{ENTRY}]\n'
                '    allow_network: true\n    ttl: 20s\n'
                '  - id: no-injection-control\n'
                f'    argv: {argv}\n'
                '    allow_network: true\n    ttl: 20s\n'
            )
            initialized = self.cli("initialize v2 environment", "env", "init", "dev")
            if "root key in macOS Keychain" not in initialized.stdout:
                raise RuntimeError("CLI did not report the native macOS Keychain vault")
            self.security("verify newly stored root-key metadata", "find-generic-password", "-s", "ironrun/env/vault-keys")
            self.observed.append("actual native root-key item saved; metadata lookup only")
            self.cli("persist synthetic value", "env", "set", "dev", ENTRY, "--from-stdin", "--unsafe", input_text=self.value + "\n")
            vaults = list((Path(self.env["HOME"]) / ".ironrun" / "vaults").glob("*.irvault"))
            if len(vaults) != 1 or self.value.encode() in vaults[0].read_bytes():
                raise RuntimeError("expected one encrypted vault without the full plaintext fixture")
            document = json.loads(vaults[0].read_text())
            if document.get("cipher") != "AES-256-GCM+wrapped-scope-keys" or not document.get("scopes"):
                raise RuntimeError("expected populated encrypted v2 vault document")
            self.observed.append("synthetic value persisted in encrypted vault")

            # Each invocation is a new CLI process and must reopen its root key
            # through the real selected Keychain before decrypting the vault.
            for attempt in range(2):
                output = self.cli(f"reopen native store and run child {attempt + 1}", "run", "native-check")
                if "NATIVE_OK" not in output.stdout or "[REDACTED]" not in output.stdout or "[REDACTED]" not in output.stderr:
                    raise RuntimeError("child sentinel and filtered stdout/stderr were not observed")
            self.observed.append("two fresh CLI processes receive exact value and filter both streams")
            control = self.cli("non-vacuous no-injection control", "run", "no-injection-control", expect_success=False)
            if control.returncode == 0 or "NATIVE_MISSING" not in control.stdout or "NATIVE_OK" in control.stdout:
                raise RuntimeError("control child did not detect missing injection")
            self.observed.append("control child starts and fails without injected credential")
        except Exception as error:
            self.failure_stage = self.stage
            self.primary_failure = {
                "stage": self.stage, "error_type": type(error).__name__,
                "reason": str(error) if isinstance(error, RuntimeError) else "native fixture operation failed",
            }
            raise
        finally:
            # Attempt every restoration even if another cleanup step fails.
            for needed, label, args in [
                # With no original path, Apple's documented -s form unsets it.
                (keychain_attempted, "restore default keychain", ["default-keychain", "-d", "user", "-s", *original_default]),
                (keychain_attempted, "restore keychain search list", ["list-keychains", "-d", "user", "-s", *original_search]),
                (self.keychain.exists(), "delete isolated keychain", ["delete-keychain", str(self.keychain)]),
            ]:
                if needed:
                    try:
                        # Only preference changes and deletion of this new
                        # temporary keychain occur here. Their arguments/input
                        # contain no password/root key, so metadata stderr is
                        # safe to retain. Never apply this to item operations.
                        process = self.security(label, *args, expect_success=False)
                        record = {
                            "stage": label, "returncode": process.returncode,
                            "stdout": process.stdout[:1000], "stderr": process.stderr[:500],
                        }
                        self.cleanup_operations.append(record)
                        if process.returncode:
                            self.cleanup_failures.append(record)
                    except Exception as error:
                        self.cleanup_failures.append({"stage": label, "error_type": type(error).__name__})
            if keychain_attempted:
                for kind, expected in [("default", original_default), ("search", original_search)]:
                    label = "verify restored " + kind
                    try:
                        restored = self.keychain_metadata(label, kind)
                        if restored != expected:
                            self.cleanup_failures.append({"stage": label, "reason": "restored metadata differs", "expected_paths": expected, "observed_paths": restored})
                    except Exception as error:
                        self.cleanup_failures.append({"stage": label, "error_type": type(error).__name__, "reason": str(error) if isinstance(error, RuntimeError) else "metadata verification failed"})
                if not self.cleanup_failures:
                    self.observed.append("original default and search list restored; new keychain deleted")
            # Preserve a primary isolation/product failure even when cleanup
            # also fails. Both are reported; cleanup can never turn a pass on.
            if self.cleanup_failures and self.primary_failure is None:
                self.failure_stage = self.cleanup_failures[0]["stage"]
                raise RuntimeError("keychain cleanup failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument(
        "--disposable-account", action="store_true",
        help="Confirm this is a disposable macOS account/runner; user keychain preferences will change temporarily.",
    )
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("real macOS Keychain verification requires macOS; no substitute or successful skip is used")
    if not args.disposable_account:
        parser.error("use only a disposable macOS account/runner and pass --disposable-account")
    binary = args.binary.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="ironrun-native-keychain-") as directory:
        check = NativeKeychainCheck(binary, Path(directory))
        try:
            check.execute()
        except Exception as error:
            # Never print subprocess args, item-operation output or exception
            # repr. Only bounded password-free preference metadata is retained.
            reason = str(error) if isinstance(error, RuntimeError) else "native fixture operation failed"
            print(json.dumps({"result": "failed", "stage": check.failure_stage or check.stage, "error_type": type(error).__name__, "reason": reason, "primary_failure": check.primary_failure, "cleanup_failures": check.cleanup_failures, "metadata": check.metadata_observations, "cleanup_operations": check.cleanup_operations, "observed": check.observed}))
            return 1
        print(json.dumps({"result": "passed", "backend": "actual macOS security CLI and dedicated new Keychain", "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(), "observed": check.observed, "metadata": check.metadata_observations, "cleanup_operations": check.cleanup_operations, "limits": "synthetic values; saved-command CLI path; no actual model, agent host or human approval usability"}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
