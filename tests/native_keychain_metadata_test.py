"""Pure metadata-state checks; these do not simulate native Keychain success."""

import subprocess
import tempfile
import unittest
from pathlib import Path
import stat

from native_keychain_test import NativeKeychainCheck, parse_keychain_metadata


class KeychainMetadataTests(unittest.TestCase):
    def result(self, status=0, stdout="", stderr=""):
        return subprocess.CompletedProcess(["/usr/bin/security"], status, stdout, stderr)

    def test_default_path_preserves_spaces(self):
        result = self.result(stdout='    "/temporary/test home/login.keychain-db"\n')
        self.assertEqual(parse_keychain_metadata(result, "default"), ["/temporary/test home/login.keychain-db"])

    def test_documented_absent_default_is_valid_state(self):
        result = self.result(1, stderr="security: SecKeychainCopyDomainDefault user: A default keychain could not be found.\n")
        self.assertEqual(parse_keychain_metadata(result, "default"), [])

    def test_successful_empty_default_and_search_list_are_valid(self):
        for kind in ["default", "search"]:
            with self.subTest(kind=kind):
                self.assertEqual(parse_keychain_metadata(self.result(), kind), [])

    def test_successful_search_list_preserves_order(self):
        result = self.result(stdout='"/first.keychain-db"\n"/second path/login.keychain-db"\n')
        self.assertEqual(parse_keychain_metadata(result, "search"), ["/first.keychain-db", "/second path/login.keychain-db"])

    def test_other_failures_remain_failures_with_metadata_diagnostic(self):
        for result, kind in [
            (self.result(1, stderr="security: user interaction is not allowed"), "default"),
            (self.result(1), "default"),
            (self.result(2, stderr="security: SecKeychainCopyDomainDefault user: A default keychain could not be found."), "default"),
            (self.result(1, stdout='"/unexpected.keychain"', stderr="security: SecKeychainCopyDomainDefault user: A default keychain could not be found."), "default"),
            (self.result(1, stderr="security: SecKeychainCopyDomainDefault user: A default keychain could not be found.\nadditional error"), "default"),
            (self.result(1, stderr="security: SecKeychainCopyDomainDefault user: A default keychain could not be found."), "search"),
        ]:
            with self.subTest(status=result.returncode, stderr=result.stderr, kind=kind):
                with self.assertRaisesRegex(RuntimeError, "metadata query failed"):
                    parse_keychain_metadata(result, kind)

    def test_unexpected_success_diagnostic_is_not_ignored(self):
        with self.assertRaisesRegex(RuntimeError, "metadata query failed"):
            parse_keychain_metadata(self.result(stderr="unexpected warning"), "default")

    def test_multiple_defaults_or_malformed_paths_are_rejected(self):
        for output in ['"/first" "/second"', '"/unterminated']:
            with self.subTest(output=output):
                with self.assertRaisesRegex(RuntimeError, "metadata output is invalid"):
                    parse_keychain_metadata(self.result(stdout=output), "default")


class FailureDiagnosticsTests(unittest.TestCase):
    def test_isolation_failure_survives_cleanup_failure(self):
        class CommandResultFixture(NativeKeychainCheck):
            def security(self, label, *args, **kwargs):
                self.stage = label
                stdout = ""
                stderr = ""
                status = 0
                if label in {"read default keychain metadata", "verify restored default"}:
                    stdout = '"/previous/default.keychain-db"\n'
                elif label == "verify isolated default":
                    stdout = f'"{self.keychain}"\n'
                elif label == "verify isolated search list":
                    stdout = f'"{self.keychain}"\n"/unexpected/metadata-only.keychain-db"\n'
                elif label == "restore default keychain":
                    status = 1
                    stderr = "security: explicit fixture cleanup failure"
                process = subprocess.CompletedProcess(["/usr/bin/security"], status, stdout, stderr)
                if kwargs.get("expect_success", True) and status:
                    raise RuntimeError(f"{label}: exit {status}")
                return process

            def cli(self, *args, **kwargs):
                raise AssertionError("failed isolation must prevent every Ironrun invocation")

        with tempfile.TemporaryDirectory() as directory:
            check = CommandResultFixture(Path("/not-executed/ironrun"), Path(directory))
            with self.assertRaisesRegex(RuntimeError, "credential search list is not isolated"):
                check.execute()
            self.assertEqual(check.primary_failure["stage"], "verify isolated search list")
            self.assertEqual(check.cleanup_failures[0]["stage"], "restore default keychain")
            self.assertIn("explicit fixture cleanup failure", check.cleanup_failures[0]["stderr"])
            search = next(record for record in check.metadata_observations if record["stage"] == "verify isolated search list")
            self.assertEqual(search["count"], 2)
            self.assertEqual(search["paths"][1], "/unexpected/metadata-only.keychain-db")

    def test_fresh_home_contains_private_native_preference_parents(self):
        with tempfile.TemporaryDirectory() as directory:
            check = NativeKeychainCheck(Path("/not-executed/ironrun"), Path(directory))
            for relative in ["Library", "Library/Preferences"]:
                path = Path(check.env["HOME"]) / relative
                self.assertTrue(path.is_dir())
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)

    def test_absent_default_is_restored_by_deleting_only_the_new_keychain(self):
        class CommandResultFixture(NativeKeychainCheck):
            labels = []

            def security(self, label, *args, **kwargs):
                self.stage = label
                self.labels.append(label)
                stdout, stderr, status = "", "", 0
                if label == "create isolated keychain":
                    self.keychain.touch(mode=0o600)
                elif label in {"read default keychain metadata", "verify restored default"}:
                    status = 1
                    stderr = "security: SecKeychainCopyDomainDefault user: A default keychain could not be found."
                elif label == "verify isolated default":
                    stdout = f'"{self.keychain}"\n'
                elif label == "verify isolated search list":
                    stdout = f'"{self.keychain}"\n"/unexpected/metadata-only.keychain-db"\n'
                elif label == "delete isolated keychain":
                    self.keychain.unlink()
                elif label == "restore default keychain":
                    raise AssertionError("absent default must not use the broken null-keychain API")
                return subprocess.CompletedProcess(["/usr/bin/security"], status, stdout, stderr)

            def cli(self, *args, **kwargs):
                raise AssertionError("failed isolation must prevent every Ironrun invocation")

        with tempfile.TemporaryDirectory() as directory:
            check = CommandResultFixture(Path("/not-executed/ironrun"), Path(directory))
            with self.assertRaisesRegex(RuntimeError, "credential search list is not isolated"):
                check.execute()
            self.assertNotIn("restore default keychain", check.labels)
            self.assertLess(check.labels.index("delete isolated keychain"), check.labels.index("restore keychain search list"))
            self.assertFalse(check.cleanup_failures)
            self.assertFalse(check.keychain.exists())


if __name__ == "__main__":
    unittest.main()
