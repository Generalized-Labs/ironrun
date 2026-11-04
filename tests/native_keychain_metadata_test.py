"""Pure metadata-state checks; these do not simulate native Keychain success."""

import subprocess
import unittest

from native_keychain_test import parse_keychain_metadata


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


if __name__ == "__main__":
    unittest.main()
