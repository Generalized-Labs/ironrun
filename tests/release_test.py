"""Offline release checks: python3 -m unittest discover -s tests -p release_test.py -v.

curl and cosign are fixture executables. These tests exercise the real install
and action shell flows, including the verifier's requested identity, without
network access or signing credentials. They do not validate Sigstore crypto.
"""

import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[1]


def run_block(path, step_name):
    """Read one literal run block from these repository-owned workflow files."""
    content = path.read_text()
    step = content.index("- name: " + step_name)
    match = re.search(r"^( +)run: \|\n", content[step:], re.MULTILINE)
    if not match:
        raise AssertionError(f"no run block for {step_name}")
    body = content[step + match.end():].splitlines()
    indent = len(match.group(1)) + 2
    lines = []
    for line in body:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        lines.append(line[indent:])
    return "\n".join(lines) + "\n"


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="ironrun-release-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.fixtures = self.directory / "fixtures"
        self.fixtures.mkdir()
        self.bin = self.directory / "tools"
        self.bin.mkdir()
        self.target = self.directory / "installed"
        self.artifact = "ironrun_Linux_x86_64.tar.gz"
        with tarfile.open(self.fixtures / self.artifact, "w:gz") as archive:
            body = b"#!/bin/sh\necho fixture-ironrun\n"
            info = tarfile.TarInfo("ironrun")
            info.mode = 0o755
            info.size = len(body)
            archive.addfile(info, io.BytesIO(body))
        checksum = hashlib.sha256((self.fixtures / self.artifact).read_bytes()).hexdigest()
        (self.fixtures / "checksums.txt").write_text(f"{checksum}  {self.artifact}\n")
        self.sign_as("v1.2.3")
        self.tool("uname", "import sys\nprint('Linux' if sys.argv[1] == '-s' else 'x86_64')\n")
        self.tool("curl", """
            import os, pathlib, shutil, sys
            from urllib.parse import urlparse
            args = sys.argv[1:]
            url = next(arg for arg in args if arg.startswith('https://'))
            source = pathlib.Path(os.environ['FIXTURES']) / pathlib.Path(urlparse(url).path).name
            if not source.is_file():
                sys.exit(22)
            shutil.copyfile(source, args[args.index('-o') + 1])
        """)
        self.tool("cosign", """
            import json, pathlib, re, sys
            args = sys.argv[1:]
            bundle = json.loads(pathlib.Path(args[args.index('--bundle') + 1]).read_text())
            if '--certificate-identity-regexp' in args:
                pattern = args[args.index('--certificate-identity-regexp') + 1]
                valid = re.search(pattern, bundle['identity']) is not None
            else:
                valid = args[args.index('--certificate-identity') + 1] == bundle['identity']
            sys.exit(0 if valid else 1)
        """)
        self.env = {
            "PATH": str(self.bin) + os.pathsep + os.defpath,
            "HOME": str(self.directory),
            "FIXTURES": str(self.fixtures),
            "RUNNER_TEMP": str(self.directory / "runner"),
            "GITHUB_PATH": str(self.directory / "github-path"),
        }

    def tool(self, name, content):
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(content))
        path.chmod(0o755)

    def sign_as(self, tag):
        identity = f"https://github.com/Generalized-Labs/ironrun/.github/workflows/release.yml@refs/tags/{tag}"
        for name in [self.artifact, "checksums.txt"]:
            (self.fixtures / (name + ".sigstore.json")).write_text(json.dumps({"identity": identity}))

    def invoke(self, flow, version="v1.2.3"):
        if flow == "installer":
            cmd = ["sh", str(ROOT / "install.sh"), "--version", version, "--dir", str(self.target)]
            target = self.target / "ironrun"
        else:
            script = run_block(ROOT / "action.yml", "Download verified ironrun release")
            cmd = ["bash", "-c", script]
            self.env["INPUT_VERSION"] = version
            target = Path(self.env["RUNNER_TEMP"]) / "ironrun/bin/ironrun"
        result = subprocess.run(cmd, env=self.env, text=True, capture_output=True, timeout=15)
        return result, target

    def check_failure(self, flow, version="v1.2.3"):
        result, target = self.invoke(flow, version)
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse(target.exists(), "failed verification installed a binary")

    def test_matching_release_installs(self):
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                result, target = self.invoke(flow)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertTrue(target.is_file())

    def test_different_signed_release_is_rejected(self):
        self.sign_as("v1.2.2")
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                self.check_failure(flow)

    def test_version_dots_are_literal_and_tag_is_end_anchored(self):
        for wrong_tag in ["v1x2x3", "v1.2.30", "v1.2.3-rc.1"]:
            self.sign_as(wrong_tag)
            for flow in ["installer", "action"]:
                with self.subTest(flow=flow, wrong_tag=wrong_tag):
                    self.check_failure(flow)

    def test_matching_prereleases_install(self):
        for tag in ["v1.2.3-beta.1", "v1.2.3-preview-build"]:
            self.sign_as(tag)
            for flow in ["installer", "action"]:
                with self.subTest(flow=flow, tag=tag):
                    result, target = self.invoke(flow, tag)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertTrue(target.is_file())

    def test_hyphenated_prerelease_identity_is_end_anchored(self):
        self.sign_as("v1.2.3-preview-build-extra")
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                self.check_failure(flow, "v1.2.3-preview-build")

    def test_tampered_archive_is_rejected(self):
        with (self.fixtures / self.artifact).open("ab") as archive:
            archive.write(b"tampered")
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                self.check_failure(flow)

    def test_missing_bundle_is_rejected(self):
        (self.fixtures / (self.artifact + ".sigstore.json")).unlink()
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                self.check_failure(flow)

    def test_missing_checksum_is_rejected(self):
        (self.fixtures / "checksums.txt").write_text("0" * 64 + "  other.tar.gz\n")
        for flow in ["installer", "action"]:
            with self.subTest(flow=flow):
                self.check_failure(flow)


class ReleaseConfigurationTests(unittest.TestCase):
    def test_release_is_draft_until_signing_finishes(self):
        config = (ROOT / ".goreleaser.yml").read_text()
        self.assertRegex(config, r"(?m)^  draft: true$")
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        sign = workflow.index("- name: Keyless-sign release artifacts and checksums")
        promote = workflow.index("- name: Publish verified GitHub release")
        npm = workflow.index("- name: Stage release candidate on npm")
        self.assertLess(sign, promote)
        self.assertLess(promote, npm)
        self.assertIn("verify-blob", run_block(ROOT / ".github/workflows/release.yml", "Keyless-sign release artifacts and checksums"))

    def test_all_prereleases_route_to_next(self):
        workflow = (ROOT / ".github/workflows/release.yml").read_text()
        # The workflow's predicates are tested against both usual RCs and valid
        # non-RC SemVer tags; stable versions must select only the stable step.
        candidates = re.search(r"name: Stage release candidate on npm\n\s+if: (.+)", workflow).group(1)
        stable = re.search(r"name: Publish stable npm launcher\n\s+if: (.+)", workflow).group(1)
        needle = re.search(r"contains\(github.ref_name, '([^']+)'\)", candidates).group(1)
        stable_needle = re.search(r"!contains\(github.ref_name, '([^']+)'\)", stable).group(1)
        for tag in ["v1.2.3-rc.1", "v1.2.3-alpha.1", "v1.2.3-beta.1", "v1.2.3-preview-build"]:
            self.assertIn(needle, tag)
            self.assertIn(stable_needle, tag)
        self.assertNotIn(needle, "v1.2.3")
        self.assertNotIn(stable_needle, "v1.2.3")

    def test_release_stamp_uses_commit_date(self):
        config = (ROOT / ".goreleaser.yml").read_text()
        self.assertIn("buildinfo.Date={{.CommitDate}}", config)
        self.assertNotIn("buildinfo.Date={{.Date}}", config)


if __name__ == "__main__":
    unittest.main()
