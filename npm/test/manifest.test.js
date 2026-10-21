import test from "node:test";
import assert from "node:assert/strict";
import { validateReleaseManifest } from "../lib/manifest.js";

function fixture(version = "1.2.3") {
  const artifacts = {};
  for (const [key, filename] of Object.entries({
    "darwin-x64": "ironrun_Darwin_x86_64.tar.gz",
    "darwin-arm64": "ironrun_Darwin_arm64.tar.gz",
    "linux-x64": "ironrun_Linux_x86_64.tar.gz",
    "linux-arm64": "ironrun_Linux_arm64.tar.gz",
  })) {
    artifacts[key] = { filename, size: 100, sha256: "a".repeat(64), binarySize: 200, binarySha256: "b".repeat(64) };
  }
  return { version, artifacts };
}

test("complete stable and prerelease manifests are accepted", () => {
  for (const version of ["1.2.3", "1.2.3-rc.1", "1.2.3-beta.2+build.1"]) {
    assert.doesNotThrow(() => validateReleaseManifest({ version }, fixture(version)));
  }
});

test("unprepared checkout and mismatched releases cannot be published", () => {
  assert.throws(() => validateReleaseManifest({ version: "0.5.1" }, { version: "1.0.0", artifacts: {} }), /versions differ/);
  assert.throws(() => validateReleaseManifest({ version: "1.2.3" }, { version: "1.2.3", artifacts: {} }), /platform/);
});

test("malformed versions and artifact metadata are rejected", () => {
  for (const version of ["v1.2.3", "01.2.3", "1.2", "1.2.3-01", "1.2.3/evil"]) {
    assert.throws(() => validateReleaseManifest({ version }, fixture(version)), /version/);
  }
  for (const [field, value] of [["filename", "../binary"], ["size", 0], ["size", 1.5], ["binarySize", -1], ["sha256", "abc"], ["binarySha256", "g".repeat(64)]]) {
    const manifest = fixture();
    manifest.artifacts["linux-x64"][field] = value;
    assert.throws(() => validateReleaseManifest({ version: "1.2.3" }, manifest), new RegExp(field));
  }
  const manifest = fixture();
  delete manifest.artifacts["darwin-arm64"];
  assert.throws(() => validateReleaseManifest({ version: "1.2.3" }, manifest), /platform/);
});
