import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { platformKey, sha256, verifyFile } from "../lib/launcher.js";

test("platform mapping is explicit", () => {
  assert.equal(platformKey("darwin", "arm64"), "darwin-arm64");
  assert.equal(platformKey("linux", "x64"), "linux-x64");
  assert.throws(() => platformKey("win32", "x64"), /unsupported platform/);
});

test("verified cache rejects modified and truncated files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ironrun-launcher-test-"));
  const file = join(directory, "ironrun");
  await writeFile(file, "verified-native-binary");
  const hash = await sha256(file);
  assert.equal(await verifyFile(file, 22, hash), true);
  await writeFile(file, "modified");
  assert.equal(await verifyFile(file, 22, hash), false);
});
