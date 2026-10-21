import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { artifactNames } from "../lib/manifest.js";

test("manifest builder validates archives before updating publication metadata", async (t) => {
  const root = await mkdtemp(join(tmpdir(), "ironrun-manifest-test-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pkgRoot = join(root, "npm");
  const dist = join(root, "dist");
  const source = join(root, "source");
  await mkdir(pkgRoot);
  await mkdir(dist);
  await mkdir(source);
  await cp(new URL("../lib", import.meta.url), join(pkgRoot, "lib"), { recursive: true });
  await cp(new URL("../scripts", import.meta.url), join(pkgRoot, "scripts"), { recursive: true });
  await writeFile(join(pkgRoot, "package.json"), JSON.stringify({ type: "module", version: "0.0.0" }));
  await writeFile(join(pkgRoot, "manifest.json"), JSON.stringify({ version: "0.0.0", artifacts: {} }));
  const binary = "synthetic native binary fixture\n";
  await writeFile(join(source, "ironrun"), binary);
  const checksums = [];
  for (const filename of Object.values(artifactNames)) {
    const archive = join(dist, filename);
    const tar = spawnSync("tar", ["-czf", archive, "-C", source, "ironrun"], { encoding: "utf8" });
    assert.equal(tar.status, 0, tar.stderr);
    const digest = createHash("sha256").update(await readFile(archive)).digest("hex");
    checksums.push(`${digest}  ${filename}`);
  }
  await writeFile(join(dist, "checksums.txt"), checksums.join("\n") + "\n");
  const build = (version) => spawnSync(process.execPath, [join(pkgRoot, "scripts/build-manifest.mjs"), version, dist], { encoding: "utf8" });
  const valid = build("v1.2.3-rc.1");
  assert.equal(valid.status, 0, valid.stderr);
  const manifestBefore = await readFile(join(pkgRoot, "manifest.json"), "utf8");
  const packageBefore = await readFile(join(pkgRoot, "package.json"), "utf8");
  const manifest = JSON.parse(manifestBefore);
  assert.equal(manifest.version, "1.2.3-rc.1");
  assert.equal(JSON.parse(packageBefore).version, manifest.version);
  assert.equal(Object.keys(manifest.artifacts).length, 4);
  for (const artifact of Object.values(manifest.artifacts)) {
    assert.equal(artifact.binarySize, Buffer.byteLength(binary));
    assert.equal(artifact.binarySha256, createHash("sha256").update(binary).digest("hex"));
  }
  const guard = spawnSync(process.execPath, [join(pkgRoot, "scripts/validate-manifest.mjs")], { encoding: "utf8" });
  assert.equal(guard.status, 0, guard.stderr);
  await writeFile(join(dist, Object.values(artifactNames)[0]), "tampered archive");
  const invalid = build("v1.2.4");
  assert.notEqual(invalid.status, 0);
  assert.match(invalid.stderr, /checksum mismatch/);
  assert.equal(await readFile(join(pkgRoot, "manifest.json"), "utf8"), manifestBefore);
  assert.equal(await readFile(join(pkgRoot, "package.json"), "utf8"), packageBefore);
});
