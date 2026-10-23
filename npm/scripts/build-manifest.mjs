import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { artifactNames, validateReleaseManifest } from "../lib/manifest.js";

const version = process.argv[2]?.replace(/^v/, "");
const dist = resolve(process.argv[3] ?? "dist");
if (!version) throw new Error("usage: build-manifest.mjs VERSION DIST");
const packagePath = new URL("../package.json", import.meta.url);
const manifestPath = new URL("../manifest.json", import.meta.url);
const pkg = JSON.parse(await readFile(packagePath, "utf8"));
pkg.version = version;

const checksums = new Map((await readFile(join(dist, "checksums.txt"), "utf8")).trim().split("\n").map((line) => {
  const [hash, filename] = line.trim().split(/\s+/, 2);
  return [filename, hash];
}));
const artifacts = {};
for (const [key, filename] of Object.entries(artifactNames)) {
  const archive = join(dist, filename);
  const expected = checksums.get(filename);
  if (!expected) throw new Error(`checksums.txt is missing ${filename}`);
  const actual = createHash("sha256").update(await readFile(archive)).digest("hex");
  if (actual !== expected) throw new Error(`release checksum mismatch for ${filename}`);
  const directory = await mkdtemp(join(tmpdir(), "ironrun-manifest-"));
  try {
    const unpack = spawnSync("tar", ["-xzf", archive, "-C", directory]);
    if (unpack.status !== 0) throw new Error(`cannot extract ${filename}`);
    const binary = join(directory, "ironrun");
    const binaryData = await readFile(binary);
    artifacts[key] = {
      filename,
      size: (await stat(archive)).size,
      sha256: actual,
      binarySize: binaryData.length,
      binarySha256: createHash("sha256").update(binaryData).digest("hex")
    };
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}
const manifest = { version, artifacts };
validateReleaseManifest(pkg, manifest);
await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + "\n");
await writeFile(packagePath, JSON.stringify(pkg, null, 2) + "\n");
