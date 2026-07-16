import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const version = process.argv[2]?.replace(/^v/, "");
const dist = resolve(process.argv[3] ?? "dist");
if (!version) throw new Error("usage: build-manifest.mjs VERSION DIST");
const packagePath = new URL("../package.json", import.meta.url);
const manifestPath = new URL("../manifest.json", import.meta.url);
const pkg = JSON.parse(await readFile(packagePath, "utf8"));
pkg.version = version;
await writeFile(packagePath, JSON.stringify(pkg, null, 2) + "\n");

const checksums = new Map((await readFile(join(dist, "checksums.txt"), "utf8")).trim().split("\n").map((line) => {
  const [hash, filename] = line.trim().split(/\s+/, 2);
  return [filename, hash];
}));
const names = {
  "darwin-x64": "ironrun_Darwin_x86_64.tar.gz",
  "darwin-arm64": "ironrun_Darwin_arm64.tar.gz",
  "linux-x64": "ironrun_Linux_x86_64.tar.gz",
  "linux-arm64": "ironrun_Linux_arm64.tar.gz"
};
const artifacts = {};
for (const [key, filename] of Object.entries(names)) {
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
await writeFile(manifestPath, JSON.stringify({ version, artifacts }, null, 2) + "\n");
