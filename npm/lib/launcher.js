import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { chmod, mkdir, open, readFile, rename, rm, stat, writeFile } from "node:fs/promises";
import { homedir, platform, arch } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageRoot = join(here, "..");

export function platformKey(os = platform(), cpu = arch()) {
  const osName = os === "darwin" ? "darwin" : os === "linux" ? "linux" : "";
  const cpuName = cpu === "x64" ? "x64" : cpu === "arm64" ? "arm64" : "";
  if (!osName || !cpuName) {
    throw new Error(`unsupported platform ${os}/${cpu}; use a native release from GitHub`);
  }
  return `${osName}-${cpuName}`;
}

export async function sha256(path) {
  const data = await readFile(path);
  return createHash("sha256").update(data).digest("hex");
}

export async function verifyFile(path, expectedSize, expectedHash) {
  try {
    const info = await stat(path);
    if (!info.isFile() || info.size !== expectedSize) return false;
    return (await sha256(path)) === expectedHash;
  } catch {
    return false;
  }
}

function cacheRoot(version) {
  const base = platform() === "darwin" ? join(homedir(), "Library", "Caches") : join(homedir(), ".cache");
  return join(base, "ironrun", `v${version}`);
}

async function loadRelease() {
  const pkg = JSON.parse(await readFile(join(packageRoot, "package.json"), "utf8"));
  const manifest = JSON.parse(await readFile(join(packageRoot, "manifest.json"), "utf8"));
  if (manifest.version !== pkg.version) {
    throw new Error("package and artifact manifest versions differ; reinstall the npm package");
  }
  const key = platformKey();
  const artifact = manifest.artifacts[key];
  if (!artifact) {
    throw new Error(`no verified v${pkg.version} artifact exists for ${key}`);
  }
  for (const field of ["filename", "size", "sha256", "binarySize", "binarySha256"]) {
    if (!artifact[field]) throw new Error(`artifact manifest is missing ${field}; refusing execution`);
  }
  return { version: pkg.version, artifact };
}

async function acquireLock(path) {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      return await open(path, "wx", 0o600);
    } catch (error) {
      if (error?.code !== "EEXIST") throw error;
      try {
        const info = await stat(path);
        if (Date.now() - info.mtimeMs > 120_000) await rm(path, { force: true });
      } catch {}
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  throw new Error("another launcher held the cache lock for 30s; remove the stale ironrun cache lock and retry");
}

async function downloadVerified(version, artifact, directory, binaryPath) {
  const unique = `${process.pid}-${Date.now()}`;
  const archive = join(directory, `.download-${unique}`);
  const extract = join(directory, `.extract-${unique}`);
  try {
    const url = `https://github.com/generalized-labs/ironrun/releases/download/v${version}/${artifact.filename}`;
    let response;
    try {
      response = await fetch(url, { redirect: "follow" });
    } catch {
      throw new Error(`cannot reach GitHub for v${version}; connect to the network or install from a verified release archive`);
    }
    if (!response.ok) {
      throw new Error(`GitHub returned ${response.status} for ${artifact.filename}; verify that release v${version} is published`);
    }
    await writeFile(archive, new Uint8Array(await response.arrayBuffer()), { mode: 0o600 });
    if (!(await verifyFile(archive, artifact.size, artifact.sha256))) {
      throw new Error("downloaded archive failed size or SHA-256 verification; nothing was executed");
    }
    await mkdir(extract, { mode: 0o700 });
    const unpack = spawnSync("tar", ["-xzf", archive, "-C", extract], { stdio: "pipe" });
    if (unpack.status !== 0) {
      throw new Error("verified archive could not be extracted; install a working tar command and retry");
    }
    const candidate = join(extract, "ironrun");
    if (!(await verifyFile(candidate, artifact.binarySize, artifact.binarySha256))) {
      throw new Error("extracted native binary failed SHA-256 verification; nothing was executed");
    }
    await chmod(candidate, 0o755);
    await rename(candidate, binaryPath);
  } finally {
    await rm(archive, { force: true });
    await rm(extract, { recursive: true, force: true });
  }
}

export async function verifiedBinary() {
  const { version, artifact } = await loadRelease();
  const directory = cacheRoot(version);
  const binaryPath = join(directory, "ironrun");
  await mkdir(directory, { recursive: true, mode: 0o700 }).catch(() => {
    throw new Error(`cache is not writable at ${directory}; fix its ownership or install the native binary directly`);
  });
  if (await verifyFile(binaryPath, artifact.binarySize, artifact.binarySha256)) return binaryPath;
  const lockPath = join(directory, ".download.lock");
  const lock = await acquireLock(lockPath);
  try {
    if (!(await verifyFile(binaryPath, artifact.binarySize, artifact.binarySha256))) {
      await rm(binaryPath, { force: true });
      await downloadVerified(version, artifact, directory, binaryPath);
    }
  } finally {
    await lock.close();
    await rm(lockPath, { force: true });
  }
  return binaryPath;
}

export async function launch(args) {
  const binary = await verifiedBinary();
  const child = spawn(binary, args, { stdio: "inherit", env: process.env });
  for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
    process.once(signal, () => child.kill(signal));
  }
  const result = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (code, signal) => resolve({ code, signal }));
  });
  if (result.signal) {
    process.kill(process.pid, result.signal);
    return;
  }
  process.exitCode = result.code ?? 1;
}
