import test from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir, platform } from "node:os";
import { join } from "node:path";
import { platformKey } from "../lib/launcher.js";

const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "ironrun launcher "));
  t.after(() => rm(root, { recursive: true, force: true }));
  const pkg = join(root, "npm");
  const source = join(root, "source");
  await mkdir(pkg);
  await mkdir(source);
  await cp(new URL("../lib", import.meta.url), join(pkg, "lib"), { recursive: true });
  await cp(new URL("../bin", import.meta.url), join(pkg, "bin"), { recursive: true });
  await writeFile(join(pkg, "package.json"), JSON.stringify({ type: "module", version: "1.2.3" }));
  const body = Buffer.from("#!/bin/sh\ncase \"$1\" in\n  signal) kill -TERM $$ ;;\n  exit) exit 7 ;;\n  wait) printf 'ready\\n'; exec sleep 30 ;;\n  *) printf 'fixture:%s\\n' \"$1\" ;;\nesac\n");
  await writeFile(join(source, "ironrun"), body, { mode: 0o755 });
  const archive = join(root, "release.tar.gz");
  const tar = spawnSync("tar", ["-czf", archive, "-C", source, "ironrun"], { encoding: "utf8" });
  assert.equal(tar.status, 0, tar.stderr);
  const bytes = await readFile(archive);
  await writeFile(join(pkg, "manifest.json"), JSON.stringify({
    version: "1.2.3",
    artifacts: { [platformKey()]: { filename: "release.tar.gz", size: bytes.length, sha256: digest(bytes), binarySize: body.length, binarySha256: digest(body) } },
  }));
  // Replace only the home-directory lookup and HTTP transport inside this test
  // subprocess. The real launcher, tar extraction and hash checks still run.
  const preload = join(root, "fixture.mjs");
  await writeFile(preload, `
    import os from 'node:os';
    import { syncBuiltinESMExports } from 'node:module';
    import { readFile, appendFile } from 'node:fs/promises';
    os.homedir = () => ${JSON.stringify(root)};
    syncBuiltinESMExports();
    globalThis.fetch = async () => {
      await appendFile(${JSON.stringify(join(root, "fetches"))}, 'fetch\\n');
      if (process.env.IRONRUN_FIXTURE_OFFLINE === '1') throw new Error('fixture offline');
      return new Response(await readFile(${JSON.stringify(archive)}));
    };
  `);
  const base = platform() === "darwin" ? join(root, "Library", "Caches") : join(root, ".cache");
  const cache = join(base, "ironrun", "v1.2.3");
  function run(arg, extraEnv = {}, onChild) {
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--import", preload, join(pkg, "bin", "ironrun.js"), arg], {
        env: { ...process.env, ...extraEnv }, stdio: ["ignore", "pipe", "pipe"], timeout: 10000,
      });
      let stdout = "", stderr = "";
      child.stdout.on("data", (data) => { stdout += data; });
      child.stderr.on("data", (data) => { stderr += data; });
      onChild?.(child);
      child.on("error", reject);
      child.on("close", (code, signal) => resolve({ code, signal, stdout, stderr }));
    });
  }
  return { root, pkg, archive, cache, run };
}

test("launcher verifies cold download, uses warm cache offline, and repairs corruption", async (t) => {
  const f = await fixture(t);
  const cold = await f.run("argument with spaces");
  assert.equal(cold.code, 0, cold.stderr);
  assert.equal(cold.stdout, "fixture:argument with spaces\n");
  const warm = await f.run("warm", { IRONRUN_FIXTURE_OFFLINE: "1" });
  assert.equal(warm.code, 0, warm.stderr);
  assert.equal(await readFile(join(f.root, "fetches"), "utf8"), "fetch\n");
  await writeFile(join(f.cache, "ironrun"), "corrupt cache");
  const repaired = await f.run("repaired");
  assert.equal(repaired.code, 0, repaired.stderr);
  assert.equal(repaired.stdout, "fixture:repaired\n");
  assert.equal(await readFile(join(f.root, "fetches"), "utf8"), "fetch\nfetch\n");
});

test("launcher rejects a tampered archive without executing it", async (t) => {
  const f = await fixture(t);
  await writeFile(f.archive, "tampered archive");
  const result = await f.run("must-not-run");
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /failed size or SHA-256 verification/);
});

test("concurrent cold launches share one verified download", async (t) => {
  const f = await fixture(t);
  const results = await Promise.all([f.run("one"), f.run("two")]);
  for (const result of results) assert.equal(result.code, 0, result.stderr);
  assert.equal(await readFile(join(f.root, "fetches"), "utf8"), "fetch\n");
});

test("launcher preserves child exit code and independently raised signal", async (t) => {
  const f = await fixture(t);
  const exited = await f.run("exit");
  assert.equal(exited.code, 7, exited.stderr);
  const signaled = await f.run("signal");
  assert.equal(signaled.signal, "SIGTERM", JSON.stringify(signaled));
  assert.equal(signaled.code, null);
});


test("launcher forwards termination requested by its caller", async (t) => {
  const f = await fixture(t);
  const result = await f.run("wait", {}, (child) => {
    child.stdout.once("data", () => child.kill("SIGTERM"));
  });
  assert.equal(result.stdout, "ready\n");
  assert.equal(result.signal, "SIGTERM", JSON.stringify(result));
  assert.equal(result.code, null);
});

test("cold offline launch fails without executing a binary", async (t) => {
  const f = await fixture(t);
  const result = await f.run("must-not-run", { IRONRUN_FIXTURE_OFFLINE: "1" });
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /cannot reach GitHub/);
});

test("archive hash alone is insufficient: extracted binary must match too", async (t) => {
  const f = await fixture(t);
  const path = join(f.pkg, "manifest.json");
  const manifest = JSON.parse(await readFile(path, "utf8"));
  manifest.artifacts[platformKey()].binarySha256 = "0".repeat(64);
  await writeFile(path, JSON.stringify(manifest));
  const result = await f.run("must-not-run");
  assert.notEqual(result.code, 0);
  assert.equal(result.stdout, "");
  assert.match(result.stderr, /extracted native binary failed SHA-256/);
});
