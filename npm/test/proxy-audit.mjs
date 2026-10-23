// Run with `node test/proxy-audit.mjs`. This characterizes the current Node
// runtime; it does not add proxy support to the production launcher.
import assert from "node:assert/strict";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { artifactNames } from "../lib/manifest.js";
import { platformKey } from "../lib/launcher.js";

const digest = (data) => createHash("sha256").update(data).digest("hex");
const fixtureOutput = "proxy-fixture:argument with spaces";
const [major, minor] = process.versions.node.split(".").map(Number);
const supportsEnvProxy = major >= 24 || (major === 22 && minor >= 21);

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve(server.address().port);
    });
  });
}

test(`real launcher proxy transport on Node ${process.versions.node}`, { timeout: 30_000 }, async (t) => {
  const root = await mkdtemp(join(tmpdir(), "ironrun proxy audit "));
  const sockets = new Set();
  const servers = [];
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    await rm(root, { recursive: true, force: true });
  });
  const track = (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  };
  const certPath = join(root, "cert.pem");
  const keyPath = join(root, "key.pem");
  const certificate = spawnSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", keyPath,
    "-out", certPath, "-days", "1", "-subj", "/CN=github.com", "-addext",
    "subjectAltName=DNS:github.com,DNS:release-assets.githubusercontent.com",
  ], { encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL" });
  assert.equal(certificate.status, 0, certificate.error?.message ?? certificate.stderr);

  const source = join(root, "source");
  await mkdir(source);
  const binary = Buffer.from("#!/bin/sh\nprintf 'proxy-fixture:%s\\n' \"$1\"\n");
  await writeFile(join(source, "ironrun"), binary, { mode: 0o755 });
  const archivePath = join(root, "release.tar.gz");
  const tar = spawnSync("tar", ["-czf", archivePath, "-C", source, "ironrun"], {
    encoding: "utf8", timeout: 10_000, killSignal: "SIGKILL",
  });
  assert.equal(tar.status, 0, tar.error?.message ?? tar.stderr);
  const archive = await readFile(archivePath);
  const filename = artifactNames[platformKey()];
  const releasePath = `/generalized-labs/ironrun/releases/download/v1.2.3/${filename}`;
  let mode = "valid";
  let events = [];
  const origin = https.createServer({ key: await readFile(keyPath), cert: await readFile(certPath) }, (req, res) => {
    events.push({ kind: "https", host: req.headers.host, path: req.url });
    if (req.headers.host === "github.com" && req.url === releasePath) {
      res.writeHead(302, { location: "https://release-assets.githubusercontent.com/fixture.tar.gz" });
      res.end();
    } else if (req.headers.host === "release-assets.githubusercontent.com" && req.url === "/fixture.tar.gz") {
      res.end(mode === "tamper" ? Buffer.from("tampered fixture archive") : archive);
    } else {
      res.writeHead(404);
      res.end();
    }
  });
  servers.push(origin);
  origin.on("connection", track);
  const originPort = await listen(origin);
  const proxy = http.createServer((_req, res) => { res.writeHead(405); res.end(); });
  servers.push(proxy);
  proxy.on("connection", track);
  proxy.on("connect", (req, socket, head) => {
    events.push({ kind: "connect", target: req.url });
    if (mode === "proxy-fails") {
      socket.end("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n");
      return;
    }
    if (!["github.com:443", "release-assets.githubusercontent.com:443"].includes(req.url)) {
      socket.destroy();
      return;
    }
    const upstream = net.connect(originPort, "127.0.0.1", () => {
      socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      socket.pipe(upstream);
      upstream.pipe(socket);
    });
    track(upstream);
    upstream.on("error", () => socket.destroy());
    socket.on("error", () => upstream.destroy());
    socket.on("close", () => upstream.destroy());
  });
  const proxyURL = `http://127.0.0.1:${await listen(proxy)}`;

  async function fixture(label) {
    const work = join(root, label);
    const pkg = join(work, "npm");
    await mkdir(pkg, { recursive: true });
    await cp(new URL("../lib", import.meta.url), join(pkg, "lib"), { recursive: true });
    await cp(new URL("../bin", import.meta.url), join(pkg, "bin"), { recursive: true });
    await writeFile(join(pkg, "package.json"), JSON.stringify({ type: "module", version: "1.2.3" }));
    await writeFile(join(pkg, "manifest.json"), JSON.stringify({
      version: "1.2.3",
      artifacts: { [platformKey()]: {
        filename, size: archive.length, sha256: digest(archive),
        binarySize: binary.length, binarySha256: digest(binary),
      } },
    }));
    const preload = join(work, "guard.mjs");
    const networkLog = join(work, "blocked-network.jsonl");
    // Keep fetch, TLS, hashing, extraction and child execution real. Only home
    // lookup and outbound-network guards change in the isolated child. A
    // missing proxy opt-in must fail locally rather than contact real GitHub.
    await writeFile(preload, `
      import os from "node:os";
      import dns from "node:dns";
      import net from "node:net";
      import { appendFileSync } from "node:fs";
      import { syncBuiltinESMExports } from "node:module";
      os.homedir = () => ${JSON.stringify(work)};
      const blocked = (host) => {
        appendFileSync(${JSON.stringify(networkLog)}, JSON.stringify({ host }) + "\\n");
        const error = new Error("fixture blocks non-loopback connections");
        error.code = "ENOTFOUND";
        return error;
      };
      const lookup = dns.lookup;
      dns.lookup = function(host, options, callback) {
        if (host === "127.0.0.1" || host === "::1" || host === "localhost") {
          return lookup.apply(this, arguments);
        }
        if (typeof options === "function") callback = options;
        const error = blocked(host);
        queueMicrotask(() => callback(error));
      };
      const connect = net.Socket.prototype.connect;
      net.Socket.prototype.connect = function(...args) {
        const options = Array.isArray(args[0]) ? args[0][0] : args[0];
        const host = typeof options === "object" ? options.host : args[1];
        if (typeof host === "string" && net.isIP(host) && host !== "127.0.0.1" && host !== "::1") {
          const error = blocked(host);
          queueMicrotask(() => this.destroy(error));
          return this;
        }
        return connect.apply(this, args);
      };
      syncBuiltinESMExports();
    `);
    return { pkg, preload, networkLog };
  }

  async function run(f, { optIn = true, trust = true, noProxy = false, npmProxyOnly = false } = {}) {
    // Do not inherit proxy credentials, NODE_OPTIONS, or TLS overrides from
    // the caller. The only extra trusted certificate belongs to this fixture.
    const env = {
      PATH: process.env.PATH,
      ...(npmProxyOnly
        ? { npm_config_proxy: proxyURL, npm_config_https_proxy: proxyURL }
        : { HTTP_PROXY: proxyURL, HTTPS_PROXY: proxyURL }),
      ...(optIn ? { NODE_USE_ENV_PROXY: "1" } : {}),
      ...(trust ? { NODE_EXTRA_CA_CERTS: certPath } : {}),
      ...(noProxy ? { NO_PROXY: "github.com" } : {}),
    };
    return new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--import", f.preload, join(f.pkg, "bin/ironrun.js"), "argument with spaces"], {
        env, stdio: ["ignore", "pipe", "pipe"], timeout: 5_000, killSignal: "SIGKILL",
      });
      let stdout = "", stderr = "";
      child.stdout.on("data", (data) => { stdout += data; });
      child.stderr.on("data", (data) => { stderr += data; });
      child.once("error", reject);
      child.once("close", (code, signal) => {
        if (signal) reject(new Error(`fixture child terminated by ${signal}: ${stderr}`));
        else resolve({ code, stdout: stdout.trim(), stderr: stderr.trim() });
      });
    });
  }

  async function blockedNetwork(f) {
    try { return await readFile(f.networkLog, "utf8"); }
    catch (error) { if (error.code === "ENOENT") return ""; throw error; }
  }

  if (!supportsEnvProxy) {
    await t.test("runtime has no built-in environment-proxy opt-in; external fallback is blocked", async () => {
      const f = await fixture("unsupported-env-opt-in");
      const result = await run(f);
      assert.notEqual(result.code, 0);
      assert.equal(result.stdout, "");
      assert.match(result.stderr, /cannot reach GitHub/);
      assert.equal(events.length, 0);
      assert.match(await blockedNetwork(f), /github\.com/);
    });
    return;
  }

  const cases = [
    ["valid proxied HTTPS redirect", {}, "valid"],
    ["no startup opt-in", { optIn: false }, "valid"],
    ["npm proxy configuration alone", { npmProxyOnly: true }, "valid"],
    ["NO_PROXY bypass", { noProxy: true }, "valid"],
    ["tampered archive", {}, "tamper"],
    ["untrusted certificate", { trust: false }, "valid"],
    ["failed proxy", {}, "proxy-fails"],
  ];
  for (const [name, options, expectedMode] of cases) {
    await t.test(name, async (subtest) => {
      mode = expectedMode;
      events = [];
      const f = await fixture(name);
      const result = await run(f, options);
      if (name === "valid proxied HTTPS redirect") {
        assert.equal(result.code, 0, result.stderr);
        assert.equal(result.stdout, fixtureOutput);
        assert.equal(await blockedNetwork(f), "");
        for (const target of ["github.com:443", "release-assets.githubusercontent.com:443"]) {
          assert.ok(events.some((event) => event.kind === "connect" && event.target === target));
        }
        await subtest.test("warm cache works without a usable proxy", async () => {
          events = [];
          mode = "proxy-fails";
          const warm = await run(f);
          assert.equal(warm.code, 0, warm.stderr);
          assert.equal(warm.stdout, fixtureOutput);
          assert.equal(events.length, 0);
        });
      } else {
        assert.notEqual(result.code, 0, JSON.stringify({ name, result, events }));
        assert.equal(result.stdout, "");
        if (["no startup opt-in", "npm proxy configuration alone", "NO_PROXY bypass"].includes(name)) {
          assert.equal(events.length, 0);
          assert.match(await blockedNetwork(f), /github\.com/);
        } else {
          assert.equal(await blockedNetwork(f), "", "proxy failure must not cause direct fallback");
          assert.ok(events.some((event) => event.kind === "connect"));
        }
        if (name === "tampered archive") assert.match(result.stderr, /failed size or SHA-256 verification/);
        if (name === "untrusted certificate" || name === "failed proxy") {
          assert.match(result.stderr, /cannot reach GitHub/);
          assert.ok(events.every((event) => event.kind === "connect"));
        }
      }
    });
  }
});
