import { readFile } from "node:fs/promises";
import { validateReleaseManifest } from "../lib/manifest.js";

const pkg = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));
validateReleaseManifest(pkg, manifest);
console.log(`Release manifest for ${pkg.version} covers all supported platforms.`);
