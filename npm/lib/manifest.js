const identifier = "(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)";
const semver = new RegExp(`^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(?:-${identifier}(?:\\.${identifier})*)?(?:\\+[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*)?$`);

export const artifactNames = Object.freeze({
  "darwin-x64": "ironrun_Darwin_x86_64.tar.gz",
  "darwin-arm64": "ironrun_Darwin_arm64.tar.gz",
  "linux-x64": "ironrun_Linux_x86_64.tar.gz",
  "linux-arm64": "ironrun_Linux_arm64.tar.gz",
});

// Validate publication metadata, not artifact authenticity. build-manifest.mjs
// checks archive bytes against checksums; the release pipeline verifies signing.
export function validateReleaseManifest(pkg, manifest) {
  if (typeof pkg?.version !== "string" || !semver.test(pkg.version)) {
    throw new Error("package version must be valid SemVer without a v prefix");
  }
  if (manifest?.version !== pkg.version) {
    throw new Error("package and artifact manifest versions differ; build the release manifest before publishing");
  }
  for (const [platform, filename] of Object.entries(artifactNames)) {
    const artifact = manifest.artifacts?.[platform];
    if (!artifact || typeof artifact !== "object") {
      throw new Error(`missing release platform ${platform}; build the release manifest before publishing`);
    }
    if (artifact.filename !== filename) {
      throw new Error(`${platform}: invalid filename (expected ${filename})`);
    }
    for (const field of ["size", "binarySize"]) {
      if (!Number.isSafeInteger(artifact[field]) || artifact[field] <= 0) {
        throw new Error(`${platform}: ${field} must be a positive safe integer`);
      }
    }
    for (const field of ["sha256", "binarySha256"]) {
      if (typeof artifact[field] !== "string" || !/^[a-f0-9]{64}$/.test(artifact[field])) {
        throw new Error(`${platform}: ${field} must be a lowercase SHA-256 digest`);
      }
    }
  }
}
