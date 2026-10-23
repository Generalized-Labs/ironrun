# REA follow-up on clean source 803aa42

REA 6.7.0 inspected inert npm source and embedded Go build metadata. The captured
source was clean commit `803aa420d35af969ca4ff858a374a7dcdf20796d`; later paper
and documentation edits are separate. Exact source hashes and the build command
are in `source-provenance.json`. `rea-summary.json` contains compact results and
raw-output hashes. No target Ironrun binary was executed.

## Native artifact

The verified Go 1.26.10 compiler built Linux amd64 with `CGO_ENABLED=0` and
`-trimpath`. REA and independent `go version -m` inspection agree on revision
`803aa42`, `vcs.modified=false`, architecture, compiler version, and build flags.
The artifact is 31,008,898 bytes, SHA-256
`87e01d39496885e1ad284e520f0363710765e1c6f35399c76dbd03faa1e5e056`.
Its hash was independently recomputed after inspection.

This is a local development build without release stripping/stamping flags,
signatures, or SBOM generation. It is neither a published release nor a direct
reproducibility comparison with the earlier stripped snapshot or v0.5.0 assets.
The historical public binaries reported Go 1.26.5 and `vcs.modified=true`; those
metadata observations remain separately recorded. Metadata inspection is not
native-code decompilation or a dynamic security audit.

The original provenance's `go_binary_sha256` identifies the **compiler** binary
(`9c2a37ae5b21ba1d5a004bb9ab4d0c64de6fc5778e9d30487adccea62678b8b5`).
The compact summary explicitly distinguishes that from the Ironrun artifact.

## npm source reconstruction

- 13 relevant files, 11 JavaScript files parsed, zero parse failures.
- 153 structural observations; zero declared-integrity contradictions.
- Application graph coverage is **partial**. Semantic coverage is **unknown**,
  with 1,628 explicit unknowns, including unsupported asynchronous value flow.

These counts describe tool extraction, not vulnerabilities or proof of full
runtime coverage. The inventory covers the supplied source directory, not a
published npm tarball. The reconstruction exposes the launcher/manifest/scripts
relationships; source review and the existing real subprocess tests establish
the archive/hash/spawn and startup-signal behavior. In particular, asynchronous
callbacks and signal ordering cannot be certified from structural observations.

Zero inventory contradictions does not mean the package is ready to publish.
The checked-in bootstrap manifest remains intentionally unprepared. The actual
publication validator was independently invoked and rejected it with “build the
release manifest before publishing,” as designed. A real release must first
prepare matching archive/binary hashes and pass the final publication checks.

Raw outputs stay outside the repository: `npm-analysis.json` is about 8.8 MB,
and the local native binary is about 31 MB. The compact summary preserves their
hashes and explicit coverage limits. No production defect is inferred merely
from an unresolved relation or observation count.
