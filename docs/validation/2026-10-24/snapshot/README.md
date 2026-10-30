# Selected unpublished snapshot evidence

`REPORT.md` and `verification-summary.json` describe the original full local
snapshot directory. This compact archive retains raw command statuses/logs,
source/tool identities, checksums, metadata, cask output, and the four run-2
SBOMs. Native binaries, release archives, downloaded tools, and duplicate run-1
SBOMs remain outside source control. `full-workspace-inventory.json` records
their observed hashes; their presence is not implied in this compact archive.
`verify_outputs.py` needs the original full outputs to repeat those checks.

`artifact-manifest.json` hashes files actually retained here. The original
build inputs include an earlier README than the final documentation corrections.
After these builds, CI required rewording two setup errors to begin in lowercase;
the snapshots precede that message-only change. See `../ci-followup/` for the
exact patch, final source identity, and verification. No tagged or signed release
was produced.
