# Staticcheck wording follow-up

At `5320554`, both Linux/macOS race jobs, all three Node jobs, govulncheck,
stdout-redaction, Fuzz, and Dogfood passed. The lint job failed only on ST1005:
two `fmt.Errorf` strings began with the capitalized proper name "Codex".
`lint-failure-5320554.log` preserves that decoded job log.

The fix changes their openings to "unrecognized Codex server list" and
"unrecognized Codex server record". It changes no branch, mutation, registration,
authorization, or timing behavior. `source-followup.json` binds the old and new
source bytes and exact patch. The earlier race/REA/snapshot measurements retain
their original sources; snapshots were not rebuilt for these message edits.

After the fix, the focused setup regressions pass under the race detector and
`staticcheck ./...` exits zero using pinned v0.8.2 (the version installed by the
failed CI run). Its first local analysis attempt stopped because the default
cache directory was read-only; that failed tool attempt is retained separately.
Using a writable XDG cache resolved the environment issue without changing code.
Tool version, executable hash, commands, statuses and logs are retained here.

The PR checks record the final commit's complete remote outcomes. No release or
publication was performed. `artifact-manifest.json` hashes the selected retained
files and excludes itself; caches and downloaded executables are not bundled.
