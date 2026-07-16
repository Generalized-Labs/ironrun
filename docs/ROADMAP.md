# Roadmap

## v1.0 local GA

- Global Projects and Inbox workspace.
- Direct-entry policy v2 with reversible version-1 migration.
- Automatic sealed-run request, approval, and continuation.
- Environment and file secrets with output redaction and cleanup.
- Owner-only value-blind daemon for macOS and Linux.
- GitHub Releases, verified installer, custom Homebrew tap, SBOMs, provenance,
  and keyless Sigstore bundles.

GA requires the security, migration, cross-platform, distribution, and
usability gates documented in the release checklist. External dogfooding is a
real release gate, not something the automated test suite can substitute for.

## After demonstrated demand

Cloud development starts only after repeated local use shows a need for
encrypted multi-device or team synchronization. Unlimited local projects,
environments, secrets, commands, agents, and self-hosted use remain MIT-licensed
and free.

Possible hosted work is deliberately outside the v1 security boundary:

- client-side encrypted synchronization;
- organization policy and approval routing;
- managed audit retention;
- team recovery and device enrollment.

No secret-adjacent product telemetry or cloud dependency belongs in the local
core.
