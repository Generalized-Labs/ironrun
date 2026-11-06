# Developer pilot before stable release

This is a proposed validation protocol for developers and small teams. No human
sessions or completion rates have been collected. It complements the required
[release checklist](RELEASE_CHECKLIST.md), whose stable-release gates still apply.

Updated November 6, 2026 (America/New_York). The
[latest source-bound evidence](validation/2026-11-06/README.md) covers the tested
`b5b0059` diagnostic candidate, actual disposable-runner macOS Keychain CI, and
bounded Linux Claude Code/OpenCode fixtures. It does not close the human rows
below. Documentation changes do not retarget that tested build.

The maintainer selected a preview launch after readiness checks. Start with
actual Mac sessions in Codex, Claude Code, and OpenCode, then Cursor's desktop
editor on a Linux PC if a supported package and graphical session are available.
Use the concrete [real-host walkthrough and result matrix](HOST_E2E.md); its
native Keychain/Secret Service and interactive-host rows remain pending until
observed. Then invite 8–12 external developers, retaining the existing stable
pilot's Codex/Claude Code/Cursor representation and recording OpenCode separately.
Use disposable projects and
synthetic credentials. Record host, OS, Ironrun version, exact source/artifact
identity, and whether the native credential store is available. Do not record
real credentials, unredacted command output, or unrelated client configuration.

## Tasks and observations

Complete setup, native-store write and fresh-process use, host tool discovery,
informed approval, and in-place continuation
on each host separately. Preserve host/version-specific failures rather than
extrapolating one client's success to the others. Before preview publication,
complete the applicable signed-artifact and installation checks in
[LAUNCH_READINESS.md](LAUNCH_READINESS.md); synthetic captures alone do not close
these real-host checks.

| Task | Observe | Existing stable-release target |
| --- | --- | --- |
| Install, run `ironrun setup`, verify MCP tools in the host, then run the first sealed command | Time from clean start, each repair step, help required, actual host connection | First successful command within two minutes; at least 8/10 onboard unaided |
| Add a synthetic environment entry through local input | Time, misplaced input, whether policy or chat receives a value | Entry added within 20 seconds |
| Ask the agent to run a command requiring workspace approval | Time until Inbox visibility, whether project/environment/session and review deadline are understood | Request visible within 250 ms; informed approval within 15 seconds |
| Approve locally while the MCP call waits | Whether the original call resumes, number of retries or restarts | At least 7/10 complete the approval flow |
| Review the host's tool approval and Ironrun's grant independently | Which boundary blocked a call, actual child execution, and whether the user understands the scopes | Host approval must not be confused with Ironrun authorization |
| Fulfil a missing synthetic secret locally | Entry once, automatic continuation, restart or chat handoff | Original call resumes within 45 seconds |
| Deny, let a request/grant expire, revoke, cancel, time out, restart, and retry | Clear status, actual child effects, leftover pending requests, new-session grant requirements, and recovery path | Expiry and revocation respected; no unexpected execution; canceled/disconnected calls are not assumed to resume |
| Compare workspace and strict saved-command execution | Workspace normal network versus the saved command's own policy and separate lease | No silent transfer of workspace permissions into strict policy |
| Start with custom or malformed MCP configuration | Preserved settings, understandable per-client status, successful manual recovery | No configuration loss; observe recovery time without inventing a threshold |

Use monotonic timestamps for timings. Define start and end events before the
session and retain failed/abandoned tasks. Separate unaided completion from
moderator-assisted recovery. Existing numeric targets are acceptance goals,
not measured results or statistically established usability claims. Record
actual cohort denominators when the cohort is not exactly ten.

## Session record

For each task, retain a pseudonymous participant ID, start/end event and elapsed
time, pass/fail/abandoned status, help given, observed error, and a short account
of what the participant expected. Confirm the command's actual outcome rather
than treating setup success or a request ID as execution success. Inspect any
shared recording for credentials before retaining it.

Compare the setup summary with what the host actually loads. Earlier Linux Codex
CLI evidence uses a scripted model and synthetic native root-key adapter. Later
Claude Code/OpenCode fixtures use actual Linux Secret Service: ten lifecycle
cases on an earlier identified binary, then two fresh approval/resume cases on
the clean `b5b0059` diagnostic archive member. Model responses and CLI approvals
remain scripted. Actual macOS Keychain CI also passes on a disposable runner.
None establishes human TUI use, real-model judgment, default host permission UX,
or another host's result. Keep source-build success separate from signed-install
and Gatekeeper checks. Test interactive prompts, denial, expiry, cancellation,
timeout, and continuation in real sessions.

To reduce setup effort, prepare one pinned source build and one disposable project
per host. Start with real tool discovery, native-store use, approval and resumed
execution; if that smoke fails, fix the concrete defect before repeating it.
After a smoke passes, continue the complete per-host walkthrough with the same
identified build. A quick smoke is not the full pilot. Keep approvals enabled,
give the operator one requested UI action at a time, and preserve existing
configuration and vaults. Never run the disposable-account Keychain CI fixture
on the maintainer's primary Mac account. Record unsupported host controls as
blocked; do not invent settings or fill missing observations with fixture results.

## Preview and stable decisions

Before preview publication, close the applicable automated/runtime and
signed-installation checks, review the per-host matrix and all failed cases,
and state any remaining platform/host limitations explicitly. A source build,
config registration, scripted host capture, or completed report design does
not independently close these gates. The research report can first receive a
Vercel preview with accurate evidence labels; main-site integration follows
the runtime readiness decision. The existing team's access grant and the PR's
Hobby/private-organization deployment refusal are separate blockers. Restore
access and inspect plan eligibility before deploying; do not make the repository
public or change billing as an unreviewed workaround. Actual edge and browser
checks must pass before site promotion.

Fix any credential disclosure, configuration loss, or authorization bypass before
expanding the pilot. Follow the checklist's five-project, seven-day dogfood,
return-use, platform, installation, and signing gates before stable release.
Use the selected preview designation; do not describe unmeasured
targets as achieved or label the build stable while required gates remain open.

No invitations, telemetry collection, release, or external publication are
performed by preparing this protocol. The selected channel is preview. The
existing stable checklist's human cohort and platform gates are unchanged;
OpenCode extends the maintainer checks without replacing that required cohort.
