# Concurrency fixes — October 21, 2026

## Vault initialization

Before: concurrent first Open calls could both observe a missing protected key,
generate different root keys, and overwrite one another in the key manager. A
successful vault write through the obsolete handle then failed integrity checks
on reopen. A synthetic protector barrier reproduced two saved keys and ErrIntegrity.

After: kernel-backed initialization locks serialize key load/generation/save and
initial document verification. Locks release on process exit; the lock file stays
to prevent separate-inode races. Ordinary mutation locks are not nested. The
regression verifies one persisted key, successful writes through both returned
handles, and readable values after reopening. It failed before the fix and
passed repeated race tests. Vault tests cross-compiled for Darwin arm64 and
Windows amd64; Windows is not an announced launch platform.

## Proposal and approval integrity

Before: concurrent MCP workers could both accept different proposals with one
previously unused ID. A dashboard refresh could also reorder the selected row
between review and confirmation. An actual MCP stdio probe accepted both
conflicting variants in 23 of 30 pairs (another initial probe saw 27 of 30).

After: creation, rejection and promotion share a cross-process transaction lock.
Pending IDs are immutable; approval binds the reviewed contents to a digest and
rechecks it while locked. The dashboard freezes the reviewed proposal, preserves
it across reordered lists, and cancels confirmation if it changes or disappears.
The final live MCP probe accepted both conflicting variants in 0 of 30 pairs.
This observation is illustrative, not a statistical security bound.

Race tests cover concurrent immutable creation, 32 conflicting MCP proposals,
stale CLI approval digests, and dashboard reorder/replacement behavior. Human
prompts occur outside the transaction lock; no recursive locking path was found.
The lock is never stolen by age. A process crash can leave a pending lock that
requires operator recovery; SECURITY.md documents the procedure.

## Review and proof

The author and an independent reviewer traced each fix and its callers. Focused
Go 1.26.10 race runs and the complete repository race suite pass. No remaining
blocker was found in these reviewed repairs. Reviews were bounded and do not
establish absence of unrelated defects. The first independent auth test attempt
failed because temporary storage was full; the workspace-cache rerun passed.

Raw evidence: vault-race-tests.txt, approval-race-tests.txt,
proposal-race-before.txt and proposal-race-after.txt. Run the optional synthetic
stdio probe with `python3 proposal-race-probe.py.txt /absolute/path/to/ironrun`.
Maintained regression tests are in the corresponding vault, pending, CLI, MCP,
and TUI test packages. These findings are separate from the paper's historical
49-defect tally; original audit records remain needed for that tally.
