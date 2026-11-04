# Initial native probe path-assumption failure

The initial native probe reached actual Secret Service root-key persistence,
CLI environment setup, MCP approval/loopback/redaction, strict attempted-dial
blocking, revocation/denial, and daemon restart followed by a successful new CLI
vault reopen. It then failed its final instrumentation assertion because the
driver searched for `*.json` vaults; the actual source uses `*.irvault`.

Raw first-run logs and original driver bytes are retained at this root. No
product source was changed. The final run uses a fresh project/home/collection
under `final/`, corrects only that vault extension and output-directory selection,
and re-executes the complete probe. First-run stores and binary fixtures are
not included in the compact evidence manifest or public artifacts.
