from pathlib import Path
import datetime, hashlib, json, os, stat, subprocess
ROOT=Path(__file__).resolve().parent
REPO=Path('/workspace/ironrun-product-review')
BIN=Path('/workspace/ironrun-product-tools/ironrun-setup-fixed')
EXPECTED='2d75777c7f9bd44c0b8e42be50384d3d54cc5d05d66c792c0044c4ec0b8e4df7'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(BIN)==EXPECTED
names=['malformed-and-codex-failure','stale-registration','codex-unavailable','write-only-config']
rows=[]
for name in names+['workspace-expiry']:
 p=ROOT/(name+'.capture.json');x=json.loads(p.read_text());n=x['normalized_result'];m=n['manifest']
 assert m['rea_version']=='6.7.0' and n['exit']['code']==0 and n['settlement']['state']=='quiesced'
 rows.append({'scenario':name,'capture':p.name,'capture_sha256':sha(p),'evidence_id':x['evidence_id'],'exit':n['exit'],'settlement':n['settlement'],'truncated':n['truncated'],'filesystem_hash_omissions':{k:n['truncation_details'][k]['hash_omissions'] for k in ['filesystem_before','filesystem_after']},'selected_executable':m['scenario']['executable'],'selected_executable_sha256':m['selected_executable_sha256'],'driver':m['scenario']['arguments'][0],'driver_sha256':sha(Path(m['scenario']['arguments'][0]))})
preservation=json.loads((ROOT/'preservation-results.json').read_text())
assert preservation['all_assertions_passed']
for name in names:
 result=json.loads((ROOT/(name+'.result.json')).read_text())
 assert result['binary_sha256']==EXPECTED and result['uid']==1000 and result['program_exit_code']==0
 text=result['stdout'];assert 'host connections not checked' in text and 'automatically' not in text
 if name=='malformed-and-codex-failure':assert text.count('needs attention')==3 and 'exit status 23' in text
 if name=='stale-registration':assert text.count('needs inspection')==2 and 'Codex returned an unrecognized server list; configuration was not changed' in text
 if name=='codex-unavailable':assert 'CLI unavailable' in text and text.count('configuration written')==2
 if name=='write-only-config':assert text.count('permission denied')==2 and 'CLI unavailable' in text
mcp=json.loads((ROOT/'mcp/workspace-expiry.result.json').read_text());assert mcp['binary_sha256']==EXPECTED and mcp['uid']==1000
assert mcp['pending_ttl_seconds']==900 and mcp['requested_grant_ttl_seconds']==7200
srcfiles=subprocess.check_output(['git','ls-files','--cached','--others','--exclude-standard'],cwd=REPO,text=True).splitlines()
sources={f:sha(REPO/f) for f in sorted(set(srcfiles)) if f.endswith('.go') or f in ['go.mod','go.sum']}
(ROOT/'runtime-source-sha256.json').write_text(json.dumps({'base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=REPO,text=True).strip(),'dirty_worktree':True,'scope':'All indexed or nonignored Go files plus go.mod and go.sum; source identity recorded after captures, not an atomic build provenance attestation.','files':sources},indent=2)+'\n')
summary={'created_at_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'synthetic_only':True,'rea_cli_version':'6.7.0','runtime_binary':str(BIN),'runtime_binary_sha256':EXPECTED,'source_identity':'runtime-source-sha256.json','captures':rows,'setup_assertions':'All four setup scenarios exit0 and report per-client status without claiming a verified host connection; all pre-existing malformed, stale, and unreadable client config bytes and modes are preserved.','preservation_results':'preservation-results.json','workspace_deadline_assertions':{'pending_review_ttl_seconds':900,'requested_grant_ttl_seconds':7200,'message_deadline_equals_persisted_expiry_to_RFC3339_seconds':True,'result':'mcp/workspace-expiry.result.json'},'limitations':['REA selected executable is Python, not Ironrun. Both wrappers assert the separate Ironrun binary SHA256 before running it; path digest samples are not atomic operating-system image bindings.','Setup wrappers run the product with stdin as a pipe (nonTTY) so these captures exercise noninteractive setup only. They do not exercise native-store prompts or the TUI.','The wrapper invokes Ironrun with an explicit synthetic HOME, PATH, IRONRUN_HOME and XDG directories. REA itself reports inherited ambient environment as unknown. No project credentials or actual host configs were used.','Process observations are sampled, not complete fork tracing. Filesystem observations are before/after snapshots, not syscall traces, so these do not prove absence of transient writes.','Write-only0200 config files are unreadable to UID1000. REA reports truncated filesystem evidence with EACCES hash omissions in both snapshots. Separate post-capture inspection temporarily adds owner-read, verifies bytes against precomputed fixture hashes, and restores0200; those byte checks are outside REA capture.','No actual Claude Code, Codex, or Cursor host-to-MCP connection, model invocation, network observation or human usability session is established. Codex behavior in these setup cases uses controlled fixture scripts.','The initial MCP capture lacked a driver binary digest assertion. It is retained separately under mcp-initial-capture; the final top-level workspace-expiry capture is a fresh fixture run with digest and exact response assertions.','Before-state records under /workspace/ironrun-product-research/launch-flow-audit2 are historical reproductions, not a formal replay-equivalence claim over identical binary/scenario identity.']}
(ROOT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print(json.dumps({'all_assertions_passed':True,'captures':len(rows),'setup_scenarios':4,'source_files':len(sources),'write_only_hash_omissions_explicit':True}))
