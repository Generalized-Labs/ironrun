from pathlib import Path
import hashlib
import json
import shutil

root=Path('/workspace/ironrun-product-research/launch-20261026/codex-host')
final=root/'mcp-1793101315525752139'
selected=root/'selected-final-copy'
selected.mkdir(exist_ok=True)
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()

def copy(p,dest):
    dest.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(p,dest)
    assert p.read_bytes()==dest.read_bytes()

summary=json.loads((final/'summary.json').read_text())
assert summary['passed'] and summary['source_stable_since_build'] and summary['driver_unchanged']
assert digest(root/'probe_codex_host.py')==summary['driver_sha256']
assert json.loads((final/'runtime-source-build.json').read_text())['before']['mcp/server.go']=='c585b0004ea56fa2de402987269ed1caa0446795b19648dab2caaa47dc0464d2'
copy(root/'probe_codex_host.py',selected/'probe_codex_host.py')
copy(root/'official-doc-excerpts.txt',selected/'official-doc-excerpts.txt')
for p in final.iterdir():
    if p.is_file() and p.suffix in ['.txt','.json'] and p.name!='model-requests.json':
        copy(p,selected/'final'/p.name)
copy(final/'home/codex/config.toml',selected/'final/config.toml')
copy(final/'project/ironrun.yml',selected/'final/policy.yml')
copy(final/'project/AGENTS.md',selected/'final/project-instructions.txt')
requests=json.loads((final/'model-requests.json').read_text())
observations=[]
for record in requests:
    body=record['body']; catalog=[t for t in body['tools'] if t.get('name')=='mcp__ironrun']
    input_items=body.get('input',[])
    observations.append(dict(path=record['path'],authorization_header_present=record['authorization_header_present'],
                             observed_monotonic_ns=record['observed_monotonic_ns'],model=body['model'],
                             ironrun_tools=catalog,
                             tool_input_items=[i for i in input_items if i.get('type') in ['function_call','function_call_output']],
                             instructions_omitted=True,other_prompt_messages_omitted=True))
(selected/'final/model-observations.json').write_text(json.dumps(observations,indent=2)+'\n')
inventory={'scope':'Original full requests retained locally; compact observations omit built-in instructions and unrelated prompt messages.',
           'raw_request_file':str(final/'model-requests.json'),'sha256':digest(final/'model-requests.json'),
           'bytes':(final/'model-requests.json').stat().st_size}
(selected/'final/raw-request-inventory.json').write_text(json.dumps(inventory,indent=2)+'\n')
for label,folder in [('host-approval-gate','mcp-1793100105862893015'),('earlier-success','mcp-1793100154842480305')]:
    old=root/folder
    for name in ['summary.json','codex-exec.result.json','codex-exec.stdout.txt','codex-exec.stderr.txt']:
        copy(old/name,selected/label/name)
    copy(old/'home/codex/config.toml',selected/label/'config.toml')
case_notes=[]
for p in sorted(root.glob('*/summary.json')):
    s=json.loads(p.read_text())
    if 'mode' not in s:
        continue
    case_notes.append(dict(directory=p.parent.name,summary_sha256=digest(p),
                           mode=s['mode'],codex_exit=s['codex_exit'],requests=s['model_requests'],
                           tool_fixture_error=s.get('fixture_error'),loopback_requests=s.get('loopback_requests'),
                           source_binding='complete before/after Go/module manifest' if (p.parent/'runtime-source-build.json').exists() else 'earlier limited source metadata'))
(selected/'case-inventory.json').write_text(json.dumps(case_notes,indent=2)+'\n')
(selected/'summary.json').write_text(json.dumps(dict(final_case=str(final),result=summary,
    retained_success=True,actual_host='Codex CLI0.159.2 on Linux amd64',
    model='Scripted local Responses SSE fixture, not a real model',
    native_store='Synthetic secret-tool root-key adapter; actual Ironrun v2 encrypted vault used',
    approval='Codex MCP server preapproved only in isolated fixture config; Ironrun grant separately required and applied using actual CLI',
    local_endpoint_checks='No loopback request during100ms pending observation; exactly one matching synthetic credential header after grant; output redacted in host and model input',
    unsupported=['Default host onboarding','Interactive host approval UX','Real model judgment','macOS or Linux Secret Service','Claude Code/OpenCode/Cursor','External service authentication','Background host network traffic tracing']),indent=2)+'\n')
print(json.dumps({'selected':str(selected),'files':len(list(selected.rglob('*'))),'summary_passed':summary['passed']}))
