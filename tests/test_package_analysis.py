import hashlib
import hmac
import io
import json
from datetime import datetime, timedelta, timezone
import subprocess
import zipfile

import pytest
from fastapi.testclient import TestClient

from skill_sandbox.app import scan_upload, app
from skill_sandbox.package_formats import bounded_data, PLUGIN_SCHEMA, MCP_SCHEMA
from skill_sandbox.package_review import validate_update, evaluate
from skill_sandbox.review_evidence import canonical_payload
from payloads.package_fixtures import CODE_AS_MARKDOWN_VARIATIONS


def archive(files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as handle:
        for path, value in files.items():
            handle.writestr(path, value if isinstance(value, (str, bytes)) else json.dumps(value))
    return output.getvalue()


def scan(files, **kwargs):
    return scan_upload(archive(files), 'fixture.zip', **kwargs)


def skill(extra=''):
    return f'---\nname: demo\ndescription: Harmless fixture\n{extra}---\nSummarize the supplied text.\n'


@pytest.mark.parametrize('files', CODE_AS_MARKDOWN_VARIATIONS)
def test_code_in_reference_markdown_and_invocation(files):
    result = scan(files)
    entry = next(e for e in result['files'] if e['path'].endswith('.py.md'))
    assert entry['effective_artifact_role'] == 'execution_component'
    assert {'code_in_text_artifact', 'declared_execution_target'} <= {f['id'] for f in entry['findings']}
    assert result['package_analysis']['execution_references']
    assert result['governance_profile']['sandbox_required']


def test_benign_code_fence_is_documentation_evidence_not_executable_file():
    result = scan({'demo/SKILL.md': skill(), 'demo/references/example.md': 'Example:\n```python\nprint("hello")\n```'})
    entry = next(e for e in result['files'] if e['path'].endswith('example.md'))
    assert entry['content_analysis']['evidence'] == ['documented_code_fence']
    assert not entry['content_analysis']['code_like']
    assert 'code_in_text_artifact' not in {f['id'] for f in entry['findings']}


@pytest.mark.parametrize('path,data,runtime,profile', [
    ('p/.claude-plugin/plugin.json', {'name': 'demo'}, 'claude-code', 'claude-plugin'),
    ('p/.codex-plugin/plugin.json', {'name': 'demo'}, 'openai', 'codex-plugin'),
    ('p/.cursor-plugin/plugin.json', {'name': 'demo'}, 'cursor', 'cursor-plugin'),
    ('p/gemini-extension.json', {'name': 'demo', 'version': '1.0.0'}, 'gemini', 'gemini-extension'),
    ('p/openclaw.plugin.json', {'id': 'demo', 'configSchema': {'type': 'object'}}, 'openclaw', 'openclaw-plugin'),
])
def test_native_manifest_profiles(path, data, runtime, profile):
    result = scan({path: data})['package_analysis']
    assert result['packages'][0]['profile'] == profile
    assert runtime in {item['runtime'] for item in result['runtime_targets']}
    assert not result['format_findings']


@pytest.mark.parametrize('directory,runtime', [('.github', 'copilot'), ('.kiro', 'kiro'), ('.devin', 'cascade'), ('.windsurf', 'cascade'), ('.gemini', 'gemini')])
def test_common_skills_runtime_indicators(directory, runtime):
    result = scan({f'{directory}/skills/demo/SKILL.md': skill()})
    assert runtime in {item['runtime'] for item in result['package_analysis']['runtime_targets']}
    assert result['package_analysis']['publisher_provenance'] == 'unverified'


def test_portable_and_legacy_manifest_conflict_and_schema_local_only(monkeypatch):
    monkeypatch.setattr('requests.get', lambda *a, **k: pytest.fail('Static scan contacted network'))
    result = scan({'p/plugin.json': {'$schema': PLUGIN_SCHEMA, 'name': 'demo', 'unknown': True},
                   'p/.claude-plugin/plugin.json': {'name': 'demo'},
                   'p/mcp.json': {'$schema': MCP_SCHEMA, 'mcpServers': {}}})
    ids = {i['id'] for i in result['package_analysis']['format_findings']}
    assert {'unknown_manifest_field', 'multiple_manifest_profiles'} <= ids
    assert not any(i['severity'] == 'error' for i in result['package_analysis']['format_findings'])
    result = scan({'p/plugin.json': {'$schema': 'https://invalid.example/schema', 'name': 'demo'}})
    assert result['package_analysis']['format_findings'][0]['id'] == 'unsupported_schema'


@pytest.mark.parametrize('document,kind', [('a: 1\na: 2', 'yaml'), ('a: &anchor [a]\nb: *anchor', 'yaml'), ('{"a":1,"a":2}', 'json'), ('[' * 40 + '0' + ']' * 40, 'json')])
def test_ambiguous_or_unbounded_config_rejected(document, kind):
    with pytest.raises(ValueError):
        bounded_data(document, kind)


def test_runtime_specific_frontmatter_and_optional_metadata():
    result = scan({'demo/SKILL.md': skill('disable-model-invocation: true\n')}, target_runtime='claude-code')
    assert not result['package_analysis']['format_findings']
    assert result['governance_evidence']['metadata'][0]['missing_recommended_fields']
    result = scan({'demo/SKILL.md': skill('disable-model-invocation: true\n')}, target_runtime='claude-upload')
    assert any(i['id'] == 'skill_frontmatter' for i in result['package_analysis']['format_findings'])


def test_components_transports_secrets_and_paths():
    result = scan({'p/plugin.json': {'$schema': PLUGIN_SCHEMA, 'name': 'demo'},
                   'p/mcp.json': {'$schema': MCP_SCHEMA, 'mcpServers': {
                       'launch': {'type': 'stdio', 'command': './server.py', 'env': {'API_KEY': 'literal-fixture-only'}},
                       'remote': {'type': 'http', 'url': 'http://example.invalid/mcp?token=do-not-display'},
                       'escape': {'type': 'stdio', 'command': '../outside.py'}}},
                   'p/server.py': 'print("fixture")'})
    assert 'component_path' in {i['id'] for i in result['package_analysis']['format_findings']}
    findings = {i['id'] for e in result['files'] for i in e['findings']}
    assert {'literal_credential_declaration', 'insecure_component_transport', 'declared_process_launch', 'declared_execution_target'} <= findings
    assert all('do-not-display' not in item.get('value', '') for item in result['package_analysis']['dependencies'])


def test_frontmatter_hook_is_inventoried():
    result = scan({'demo/SKILL.md': skill('hooks:\n  Stop:\n    - command: python ./check.py.md\n'), 'demo/check.py.md': 'print("fixture")'})
    assert result['package_analysis']['execution_references'][0]['target'] == 'demo/check.py.md'


def test_coverage_inventory_binary_and_rejected_paths():
    result = scan({'demo/SKILL.md': skill(), 'demo/assets/logo.png': b'\x89PNG\r\n\x1a\n\x00binary', '../escape.md': 'fixture', 'demo/references/disguised.md': b'MZ\x00fixture'})
    assert result['coverage']['status'] == 'partial'
    assert len(result['inventory']) == 4
    assert result['coverage']['analyzed_files'] == 1
    assert result['governance_profile']['approval_required']
    assert result['readiness']['status'] == 'needs_review'
    logo = next(e for e in result['files'] if e['path'].endswith('logo.png'))
    assert logo['asset_inspection']['status'] == 'malformed'
    assert any(f['category'] == 'asset_structure' for f in logo['findings'])
    disguised = next(e for e in result['files'] if e['path'].endswith('disguised.md'))
    assert disguised['content_extension_mismatch']
    assert disguised['assessment_state'] == 'executable_not_analyzed'


def test_text_budget_does_not_claim_complete():
    result = scan_upload(b'x' * (1024 * 1024 + 1), 'large.txt')
    assert result['coverage']['status'] == 'partial'
    assert result['files'][0]['assessment_state'] == 'limited_or_truncated'


def test_24_checks_and_fingerprints_and_shared_backend_parity():
    from webapp.skill_scanner import scan_upload as web_scan
    data = archive({'demo/SKILL.md': skill()})
    result = scan_upload(data, 'fixture.zip')
    assert result == web_scan(data, 'fixture.zip')
    assert len(result['check_results']) == 24
    assert result['governance_evidence']['artifact_sha256'] == hashlib.sha256(data).hexdigest()
    assert result['inventory'][0]['sha256'] == hashlib.sha256(skill().encode()).hexdigest()
    assert result['governance_evidence']['evaluation']['status'] == 'not_assessed'


def envelope_for(data, key):
    now = datetime.now(timezone.utc)
    cases = [{'kind': kind, 'passed': True} for kind in ('positive_trigger', 'negative_trigger', 'coexistence', 'bounded_workflow')]
    payload = {'artifact_sha256': hashlib.sha256(data).hexdigest(), 'issued_at': (now-timedelta(minutes=1)).isoformat(),
               'expires_at': (now+timedelta(hours=1)).isoformat(), 'controls': {'evaluation': {'status': 'pass', 'cases': cases}, 'tenant_access': {'status': 'pass'}}}
    return {'issuer': 'test-reviewer', 'payload': payload, 'signature': hmac.new(bytes.fromhex(key), canonical_payload(payload), hashlib.sha256).hexdigest()}


def test_authenticated_evidence_and_tamper_rejection(tmp_path, monkeypatch):
    data = archive({'demo/SKILL.md': skill()})
    key = '11' * 32
    keys = tmp_path / 'keys.json'
    keys.write_text(json.dumps({'test-reviewer': key}))
    monkeypatch.setenv('INJECTICIDE_EVIDENCE_KEYS', str(keys))
    envelope = envelope_for(data, key)
    evidence = scan_upload(data, 'fixture.zip', governance_evidence={'envelope': envelope})['governance_evidence']
    assert evidence['evaluation']['status'] == 'passed_by_authenticated_issuer'
    assert evidence['evidence_authentication']['status'] == 'authenticated_issuer_assertion'
    envelope['payload']['controls']['evaluation']['cases'][0]['passed'] = False
    envelope['signature'] = hmac.new(bytes.fromhex(key), canonical_payload(envelope['payload']), hashlib.sha256).hexdigest()
    failed = scan_upload(data, 'fixture.zip', governance_evidence={'envelope': envelope})
    assert failed['readiness']['status'] == 'needs_review'
    assert failed['governance_profile']['brokered_tokens']['decision'] == 'require_further_analysis'
    envelope['payload']['artifact_sha256'] = 'wrong'
    evidence = scan_upload(data, 'fixture.zip', governance_evidence={'envelope': envelope})['governance_evidence']
    assert evidence['evaluation']['status'] == 'not_assessed'
    assert evidence['evidence_authentication']['status'] == 'not_verified'


@pytest.mark.parametrize('configured,outcome', [(False, 0), (True, 0), (True, 1), (True, 'timeout')])
def test_signature_verifier_uses_only_configured_program(tmp_path, monkeypatch, configured, outcome):
    calls = []
    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        if outcome == 'timeout':
            raise subprocess.TimeoutExpired(argv, 10)
        return subprocess.CompletedProcess(argv, outcome)
    monkeypatch.setattr('skill_sandbox.package_evidence.subprocess.run', run)
    monkeypatch.delenv('INJECTICIDE_OMS_VERIFIER', raising=False)
    monkeypatch.delenv('INJECTICIDE_OMS_TRUST_ANCHOR', raising=False)
    if configured:
        for key in ('VERIFIER', 'TRUST_ANCHOR'):
            path = tmp_path / key
            path.write_text('fixture')
            monkeypatch.setenv('INJECTICIDE_OMS_' + key, str(path))
    result = scan({'demo/SKILL.md': skill(), 'demo/skill.oms.sig': 'fixture'})['governance_evidence']['signature_verification']
    assert result['status'] == ('verified' if configured and outcome == 0 else 'not_verified')
    assert bool(calls) == configured
    if calls:
        assert calls[0][1]['timeout'] == 10
        assert calls[0][0][1:3] == ['verify', 'certificate']


def test_update_registry_and_unconfigured_evaluation(monkeypatch):
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    assert validate_update(root / 'docs/research/2026-10-19-skill-plugin-governance')['checks'] == 24
    monkeypatch.delenv('INJECTICIDE_EVALUATION_RUNNER', raising=False)
    with pytest.raises(ValueError, match='isolated evaluation runner'):
        evaluate('missing.zip')


def test_api_target_validation_and_busy_slot(monkeypatch):
    import skill_sandbox.app as sandbox
    client = TestClient(app)
    response = client.post('/scan', files={'file': ('SKILL.md', skill())}, data={'target_runtime': 'unknown'})
    assert response.status_code == 400
    sandbox.SCAN_SLOT.acquire()
    try:
        assert client.post('/scan', files={'file': ('SKILL.md', skill())}).status_code == 429
    finally:
        sandbox.SCAN_SLOT.release()
    assert client.post('/scan', files={'file': ('demo/SKILL.md', skill())}, data={'target_runtime': 'generic'}).status_code == 200


@pytest.mark.parametrize('mutation', ['expired', 'future', 'hash', 'signature', 'issuer'])
def test_invalid_evidence_never_authenticates(tmp_path, monkeypatch, mutation):
    from skill_sandbox.review_evidence import verify_envelope
    data = b'fixture'
    key = '22' * 32
    keys = tmp_path / 'keys.json'
    keys.write_text(json.dumps({'test-reviewer': key}))
    monkeypatch.setenv('INJECTICIDE_EVIDENCE_KEYS', str(keys))
    envelope = envelope_for(data, key)
    if mutation == 'expired':
        envelope['payload']['expires_at'] = '2020-01-01T00:00:00Z'
    elif mutation == 'future':
        envelope['payload']['issued_at'] = '2099-01-01T00:00:00Z'
    elif mutation == 'hash':
        envelope['payload']['artifact_sha256'] = 'wrong'
    elif mutation == 'issuer':
        envelope['issuer'] = 'untrusted'
    envelope['signature'] = hmac.new(bytes.fromhex(key), canonical_payload(envelope['payload']), hashlib.sha256).hexdigest()
    if mutation == 'signature':
        envelope['signature'] = '0' * 64
    assert verify_envelope(envelope, hashlib.sha256(data).hexdigest())['status'] == 'not_verified'


def test_unsigned_claims_are_not_trusted():
    data = archive({'demo/SKILL.md': skill()})
    result = scan_upload(data, 'fixture.zip', governance_evidence={'artifact_sha256': hashlib.sha256(data).hexdigest(), 'evaluation': {'status': 'pass'}, 'tenant_access': True})
    assert result['governance_evidence']['evaluation']['status'] == 'declared_unverified'
    assert not result['readiness']['tenant_policy_verified']


def test_explicit_evaluation_runner_contract(tmp_path, monkeypatch):
    runner = tmp_path / 'trusted-runner'
    runner.write_text('fixture')
    artifact = tmp_path / 'fixture.zip'
    artifact.write_bytes(b'fixture')
    monkeypatch.setenv('INJECTICIDE_EVALUATION_RUNNER', str(runner))
    def run(argv, **kwargs):
        from pathlib import Path
        assert argv[0] == str(runner)
        assert kwargs['shell'] is False and kwargs['timeout'] == 120
        Path(argv[argv.index('--output') + 1]).write_text(json.dumps({'status': 'pass', 'cases': [
            {'kind': kind, 'passed': True} for kind in ('positive_trigger', 'negative_trigger', 'coexistence', 'bounded_workflow')]}))
    monkeypatch.setattr('skill_sandbox.package_review.subprocess.run', run)
    assert evaluate(artifact)['status'] == 'runner_claim_requires_authenticated_issuer_envelope'


def test_web_api_forwards_profile_and_evidence(monkeypatch):
    import webapp.api as web
    class Response:
        status_code = 200
        def raise_for_status(self):
            pass
        def json(self):
            return {'forwarded': True}
    class Session:
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass
        def post(self, url, **kwargs):
            assert url == 'http://sandbox.internal/scan'
            assert kwargs['data'] == {'target_runtime': 'cursor', 'governance_evidence': '{}'}
            assert kwargs['files']['file'][0] == 'SKILL.md'
            return Response()
    monkeypatch.setattr(web.requests, 'Session', Session)
    monkeypatch.setenv('SKILL_SANDBOX_URL', 'http://sandbox.internal')
    client = TestClient(web.app)
    result = client.post('/api/skills/scan', files={'file': ('SKILL.md', skill())}, data={'target_runtime': 'cursor'}).json()
    assert result['forwarded'] is True
    assert result['vendor_verification']['verification'] == 'STATUS: UNKNOWN — UNVERIFIED'
    assert client.post('/api/skills/scan', files={'file': ('SKILL.md', skill())}, data={'governance_evidence': '[]'}).status_code == 400
    assert 'cursor' in client.get('/api/skills/profiles').json()['runtimes']


def test_structured_projection_is_partial():
    document = archive({'word/document.xml': '<document><text>Fixture</text></document>'})
    result = scan({'demo/SKILL.md': skill(), 'demo/references/document.docx': document})
    assert result['coverage']['status'] == 'partial'
    assert result['coverage']['states']['structured_content_analyzed'] == 1


def test_missing_manifest_metadata_and_invalid_schema_do_not_allow_execution():
    result = scan({'p/plugin.json': {'$schema': PLUGIN_SCHEMA, 'name': 42}})
    assert result['readiness']['status'] == 'needs_review'
    assert result['governance_profile']['brokered_tokens']['decision'] == 'require_further_analysis'


def test_portable_mcp_requires_schema_and_mcpb_identified():
    result = scan({'p/plugin.json': {'$schema': PLUGIN_SCHEMA, 'name': 'demo'}, 'p/mcp.json': {'mcpServers': {}}})
    assert any(i['id'] == 'manifest_schema' for i in result['package_analysis']['format_findings'])
    result = scan({'manifest.json': {'manifest_version': '0.3', 'name': 'demo', 'server': {'type': 'python', 'entry_point': 'server.py'}}, 'server.py': 'print("fixture")'})
    assert result['package_analysis']['packages'][0]['profile'] == 'mcpb'


def test_install_scripts_and_decode_references():
    result = scan({'p/package.json': {'scripts': {'postinstall': 'node ./install.js'}},
                   'p/install.js': 'console.log("fixture");', 'p/demo.md': 'base64 -d blob.txt > decoded.py', 'p/blob.txt': 'Zml4dHVyZQ=='})
    references = result['package_analysis']['execution_references']
    assert {'p/install.js', 'p/blob.txt'} <= {item['target'] for item in references}
    assert any(item['kind'] == 'package_script' for item in result['package_analysis']['components'])


def test_reference_budget_marks_coverage_partial():
    result = scan({'p/demo.md': '\n'.join('Run python script.py' for _ in range(70)), 'p/script.py': 'print("fixture")'})
    assert result['coverage']['status'] == 'partial'
    assert result['coverage']['component_inventory_limited']


def test_rejected_duplicate_cannot_replace_analysis_of_original():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as handle:
        handle.writestr('demo/check.py.md', 'print("fixture")')
        with pytest.warns(UserWarning):
            handle.writestr('demo/check.py.md', 'Duplicate excluded content')
    result = scan_upload(data.getvalue(), 'duplicate.zip')
    assert len(result['inventory']) == 2
    assert result['files'][0]['content_analysis']['code_like']
    assert 'code_in_text_artifact' in {f['id'] for f in result['files'][0]['findings']}


def test_user_apply_notes_double_fence_extraction_and_policy_signal():
    from pathlib import Path
    from skill_sandbox.package_threats import embedded_blocks
    document = (Path(__file__).parent / 'fixtures/package_snippets/apply_notes.py.md').read_text()
    result = scan({'demo/SKILL.md': skill(), 'demo/scripts/apply_notes.py.md': document})
    entry = next(e for e in result['files'] if e['path'].endswith('apply_notes.py.md'))
    assert entry['content_analysis']['code_like']
    assert entry['content_analysis']['language'] == 'python'
    assert entry['effective_artifact_role'] == 'execution_component'
    assert entry['file_type_policy']['potential_upload_control_bypass']
    assert not entry['file_type_policy']['organization_policy_verified']
    assert entry['file_type_policy']['malware_determination'] == 'not_established'
    assert {'code_in_text_artifact', 'executable_packaged_as_document', 'declared_execution_target'} <= {f['id'] for f in entry['findings']}
    references = result['package_analysis']['execution_references']
    assert any(r['kind'] == 'declared_fence_extraction' and r['target'] == entry['path'] and r['generated_target'] == 'demo/apply_notes.py' for r in references)
    assert any(r['kind'] == 'declared_interpreter_invocation' and r['target'] == entry['path'] and r.get('generated_target') == 'demo/apply_notes.py' for r in references)
    assert any('prs.save(pptx_path)' in block['text'] for block in embedded_blocks(document))
    assert result['governance_profile']['sandbox_required']


def test_ordinary_documentation_code_does_not_get_upload_bypass_label():
    result = scan({'demo/SKILL.md': skill(), 'demo/references/example.md': '```python\nprint("hello")\n```'})
    entry = next(e for e in result['files'] if e['path'].endswith('example.md'))
    assert 'file_type_policy' not in entry
    assert 'executable_packaged_as_document' not in {f['id'] for f in entry['findings']}


@pytest.mark.parametrize('extension,language,body', [
    ('js', 'javascript', 'console.log("fixture");'), ('ts', 'typescript', 'const marker: string = "fixture";'),
    ('sh', 'bash', 'printf "fixture\\n"'), ('ps1', 'powershell', 'Write-Output "fixture"'),
    ('rb', 'ruby', 'puts "fixture"'), ('pl', 'perl', 'print "fixture";'),
    ('php', 'php', '<?php echo "fixture";'), ('lua', 'lua', 'print("fixture")'),
    ('cmd', 'batch', '@echo off\necho fixture'), ('r', 'r', 'print("fixture")'),
])
def test_multiple_languages_behind_document_extension(extension, language, body):
    filename = f'demo/scripts/helper.{extension}.md'
    result = scan({'demo/SKILL.md': skill(), filename: f'```{language}\n{body}\n```\n'})
    entry = next(e for e in result['files'] if e['path'] == filename)
    assert entry['content_analysis']['code_like']
    assert entry['file_type_policy']['potential_upload_control_bypass']
    assert 'executable_packaged_as_document' in {f['id'] for f in entry['findings']}


@pytest.mark.parametrize('extension,language,runner', [('js', 'javascript', 'node'), ('sh', 'bash', 'bash'), ('ps1', 'powershell', 'pwsh -File'), ('rb', 'ruby', 'ruby'), ('pl', 'perl', 'perl'), ('php', 'php', 'php')])
def test_extraction_of_script_from_ordinary_named_document(extension, language, runner):
    document = (f"sed -n '/START/,/END/p' scripts/helper.me | sed '1d;$d' > helper.{extension}\n"
                f'{runner} helper.{extension}\n```{language}\nfixture_source\n```\n')
    result = scan({'demo/SKILL.md': skill(), 'demo/scripts/helper.me': document})
    entry = next(e for e in result['files'] if e['path'].endswith('helper.me'))
    assert entry['file_type_policy']['potential_upload_control_bypass']
    assert any(r['kind'] == 'declared_interpreter_invocation' and r.get('generated_target') == f'demo/helper.{extension}' for r in result['package_analysis']['execution_references'])


@pytest.mark.parametrize('body,language', [
    ('const fs = require("node:fs");\nconsole.log("fixture");', 'javascript'),
    ('$message = "fixture"\nWrite-Output $message', 'powershell'),
    ('<?php echo "fixture";', 'php'), ('@echo off\necho fixture', 'batch'),
    ('use strict;\nprint "fixture";', 'perl'), ('require "json"\nputs "fixture"', 'ruby'),
    ('#!/bin/sh\nprintf "fixture"', 'shebang'),
])
def test_script_syntax_in_unknown_extension(body, language):
    result = scan_upload(body.encode(), 'helper.me')
    entry = result['files'][0]
    assert entry['content_analysis']['language'] == language
    assert entry['file_type_policy']['potential_upload_control_bypass']
