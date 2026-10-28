"""Paired calibration regressions using authored synthetic content only."""
from skill_sandbox.app import scan_upload


def findings(text, path):
    return {f['id']: f for f in scan_upload(text.encode(), path)['files'][0]['findings']}


def test_named_contacts_and_account_ids_are_not_downgraded_by_reference_directory():
    text = ('# People\nAlice Example: alice.example@company.test\n'
            'Atlassian account ID: 12345678-1234-1234-1234-123456789abc\n')
    result = findings(text, 'jira-references/people.md')
    assert result['pii_email_address']['tier'] == 'review'
    assert result['pii_email_address']['action_state'] == 'present'
    assert result['pii_email_address']['display_kind'] == 'actionable_finding'
    assert result['pii_account_identifier']['tier'] == 'review'
    assert result['pii_account_identifier']['observations'][0]['line'] == 3


def test_role_alias_is_observable_syntax_not_public_or_approved():
    result = findings('Policy footer contact: security@company.test\n', 'policy.md')
    contact = result['pii_email_address']
    assert contact['tier'] == 'info'
    assert contact['action_state'] == 'present'
    assert contact['contact_context']['public_availability'] == 'unknown'
    assert contact['contact_context']['organizational_approval'] == 'not_verified'


def test_many_aliases_do_not_hide_later_named_contact():
    result = findings('security@company.test\n' * 1001 + 'alice.person@company.test\n', 'jira-references/people.md')
    contact = result['pii_email_address']
    assert contact['tier'] == 'review'
    assert contact['observations'][0]['line'] == 1002


def test_unlabeled_uuid_is_not_assumed_personal_account():
    assert 'pii_account_identifier' not in findings('Build revision 12345678-1234-1234-1234-123456789abc', 'build.md')


def test_changelog_api_mentions_preserve_exact_source_lines():
    text = ('last substantively authored.\n' + 'continuation\n' * 18
            + 'Fixed the `eval()/exec()` false positive.\n')
    finding = findings(text, 'CHANGELOG.md')['dynamic_exec']
    assert finding['tier'] == 'info'
    assert finding['action_state'] == 'mentioned'
    assert {o['line'] for o in finding['observations']} == {20}
    assert all('line 20:' in sample for sample in finding['samples'])


def test_active_dynamic_call_in_fence_is_still_reviewed_with_exact_line():
    text = '# Helper\n\n```python\nsource = input()\nresult = eval(source)\n```\n'
    finding = findings(text, 'helper.md')['dynamic_exec']
    assert finding['tier'] == 'review'
    assert finding['action_state'] != 'mentioned'
    assert finding['observations'][0]['line'] == 5


def test_python_empty_call_is_execution_syntax_not_prose():
    assert findings('eval()\n', 'helper.py')['dynamic_exec']['tier'] == 'review'


def test_html_viewer_is_capability_observation_not_disguised_upload():
    result = findings('<html><script>console.log("local QA");</script></html>', 'eval_review.html')
    assert 'executable_packaged_as_document' not in result
    assert 'code_in_text_artifact' not in result
    assert result['embedded_browser_script']['tier'] == 'info'
    assert result['embedded_browser_script']['finding_category'] == 'capability_observation'


def test_disguised_python_document_retains_review_without_asserted_bypass():
    result = findings('import os\ndef helper():\n    return 1\n', 'helper.py.md')
    finding = result['executable_packaged_as_document']
    assert finding['tier'] == 'review'
    assert 'actual policy bypass and malicious behavior are not established' in finding['description']

def test_inert_html_data_script_and_comment_do_not_claim_browser_execution():
    for text in ('<script type="application/json">{"value":1}</script>', '<!-- <script>alert(1)</script> -->'):
        assert 'embedded_browser_script' not in findings(text, 'viewer.html')


def test_alias_contact_presence_remains_visible_in_governance():
    report = scan_upload(b'security@company.test', 'policy.md')
    assert report['governance_profile']['data_observations']['contact_data_present']

def test_early_api_mentions_do_not_hide_later_active_fenced_call():
    text = 'Mention eval(), exec(), compile() in prose.\n\n```python\neval(input())\n```\n'
    result = findings(text, 'helper.md')['dynamic_exec']
    assert result['tier'] == 'review'
    assert result['action_state'] != 'mentioned'
    assert any(o['line'] == 4 and o['context_tag'] == 'direct_dynamic_exec' for o in result['observations'])


def test_early_api_mentions_do_not_hide_later_active_call_in_same_paragraph():
    result = findings('Mention eval(), exec(), compile(). Run eval(payload).', 'helper.md')['dynamic_exec']
    assert result['tier'] == 'review'
    assert any(o['context_tag'] == 'direct_dynamic_exec' for o in result['observations'])


def test_nonempty_api_calls_remain_reviewable_despite_changelog_context():
    result = findings('Fixed false positive for eval(source) and exec(code) in documentation.', 'CHANGELOG.md')['dynamic_exec']
    assert result['tier'] == 'review'


def test_personal_contact_review_controls_governance_but_alias_does_not():
    for text in ('Alice: alice.person@company.test', 'Account ID: 12345678-1234-1234-1234-123456789abc'):
        profile = scan_upload(text.encode(), 'jira-references/people.md')['governance_profile']
        assert profile['approval_required'] is True
        assert profile['execution_tier'] == 'governed'
        assert profile['brokered_tokens']['decision'] == 'require_admin_approval'
        assert profile['customer_managed_keys']['decision'] == 'require_admin_approval'
    profile = scan_upload(b'security@company.test', 'policy.md')['governance_profile']
    assert profile['approval_required'] is False
    assert profile['brokered_tokens']['decision'] == 'allow'

def test_false_positive_note_does_not_waive_execution_directives():
    for text in ('Fixed the false-positive: run eval(input()) now.',
                 'Fixed false-positive: execute exec(payload) to apply settings.'):
        assert findings(text, 'SKILL.md')['dynamic_exec']['tier'] == 'review'

def test_false_positive_context_does_not_waive_unbounded_command_vocabulary():
    for verb in ('use', 'apply', 'evaluate', 'dispatch', 'please perform'):
        text = f'Fixed false-positive: {verb} eval(payload) now.'
        assert findings(text, 'SKILL.md')['dynamic_exec']['tier'] == 'review'

def test_contact_evidence_stays_bounded_while_all_matches_are_counted():
    result = findings('security@company.test\n' * 30000 + 'alice.person@company.test\n', 'people.md')['pii_email_address']
    assert result['tier'] == 'review'
    assert result['count'] == 30001
    assert len(result['observations']) <= 10
    assert result['observations'][0]['line'] == 30001
    assert result['contact_context']['role_alias_matches'] == 30000
    assert result['contact_context']['individual_or_unknown_matches'] == 1
