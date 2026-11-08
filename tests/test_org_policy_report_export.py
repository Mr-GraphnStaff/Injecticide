"""Exercise the actual report formatter with hostile and legacy policy data."""
import json
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]


def test_policy_export_preserves_decisions_and_escapes_author_supplied_markup():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node is needed to exercise the browser report formatter")
    source = (ROOT / "webapp/static/app.js").read_text(encoding="utf-8")
    start = source.index("function formatOrganizationPolicyMarkdown(")
    end = source.index("function formatSkillScanMarkdown(", start)
    script = r"""
const assert = require('node:assert/strict');
const vm = require('node:vm');
let input = ''; process.stdin.setEncoding('utf8');
process.stdin.on('data', text => input += text);
process.stdin.on('end', () => {
    const ctx = { asArray: x => Array.isArray(x) ? x : [], Date };
    vm.createContext(ctx); vm.runInContext(JSON.parse(input), ctx);
    const hostile = '<script>alert(1)</script> [fake](https://example.invalid)';
    const report = {technical_verdict: {risk_classification: {recommendation:'block_by_default'}},
        organization_disposition:'allow',authority:'declared_unverified',evaluation_date:'2026-11-08',
        policy:{name:hostile,organization:'Synthetic',sha256:'a'.repeat(64),compiled_date:'2026-11-08'},
        exceptions_applied:[{rule_id:'R1',path:'ref.md',finding_id:'prompt_override',approver:'Named reviewer',rationale:'Documented example'}],
        residual_findings:[{path:'unread.db',id:'database_not_cleared'}],
        coverage_limits:[{path:'unread.db',status:'partial',accepted_by:[]}],
        deciding_rules:[{id:'R1',effect:'allow_exception'}],
        limits:['Not authenticated'],not_statically_checkable:[{requirement:'Runtime check'}]};
    const fixture = {filename:'fixture.skill',policy_evaluation:{status:'applied',organization_report:report,rules:[]}};
    const before = JSON.stringify(fixture);
    const markdown = ctx.formatOrganizationPolicyMarkdown(fixture,{display_version:'0.16.1'});
    for(const marker of ['block_by_default','allow','a'.repeat(64),'declared','Named reviewer','ref.md','unread.db','partial','Runtime check','scanner verdict']) {
        // Identifier punctuation is Markdown-escaped; test the resulting text.
        assert.ok(markdown.replace(/\\/g,'').includes(marker), marker);
    }
    assert.ok(markdown.includes('&lt;script&gt;'));
    assert.ok(!markdown.includes('<script>'));
    assert.ok(!markdown.includes('[fake](https://example.invalid)'));
    assert.equal(JSON.stringify(fixture),before,'formatting never changes scan evidence');
    const legacy = ctx.formatOrganizationPolicyMarkdown({policy_evaluation:{status:'applied',decision:'allow'}},{});
    assert.match(legacy,/Scan again/); assert.match(legacy,/No company acceptance/);
    report.fallback_reason='Policy rejected entirely'; report.errors=[{message:'Unknown finding'}];
    fixture.policy_evaluation.status='invalid';
    const invalid=ctx.formatOrganizationPolicyMarkdown(fixture,{});
    assert.match(invalid,/Policy not applied/);assert.match(invalid,/Unknown finding/);
});
"""
    completed = subprocess.run([node, "-e", script], input=json.dumps(source[start:end]), text=True,
                               capture_output=True, timeout=20)
    assert completed.returncode == 0, completed.stdout + completed.stderr
