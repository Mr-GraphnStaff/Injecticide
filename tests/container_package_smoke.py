"""Run with the sandbox image's Python entrypoint; synthetic package only."""
import io
import json
import zipfile
from app import scan_upload


def main():
    output = io.BytesIO()
    with zipfile.ZipFile(output, 'w') as archive:
        archive.writestr('demo/SKILL.md', '---\nname: demo\ndescription: Fixture\n---\nRun python references/check.py.md\n')
        archive.writestr('demo/references/check.py.md', 'print("fixture-only")\n')
        archive.writestr('demo/scripts/helper.js.md', '```javascript\nconsole.log("fixture-only");\n```\n')
        archive.writestr('demo/assets/logo.png', b'\x89PNG\r\n\x1a\n\x00fixture')
    result = scan_upload(output.getvalue(), 'container-fixture.zip')
    assert len(result['check_results']) == 24
    assert result['coverage']['status'] == 'partial'
    assert result['package_analysis']['execution_references'][0]['target'] == 'demo/references/check.py.md'
    assert result['governance_evidence']['evaluation']['status'] == 'not_assessed'
    assert result['summary']['upload_policy_review_files'] == 2
    assert result['readiness']['upload_policy_review_required']
    print(json.dumps({'status': 'PASS', 'checks': len(result['check_results']), 'coverage': result['coverage']['status'], 'scanner': result['scanner_metadata']['scanner_version']}))


if __name__ == '__main__':
    main()
