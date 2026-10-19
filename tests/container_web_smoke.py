"""Run through the web image's Python entrypoint, with networking disabled."""
import io
import json
import zipfile
from fastapi.testclient import TestClient
from webapp.api import app


def main():
    data = io.BytesIO()
    with zipfile.ZipFile(data, 'w') as archive:
        archive.writestr('demo/SKILL.md', '---\nname: demo\ndescription: Fixture\n---\nSummarize text.')
        archive.writestr('demo/scripts/helper.ps1.md', '```powershell\nWrite-Output "fixture-only"\n```\n')
    client = TestClient(app)
    response = client.post('/api/skills/scan', files={'file': ('fixture.zip', data.getvalue())}, data={'target_runtime': 'generic'})
    assert response.status_code == 200, response.text
    result = response.json()
    assert len(result['check_results']) == 24
    assert result['package_analysis']['target_runtime'] == 'generic'
    assert result['summary']['upload_policy_review_files'] == 1
    assert client.get('/api/skills/profiles').status_code == 200
    print(json.dumps({'status': 'PASS', 'api_status': response.status_code, 'checks': len(result['check_results']), 'scanner': result['scanner_metadata']['scanner_version']}))


if __name__ == '__main__':
    main()
