"""Execute the real Bash functions in conditional context with fake side effects."""
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
BASH = str(Path('C:/Program Files/Git/bin/bash.exe')) if os.name == 'nt' else shutil.which('bash')
pytestmark = pytest.mark.skipif(not BASH or not Path(BASH).is_file(), reason='Bash unavailable')


def run_functions(tmp_path, suffix, **environment):
    source = (ROOT / 'deploy/pi/injecticide-deploy').read_text(encoding='utf8')
    prefix = source.rsplit('\nmain "$@"', 1)[0]
    script = tmp_path / 'harness.sh'
    script.write_text(prefix + '\n' + suffix, encoding='utf8', newline='\n')
    return subprocess.run([BASH, str(script)], text=True, capture_output=True,
                          env={**os.environ, **environment}, check=False)


@pytest.mark.parametrize('failure', ['checkout','config','down','pull','remove','build','up','health'])
def test_critical_failure_cannot_be_hidden_by_later_success_inside_if(tmp_path, failure):
    trace = tmp_path / 'trace'
    result = run_functions(tmp_path, r'''
record() { printf '%s\n' "$1" >> "$TRACE"; [[ "$1" != "$FAIL_AT" ]]; }
git() { record checkout; }
compose() { record "$2"; }
remove_injecticide_images() { record remove; }
wait_for_health() { record health; }
if deploy_commit 1111111111111111111111111111111111111111; then
  exit 42
else
  exit 0
fi
''', TRACE=trace.as_posix(), FAIL_AT=failure)
    assert result.returncode == 0, result.stdout + result.stderr
    steps = ['checkout','config','down','pull','remove','build','up','health']
    assert trace.read_text().splitlines() == steps[:steps.index(failure)+1]


def test_failed_image_enumeration_is_not_a_successful_empty_list(tmp_path):
    result = run_functions(tmp_path, '''
docker() { return 9; }
if remove_injecticide_images; then exit 42; else exit 0; fi
''')
    assert result.returncode == 0, result.stdout + result.stderr


def test_healthy_web_page_does_not_hide_unhealthy_sandbox(tmp_path):
    result = run_functions(tmp_path, r'''
curl() { return 0; }
sleep() { return 0; }
docker() {
  if [[ "${@: -1}" == "injecticide-skill-sandbox" ]]; then
    printf 'restarting unhealthy\n'
  else
    printf 'running healthy\n'
  fi
}
if wait_for_health; then exit 42; else exit 0; fi
''')
    assert result.returncode == 0, result.stdout + result.stderr
