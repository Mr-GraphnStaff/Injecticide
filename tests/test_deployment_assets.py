from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_deploys_only_after_validation() -> None:
    pipeline = yaml.safe_load((ROOT / "azure-pipelines.yml").read_text(encoding="utf-8"))

    assert [stage["stage"] for stage in pipeline["stages"]] == [
        "Validate",
        "DeployProduction",
    ]
    deployment = pipeline["stages"][1]
    assert deployment["dependsOn"] == "Validate"
    assert "refs/heads/master" in deployment["condition"]
    job = deployment["jobs"][0]
    assert job["environment"] == "injecticide-pi-production"
    assert job["pool"]["name"] == "Injecticide Pi Private"


def test_deploy_wrapper_restricts_source_and_commit() -> None:
    wrapper = (ROOT / "deploy" / "pi" / "injecticide-deploy").read_text(
        encoding="utf-8"
    )

    assert 'REMOTE_URL="https://github.com/Mr-GraphnStaff/Injecticide.git"' in wrapper
    assert "^[0-9a-f]{40}$" in wrapper
    assert "merge-base --is-ancestor" in wrapper
    assert "origin/master" in wrapper
    assert "down --remove-orphans" in wrapper
    assert "build --no-cache --pull" in wrapper
    assert "remove_injecticide_images" in wrapper
    assert "wait_for_health" in wrapper
    assert "Rolling back" in wrapper


def test_agent_sudo_rule_exposes_only_the_fixed_wrapper() -> None:
    rule = (ROOT / "deploy" / "pi" / "injecticide-deploy.sudoers").read_text(
        encoding="utf-8"
    )

    assert rule.strip() == (
        "azdo-injecticide ALL=(root) NOPASSWD: "
        "/usr/local/sbin/injecticide-deploy *"
    )


def test_reverse_proxy_accepts_skill_upload_limit() -> None:
    nginx_config = (ROOT / "nginx.conf").read_text(encoding="utf-8")

    assert "client_max_body_size 34m;" in nginx_config
