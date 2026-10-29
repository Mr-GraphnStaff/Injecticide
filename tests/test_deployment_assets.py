from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_deploys_only_after_validation() -> None:
    pipeline = yaml.safe_load((ROOT / "azure-pipelines.yml").read_text(encoding="utf-8"))

    assert [stage["stage"] for stage in pipeline["stages"]] == [
        "Validate",
        "QualifyAutomatic",
        "DeployAutomatic",
        "DeployProduction",
        "ObsessionDaily",
    ]
    deployment = next(stage for stage in pipeline["stages"] if stage["stage"] == "DeployProduction")
    assert deployment["dependsOn"] == ["Validate", "QualifyAutomatic"]
    assert "dependencies.Validate.result, 'Succeeded'" in deployment["condition"]
    assert "eligibility.eligible'], 'false'" in deployment["condition"]
    assert "refs/heads/master" in deployment["condition"]
    job = deployment["jobs"][0]
    assert job["environment"] == "injecticide-pi-production"
    assert job["pool"]["name"] == "Injecticide Pi Private"

    checks = pipeline["stages"][0]["jobs"][0]["steps"]
    names = [step.get("displayName", "") for step in checks]
    smoke = next(i for i, name in enumerate(names) if "packaged scanner" in name.lower() or "scanner image" in name.lower())
    assert names.index("Build container candidates") < smoke
    script = checks[smoke].get("script", checks[smoke].get("bash", ""))
    assert "docker run" in script and "--network none" in script
    assert "--read-only" in script and "scan_upload" in script


def test_automatic_delivery_requalifies_sha_and_schedule_uses_existing_pi():
    pipeline = yaml.safe_load((ROOT / "azure-pipelines.yml").read_text(encoding="utf-8"))
    stages = {stage["stage"]: stage for stage in pipeline["stages"]}
    automatic = stages["DeployAutomatic"]
    assert automatic["dependsOn"] == ["Validate", "QualifyAutomatic"]
    assert "eligibility.qualified_sha'], variables['Build.SourceVersion']" in automatic["condition"]
    assert "eligibility.eligible'], 'true'" in automatic["condition"]
    script = automatic["jobs"][0]["steps"][-1]["bash"]
    assert "qualify-commit --require-eligible" in script
    assert 'injecticide-deploy "${BUILD_SOURCEVERSION}"' in script
    daily = stages["ObsessionDaily"]
    assert "Build.Reason'], 'Schedule'" in daily["condition"]
    assert daily["jobs"][0]["pool"]["name"] == "Injecticide Pi Private"
    assert pipeline["schedules"][0]["always"] is True
    assert pipeline["schedules"][0]["cron"] == "0 11 * * *"


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


def test_all_injecticide_services_have_bounded_logs() -> None:
    config = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    for name in ("injecticide", "skill_sandbox", "nginx"):
        logging = config["services"][name]["logging"]
        assert logging["driver"] == "json-file"
        assert logging["options"] == {"max-size": "10m", "max-file": "3"}
