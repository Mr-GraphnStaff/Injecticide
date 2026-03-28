"""
Injecticide Web Application - FastAPI Backend
"""

from fastapi import FastAPI, HTTPException, WebSocket, UploadFile, File
from fastapi.websockets import WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, StrictInt
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import asyncio
import time
from pathlib import Path
import subprocess
import sys
import os
import signal
import zipfile
import requests
import logging
import tomllib
from functools import lru_cache

# Add parent directory to path to import Injecticide modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core Injecticide modules
from analyzer import analyze
from endpoints import create_endpoint
from generator import build_payload_suite
from payloads import get_all_payloads
from reporter import ReportGenerator, build_summary
from webapp.config_loader import (
    get_endpoint_options,
    get_payload_presets,
    resolve_endpoint,
    resolve_payload_preset,
)
from webapp.skill_scanner import scan_upload, MAX_UPLOAD_BYTES

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
PROJECT_ROOT = BASE_DIR.parent

PAYLOAD_CATEGORY_METADATA = {
    "baseline": {"name": "Baseline Injections", "description": "Standard prompt injection tests"},
    "policy": {"name": "Policy Violations", "description": "Safety guardrail tests"},
    "extraction": {"name": "Data Extraction", "description": "Attempts to exfiltrate hidden or prior context"},
    "jailbreak": {"name": "Jailbreaks", "description": "Prompts that attempt to bypass core instructions"},
    "encoding": {"name": "Encoding & Obfuscation", "description": "Attacks that use encoding tricks to avoid filters"},
    "context": {"name": "Context Manipulation", "description": "Efforts to reorder, override, or poison conversation flow"},
    "roleplay": {"name": "Roleplay Attacks", "description": "Persona and scenario-based jailbreak prompts"},
    "insurance_us_ca": {"name": "Insurance (US/CA)", "description": "Industry-specific prompts for insurance workflows"},
    "esf": {
        "name": "Epistemic Stress Framework (ESF)",
        "description": "Probes that test uncertainty handling, contradiction resolution, and epistemic integrity",
    },
}

app = FastAPI(
    title="Injecticide",
    description="LLM Security Testing Platform",
    version="2.0.0",
    docs_url="/api/docs",
)

logger = logging.getLogger("injecticide.webapp")
if not logger.handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@lru_cache(maxsize=1)
def get_build_info() -> Dict[str, str]:
    package_version = "unknown"
    pyproject_path = PROJECT_ROOT / "pyproject.toml"
    if pyproject_path.exists():
        with pyproject_path.open("rb") as handle:
            package_version = tomllib.load(handle).get("project", {}).get("version", "unknown")

    git_commit = "unknown"
    git_dirty = False
    try:
        git_commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=PROJECT_ROOT,
            text=True,
        ).strip()
        git_dirty = bool(
            subprocess.check_output(
                ["git", "status", "--porcelain"],
                cwd=PROJECT_ROOT,
                text=True,
            ).strip()
        )
    except Exception:
        pass

    asset_version = _get_asset_version()

    return {
        "app_version": app.version,
        "package_version": package_version,
        "git_commit": git_commit,
        "git_dirty": git_dirty,
        "asset_version": asset_version,
        "display_version": f"{app.version} ({git_commit})" if git_commit != "unknown" else app.version,
    }


def _get_asset_version() -> str:
    asset_paths = [
        STATIC_DIR / "index.html",
        STATIC_DIR / "app.js",
        STATIC_DIR / "pages" / "Home.jsx",
    ]
    mtimes = [int(path.stat().st_mtime) for path in asset_paths if path.exists()]
    if not mtimes:
        return app.version
    return str(max(mtimes))

test_sessions = {}
session_connections = {}


class TestStartRequest(BaseModel):
    target_service: str = Field(..., min_length=1)
    api_key: Optional[str] = None
    model: Optional[str] = None
    endpoint_url: Optional[str] = None
    endpoint_name: Optional[str] = None
    payload_preset: Optional[str] = None
    test_categories: List[str] = Field(default_factory=list)
    custom_payloads: List[str] = Field(default_factory=list)
    max_requests: StrictInt = Field(default=50, gt=0)
    delay_between_requests: float = Field(default=0.0, ge=0.0)
    requests_per_minute: StrictInt = Field(default=60, gt=0)
    requests_per_hour: StrictInt = Field(default=1000, gt=0)


def _resolve_test_config(request: TestStartRequest) -> Dict[str, Any]:
    endpoint_config = resolve_endpoint(request.endpoint_name)
    preset_config = resolve_payload_preset(request.payload_preset)

    config = request.model_dump()

    if endpoint_config:
        config["target_service"] = endpoint_config.get("target_service") or config["target_service"]
        config["model"] = endpoint_config.get("model") or config.get("model")
        config["endpoint_url"] = endpoint_config.get("endpoint_url") or config.get("endpoint_url")
        config["api_key"] = config.get("api_key") or endpoint_config.get("api_key")

    if preset_config:
        preset_categories = preset_config.get("test_categories") or []
        preset_custom = preset_config.get("custom_payloads") or []
        if preset_categories:
            config["test_categories"] = preset_categories
        if preset_custom:
            config["custom_payloads"] = preset_custom + config.get("custom_payloads", [])

    if not config.get("api_key"):
        raise HTTPException(status_code=400, detail="API key required for selected endpoint")

    if not config.get("test_categories"):
        raise HTTPException(status_code=400, detail="At least one payload category is required")

    return config


def _build_sender(config: Dict[str, Any]):
    try:
        endpoint = create_endpoint(
            config["target_service"],
            api_key=config["api_key"],
            model=config.get("model"),
            endpoint_url=config.get("endpoint_url"),
            requests_per_minute=config.get("requests_per_minute", 60),
            requests_per_hour=config.get("requests_per_hour", 1000),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    delay = config.get("delay_between_requests", 0)

    def send(payload: str) -> str:
        if delay:
            time.sleep(delay)
        return endpoint.send_with_rate_limit(payload)

    return send


def _session_view(session: Dict[str, Any]) -> Dict[str, Any]:
    view = dict(session)
    results = list(session.get("results", []))
    view["results"] = results
    view["total_tests"] = session.get("total_payloads", 0)
    view["progress"] = session.get("completed_payloads", 0)
    view["summary"] = build_summary(results)
    return view


async def _broadcast_session_update(session_id: str) -> None:
    session = test_sessions.get(session_id)
    if not session:
        return
    payload = jsonable_encoder(_session_view(session))
    connections = list(session_connections.get(session_id, set()))
    for websocket in connections:
        try:
            await websocket.send_json(payload)
        except Exception as exc:
            logger.warning("WebSocket send failed for session %s: %s", session_id, exc)
            session_connections.get(session_id, set()).discard(websocket)


async def _run_test_session(session_id: str, config: Dict[str, Any]) -> None:
    session = test_sessions[session_id]
    session["status"] = "running"
    session["started_at"] = datetime.utcnow().isoformat()
    await _broadcast_session_update(session_id)

    logger.info(
        "Session %s starting: service=%s categories=%s max_requests=%s",
        session_id,
        config.get("target_service"),
        config.get("test_categories"),
        config.get("max_requests"),
    )

    try:
        send_fn = _build_sender(config)
        payloads = build_payload_suite(
            config.get("test_categories", []),
            config.get("custom_payloads", []),
        )

        session["total_payloads"] = len(payloads)

        for index, (payload, category) in enumerate(payloads):
            if session.get("cancel_requested"):
                logger.info("Session %s cancellation requested", session_id)
                session["status"] = "cancelled"
                break

            if index >= config.get("max_requests", len(payloads)):
                logger.info("Session %s reached max requests", session_id)
                break

            try:
                response = send_fn(payload)
                flags = analyze(response)
                result = {
                    "payload": payload,
                    "category": category,
                    "flags": flags,
                    "response_length": len(str(response)),
                    "detected": any(flags.values()),
                }
            except Exception as exc:
                logger.exception("Session %s payload failed", session_id)
                result = {
                    "payload": payload,
                    "category": category,
                    "flags": {},
                    "detected": False,
                    "error": str(exc),
                }

            session["results"].append(result)
            session["completed_payloads"] = len(session["results"])
            await _broadcast_session_update(session_id)

    except Exception as exc:
        logger.exception("Session %s failed to execute", session_id)
        session["status"] = "failed"
        session["error"] = str(exc)
    else:
        if session.get("status") != "cancelled":
            session["status"] = "completed"
    finally:
        session["completed_at"] = datetime.utcnow().isoformat()
        await _broadcast_session_update(session_id)
        logger.info("Session %s finished with status %s", session_id, session["status"])

# ----------------------------
# CONFIG OPTIONS ENDPOINT
# ----------------------------
@app.get("/api/config/options")
async def get_config_options():
    """Provide saved endpoint and payload preset options for the UI."""

    return {
        "endpoints": get_endpoint_options(),
        "payload_presets": get_payload_presets(),
    }


@app.get("/api/app/version")
async def get_app_version():
    """Return visible build/version info for the UI."""

    return get_build_info()

# ----------------------------
# RESTORED ENDPOINT (THE FIX)
# ----------------------------
@app.get("/api/payloads")
async def get_available_payloads():
    """Get list of available payload categories"""

    def _format_category(category_id: str, payloads: List[str]):
        meta = PAYLOAD_CATEGORY_METADATA.get(category_id, {})
        return {
            "id": category_id,
            "name": meta.get("name", category_id.replace("_", " ").title()),
            "description": meta.get("description", "Payload collection"),
            "count": len(payloads),
            "examples": payloads[:3] if payloads else [],
        }

    categories = []
    payload_registry = get_all_payloads()

    for category_id, payloads in payload_registry.items():
        categories.append(_format_category(category_id, payloads))

    return {"categories": categories}

# ----------------------------

@app.post("/api/test/start")
async def start_test(request: TestStartRequest):
    """Start a test session and return its session data."""

    config = _resolve_test_config(request)
    session_id = str(uuid.uuid4())

    session = {
        "session_id": session_id,
        "status": "queued",
        "cancel_requested": False,
        "created_at": datetime.utcnow().isoformat(),
        "completed_at": None,
        "started_at": None,
        "total_payloads": 0,
        "completed_payloads": 0,
        "results": [],
        "config": {
            "target_service": config.get("target_service"),
            "model": config.get("model"),
            "endpoint_name": config.get("endpoint_name"),
            "payload_preset": config.get("payload_preset"),
            "test_categories": config.get("test_categories"),
            "custom_payloads": config.get("custom_payloads"),
            "max_requests": config.get("max_requests"),
            "delay_between_requests": config.get("delay_between_requests"),
            "requests_per_minute": config.get("requests_per_minute"),
            "requests_per_hour": config.get("requests_per_hour"),
        },
    }

    test_sessions[session_id] = session
    session_connections.setdefault(session_id, set())

    logger.info("Session %s queued", session_id)
    asyncio.create_task(_run_test_session(session_id, config))
    return _session_view(session)


@app.websocket("/ws/{session_id}")
async def session_updates(websocket: WebSocket, session_id: str):
    await websocket.accept()
    session_connections.setdefault(session_id, set()).add(websocket)
    logger.info("WebSocket connected for session %s", session_id)

    if session_id in test_sessions:
        await websocket.send_json(jsonable_encoder(_session_view(test_sessions[session_id])))

    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("WebSocket disconnected for session %s", session_id)
    finally:
        session_connections.get(session_id, set()).discard(websocket)


@app.get("/api/test/{session_id}/report")
async def get_report(session_id: str, format: str = "html"):
    session = test_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Test session not found")

    report_config = {
        "target_service": session.get("config", {}).get("target_service"),
        "model": session.get("config", {}).get("model"),
        "payload_categories": session.get("config", {}).get("test_categories", []),
    }

    generator = ReportGenerator(session.get("results", []), report_config)
    try:
        content = generator.generate(format)
    except ValueError:
        raise HTTPException(status_code=400, detail="Unsupported report format")

    media_type = {
        "html": "text/html",
        "json": "application/json",
        "csv": "text/csv",
    }[format]

    filename = f"injecticide-report-{session_id}.{format}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return Response(content=content, media_type=media_type, headers=headers)


@app.post("/api/test/{session_id}/cancel")
async def cancel_test(session_id: str):
    session = test_sessions.get(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Test session not found")

    if session["status"] in {"completed", "failed", "cancelled"}:
        return _session_view(session)

    session["cancel_requested"] = True
    session["status"] = "cancelling"
    await _broadcast_session_update(session_id)
    return _session_view(session)


@app.get("/")
async def root():
    static_file = STATIC_DIR / "index.html"
    if static_file.exists():
        build_info = get_build_info()
        asset_version = build_info.get("asset_version", app.version)
        html = static_file.read_text(encoding="utf-8")
        html = html.replace("/static/pages/Home.jsx", f"/static/pages/Home.jsx?v={asset_version}")
        html = html.replace("/static/app.js", f"/static/app.js?v={asset_version}")
        return HTMLResponse(content=html, headers={"Cache-Control": "no-store"})
    return {"message": "Injecticide API"}

@app.post("/api/skills/scan")
async def scan_skill_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    sandbox_url = os.getenv("SKILL_SANDBOX_URL")
    sandbox_exts = (".skill", ".zip", ".md", ".tar", ".tar.gz", ".tgz")
    local_exts = (".skill", ".zip", ".md")
    allowed = sandbox_exts if sandbox_url else local_exts

    if not file.filename.lower().endswith(allowed):
        raise HTTPException(status_code=400, detail="Unsupported file type")

    try:
        data = await file.read()
        if len(data) > MAX_UPLOAD_BYTES:
            raise ValueError("Upload exceeds size limit")

        if sandbox_url:
            r = requests.post(
                f"{sandbox_url.rstrip('/')}/scan",
                files={"file": (file.filename, data, file.content_type)},
                timeout=(5, 30),
            )
            r.raise_for_status()
            return r.json()
        else:
            return scan_upload(data, file.filename)

    except requests.RequestException:
        raise HTTPException(status_code=502, detail="Skill sandbox unavailable")
    except zipfile.BadZipFile:
        raise HTTPException(status_code=400, detail="Invalid zip archive")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

async def _shutdown_server():
    await asyncio.sleep(0.1)
    os.kill(os.getpid(), signal.SIGINT)

@app.post("/api/app/close")
async def close_application():
    asyncio.create_task(_shutdown_server())
    return {"status": "shutting_down"}

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
