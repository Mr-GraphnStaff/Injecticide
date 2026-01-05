"""
Injecticide Web Application - FastAPI Backend
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field, StrictInt
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json
import asyncio
from pathlib import Path
import sys
import os
import signal
import zipfile
import requests

# Add parent directory to path to import Injecticide modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core Injecticide modules
from reporter import ReportGenerator
from analyzer import analyze
from generator import policy_violation_payloads
from payloads import get_all_payloads
from endpoints_new import AnthropicEndpoint, OpenAIEndpoint, AzureOpenAIEndpoint
from webapp.config_loader import (
    get_endpoint_options,
    get_payload_presets,
    resolve_endpoint,
    resolve_payload_preset,
)
from webapp.skill_scanner import scan_upload, MAX_UPLOAD_BYTES

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

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

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

test_sessions = {}

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

@app.get("/")
async def root():
    static_file = STATIC_DIR / "index.html"
    if static_file.exists():
        return FileResponse(str(static_file))
    return {"message": "Injecticide API"}

@app.post("/api/skills/scan")
async def scan_skill_file(file: UploadFile = File(...)):
    if not file.filename:
        raise HTTPException(status_code=400, detail="Missing filename")

    sandbox_url = os.getenv("SKILL_SANDBOX_URL")
    sandbox_exts = (".skill", ".zip", ".tar", ".tar.gz", ".tgz")
    local_exts = (".skill", ".zip")
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

def _build_payloads_for_categories(categories, custom):
    payloads = []
    registry = get_all_payloads()

    for cat in categories:
        items = registry.get(cat) or (policy_violation_payloads() if cat == "policy" else [])
        payloads.extend([(p, cat) for p in items])

    payloads.extend([(c, "custom") for c in custom])
    return payloads

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
