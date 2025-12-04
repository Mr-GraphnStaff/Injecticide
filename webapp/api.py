"""
Injecticide Web Application - FastAPI Backend
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket
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

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

PAYLOAD_CATEGORY_METADATA = {
    "baseline": {
        "name": "Baseline Injections",
        "description": "Standard prompt injection tests",
    },
    "policy": {
        "name": "Policy Violations",
        "description": "Safety guardrail tests",
    },
    "extraction": {
        "name": "Data Extraction",
        "description": "Attempts to exfiltrate hidden or prior context",
    },
    "jailbreak": {
        "name": "Jailbreaks",
        "description": "Prompts that attempt to bypass core instructions",
    },
    "encoding": {
        "name": "Encoding & Obfuscation",
        "description": "Attacks that use encoding tricks to avoid filters",
    },
    "context": {
        "name": "Context Manipulation",
        "description": "Efforts to reorder, override, or poison conversation flow",
    },
    "roleplay": {
        "name": "Roleplay Attacks",
        "description": "Persona and scenario-based jailbreak prompts",
    },
    "insurance_us_ca": {
        "name": "Insurance (US/CA)",
        "description": "Industry-specific prompts for insurance workflows",
    },
}

app = FastAPI(
    title="Injecticide",
    description="LLM Security Testing Platform",
    version="2.0.0",
    docs_url="/api/docs"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory session storage
test_sessions = {}

# Request/Response Models
class TestRequest(BaseModel):
    target_service: str = Field(..., description="LLM service to test")
    api_key: Optional[str] = Field(None, description="API key for the service")
    model: Optional[str] = Field(None, description="Model to test")
    endpoint_url: Optional[str] = Field(None, description="Custom endpoint URL for Azure OpenAI")
    endpoint_name: Optional[str] = Field(None, description="Saved endpoint configuration name")
    payload_preset: Optional[str] = Field(None, description="Preset payload selection")
    test_categories: List[str] = Field(default=["baseline"])
    custom_payloads: List[str] = Field(default=[])
    max_requests: StrictInt = Field(..., gt=0, description="Maximum number of payloads to execute")
    delay_between_requests: float = Field(default=0.5, ge=0)

class TestSession(BaseModel):
    session_id: str
    status: str  # pending, running, completed, failed
    progress: int
    total_tests: int
    max_requests: int
    results: List[Dict[str, Any]]
    summary: Optional[Dict[str, Any]]
    created_at: datetime
    completed_at: Optional[datetime]
    endpoint_name: Optional[str] = None
    payload_preset: Optional[str] = None

# API Routes
@app.get("/")
async def root():
    """Serve the web interface"""
    static_file = STATIC_DIR / "index.html"
    if static_file.exists():
        return FileResponse(str(static_file))
    return {"message": "Injecticide API - Use /api/docs for documentation"}

@app.post("/api/test/start", response_model=TestSession)
async def start_test(request: TestRequest, background_tasks: BackgroundTasks):
    """Start a new security test session"""
    
    session_id = str(uuid.uuid4())
    session = TestSession(
        session_id=session_id,
        status="pending",
        progress=0,
        total_tests=0,
        max_requests=request.max_requests,
        results=[],
        summary=None,
        created_at=datetime.now(),
        completed_at=None
    )

    test_sessions[session_id] = jsonable_encoder(session)
    
    # Run test in background
    background_tasks.add_task(run_test_session, session_id, request)

    print(f"[Session {session_id}] Starting with max_requests={request.max_requests}")
    
    return session

@app.get("/api/test/{session_id}", response_model=TestSession)
async def get_test_status(session_id: str):
    """Get the status of a test session"""
    
    if session_id not in test_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return TestSession(**test_sessions[session_id])

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket for real-time test updates"""
    
    await websocket.accept()
    
    if session_id not in test_sessions:
        await websocket.send_json({"error": "Session not found"})
        await websocket.close()
        return
    
    # Send updates while test is running
    try:
        while test_sessions[session_id]["status"] in ["pending", "running"]:
            await websocket.send_json(test_sessions[session_id])
            await asyncio.sleep(1)
        
        # Send final result
        await websocket.send_json(test_sessions[session_id])
    except Exception as e:
        print(f"WebSocket error: {e}")
    finally:
        await websocket.close()

@app.get("/api/test/{session_id}/report")
async def download_report(session_id: str, format: str = "html"):
    """Download test report"""
    
    if session_id not in test_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = test_sessions[session_id]
    
    if session["status"] != "completed":
        raise HTTPException(status_code=400, detail="Test not completed")
    
    # Generate report
    config = {
        "target_service": session.get("target_service", "unknown"),
        "model": session.get("model", "unknown")
    }
    generator = ReportGenerator(session["results"], config)
    
    report = generator.generate(format=format)
    
    if format == "html":
        return HTMLResponse(content=report)
    elif format == "json":
        return JSONResponse(content=json.loads(report))
    else:
        return {"content": report, "format": format}


@app.get("/api/config/options")
async def get_ui_options():
    """Provide endpoint and payload preset options for the frontend."""

    return {
        "endpoints": get_endpoint_options(),
        "payload_presets": get_payload_presets(),
    }

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

@app.post("/api/analyze")
async def analyze_response(payload: Dict[str, str]):
    """Analyze text for injection indicators"""
    
    text = payload.get("text", "")
    flags = analyze(text)
    return {
        "text": text,
        "flags": flags,
        "detected": any(flags.values())
    }


async def _shutdown_server():
    """Request a graceful shutdown of the running Uvicorn server."""

    # Give the response a chance to flush before stopping the process
    await asyncio.sleep(0.1)
    os.kill(os.getpid(), signal.SIGINT)


@app.post("/api/app/close")
async def close_application():
    """Schedule a graceful shutdown so the frontend can stop the app safely."""

    asyncio.create_task(_shutdown_server())
    return {"status": "shutting_down"}


def _build_payloads_for_categories(selected_categories: List[str], custom_payloads: List[str]):
    payload_registry = get_all_payloads()
    payloads = []

    for category in selected_categories:
        available_payloads = payload_registry.get(category)

        if not available_payloads and category == "policy":
            available_payloads = policy_violation_payloads()

        if not available_payloads:
            print(f"[Payloads] Skipping unknown category: {category}")
            continue

        payloads.extend([(payload, category) for payload in available_payloads])

    for custom in custom_payloads:
        payloads.append((custom, "custom"))

    return payloads


# Background task to run tests
async def run_test_session(session_id: str, request: TestRequest):
    """Run the actual test session"""

    session = test_sessions[session_id]
    session["status"] = "running"
    session["target_service"] = request.target_service
    session["model"] = request.model
    session["endpoint_name"] = request.endpoint_name
    session["payload_preset"] = request.payload_preset

    try:
        selected_endpoint = resolve_endpoint(request.endpoint_name)
        target_service = selected_endpoint.get("target_service", request.target_service) if selected_endpoint else request.target_service
        api_key = request.api_key or (selected_endpoint.get("api_key") if selected_endpoint else None)
        model = request.model or (selected_endpoint.get("model") if selected_endpoint else None)
        endpoint_url = request.endpoint_url or (selected_endpoint.get("endpoint_url") if selected_endpoint else None)

        if not api_key:
            raise ValueError("No API key provided for the selected endpoint")

        session["target_service"] = target_service
        session["model"] = model
        session["endpoint_name"] = request.endpoint_name

        payload_preset = resolve_payload_preset(request.payload_preset)
        test_categories = request.test_categories
        custom_payloads = list(request.custom_payloads)

        if payload_preset:
            if payload_preset.get("test_categories"):
                test_categories = payload_preset["test_categories"]
            if payload_preset.get("custom_payloads"):
                custom_payloads = payload_preset["custom_payloads"] + custom_payloads

        if not test_categories:
            raise ValueError("No test categories selected for execution")

        # Build endpoint
        if target_service == "anthropic":
            endpoint = AnthropicEndpoint(
                api_key=api_key,
                model=model or "claude-3-opus-20240229"
            )
        elif target_service == "openai":
            endpoint = OpenAIEndpoint(
                api_key=api_key,
                model=model or "gpt-4"
            )
        elif target_service == "azure_openai":
            # Azure needs endpoint URL - should be passed in request
            endpoint = AzureOpenAIEndpoint(
                api_key=api_key,
                endpoint=endpoint_url or "https://your-resource.openai.azure.com",
                deployment_name=model or "gpt-4"
            )
        else:
            raise ValueError(f"Unsupported service: {target_service}")

        # Gather payloads
        unique_categories = list(dict.fromkeys(test_categories))
        payloads = _build_payloads_for_categories(unique_categories, custom_payloads)

        enforced_max_requests = request.max_requests
        session["max_requests"] = enforced_max_requests
        print(
            f"[Session {session_id}] Enforcing max_requests={enforced_max_requests} across {len(payloads)} payloads"
        )

        session["total_tests"] = min(len(payloads), enforced_max_requests)

        # Run tests
        results = []
        for i, (payload, category) in enumerate(payloads[:enforced_max_requests]):
            if request.delay_between_requests > 0:
                await asyncio.sleep(request.delay_between_requests)
            
            try:
                # Run synchronously in thread pool to avoid blocking
                response = await asyncio.get_event_loop().run_in_executor(
                    None, endpoint.send, payload
                )
                flags = analyze(response)
                
                result = {
                    "payload": payload,
                    "category": category,
                    "flags": flags,
                    "response_preview": str(response)[:200],
                    "detected": any(flags.values()),
                    "timestamp": datetime.now().isoformat()
                }
                
                results.append(result)
                session["results"] = results
                session["progress"] = i + 1
                
            except Exception as e:
                results.append({
                    "payload": payload,
                    "category": category,
                    "error": str(e),
                    "flags": {},
                    "detected": False
                })
                session["results"] = results
                session["progress"] = i + 1
        
        # Generate summary
        total = len(results)
        detections = sum(1 for r in results if r.get("detected"))
        
        session["summary"] = {
            "total_tests": total,
            "vulnerabilities_detected": detections,
            "detection_rate": f"{(detections/total*100):.1f}%" if total > 0 else "0%",
            "categories_tested": list(set(r["category"] for r in results))
        }
        
        session["status"] = "completed"
        session["completed_at"] = datetime.now().isoformat()
        
    except Exception as e:
        session["status"] = "failed"
        session["summary"] = {"error": str(e)}
        print(f"Test session error: {e}")

# Serve static files and branding assets
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.mount("/images", StaticFiles(directory=str(STATIC_DIR / "images")), name="images")
    app.mount("/icons", StaticFiles(directory=str(STATIC_DIR / "icons")), name="icons")

if __name__ == "__main__":
    import uvicorn
    print("Starting Injecticide Web Server...")
    print("Web UI: http://localhost:8000")
    print("API Docs: http://localhost:8000/api/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
