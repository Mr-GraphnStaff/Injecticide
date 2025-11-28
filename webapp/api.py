"""
Injecticide Web Application - API Routes
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json
import asyncio
import time
from pathlib import Path

# Import core Injecticide modules
import sys
sys.path.append('..')
from config import TestConfig
from reporter import ReportGenerator
from analyzer import analyze
from generator import generate_payloads, policy_violation_payloads
from endpoints import AnthropicEndpoint, OpenAIEndpoint

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

# In-memory session storage (use Redis in production)
test_sessions = {}

# Request/Response Models
class TestRequest(BaseModel):
    target_service: str = Field(..., description="LLM service to test (anthropic, openai, azure_openai)")
    api_key: str = Field(..., description="API key for the service")
    model: Optional[str] = Field(None, description="Model to test")
    test_categories: List[str] = Field(default=["baseline"], description="Test categories to run")
    custom_payloads: List[str] = Field(default=[], description="Custom payloads to test")
    max_requests: int = Field(default=50, description="Maximum number of tests")
    delay_between_requests: float = Field(default=0.5, description="Delay between requests in seconds")

class TestSession(BaseModel):
    session_id: str
    status: str  # pending, running, completed, failed
    progress: int
    total_tests: int
    results: List[Dict[str, Any]]
    summary: Optional[Dict[str, Any]]
    created_at: datetime
    completed_at: Optional[datetime]

# API Routes
@app.get("/")
async def root():
    """Serve the web interface"""
    return FileResponse("webapp/static/index.html")

@app.post("/api/test/start", response_model=TestSession)
async def start_test(request: TestRequest, background_tasks: BackgroundTasks):
    """Start a new security test session"""
    
    session_id = str(uuid.uuid4())
    session = TestSession(
        session_id=session_id,
        status="pending",
        progress=0,
        total_tests=0,
        results=[],
        summary=None,
        created_at=datetime.now(),
        completed_at=None
    )
    
    test_sessions[session_id] = session
    
    # Run test in background
    background_tasks.add_task(run_test_session, session_id, request)
    
    return session

@app.get("/api/test/{session_id}", response_model=TestSession)
async def get_test_status(session_id: str):
    """Get the status of a test session"""
    
    if session_id not in test_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    return test_sessions[session_id]

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket for real-time test updates"""
    
    await websocket.accept()
    
    if session_id not in test_sessions:
        await websocket.send_json({"error": "Session not found"})
        await websocket.close()
        return
    
    # Send updates every second while test is running
    while test_sessions[session_id].status == "running":
        await websocket.send_json(jsonable_encoder(test_sessions[session_id]))
        await asyncio.sleep(1)

    # Send final result
    await websocket.send_json(jsonable_encoder(test_sessions[session_id]))
    await websocket.close()

@app.get("/api/test/{session_id}/report")
async def download_report(session_id: str, format: str = "html"):
    """Download test report"""
    
    if session_id not in test_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = test_sessions[session_id]
    
    if session.status != "completed":
        raise HTTPException(status_code=400, detail="Test not completed")
    
    # Generate report
    config = {"target_service": "unknown", "model": "unknown"}  # Get from session
    generator = ReportGenerator(session.results, config)
    
    report = generator.generate(format=format)
    
    if format == "html":
        return HTMLResponse(content=report)
    elif format == "json":
        return JSONResponse(content=json.loads(report))
    else:
        return {"content": report, "format": format}

@app.get("/api/payloads")
async def get_available_payloads():
    """Get list of available payload categories and examples"""
    
    return {
        "categories": {
            "baseline": {
                "name": "Baseline Injections",
                "description": "Standard prompt injection tests",
                "count": len(generate_payloads()),
                "examples": generate_payloads()[:3]
            },
            "policy": {
                "name": "Policy Violations",
                "description": "Tests for policy enforcement",
                "count": len(policy_violation_payloads()),
                "examples": policy_violation_payloads()[:3]
            }
        }
    }

@app.post("/api/analyze")
async def analyze_response(text: str):
    """Analyze a text response for injection indicators"""
    
    flags = analyze(text)
    return {
        "text": text,
        "flags": flags,
        "detected": any(flags.values())
    }

# Background task to run tests
async def run_test_session(session_id: str, request: TestRequest):
    """Run the actual test session"""
    
    session = test_sessions[session_id]
    session.status = "running"
    
    try:
        # Build endpoint
        if request.target_service == "anthropic":
            endpoint = AnthropicEndpoint(
                api_key=request.api_key,
                model=request.model or "claude-3-opus-20240229"
            )
        elif request.target_service == "openai":
            endpoint = OpenAIEndpoint(
                api_key=request.api_key,
                model=request.model or "gpt-4"
            )
        else:
            raise ValueError(f"Unsupported service: {request.target_service}")
        
        # Gather payloads
        payloads = []
        if "baseline" in request.test_categories:
            payloads.extend([(p, "baseline") for p in generate_payloads()])
        if "policy" in request.test_categories:
            payloads.extend([(p, "policy") for p in policy_violation_payloads()])
        
        for custom in request.custom_payloads:
            payloads.append((custom, "custom"))
        
        session.total_tests = min(len(payloads), request.max_requests)
        
        # Run tests
        for i, (payload, category) in enumerate(payloads[:request.max_requests]):
            if request.delay_between_requests > 0:
                await asyncio.sleep(request.delay_between_requests)
            
            try:
                response = endpoint.send(payload)
                flags = analyze(response)
                
                result = {
                    "payload": payload,
                    "category": category,
                    "flags": flags,
                    "response_preview": str(response)[:200],
                    "detected": any(flags.values()),
                    "timestamp": datetime.now().isoformat()
                }
                
                session.results.append(result)
                session.progress = i + 1
                
            except Exception as e:
                session.results.append({
                    "payload": payload,
                    "category": category,
                    "error": str(e),
                    "flags": {},
                    "detected": False
                })
        
        # Generate summary
        total = len(session.results)
        detections = sum(1 for r in session.results if r.get("detected"))
        
        session.summary = {
            "total_tests": total,
            "vulnerabilities_detected": detections,
            "detection_rate": f"{(detections/total*100):.1f}%" if total > 0 else "0%",
            "categories_tested": list(set(r["category"] for r in session.results))
        }
        
        session.status = "completed"
        session.completed_at = datetime.now()
        
    except Exception as e:
        session.status = "failed"
        session.summary = {"error": str(e)}

# Serve static files
app.mount("/static", StaticFiles(directory="webapp/static"), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
