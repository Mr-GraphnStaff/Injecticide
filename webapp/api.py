"""
Injecticide Web Application - FastAPI Backend
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json
import asyncio
import time
from pathlib import Path
import sys
import os

# Add parent directory to path to import Injecticide modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import core Injecticide modules
from config import TestConfig
from reporter import ReportGenerator
from analyzer import analyze
from generator import generate_payloads, policy_violation_payloads
from endpoints import AnthropicEndpoint, OpenAIEndpoint, AzureOpenAIEndpoint

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
    api_key: str = Field(..., description="API key for the service")
    model: Optional[str] = Field(None, description="Model to test")
    test_categories: List[str] = Field(default=["baseline"])
    custom_payloads: List[str] = Field(default=[])
    max_requests: int = Field(default=50)
    delay_between_requests: float = Field(default=0.5)

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
    static_file = Path("webapp/static/index.html")
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
        results=[],
        summary=None,
        created_at=datetime.now(),
        completed_at=None
    )
    
    test_sessions[session_id] = session.dict()
    
    # Run test in background
    background_tasks.add_task(run_test_session, session_id, request)
    
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

@app.get("/api/payloads")
async def get_available_payloads():
    """Get list of available payload categories"""
    
    baseline = generate_payloads()
    policy = policy_violation_payloads()
    
    return {
        "categories": {
            "baseline": {
                "name": "Baseline Injections",
                "description": "Standard prompt injection tests",
                "count": len(baseline),
                "examples": baseline[:3] if baseline else []
            },
            "policy": {
                "name": "Policy Violations", 
                "description": "Tests for policy enforcement",
                "count": len(policy),
                "examples": policy[:3] if policy else []
            }
        }
    }

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

# Background task to run tests
async def run_test_session(session_id: str, request: TestRequest):
    """Run the actual test session"""
    
    session = test_sessions[session_id]
    session["status"] = "running"
    session["target_service"] = request.target_service
    session["model"] = request.model
    
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
        elif request.target_service == "azure_openai":
            # Azure needs endpoint URL - should be passed in request
            endpoint = AzureOpenAIEndpoint(
                api_key=request.api_key,
                endpoint_url=getattr(request, 'endpoint_url', 'https://your-resource.openai.azure.com'),
                deployment_name=request.model or "gpt-4"
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
        
        session["total_tests"] = min(len(payloads), request.max_requests)
        
        # Run tests
        results = []
        for i, (payload, category) in enumerate(payloads[:request.max_requests]):
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
        session["completed_at"] = datetime.now()
        
    except Exception as e:
        session["status"] = "failed"
        session["summary"] = {"error": str(e)}
        print(f"Test session error: {e}")

# Serve static files
static_path = Path("webapp/static")
if static_path.exists():
    app.mount("/static", StaticFiles(directory="webapp/static"), name="static")

if __name__ == "__main__":
    import uvicorn
    print("Starting Injecticide Web Server...")
    print("Web UI: http://localhost:8000")
    print("API Docs: http://localhost:8000/api/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000)
