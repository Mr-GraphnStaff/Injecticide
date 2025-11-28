"""
Injecticide Web Application
Professional LLM Security Testing Platform
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
import uuid
import json
from pathlib import Path

# Import our core Injecticide modules
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
    version="2.0.0"
)

# CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Store test sessions in memory (use Redis for production)
test_sessions = {}
