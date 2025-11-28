#!/bin/bash

echo "🚀 Starting Injecticide Web Platform..."
echo "=================================="

# Check if running in Docker
if [ -f /.dockerenv ]; then
    echo "Running in Docker container"
    uvicorn webapp.api:app --host 0.0.0.0 --port 8000 --reload
else
    echo "Running locally"
    
    # Check for virtual environment
    if [ ! -d ".venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv .venv
    fi
    
    # Activate virtual environment
    source .venv/bin/activate
    
    # Install dependencies
    echo "Installing dependencies..."
    pip install -q --upgrade pip
    pip install -q -r requirements.txt
    
    # Start the application
    echo "Starting web server..."
    echo "=================================="
    echo "🌐 Web UI: http://localhost:8000"
    echo "📚 API Docs: http://localhost:8000/api/docs"
    echo "=================================="
    
    python -m uvicorn webapp.api:app --host 0.0.0.0 --port 8000 --reload
fi
