# Injecticide Web Interface

## Quick Start

### Option 1: Simple Python Script (Easiest)
```bash
# From P:\Injecticide directory
python run_web.py
```
Then open http://localhost:8000 in your browser.

### Option 2: Windows Batch File
```bash
# Double-click start-web.bat
# OR from command line:
start-web.bat
```

### Option 3: Docker (Production)
```bash
docker-compose up --build
```

## First Time Setup

1. Install Python dependencies:
```bash
pip install fastapi uvicorn requests pyyaml
# OR install all dependencies:
pip install -r requirements.txt
```

2. Start the server:
```bash
python run_web.py
```

3. Open your browser to http://localhost:8000

## Features

- **Web UI**: Beautiful dark-themed interface at http://localhost:8000
- **API Docs**: Interactive API documentation at http://localhost:8000/api/docs
- **Real-time Updates**: WebSocket connection for live test progress
- **Multiple LLMs**: Test against Anthropic, OpenAI, and Azure OpenAI
- **Professional Reports**: Download results as HTML, JSON, or CSV
- **Custom Payloads**: Add your own injection tests
- **Secure Presets**: Store API credentials and payload presets in `webapp/secure_config.yaml` for quick reuse without exposing keys to the browser

## Usage

1. Enter your API key for the LLM service you want to test
2. Select test categories (Baseline, Policy Violations)
3. Optionally add custom payloads
4. Click "Launch Attack" to start testing
5. Watch real-time results appear
6. Download professional security report when complete

## Secure presets

The web UI can offer dropdowns for saved endpoints and payload combinations. Populate `webapp/secure_config.yaml` with your deployment details (API keys stay server-side). Each entry supports:

- `endpoints`: human-readable `name`, `target_service`, optional `model` and `endpoint_url`, and the `api_key` used on the server
- `payload_presets`: named sets of `test_categories` and optional `custom_payloads`

When a preset is selected, the UI uses the stored metadata for display while the backend injects the corresponding credentials at runtime.

## Troubleshooting

If you get module import errors:
```bash
pip install -r requirements.txt
```

If the web UI doesn't load:
- Check that port 8000 is not in use
- Make sure you're in the P:\Injecticide directory
- Try the direct Python command: `python -m uvicorn webapp.api:app --port 8000`

## Architecture

```
Injecticide/
├── webapp/
│   ├── api.py          # FastAPI backend
│   └── static/
│       ├── index.html  # React frontend
│       └── app.js      # React components
├── endpoints.py        # LLM API clients
├── analyzer.py         # Response analysis
├── generator.py        # Payload generation
├── reporter.py         # Report generation
└── run_web.py         # Simple startup script
```
