"""
Simple test server for Injecticide Web UI
Run this to start the web interface without Docker
"""

import sys
import os
from pathlib import Path

def main():
    print("=" * 50)
    print("  INJECTICIDE WEB INTERFACE")
    print("=" * 50)

    # Check for required modules
    required_modules = {
        'fastapi': 'pip install fastapi',
        'uvicorn': 'pip install uvicorn',
        'requests': 'pip install requests',
        'yaml': 'pip install pyyaml'
    }

    missing_modules = []
    for module, install_cmd in required_modules.items():
        try:
            if module == 'yaml':
                __import__('yaml')
            else:
                __import__(module)
        except ImportError:
            missing_modules.append((module, install_cmd))

    if missing_modules:
        print("\n!! Missing required modules:")
        for module, cmd in missing_modules:
            print(f"  - {module}: Run '{cmd}'")
        print("\nTo install all at once:")
        print("  pip install -r requirements-minimal.txt")
        sys.exit(1)

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent))

    # Import and run
    import uvicorn

    print("\n[OK] All dependencies found!")
    print("\n[*] Starting Injecticide Web Server...")
    print("-" * 50)
    print("  Web UI:   http://localhost:8080")
    print("  API Docs: http://localhost:8080/api/docs")
    print("-" * 50)
    print("\nPress Ctrl+C to stop the server\n")

    # Run without reload on Windows to avoid multiprocessing issues
    uvicorn.run("webapp.api:app", host="0.0.0.0", port=8080, reload=False)

if __name__ == "__main__":
    main()
