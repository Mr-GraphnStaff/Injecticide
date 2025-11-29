"""
Improved Injecticide Web Server with proper cleanup
"""

import sys
import os
import signal
import atexit
from pathlib import Path
import psutil
import time

# Track our process info
MAIN_PID = os.getpid()
child_processes = []

def cleanup():
    """Kill all child processes on exit"""
    print("\n[*] Shutting down Injecticide...")
    
    # Get current process
    try:
        parent = psutil.Process(MAIN_PID)
        
        # Kill all children
        for child in parent.children(recursive=True):
            print(f"  - Terminating child process {child.pid}")
            try:
                child.terminate()
            except:
                pass
        
        # Give them time to close
        time.sleep(1)
        
        # Force kill any remaining
        for child in parent.children(recursive=True):
            try:
                child.kill()
            except:
                pass
                
    except Exception as e:
        print(f"  - Error during cleanup: {e}")
    
    print("[*] Cleanup complete")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n[!] Interrupt received, shutting down gracefully...")
    cleanup()
    sys.exit(0)

# Register cleanup handlers
atexit.register(cleanup)
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

# Windows specific
if sys.platform == "win32":
    signal.signal(signal.SIGBREAK, signal_handler)

def main():
    print("=" * 50)
    print("  INJECTICIDE WEB INTERFACE (WITH CLEANUP)")
    print("=" * 50)
    print(f"  Main Process PID: {MAIN_PID}")
    print("  Press Ctrl+C to shutdown cleanly")
    print("=" * 50)

    # Check for required modules
    required_modules = {
        'fastapi': 'pip install fastapi',
        'uvicorn': 'pip install uvicorn',
        'requests': 'pip install requests',
        'yaml': 'pip install pyyaml',
        'psutil': 'pip install psutil'
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
        print("  pip install fastapi uvicorn requests pyyaml psutil")
        sys.exit(1)

    # Add parent directory to path
    sys.path.insert(0, str(Path(__file__).parent))

    # Import and run
    import uvicorn
    from multiprocessing import freeze_support
    
    # Required for Windows
    freeze_support()

    print("\n[OK] All dependencies found!")
    print("\n[*] Starting Injecticide Web Server...")
    print("-" * 50)
    print("  Web UI:   http://localhost:8080")
    print("  API Docs: http://localhost:8080/api/docs")
    print("-" * 50)
    print("\nPress Ctrl+C for clean shutdown\n")

    try:
        # Run without reload to avoid multiprocessing issues
        uvicorn.run(
            "webapp.api:app", 
            host="0.0.0.0", 
            port=8080, 
            reload=False,
            workers=1,
            log_level="info"
        )
    except Exception as e:
        print(f"\n[!] Error: {e}")
    finally:
        cleanup()

if __name__ == "__main__":
    main()
