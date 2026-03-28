#!/usr/bin/env python3
"""
VenomStrike Web UI Launcher
For authorized security testing only.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(__file__))

from core.logger import print_banner, log_info, log_warning
from config import FLASK_HOST, FLASK_PORT, LEGAL_DISCLAIMER

def main():
    print_banner()
    print(LEGAL_DISCLAIMER)
    
    log_info(f"Starting VenomStrike Web UI...")
    log_info(f"Access at: http://{FLASK_HOST}:{FLASK_PORT}")
    log_warning("This tool is for authorized security testing ONLY")
    log_warning("Ensure you have written permission to test any target")
    
    # Set Flask secret key from env if available
    if not os.environ.get("FLASK_SECRET_KEY"):
        import secrets
        os.environ["FLASK_SECRET_KEY"] = secrets.token_hex(32)
    
    from app import app
    from config import FLASK_DEBUG
    
    app.run(
        host=FLASK_HOST,
        port=FLASK_PORT,
        debug=FLASK_DEBUG,
        use_reloader=False,
    )

if __name__ == "__main__":
    main()
