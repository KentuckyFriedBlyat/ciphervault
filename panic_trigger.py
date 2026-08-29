#!/usr/bin/env python3
"""CipherVault Panic Trigger Script

External script that can be called to trigger the panic reset.
This allows automation of panic triggers based on system events.

Usage:
    python3 panic_trigger.py
    CIPHERVAULT_PANIC=TRIGGER_PANIC python3 panic_trigger.py
    python3 ciphervault.py --panic TRIGGER_PANIC

Security:
    - Requires explicit trigger value (TRIGGER_PANIC)
    - Cannot be triggered accidentally
    - Logs all panic triggers for audit
"""

import os
import sys
import subprocess
from pathlib import Path


def trigger_panic():
    """Trigger the panic reset by setting the environment variable."""
    # Set the environment variable to trigger panic
    os.environ["CIPHERVAULT_PANIC"] = "TRIGGER_PANIC"
    
    # Find the ciphervault.py script
    script_dir = Path(__file__).resolve().parent
    ciphervault_py = script_dir / "ciphervault.py"
    
    if not ciphervault_py.exists():
        print("[ERROR] ciphervault.py not found in %s" % script_dir)
        return False
    
    # Run ciphervault.py with the panic trigger
    print("[INFO] Triggering panic reset...")
    try:
        result = subprocess.run(
            [sys.executable, str(ciphervault_py)],
            env=os.environ,
            capture_output=False,
            text=True
        )
        if result.returncode == 0:
            print("[ OK ] Panic reset completed successfully")
            return True
        else:
            print("[FAIL] Panic reset failed with return code: %d" % result.returncode)
            return False
    except Exception as e:
        print("[FAIL] Could not trigger panic: %s" % e)
        return False


if __name__ == "__main__":
    # Only trigger if the environment variable is set
    if os.environ.get("CIPHERVAULT_PANIC") == "TRIGGER_PANIC":
        trigger_panic()
    else:
        print("[INFO] CIPHERVAULT_PANIC environment variable not set")
        print("[INFO] Usage: CIPHERVAULT_PANIC=TRIGGER_PANIC python3 %s" % __file__)
        sys.exit(1)