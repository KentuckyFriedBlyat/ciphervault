"""Workspace directory globals + provision_dirs(); set by entry.main() at startup."""

from pathlib import Path

# Workspace root - set in main(); defaults to this file's directory.
WORKSPACE = None
PADS_DIR = HEXPADS_DIR = CIPHER_DIR = CLEAR_DIR = AUDIT_DIR = CERTS_DIR = None


def provision_dirs(ws):
    """Create the localized tracking tree relative to the execution path."""
    global WORKSPACE, PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR, AUDIT_DIR
    WORKSPACE = Path(ws)
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    PADS_DIR = WORKSPACE / "Manual Pads"
    HEXPADS_DIR = WORKSPACE / "HexPads"
    CIPHER_DIR = WORKSPACE / "Cipher"
    CLEAR_DIR = WORKSPACE / "Clear"
    AUDIT_DIR = WORKSPACE / "audit"
    CERTS_DIR = WORKSPACE / "certificates"
    
    # Create all directories with error handling
    for d in (PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR, AUDIT_DIR, CERTS_DIR):
        try:
            d.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            # If we can't create the audit folder, fall back to a temp directory
            if d == AUDIT_DIR:
                import tempfile
                AUDIT_DIR = Path(tempfile.gettempdir()) / "ciphervault_audit"
                AUDIT_DIR.mkdir(parents=True, exist_ok=True)
                print(f"  [WARN] Could not create audit/ folder, using {AUDIT_DIR}")
            else:
                raise
    
    # Rotate audit logs if needed (keep last 100 logs)
    _rotate_audit_logs()
    
    return PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR, AUDIT_DIR, CERTS_DIR


def _rotate_audit_logs(max_logs=100):
    """Rotate audit logs if there are more than max_logs files.
    
    Keeps the most recent logs and removes oldest ones.
    """
    if not AUDIT_DIR or not AUDIT_DIR.exists():
        return
    
    logs = sorted(AUDIT_DIR.glob("BATCH-*.txt"), key=lambda f: f.stat().st_mtime)
    if len(logs) > max_logs:
        # Remove oldest logs
        to_remove = logs[:len(logs) - max_logs]
        for log in to_remove:
            try:
                log.unlink()
            except (IOError, OSError):
                pass
