"""Workspace directory globals + provision_dirs(); set by entry.main() at startup."""

from pathlib import Path

# Workspace root - set in main(); defaults to this file's directory.
WORKSPACE = None
PADS_DIR = HEXPADS_DIR = CIPHER_DIR = CLEAR_DIR = None


def provision_dirs(ws):
    """Create the localized tracking tree relative to the execution path."""
    global WORKSPACE, PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR
    WORKSPACE = Path(ws)
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    PADS_DIR = WORKSPACE / "Manual Pads"
    HEXPADS_DIR = WORKSPACE / "HexPads"
    CIPHER_DIR = WORKSPACE / "Cipher"
    CLEAR_DIR = WORKSPACE / "Clear"
    for d in (PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR):
        d.mkdir(parents=True, exist_ok=True)
    return PADS_DIR, HEXPADS_DIR, CIPHER_DIR, CLEAR_DIR
