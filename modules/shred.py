"""Secure multi-pass deletion of plaintext files."""

from pathlib import Path
import os

def secure_shred(path, source=None, passes=3):
    """Overwrite the physical blocks of `path` with randomized binary block
    matrices (SDR-derived when a dongle is present, system entropy
    otherwise - wipe material is not key material), fsync, then unlink."""
    path = Path(path)
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > 0:
        fill = os.urandom(size)
        if source is not None and not getattr(source, "sandbox", False):
            try:
                fill = source.wipe_bytes(size)
            except Exception:
                fill = os.urandom(size)
        if len(fill) < size:      # defensive: never spin on a short wipe buffer
            fill = os.urandom(size)
        with open(path, "r+b") as f:
            for _ in range(passes):
                off = 0
                while off < size:
                    chunk = fill[off:off + min(len(fill), size - off)]
                    f.seek(off)
                    f.write(chunk)
                    off += len(chunk)
                f.flush()
                os.fsync(f.fileno())
    try:
        path.unlink()
    except FileNotFoundError:
        pass
