"""Optional external imports with graceful fallbacks (select, tkinter, tkinterdnd2)."""

try:
    import select
except ImportError:          # non-POSIX fallback (not expected on Linux)
    select = None

try:
    import tkinter as tk
    import tkinter.simpledialog as simpledialog
    from tkinter import filedialog, messagebox
except ImportError:
    tk = None                # bootstrapped at startup; re-exec after install
    simpledialog = None
    filedialog = None
    messagebox = None

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAVE_DND = True
except ImportError:
    HAVE_DND = False         # drag & drop falls back to the Load Series button
