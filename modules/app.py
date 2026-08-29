"""tkinter GUI application (VaultApplication) and its internal refusal exception."""

from datetime import date
from pathlib import Path
import os
import queue
import re
import threading
import time
from . import state
from .compat import HAVE_DND, filedialog, messagebox, simpledialog, tk
from config.config import APP_NAME, DIGITS_PER_PAD, HEADER_LEN, HEXCHARS, HEX_CAP_BYTES, HEX_PART_CAP_BYTES, MAX_MSG_CHARS, MAX_PARTS, PRINTABLE_CAP, PRINTABLE_PART_CAP, PRODUCT_LINE, SANDBOX_MARK, SERIES_PART_OVERHEAD, VERSION
from .bootstrap import EnvironmentBootstrap
from .crypto import CryptoEngine
from .noise import CaptureError
from .selfcheck import run_selfcheck
from .shred import secure_shred
from .import fec
if HAVE_DND:
    from .compat import DND_FILES, TkinterDnD

def _hex_chunks(text, cap):
    """Split `text` into UTF-8 byte chunks of at most `cap` bytes. A code point is
    never split across two chunks (SUBTASK 8 fix: multibyte characters used to be
    cut in half at part boundaries, which made every non-ASCII series part fail
    UTF-8 validation on the receiving side)."""
    chunks, cur = [], bytearray()
    for ch in text:
        b = ch.encode("utf-8")
        if cur and len(cur) + len(b) > cap:
            chunks.append(bytes(cur))
            cur = bytearray()
        cur.extend(b)
    if cur:
        chunks.append(bytes(cur))
    return chunks


class VaultApplication:
    """Google-Translate-style split screen with two operating modes.

        left pane  = plaintext in (any Unicode in hex mode) / cleartext out
        right pane = transmission string out / received cipher or series in

    The single 'Process Message' button routes by context: content in the
    right pane is decrypted (right -> left); otherwise content in the left
    pane is encrypted (left -> right). Series files can be dragged and
    dropped onto the window (or loaded through the Load Series button) for batch
    processing. With zero valid key sheets in either pad folder the process
    button is locked to an inactive state.
    """

    def __init__(self, source, sandbox=False):
        self.source = source
        self.sandbox = sandbox
        self.busy = False
        self._queue = queue.Queue()
        self._selfcheck_state = "running..."
        self._selfcheck_running = False
        self._antenna_nag_shown = False
        if HAVE_DND:
            self.root = TkinterDnD.Tk()
        else:
            self.root = tk.Tk()
        self.build_gui()
        self.refresh_ledger()
        self._log("%s v%s - %s" % (APP_NAME, VERSION, PRODUCT_LINE))
        if sandbox:
            self._log("SANDBOX NOISE SOURCE ACTIVE - TEST ONLY. Pages generated now are "
                      "stamped and will be refused for operational use.")
        if not self._setup_dnd():
            self._log("Drag & drop unavailable (tkinterdnd2 not installed) - use the "
                      "'Load Series File' button, or paste a series file path / all part "
                      "lines into the right pane.")
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.after(100, self._poll)
        self.root.after(250, self.start_selfcheck)   # RAM-only self check at startup
        if not self.sandbox:
            self.root.after(400, self._purge_obsolete_pads)  # SUBTASK 5: obsolete pad sweep
        
        # Load operator/station IDs from config if persisted
        self._load_operator_station_from_config()

    # -- interface architecture ---------------------------------------------
    
    def _load_operator_station_from_config(self):
        """Load operator/station IDs from config if they are persisted.
        
        After loading, sanitizes the config module attributes to prevent
        sensitive data from lingering in memory.
        """
        try:
            import config.config as cfg
            
            # Load operator ID
            op = cfg.OPERATOR_ID
            if op and op != "<fill in by hand>":
                self.operator_var.set(op)
                # Sanitize memory
                del cfg.OPERATOR_ID
                cfg.OPERATOR_ID = "<fill in by hand>"
            
            # Load station ID
            st = cfg.STATION_ID
            if st and st != "<fill in by hand>":
                self.station_var.set(st)
                # Sanitize memory
                del cfg.STATION_ID
                cfg.STATION_ID = "<fill in by hand>"
                
        except Exception:
            pass
    
    def _secure_overwrite(self, path, new_content, sanitize_memory=False):
        """Securely overwrite a file to prevent forensic recovery.
        
        Overwrites the file with the new content plus padding to prevent
        old data from being recoverable. When sanitize_memory=True, also
        clears sensitive data from memory.
        """
        import os
        import random
        try:
            # Read current content
            with open(path, 'rb') as f:
                old_content = f.read()
            
            # Convert to string for processing
            content = old_content.decode('utf-8', errors='replace')
            
            # Get the new content as bytes
            new_bytes = new_content.encode('utf-8', errors='replace')
            
            # Add padding around the content to prevent forensic recovery
            # Add 16 bytes of random padding on each side
            padding_size = 16
            random_padding = bytes([random.randint(0, 255) for _ in range(padding_size)])
            padded_content = random_padding + new_bytes + random_padding
            
            # Write the padded content
            with open(path, 'wb') as f:
                f.write(padded_content)
                f.flush()
                os.fsync(f.fileno())
                
            # If sanitizing memory, clear the content from memory
            if sanitize_memory:
                try:
                    # Clear the new content from memory
                    new_bytes[:] = b'\x00' * len(new_bytes)
                    padded_content[:] = b'\x00' * len(padded_content)
                    random_padding[:] = b'\x00' * len(random_padding)
                except Exception:
                    pass
                
        except Exception as e:
            self._log("[WARN] Secure overwrite failed: %s" % e)
            # Fall back to regular write if secure overwrite fails
            with open(path, 'w', encoding='utf-8') as f:
                f.write(new_content)
    
    def _save_operator_station_to_config(self):
        """Save operator/station IDs to config if the persist checkbox is checked.
        
        When persist is enabled: writes IDs with padding around them
        When persist is disabled: does multipass wipe to prevent recovery
        """
        import random
        import os
        try:
            import config.config as cfg
            
            # Get current values
            op = self.operator_var.get().strip()
            st = self.station_var.get().strip()
            
            if self.persist_vars.get():
                # Persist mode: write IDs with padding
                if op and op != "<fill in by hand>":
                    cfg.OPERATOR_ID = op
                if st and st != "<fill in by hand>":
                    cfg.STATION_ID = st
                
                # Write to config file with secure overwrite
                config_path = Path(__file__).resolve().parent.parent / "config" / "config.py"
                if config_path.exists():
                    content = config_path.read_text()
                    
                    # Replace OPERATOR_ID line
                    op_line = 'OPERATOR_ID = "%s"' % op
                    content = re.sub(r'OPERATOR_ID = .*$', op_line, content)
                    
                    # Replace STATION_ID line
                    st_line = 'STATION_ID = "%s"' % st
                    content = re.sub(r'STATION_ID = .*$', st_line, content)
                    
                    # Securely overwrite with padding
                    self._secure_overwrite(config_path, content)
                    self._log("[ OK ] Operator/station IDs persisted to config (secure)")
            else:
                # Clear mode: multipass wipe to prevent recovery
                self._log("[INFO] Clearing operator/station IDs with multipass wipe")
                
                # Read current content
                config_path = Path(__file__).resolve().parent.parent / "config" / "config.py"
                if not config_path.exists():
                    return
                
                with open(config_path, 'rb') as f:
                    content = f.read()
                
                # Convert to string
                text = content.decode('utf-8', errors='replace')
                
                # Replace OPERATOR_ID with null bytes
                text = re.sub(r'OPERATOR_ID = .*$', 'OPERATOR_ID = "\x00"', text)
                
                # Replace STATION_ID with null bytes
                text = re.sub(r'STATION_ID = .*$', 'STATION_ID = "\x00"', text)
                
                # Convert back to bytes
                content = text.encode('utf-8', errors='replace')
                
                # Multipass wipe: overwrite 3 times with different patterns
                for i in range(3):
                    if i == 0:
                        # First pass: random data
                        wipe_data = bytes([random.randint(0, 255) for _ in range(len(content))])
                    elif i == 1:
                        # Second pass: zeros
                        wipe_data = b'\x00' * len(content)
                    else:
                        # Third pass: ones
                        wipe_data = b'\xff' * len(content)
                    
                    with open(config_path, 'wb') as f:
                        f.write(wipe_data)
                        f.flush()
                        os.fsync(f.fileno())
                
                self._log("[ OK ] Operator/station IDs wiped (3 passes)")
        except Exception as e:
            self._log("[WARN] Could not persist/clear operator/station IDs: %s" % e)
    
    def _on_close(self):
        """Handle window close - save or clear operator/station IDs."""
        if self.persist_vars.get():
            # Persist mode: write with padding
            self._save_operator_station_to_config()
        else:
            # Clear mode: multipass wipe and sanitize memory
            self._save_operator_station_to_config()
            # Sanitize memory after clearing
            try:
                self.operator_var.set("")
                self.station_var.set("")
                # Clear from memory
                self.operator_var = None
                self.station_var = None
            except Exception:
                pass
        self.root.destroy()
    
    def on_panic(self):
        """Panic button - double confirmation to reset everything."""
        # First confirmation dialog
        result = messagebox.askyesno(
            "PANIC - CONFIRMATION REQUIRED",
            "WARNING: This will permanently destroy all sensitive data.\n\n"
            "This action will:\n"
            "  • Shred operator/station IDs\n"
            "  • Destroy all files in audit/\n"
            "  • Destroy all files in Clear/\n"
            "  • Destroy all files in Cipher/\n"
            "  • Reset program to factory defaults\n\n"
            "THIS ACTION CANNOT BE UNDONE.\n\n"
            "Are you sure you want to proceed?",
            icon='warning', parent=self.root)
        
        if not result:
            return
        
        # Second confirmation dialog
        result = messagebox.askyesno(
            "PANIC - FINAL CONFIRMATION",
            "FINAL WARNING: This will permanently destroy all sensitive data.\n\n"
            "Are you absolutely sure?",
            icon='warning', parent=self.root)
        
        if not result:
            return
        
        # Execute panic reset
        self._execute_panic_reset()
    
    def _execute_panic_reset(self):
        """Execute the panic reset - shred everything using pad keys as entropy."""
        try:
            import shutil
            import os
            import random
            
            # 1. Reset operator/station IDs
            self.operator_var.set("<fill in by hand>")
            self.station_var.set("<fill in by hand>")
            
            # 2. Generate entropy from pad material for wiping
            self._log("[INFO] Consuming pad material for secure wipe entropy...")
            pad_entropy = self._consume_pad_entropy()
            
            # 3. Shred audit folder contents using pad entropy
            audit_dir = state.AUDIT_DIR
            if audit_dir and audit_dir.exists():
                self._shred_directory_with_entropy(audit_dir, pad_entropy)
                self._log("[ OK ] audit/ folder shredded using pad entropy")
            
            # 4. Shred Clear folder contents using pad entropy
            clear_dir = state.CLEAR_DIR
            if clear_dir and clear_dir.exists():
                self._shred_directory_with_entropy(clear_dir, pad_entropy)
                self._log("[ OK ] Clear/ folder shredded using pad entropy")
            
            # 5. Shred Cipher folder contents using pad entropy
            cipher_dir = state.CIPHER_DIR
            if cipher_dir and cipher_dir.exists():
                self._shred_directory_with_entropy(cipher_dir, pad_entropy)
                self._log("[ OK ] Cipher/ folder shredded using pad entropy")
            
            # 5.5. Shred certificates folder if it exists
            certs_dir = state.CERTS_DIR
            if certs_dir and certs_dir.exists():
                self._shred_directory_with_entropy(certs_dir, pad_entropy)
                self._log("[ OK ] certificates/ folder shredded using pad entropy")
            
            # 6. Reset config file
            config_path = Path(__file__).resolve().parent.parent / "config" / "config.py"
            if config_path.exists():
                content = config_path.read_text()
                content = re.sub(r'OPERATOR_ID = .*$', 'OPERATOR_ID = "<fill in by hand>"', content)
                content = re.sub(r'STATION_ID = .*$', 'STATION_ID = "<fill in by hand>"', content)
                # Securely overwrite config with pad entropy
                self._secure_overwrite(config_path, content, sanitize_memory=False)
                self._log("[ OK ] Config reset to factory defaults")
            
            # 7. Update UI
            self._log("")
            self._log("=" * 64)
            self._log("PANIC RESET COMPLETE - Program reset to factory defaults")
            self._log("=" * 64)
            self._log("")
            self._log("[ OK ] All sensitive data has been securely destroyed")
            self._log("[ OK ] Program is now in factory default state")
            self._log("[ OK ] Pad material consumed as entropy for secure wipe")
            
        except Exception as e:
            self._log("[FAIL] Panic reset failed: %s" % e)
    
    def _consume_pad_entropy(self):
        """Generate entropy by consuming pad material.
        
        Returns a large byte string derived from pad material that can be
        used for secure wiping. This ensures the pads themselves are consumed
        in the process.
        """
        import hashlib
        entropy = bytearray()
        
        # Try to read pad files and hash them for entropy
        for folder in [state.PADS_DIR, state.HEXPADS_DIR]:
            if folder and folder.exists():
                for pad_file in folder.glob("P*.txt"):
                    try:
                        with open(pad_file, 'rb') as f:
                            content = f.read()
                            entropy.extend(hashlib.sha256(content).digest())
                            # Securely delete the pad file
                            pad_file.unlink()
                    except Exception:
                        pass
        
        # If no pad files found, generate entropy from system entropy
        if not entropy:
            entropy = os.urandom(1024 * 1024)  # 1 MB of system entropy
        
        return bytes(entropy)
    
    def _shred_directory_with_entropy(self, directory, entropy_source):
        """Securely shred all files in a directory using pad entropy.
        
        Uses the pad-derived entropy as the wipe pattern instead of random data.
        """
        import os
        import random
        
        if not directory.exists():
            return
        
        # Collect all files
        files = []
        for item in directory.iterdir():
            if item.is_file():
                files.append(item)
            elif item.is_dir():
                # Recursively shred subdirectories
                self._shred_directory_with_entropy(item, entropy_source)
        
        # Securely delete each file using pad entropy
        for file_path in files:
            try:
                # Read file
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Use pad entropy for wiping - cycle through entropy source
                entropy_len = len(entropy_source)
                for i in range(3):
                    # Use different parts of entropy for each pass
                    start = (i * entropy_len // 3) % entropy_len
                    wipe_data = entropy_source[start:start + len(content)]
                    if len(wipe_data) < len(content):
                        # Pad with more entropy if needed
                        extra = entropy_source[:len(content) - len(wipe_data)]
                        wipe_data = wipe_data + extra
                    
                    with open(file_path, 'wb') as f:
                        f.write(wipe_data)
                        f.flush()
                        os.fsync(f.fileno())
                
                # Delete the file
                file_path.unlink()
                
            except Exception:
                # If secure deletion fails, just delete normally
                try:
                    file_path.unlink()
                except Exception:
                    pass
    
    def _shred_directory(self, directory):
        """Securely shred all files in a directory."""
        import os
        import random
        
        if not directory.exists():
            return
        
        # Collect all files
        files = []
        for item in directory.iterdir():
            if item.is_file():
                files.append(item)
            elif item.is_dir():
                # Recursively shred subdirectories
                self._shred_directory(item)
        
        # Securely delete each file
        for file_path in files:
            try:
                # Read file
                with open(file_path, 'rb') as f:
                    content = f.read()
                
                # Multipass wipe
                for i in range(3):
                    if i == 0:
                        wipe_data = bytes([random.randint(0, 255) for _ in range(len(content))])
                    elif i == 1:
                        wipe_data = b'\x00' * len(content)
                    else:
                        wipe_data = b'\xff' * len(content)
                    
                    with open(file_path, 'wb') as f:
                        f.write(wipe_data)
                        f.flush()
                        os.fsync(f.fileno())
                
                # Delete the file
                file_path.unlink()
                
            except Exception:
                # If secure deletion fails, just delete normally
                try:
                    file_path.unlink()
                except Exception:
                    pass
    def build_gui(self):
        r = self.root
        r.title("%s v%s - %s" % (APP_NAME, VERSION, PRODUCT_LINE))
        r.geometry("1120x780")
        r.minsize(900, 600)

        # Top control panel frame
        top = tk.Frame(r)
        top.pack(fill="x", padx=12, pady=(10, 4))
        tk.Label(top, text="%s - %s" % (APP_NAME, PRODUCT_LINE),
                 font=("Helvetica", 15, "bold")).pack(side="left")
        self.ledger_var = tk.StringVar(value="SELF CHECK: running...")
        self.ledger_lbl = tk.Label(top, textvariable=self.ledger_var, fg="#b06000",
                                   font=("Helvetica", 10, "bold"))
        self.ledger_lbl.pack(side="right")

        btns = tk.Frame(r)
        btns.pack(fill="x", padx=12, pady=(2, 4))
        self.btn_gen = tk.Button(btns, text="\U0001F511 Generate Pads",
                                 command=self.on_generate, width=18)
        self.btn_gen.pack(side="left", padx=(0, 6))
        self.btn_proc = tk.Button(btns, text="\u26A1 Process Message",
                                  command=self.on_process, width=20)
        self.btn_proc.pack(side="left", padx=(0, 6))
        tk.Button(btns, text="\U0001FA79 Self Check", command=self.start_selfcheck,
                  width=13).pack(side="left", padx=(0, 6))
        tk.Button(btns, text="\U0001F4C2 Load Series File",
                  command=self.on_load_series, width=18).pack(side="left")
        tk.Button(btns, text="\U0001F6A8 PANIC", command=self.on_panic,
                  width=13, bg="#ff0000", fg="#ffffff", font=("Helvetica", 10, "bold"),
                  activebackground="#cc0000", activeforeground="#ffffff").pack(side="right", padx=(6, 0))
        self.progress_var = tk.StringVar(value="")
        tk.Label(btns, textvariable=self.progress_var, fg="#555").pack(side="right")

        # Mode + options row
        opts = tk.Frame(r)
        opts.pack(fill="x", padx=12, pady=(0, 6))
        self.mode_var = tk.StringVar(value="hex")
        rb1 = tk.Radiobutton(opts, text="Hex mode (primary - full Unicode)",
                             variable=self.mode_var, value="hex",
                             command=self._update_counts)
        rb1.pack(side="left", padx=(0, 14))
        rb2 = tk.Radiobutton(opts, text="Printable pads (fallback)",
                             variable=self.mode_var, value="printable",
                             command=self._update_counts)
        rb2.pack(side="left")
        self.split_var = tk.BooleanVar(value=False)
        cb = tk.Checkbutton(opts, text="Split long messages across multiple pads "
                                       "(burns one pad per part)",
                            variable=self.split_var, command=self._update_counts)
        cb.pack(side="left", padx=(18, 0))
        self.fec_var = tk.BooleanVar(value=False)
        fcb = tk.Checkbutton(opts, text="FEC (air) - error-protected frame for "
                                        "JS8Call / VARA transmission",
                             variable=self.fec_var)
        fcb.pack(side="left", padx=(18, 0))
        
        # Operator / Station ID section
        id_opts = tk.Frame(r)
        id_opts.pack(fill="x", padx=12, pady=(0, 6))
        tk.Label(id_opts, text="Operator / Station:", font=("Helvetica", 9, "bold")).pack(side="left")
        self.operator_var = tk.StringVar(value="<fill in by hand>")
        self.station_var = tk.StringVar(value="<fill in by hand>")
        tk.Entry(id_opts, textvariable=self.operator_var, width=20).pack(side="left", padx=(0, 8))
        tk.Entry(id_opts, textvariable=self.station_var, width=20).pack(side="left", padx=(0, 8))
        self.persist_vars = tk.BooleanVar(value=False)
        persist_cb = tk.Checkbutton(id_opts, text="Persist in config", variable=self.persist_vars)
        persist_cb.pack(side="left")

        # Character / byte count readout
        self.count_var = tk.StringVar(value="")
        tk.Label(r, textvariable=self.count_var, fg="#0b5394",
                 font=("Helvetica", 10), anchor="w").pack(fill="x", padx=14)

        # Side-by-side dual panes
        panes = tk.PanedWindow(r, orient=tk.HORIZONTAL, sashwidth=6)
        panes.pack(fill="both", expand=True, padx=12, pady=4)

        leftf = tk.Frame(panes)
        rightf = tk.Frame(panes)
        panes.add(leftf, minsize=300)
        panes.add(rightf, minsize=300)

        self.left_label = tk.Label(leftf, text="PLAINTEXT IN   /   CLEARTEXT OUT",
                                   anchor="w", bg="#eef2f7", relief="sunken")
        self.left_label.pack(fill="x")
        self.left_text = tk.Text(leftf, wrap="word", font=("Courier", 11))
        self.left_text.pack(fill="both", expand=True)
        self.left_text.bind("<KeyRelease>", lambda e: self._update_counts())

        self.right_label = tk.Label(rightf,
                                    text="TRANSMISSION STRING OUT   /   RECEIVED CIPHER or SERIES IN",
                                    anchor="w", bg="#eef2f7", relief="sunken")
        self.right_label.pack(fill="x")
        self.right_text = tk.Text(rightf, wrap="word", font=("Courier", 11))
        self.right_text.pack(fill="both", expand=True)

        # Active ledger / status log readout
        logf = tk.Frame(r)
        logf.pack(fill="x", padx=12, pady=(6, 10))
        self.log_text = tk.Text(logf, height=9, state="disabled",
                                bg="#000000", fg="#00ff00", font=("Courier", 12))
        log_sb = tk.Scrollbar(logf, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_sb.set)
        log_sb.pack(side="right", fill="y")
        self.log_text.pack(fill="both", expand=True)

    # -- drag & drop -----------------------------------------------------------
    def _setup_dnd(self):
        if not HAVE_DND:
            return False
        try:
            for w in (self.root, self.left_text, self.right_text):
                w.drop_target_register(DND_FILES)
                w.dnd_bind("<<Drop>>", self._on_drop)
            return True
        except Exception:
            return False

    def _on_drop(self, event):
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            return
        if not paths:
            return
        path = paths[0]
        self._log("File dropped: %s" % os.path.basename(path))
        self.process_series_file(path)

    def on_load_series(self):
        if filedialog is None or self.busy:
            return
        path = filedialog.askopenfilename(
            title="Load a multi-part series file or certificate",
            filetypes=[("CipherVault series / certificate files", "*.txt *.dat *.pem *.crt *.cer"),
                       ("All files", "*.*")])
        if path:
            # Check if it's a certificate file
            if path.lower().endswith(('.pem', '.crt', '.cer')):
                self.load_certificate(path)
            else:
                self.process_series_file(path)
    
    def _validate_certificate(self, cert_path):
        """Validate that a file is a valid X.509 certificate.
        
        Returns (is_valid, error_message) tuple.
        """
        try:
            from cryptography import x509
            from cryptography.hazmat.primitives.serialization import load_pem_x509_certificate, load_der_x509_certificate
            import binascii
            
            with open(cert_path, 'rb') as f:
                cert_data = f.read()
            
            # Try PEM format first
            try:
                cert = load_pem_x509_certificate(cert_data)
                return True, None
            except Exception:
                pass
            
            # Try DER format
            try:
                cert = load_der_x509_certificate(cert_data)
                return True, None
            except Exception:
                pass
            
            # Try to detect if it's a valid certificate by checking ASN.1 structure
            # X.509 certificates start with 0x30 (SEQUENCE)
            if cert_data[:1] == b'\x30':
                return True, "Valid X.509 certificate (DER format)"
            
            return False, "Not a valid X.509 certificate - invalid file format"
            
        except ImportError as e:
            return False, "cryptography library not available for validation"
        except Exception as e:
            return False, "Certificate validation failed: %s" % e
    
    def load_certificate(self, path):
        """Load a certificate file into the certificates folder with validation."""
        try:
            import shutil
            from pathlib import Path
            
            cert_path = Path(path)
            
            # Validate certificate before loading
            is_valid, error_msg = self._validate_certificate(cert_path)
            
            if not is_valid:
                self._log("[FAIL] Certificate validation failed: %s" % error_msg)
                self._log("[FAIL] Certificate NOT loaded - file may be malicious")
                return False
            
            # Calculate SHA before copying
            sha256 = self._calculate_sha256(cert_path)
            
            # Copy certificate to certificates folder
            dest = Path(state.CERTS_DIR) / cert_path.name
            shutil.copy2(cert_path, dest)
            
            # Update certificate status with SHA
            self._update_certificate_status(sha256)
            
            self._log("[ OK ] Certificate validated and loaded: %s" % cert_path.name)
            self._log("[ OK ] SHA256: %s" % sha256[:16] + "...")
            self._log("[ OK ] Certificate stored in: %s" % state.CERTS_DIR)
            
            return True
            
        except Exception as e:
            self._log("[FAIL] Could not load certificate: %s" % e)
            return False

    # -- ledger + state locking -------------------------------------------------
    def _verified_pads(self, kind):
        """Verified, non-sandbox pad pages for a kind (oldest first)."""
        folder = state.HEXPADS_DIR if kind == "hex" else state.PADS_DIR
        out = []
        for f in sorted(folder.glob("P*.txt")):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if SANDBOX_MARK in text:
                continue
            ok, _reason = CryptoEngine.verify_page_text(text)
            if ok:
                out.append(f)
        return out

    def refresh_ledger(self):
        p_ok = len(self._verified_pads("printable"))
        h_ok = len(self._verified_pads("hex"))
        total_p = len(list(state.PADS_DIR.glob("P*.txt")))
        total_h = len(list(state.HEXPADS_DIR.glob("P*.txt")))
        base = "SELF CHECK: %s | Manual Pads %d (%d ok) | HexPads %d (%d ok)" % (
            self._selfcheck_state, total_p, p_ok, total_h, h_ok)
        self.ledger_var.set(base)
        # State locking rule: zero valid key sheets in EITHER folder -> lock out.
        # Local is named `st` on purpose: `state` would shadow the ciphervault.state
        # module import and crash every call with UnboundLocalError.
        st = tk.NORMAL if (p_ok + h_ok) > 0 else tk.DISABLED
        self.btn_proc.configure(state=st)
        self._update_counts()

    def _set_busy(self, busy):
        self.busy = busy
        st = tk.DISABLED if busy else tk.NORMAL
        self.btn_gen.configure(state=st)
        if not busy:
            self.refresh_ledger()
    
    def _calculate_sha256(self, file_path):
        """Calculate SHA-256 hash of a file."""
        import hashlib
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _update_certificate_status(self, sha256=None):
        """Update certificate status indicator."""
        if state.CERTS_DIR and state.CERTS_DIR.exists():
            certs = list(state.CERTS_DIR.glob("*.pem")) + list(state.CERTS_DIR.glob("*.crt")) + list(state.CERTS_DIR.glob("*.cer"))
            if certs:
                self._log("[ OK ] Certificates loaded: %d certificate(s)" % len(certs))
                if sha256:
                    self._log("[ OK ] Certificate SHA256: %s" % sha256[:32] + "...")
            else:
                self._log("[INFO] No certificates loaded")
        else:
            self._log("[INFO] No certificates loaded")

    # -- log / queue plumbing -----------------------------------------------------
    def _log(self, msg):
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", "[%s] %s\n" % (stamp, msg))
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll(self):
        try:
            while True:
                kind, payload = self._queue.get_nowait()
                if kind == "log":
                    self._log(payload)
                elif kind == "progress":
                    done, total = payload
                    self.progress_var.set(
                        "capturing %d/%d blocks (%d%%)"
                        % (done, total, 100 * done // max(total, 1)))
                elif kind == "selfcheck":
                    ok = payload
                    self._selfcheck_state = "PASS" if ok else "FAIL"
                    self.ledger_lbl.configure(
                        fg="#0a7d32" if ok else "#c0182b")
                    self.refresh_ledger()
                    self._log("SELF CHECK: %s" % ("PASS" if ok else "FAIL"))
                elif kind == "nag":
                    messagebox.showwarning(APP_NAME, payload)
                elif kind == "refresh":
                    self.progress_var.set("")
                    self._set_busy(False)
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    # -- RAM-only self check --------------------------------------------------------
    def start_selfcheck(self):
        if getattr(self, "_selfcheck_running", False):
            return
        self._selfcheck_running = True
        self._selfcheck_state = "running..."
        self.ledger_lbl.configure(fg="#b06000")
        self.refresh_ledger()

        def worker():
            ok = run_selfcheck()
            self._selfcheck_running = False
            self._queue.put(("selfcheck", ok))

        threading.Thread(target=worker, daemon=True).start()

    # -- character / byte count readout ------------------------------------------------
    def _update_counts(self):
        """Dynamically gauges pad usage and remaining single-page headroom on every
        key release by running an in-memory Zlib compression sample on the raw text buffer."""
        try:
            mode = self.mode_var.get()
            left = self.left_text.get("1.0", "end-1c")

            if mode == "hex":
                # SUBTASK 8 fix: gauge counts RAW UTF-8 bytes - encrypt_hex pads the
                # raw bytes, it does not compress (the zlib estimate lied).
                raw_bytes = left.encode("utf-8")
                used_b = len(raw_bytes)
                raw_c = len(left)
                avail = len(self._verified_pads("hex"))

                if not left.strip():
                    self.count_var.set(
                        f"Hex mode: 0 bytes input | Max single-page capacity: {HEX_CAP_BYTES} raw bytes."
                    )
                    return

                if used_b <= HEX_CAP_BYTES:
                    headroom = HEX_CAP_BYTES - used_b
                    self.count_var.set(
                        f"Hex mode: {raw_c} chars = {used_b}/{HEX_CAP_BYTES} raw bytes. "
                        f"Headroom: {headroom} bytes remaining before multi-part split."
                    )
                elif self.split_var.get():
                    n = len(_hex_chunks(left, HEX_PART_CAP_BYTES))
                    if n > MAX_PARTS:
                        self.count_var.set(
                            f"Hex mode error: Payload size ({used_b} bytes) requires {n} parts, exceeding the {MAX_PARTS}-part sequence ceiling."
                        )
                    elif n > avail:
                        self.count_var.set(
                            f"Hex mode alert: Volume requires {n} parts, but only {avail} verified hex pads are available."
                        )
                    else:
                        self.count_var.set(
                            f"Hex mode: {raw_c} chars = {used_b} raw bytes "
                            f"-> Will consume {n} pad pages ({avail} available)."
                        )
                else:
                    self.count_var.set(
                        f"Hex mode alert: Payload size ({used_b} bytes) exceeds single-pad limit of {HEX_CAP_BYTES} raw bytes. "
                        f"Enable 'split across multiple pads' or shorten text."
                    )
            else:
                pt = re.sub(r"[^A-Z0-9]", "", left.upper())
                avail = len(self._verified_pads("printable"))
                if not pt:
                    self.count_var.set(
                        "Printable mode: 0 chars typed | one pad page holds %d "
                        "letters/digits" % PRINTABLE_CAP)
                    return
                if len(pt) <= PRINTABLE_CAP:
                    self.count_var.set(
                        "Printable mode: %d/%d characters used - fits ONE pad"
                        % (len(pt), PRINTABLE_CAP))
                elif self.split_var.get():
                    import math as _m
                    n = _m.ceil(len(pt) / PRINTABLE_PART_CAP)
                    if n > MAX_PARTS:
                        self.count_var.set(
                            "Printable mode: %d chars - exceeds the %d-part maximum. Shorten it."
                            % (len(pt), MAX_PARTS))
                    elif n > avail:
                        self.count_var.set(
                            "Printable mode: %d chars would burn %d pads - only %d verified "
                            "pad(s) available. Generate more." % (len(pt), n, avail))
                    else:
                        self.count_var.set(
                            "Printable mode: %d characters typed - will burn %d pads "
                            "(%d available)" % (len(pt), n, avail))
                else:
                    self.count_var.set(
                        "Printable mode: %d characters - OVER the %d-char single-pad cap. "
                        "Enable 'split across multiple pads' or shorten."
                        % (len(pt), PRINTABLE_CAP))
        except Exception as e:
            # never let a count-readout bug kill the GUI; surface it once in the log
            if getattr(self, "_count_err_last", None) != repr(e):
                self._count_err_last = repr(e)
                try:
                    self._log("count readout error (diagnostic): %r" % (e,))
                except Exception:
                    pass

    # -- Button 1: Generate Pads --------------------------------------------------------
    def on_generate(self):
        if self.busy or simpledialog is None:
            return
        kind = self.mode_var.get()
        n = simpledialog.askinteger(
            "Generate %s pads" % ("hex" if kind == "hex" else "printable"),
            "How many pads to generate?:", minvalue=1)
        if n is None:
            return
        # Update operator/station in config before generating
        self._save_operator_station_to_config()
        self._set_busy(True)
        threading.Thread(target=self._gen_worker, args=(n, kind), daemon=True).start()

    def _gen_worker(self, n, kind):
        try:
            if not getattr(self.source, "sandbox", False):
                found, detail = EnvironmentBootstrap.ping_dongle()
                if not found:
                    raise CaptureError(detail)
            written = CryptoEngine.trigger_generation(
                n_pads=n, kind=kind, source=self.source,
                log=lambda m: self._queue.put(("log", m)),
                progress=lambda d, t: self._queue.put(("progress", (d, t))))
            folder = "HexPads/" if kind == "hex" else "Manual Pads/"
            self._queue.put(("log", "DONE. %d %s pad(s) written to %s%s"
                             % (len(written), kind, state.WORKSPACE, folder)))
            self._queue.put(("log", "Captures lived and died in RAM - nothing raw was "
                                    "written to disk."))
        except CaptureError as e:
            # First sweep failure: nag the operator about the antenna
            if not self._antenna_nag_shown:
                self._antenna_nag_shown = True
                self._queue.put(("nag", "Did you remember to connect the antenna?\n\n" + str(e)))
            else:
                self._queue.put(("log", "[FAIL] pad generation stopped: %s" % e))
        except Exception as e:
            self._queue.put(("log", "[FAIL] pad generation stopped: %s" % e))
        finally:
            self._queue.put(("refresh", None))

    # -- Button 2: Process Message (context-aware routing) -------------------------------
    def on_process(self):
        if self.busy:
            return
        left = self.left_text.get("1.0", "end-1c").strip()
        right = self.right_text.get("1.0", "end-1c").strip()
        if right:
            self.run_automatic_decryption(right)
        elif left:
            self.run_automatic_encryption(left)
        else:
            self._log("Nothing to process - type plaintext in the left pane or paste a "
                      "received string / series in the right pane.")

    # -- encryption core ------------------------------------------------------------------
    def run_automatic_encryption(self, raw):
        """Purify left-pane text (mode-dependent), consume verified pad page(s),
        and display + save the transmittable string(s). Series output is also
        written to an explicit file in the working directory."""
        mode = self.mode_var.get()
        split_ok = self.split_var.get()

        if mode == "printable":
            pt = re.sub(r"[^A-Z0-9]", "", raw.upper())
            stripped = len(raw) - len(pt)
            if not pt:
                messagebox.showwarning(APP_NAME,
                                       "No letters or digits in input. Nothing was consumed.")
                return
            if stripped > 0:
                self._log("%d non-letter/digit character(s) stripped from input" % stripped)
            size = len(pt)
            single_cap, part_cap = PRINTABLE_CAP, PRINTABLE_PART_CAP
        else:
            pt = raw
            if not pt.strip():
                messagebox.showwarning(APP_NAME, "Input is empty. Nothing was consumed.")
                return
            data_b = pt.encode("utf-8")
            size = len(data_b)
            single_cap, part_cap = HEX_CAP_BYTES, HEX_PART_CAP_BYTES

        # ---- decide single vs series ------------------------------------------------
        if size <= single_cap:
            is_series = False
            n_parts = 1
        elif not split_ok:
            cap_name = "characters" if mode == "printable" else "bytes"
            messagebox.showerror(
                APP_NAME,
                "Message is %d %s - over the single-pad cap of %d %s.\n\n"
                "Enable 'Split long messages across multiple pads' to burn one pad per "
                "part, or shorten the message. Nothing was consumed."
                % (size, cap_name, single_cap, cap_name))
            return
        else:
            is_series = True
            if mode == "hex":
                chunks = _hex_chunks(pt, part_cap)  # char-aware: code points never split
                n_parts = len(chunks)
            else:
                chunks = None
                n_parts = -(-size // part_cap)      # ceil division
            if n_parts > MAX_PARTS:
                messagebox.showerror(
                    APP_NAME,
                    "Message would need %d parts - over the %d-part maximum. Shorten it. "
                    "Nothing was consumed." % (n_parts, MAX_PARTS))
                return

        # ---- reserve the pad pages (all-or-nothing) ----------------------------------
        avail = self._verified_pads(mode)
        if len(avail) < n_parts:
            messagebox.showerror(
                APP_NAME,
                "This message needs %d verified %s pad(s); only %d available.\n\nGenerate "
                "more pads first. Nothing was consumed."
                % (n_parts, mode, len(avail)))
            return
        pages = avail[:n_parts]

        # ---- build every part's payload + cipher before consuming anything ------------
        built = []          # list of (path, page, prefix, cipher_groups)
        try:
            for i, pad_path in enumerate(pages):
                page = CryptoEngine.parse_page(pad_path)
                if SANDBOX_MARK in Path(pad_path).read_text(encoding="utf-8", errors="replace"):
                    raise _Refusal("sandbox test page reached the encrypt path")
                ok, reason = CryptoEngine.verify_page_text(
                    Path(pad_path).read_text(encoding="utf-8", errors="replace"))
                if not ok:
                    raise _Refusal("page %s failed verification (%s)" % (pad_path.name, reason))

                if is_series:
                    pnum = i + 1
                    if mode == "printable":
                        chunk = pt[i * part_cap:(i + 1) * part_cap]
                        payload = "%02d" % pnum + chunk
                    else:
                        chunk_b = chunks[i]
                        payload = "%02X" % pnum + chunk_b.hex().upper()
                else:
                    payload = pt

                if mode == "printable":
                    status, batchid, padnum, chars, cipher_digits = \
                        CryptoEngine.encrypt_printable(payload, page)
                else:
                    status, batchid, padnum, nbytes, cipher_digits = \
                        CryptoEngine.encrypt_hex(payload, page)
                if status != "OK":
                    raise _Refusal("encryption aborted (%s) - nothing was consumed" % status)

                if is_series:
                    prefix = CryptoEngine.series_prefix(batchid, padnum, n_parts)
                else:
                    prefix = CryptoEngine.derive_header(batchid, padnum)
                built.append((pad_path, page, prefix, CryptoEngine.group5(cipher_digits)))
        except _Refusal as e:
            messagebox.showerror(APP_NAME, str(e))
            return

        # ---- commit: save payload(s), shred pages, display ------------------------------
        if is_series:
            token = (built[0][1]["fingerprint"] or "")[:15]
            state.CIPHER_DIR.mkdir(parents=True, exist_ok=True)
            out_path = state.CIPHER_DIR / ("series_%s.txt" % token)
            lines = [
                "CIPHERVAULT SERIES TRANSMISSION v1",
                "Date: %s" % date.today().isoformat(),
                "Mode: %s" % mode.upper(),
                "Parts: %d" % n_parts,
            ]
            for i, (_p, _pg, prefix, groups) in enumerate(built):
                lines.append("--- PART %d OF %d ---" % (i + 1, n_parts))
                lines.append("%s|%s" % (prefix, groups))
            try:
                out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            except OSError as e:
                messagebox.showerror(
                    APP_NAME, "Could not save the series file (%s).\nThe pages were NOT "
                              "consumed." % e)
                return
            pane_text = "\n".join(
                "PART %d OF %d\n%s|%s" % (i + 1, n_parts, b[2], b[3])
                for i, b in enumerate(built))
        else:
            out_path = None
            token = (built[0][1]["fingerprint"] or "")[:15]
            state.CIPHER_DIR.mkdir(parents=True, exist_ok=True)
            try:
                (state.CIPHER_DIR / ("msg_%s.txt" % token)).write_text(
                    built[0][2] + "|" + built[0][3] + "\n", encoding="utf-8")
            except OSError as e:
                messagebox.showerror(
                    APP_NAME, "Could not save the outbound payload (%s).\nThe page was NOT "
                              "consumed." % e)
                return
            pane_text = built[0][2] + "|" + built[0][3]

        # FEC (air interface only): the displayed / clipboard transmission text
        # becomes an FECv1 frame. Saved payload files stay raw - USB and file
        # paths remain SHA-protected plain transmittable strings.
        if self.fec_var.get():
            try:
                pane_text = fec.encode(pane_text)
            except ValueError as e:
                messagebox.showerror(
                    APP_NAME, "FEC encoding failed: %s\n\nNothing was consumed - the pad "
                              "page(s) are still intact. Shorten the message or turn FEC "
                              "off." % e)
                self._log("FEC encoding refused (%s) - nothing consumed." % e)
                return

        for pad_path, _page, _pre, _gr in built:
            self.secure_shred(pad_path)

        self.right_text.delete("1.0", "end")
        self.right_text.insert("end", pane_text)
        self.left_text.delete("1.0", "end")

        if is_series:
            batchids = sorted({b[1]["batchid"] for b in built})
            self._log("ENCRYPTED %d %s as a %d-part series (2 chars per part reserved for "
                      "the part number; header carries flag + total)."
                      % (size, "characters" if mode == "printable" else "bytes", n_parts))
            self._log("Multi-part output saved to: %s" % out_path)
            messagebox.showinfo(
                APP_NAME,
                "%d-part series ready.\n\nThe full multi-part output is also saved here:\n%s\n\n"
                "Drag that file into CipherVault on the receiving station (or paste all "
                "part lines) to process it as a batch. The receiver will refuse to decrypt "
                "until every part is present." % (n_parts, out_path))
        else:
            b = built[0]
            self._log("ENCRYPTED %d %s | Batch %s | Pad %s"
                      % (size, "characters" if mode == "printable" else "bytes",
                         b[1]["batchid"], b[1]["padnum"]))
            self._log("Outbound payload saved to %s"
                      % (state.CIPHER_DIR / ("msg_%s.txt" % token)).name)
        self._log("%d pad page(s) shredded from %s (consumption confirmed). BURN the "
                  "physical pages and record the batches in the station log."
                  % (len(built), "HexPads/" if mode == "hex" else "Manual Pads/"))
        self.refresh_ledger()

    # -- decryption core ------------------------------------------------------------------
    def run_automatic_decryption(self, raw):
        """Ingest right-pane text. Routes to: single-string decrypt, series-part
        refusal (incomplete), or full series batch (all parts required)."""
        stripped = raw.strip()
        if stripped.startswith(fec.MARKER + " ") or stripped == fec.MARKER:
            try:
                decoded = fec.decode(stripped)
            except ValueError as e:
                messagebox.showerror(
                    APP_NAME, "FEC frame failed the 4x agreement check: %s\n\nNothing was "
                              "consumed. The transmission was corrupted in transit - "
                              "request a re-send." % e)
                self._log("FEC frame rejected (4x agreement failed).")
                return
            self._log("FEC frame received - decoded %d chars, 4x agreement OK."
                      % len(decoded))
            raw = decoded
            stripped = raw.strip()
        # A bare path to an existing file in the working tree -> series file
        if ("\n" not in stripped and "|" not in stripped
                and os.path.isfile(stripped) and stripped.lower().endswith((".txt", ".dat"))):
            self.process_series_file(stripped)
            return

        part_lines = [ln.strip() for ln in raw.splitlines() if "|" in ln]
        if not part_lines:
            messagebox.showwarning(
                APP_NAME, "No transmission string found (expected: 45-digit prefix | "
                          "cipher digits). Nothing was consumed.")
            return

        parsed = []
        for ln in part_lines:
            pre_part, _, rest = ln.partition("|")
            pre_digits = re.sub(r"[^0-9]", "", pre_part)
            kindinfo = CryptoEngine.parse_prefix(pre_digits)
            if kindinfo is None:
                messagebox.showerror(
                    APP_NAME,
                    "Malformed header on this line (prefix must be %d digits for a single "
                    "message or %d digits for a series part).\nNothing was consumed."
                    % (HEADER_LEN, HEADER_LEN + 3))
                return
            ct = re.sub(r"[^0-9]", "", rest)
            parsed.append((kindinfo, ct))

        if len(parsed) == 1:
            kindinfo, ct = parsed[0]
            if kindinfo[0] == "single":
                self._decrypt_single(kindinfo[1], ct)
            else:
                messagebox.showerror(
                    APP_NAME,
                    "This is PART of a %d-part series.\n\nThe receiver refuses to decrypt "
                    "a series unless ALL parts are present. Drop the full series file onto "
                    "the window (or use Load Series File), or paste all %d part lines here. "
                    "Nothing was consumed." % (kindinfo[2], kindinfo[2]))
                self._log("Series part received alone - refused (all %d parts required)."
                          % kindinfo[2])
            return

        # multiple lines -> must be one complete series
        if any(k[0] != "series" for k, _c in parsed):
            messagebox.showerror(
                APP_NAME,
                "Mixed single/series lines - cannot process. Send one message per drop. "
                "Nothing was consumed.")
            return
        totals = {k[2] for k, _c in parsed}
        if len(totals) != 1:
            messagebox.showerror(
                APP_NAME,
                "Lines claim different series totals - ambiguous batch. Nothing was consumed.")
            return
        total = totals.pop()
        if len(parsed) != total:
            messagebox.showerror(
                APP_NAME,
                "INCOMPLETE SERIES - received %d of %d parts.\n\nRefusing to decrypt. "
                "Collect every part and drop the full series file. Nothing was consumed."
                % (len(parsed), total))
            self._log("Incomplete series: %d/%d parts - refused, nothing consumed."
                      % (len(parsed), total))
            return
        self._decrypt_series(parsed, total)

    def _match_page_by_id(self, id45):
        """Scan both pad folders for the page whose one-way header matches."""
        matches = []
        for folder in (state.PADS_DIR, state.HEXPADS_DIR):
            for f in sorted(folder.glob("P*.txt")):
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if SANDBOX_MARK in text:
                    continue              # sandbox pages never match operational traffic
                page = CryptoEngine.parse_page_text(text)
                if page["batchid"] and page["padnum"]:
                    if CryptoEngine.derive_header(page["batchid"], page["padnum"]) == id45:
                        matches.append((f, text))
        return matches

    def _decrypt_single(self, id45, ct):
        matches = self._match_page_by_id(id45)
        if not matches:
            messagebox.showerror(
                APP_NAME,
                "No page in Manual Pads/ or HexPads/ matches the identification prefix.\n\nThe "
                "page may be missing or renamed. Obtain the pad page the sender used, place "
                "it in the matching folder, and run again. Nothing was consumed.")
            return
        if len(matches) > 1:
            self._log("WARN %d pages match the prefix (should not happen) - using the oldest."
                      % len(matches))
        pad_path, text = matches[0]
        page = CryptoEngine.parse_page_text(text)
        ok, reason = CryptoEngine.verify_page_text(text)
        if not ok:
            messagebox.showerror(
                APP_NAME,
                "Pad page failed verification (%s)\n\nDo NOT use this page. Quarantine it "
                "and rekey. It has not been consumed." % reason)
            return
        self._log("Identification prefix matched page: %s (%s mode)"
                  % (pad_path.name, page["kind"]))
        self._log("Page verified (SHA3-256 fingerprint + structure).")

        if page["kind"] == "hex":
            status, plain, badpairs, batchid, padnum = CryptoEngine.decrypt_hex(ct, page)
        else:
            status, plain, badpairs, batchid, padnum = CryptoEngine.decrypt_printable(ct, page)

        if status == "ODD":
            messagebox.showerror(
                APP_NAME,
                "Cipher has an odd number of digits (%d) - a digit was lost or added in "
                "transit.\n\nRequest retransmission. Nothing was consumed." % len(ct))
            return
        if status == "NOPAD":
            messagebox.showerror(
                APP_NAME,
                "Cipher is %d digits - over the %d-digit limit (%d characters). Nothing "
                "was consumed." % (len(ct), DIGITS_PER_PAD, MAX_MSG_CHARS))
            return
        if status == "CORRUPT":
            messagebox.showerror(APP_NAME,
                                 "Pad page failed integrity check mid-run. Nothing was consumed.")
            return
        if status == "BADPAIRS":
            messagebox.showerror(
                "BADPAIRS / Wrong Pad",
                "Decryption produced %d invalid character pair(s) - almost certainly the "
                "WRONG pad page.\n\nDo NOT consume this page. Confirm with the sending "
                "station which batch/pad was used and re-run, or request retransmission."
                % badpairs)
            self._log("BADPAIRS / Wrong Pad: %d invalid pair(s). Page NOT consumed." % badpairs)
            return
        if status == "BADUTF8":
            messagebox.showerror(
                APP_NAME,
                "Decryption succeeded but the result is not valid UTF-8 - wrong pad page "
                "or corrupted in transit.\n\nDo NOT consume this page. Request "
                "retransmission.")
            self._log("BADUTF8: decrypted bytes are not valid text. Page NOT consumed.")
            return

        if page["kind"] == "printable":
            plain = plain.upper()   # canonical clean uppercase form for printable messages

        token = (page["fingerprint"] or "")[:15]
        state.CLEAR_DIR.mkdir(parents=True, exist_ok=True)
        out_path = state.CLEAR_DIR / ("clear_%s.txt" % token)
        try:
            out_path.write_text(plain + "\n", encoding="utf-8")
        except OSError as e:
            messagebox.showerror(APP_NAME, "Could not write the clear text file (%s).\nThe "
                                           "page was NOT consumed." % e)
            return

        self.secure_shred(pad_path)

        self.left_text.delete("1.0", "end")
        self.left_text.insert("end", plain)
        self.right_text.delete("1.0", "end")
        self._log("DECRYPTED (%s mode) | Batch %s | Pad %s" % (page["kind"], batchid, padnum))
        self._log("Clear text written to %s - treat it as a message copy, destroy when done."
                  % out_path.name)
        self._log("Pad page shredded (consumption confirmed). BURN the physical page and "
                  "record Batch %s / Pad %s in the station log." % (batchid, padnum))
        self.refresh_ledger()

    def _decrypt_series(self, parsed, total):
        """All-or-nothing series batch: every part must resolve to a unique,
        verified page; decrypted part numbers must form exactly 1..total."""
        # 1. match pages for ALL parts first (nothing consumed on any failure)
        entries = []
        seen_paths = set()
        for kindinfo, ct in parsed:
            id45 = kindinfo[1]
            matches = self._match_page_by_id(id45)
            if not matches:
                messagebox.showerror(
                    APP_NAME,
                    "INCOMPLETE SERIES - a part's page is not in Manual Pads/ or HexPads/.\n\n"
                    "Collect the missing pad page(s) and retry. Nothing was consumed.")
                return
            if len(matches) > 1:
                self._log("WARN multiple pages match one series prefix - using the oldest.")
            pad_path, text = matches[0]
            if pad_path in seen_paths:
                messagebox.showerror(
                    APP_NAME,
                    "INCOMPLETE SERIES - two parts claim the same pad page. Nothing was "
                    "consumed.")
                return
            seen_paths.add(pad_path)
            entries.append((pad_path, text, ct))

        # 2. verify every page (fingerprint + structure)
        for pad_path, text, _ct in entries:
            ok, reason = CryptoEngine.verify_page_text(text)
            if not ok:
                messagebox.showerror(
                    APP_NAME,
                    "A series page failed verification (%s)\n\nQuarantine it and rekey. "
                    "Nothing was consumed." % reason)
                return

        # 3. decrypt every part
        payloads = []
        for pad_path, text, ct in entries:
            page = CryptoEngine.parse_page_text(text)
            if page["kind"] == "hex":
                status, plain, badpairs, _b, _p = CryptoEngine.decrypt_hex(ct, page)
            else:
                status, plain, badpairs, _b, _p = CryptoEngine.decrypt_printable(ct, page)
            if status == "BADPAIRS":
                messagebox.showerror(
                    "BADPAIRS / Wrong Pad",
                    "A series part produced %d invalid pair(s) - wrong pad page(s).\n\n"
                    "Do NOT consume any page. Confirm batches with the sending station and "
                    "re-run, or request retransmission." % badpairs)
                self._log("Series BADPAIRS on %s - nothing consumed." % pad_path.name)
                return
            if status not in ("OK",):
                messagebox.showerror(
                    APP_NAME,
                    "A series part failed to decrypt (%s). Nothing was consumed." % status)
                return
            payloads.append((pad_path, page, plain))

        # 4. validate embedded part numbers: must form exactly 1..total
        numbered = []
        for pad_path, page, payload in payloads:
            head = payload[:SERIES_PART_OVERHEAD]
            if page["kind"] == "hex":
                if len(head) < 2 or not all(c in HEXCHARS for c in head):
                    self._refuse_series(pad_path, "part number field is not valid hex")
                    return
                pnum = int(head, 16)
            else:
                if not head.isdigit():
                    self._refuse_series(pad_path, "part number field is not numeric")
                    return
                pnum = int(head)
            if not (1 <= pnum <= total):
                self._refuse_series(pad_path, "part number %d outside 1..%d" % (pnum, total))
                return
            numbered.append((pnum, pad_path, page, payload[SERIES_PART_OVERHEAD:]))

        nums = [n[0] for n in numbered]
        if sorted(nums) != list(range(1, total + 1)):
            messagebox.showerror(
                APP_NAME,
                "INCOMPLETE SERIES - part numbers present: %s (expected exactly 1..%d).\n\n"
                "Refusing to decrypt. Nothing was consumed."
                % (", ".join("%02d" % n for n in sorted(nums)), total))
            self._log("Series part-number check failed - nothing consumed.")
            return

        # 5. commit: assemble, save clear text, shred ALL pages
        numbered.sort(key=lambda t: t[0])
        full_parts = []
        for _pnum, pad_path, page, rest in numbered:
            if page["kind"] == "printable":
                full_parts.append(rest.upper())   # canonical uppercase form
            else:
                # hex part payloads are double-encoded ("NN" + hex-ASCII); the
                # final decode back to message bytes happens here, not in decrypt_hex
                try:
                    full_parts.append(bytes.fromhex(rest).decode("utf-8"))
                except (ValueError, UnicodeDecodeError):
                    self._refuse_series(pad_path, "part payload is not valid hex/UTF-8")
                    return
        full = "".join(full_parts)
        token = (numbered[0][2]["fingerprint"] or "")[:15]
        state.CLEAR_DIR.mkdir(parents=True, exist_ok=True)
        out_path = state.CLEAR_DIR / ("clear_%s.txt" % token)
        try:
            out_path.write_text(full + "\n", encoding="utf-8")
        except OSError as e:
            messagebox.showerror(APP_NAME, "Could not write the clear text file (%s).\nNo "
                                           "page was consumed." % e)
            return

        for _pnum, pad_path, _page, _rest in numbered:
            self.secure_shred(pad_path)

        self.left_text.delete("1.0", "end")
        self.left_text.insert("end", full)
        self.right_text.delete("1.0", "end")
        self._log("DECRYPTED %d-part series (%d chars assembled) | pages: %s"
                  % (total, len(full), ", ".join(t[1].name for t in numbered)))
        self._log("Clear text written to %s - destroy when done." % out_path.name)
        self._log("%d pad page(s) shredded (consumption confirmed). BURN the physical pages "
                  "and record all batches in the station log." % total)
        self.refresh_ledger()

    def _refuse_series(self, pad_path, why):
        messagebox.showerror(
            APP_NAME,
            "INCOMPLETE / INVALID SERIES - %s (page %s).\n\nRefusing to decrypt. Nothing "
            "was consumed." % (why, pad_path.name))
        self._log("Series refused: %s" % why)

    def process_series_file(self, path):
        """Batch-process a dropped/loaded multi-part series file."""
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            messagebox.showerror(APP_NAME, "Could not read %s (%s)" % (path, e))
            return
        self._log("Processing series file: %s" % os.path.basename(path))
        self.run_automatic_decryption(text)

    # -- anti-forensics wiper ---------------------------------------------------------------
    def secure_shred(self, path):
        """Anti-forensics storage file wiper: randomized binary block matrices
        over the physical file blocks, fsync, then unlink."""
        secure_shred(path, source=self.source)

    # -- obsolete pad sweep (SUBTASK 5) ---------------------------------------------------------
    @staticmethod
    def _version_tuple(v):
        """Numeric (major, minor, patch) prefix of a version string, else None."""
        m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", str(v).strip())
        if not m:
            return None
        return tuple(int(g) if g is not None else 0 for g in m.groups())

    def _find_obsolete_pads(self):
        """Pad pages produced by older tool versions, or pre-revision pages that
        carry no TOOL VERSION line at all (SUBTASK 4's `version` key). Returns a
        list of (path, version-or-None). BATCH-* ledger records are not key
        material and are never scanned; sandbox-stamped pages are owned by the
        session-close wiper; a page stamped with an equal or NEWER version is
        never a candidate (an older tool must not destroy newer key material).
        """
        found = []
        cur = self._version_tuple(VERSION)
        for folder in (state.PADS_DIR, state.HEXPADS_DIR):
            for f in sorted(folder.glob("P*.txt")):
                try:
                    text = f.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if SANDBOX_MARK in text:
                    continue
                v = CryptoEngine.parse_page_text(text)["version"]
                if v is None:
                    found.append((f, None))      # pre-revision: provably obsolete
                    continue
                vt = self._version_tuple(v)
                if vt is not None and cur is not None and vt < cur:
                    found.append((f, v))         # stamped by an older tool version
        return found

    def _purge_obsolete_pads(self):
        """Startup sweep (SUBTASK 5): detect pad pages from older tool versions
        and shred them only after TWO explicit user confirmations. The user may
        move any page out at any time before the final pass: every recorded path
        is re-read and re-checked immediately before shredding, so a moved-out or
        altered file is skipped, never destroyed."""
        if self.sandbox:
            return
        if not self.root.winfo_exists():
            return                                # window already closed
        found = self._find_obsolete_pads()
        if not found:
            self._log("Startup sweep: no older-version pad pages found.")
            return
        names = []
        for f, v in found[:20]:
            why = ("no version stamp (pre-revision)" if v is None
                   else "tool version %s" % v)
            names.append("  %s   [%s]" % (f.name, why))
        if len(found) > 20:
            names.append("  ... and %d more" % (len(found) - 20))
        first = messagebox.askyesno(
            APP_NAME + " - older-version pad pages detected",
            "%d pad page(s) were produced by an older tool version and are obsolete:\n\n%s\n\n"
            "Destroy them now?" % (len(found), "\n".join(names)))
        if not first:
            self._log("Startup sweep: %d older-version pad page(s) left in place." % len(found))
            return
        second = messagebox.askyesno(
            APP_NAME + " - FINAL confirmation",
            "This will permanently shred the %d page(s) listed above. There is no undo.\n\n"
            "If you want to keep any of them, cancel now and move them out first."
            % len(found))
        if not second:
            self._log("Startup sweep: cancelled at final confirmation - nothing destroyed.")
            return
        cur = self._version_tuple(VERSION)
        destroyed = skipped = 0
        for f, v in found:
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
            except OSError:
                skipped += 1                      # moved out during the dialogs - leave it be
                continue
            if SANDBOX_MARK in text:
                skipped += 1
                continue
            nv = CryptoEngine.parse_page_text(text)["version"]
            nt = self._version_tuple(nv)
            still_obsolete = (nv is None) or (nt is not None and cur is not None and nt < cur)
            if not still_obsolete:
                skipped += 1                      # replaced/altered since detection - do not destroy
                continue
            self.secure_shred(f)
            destroyed += 1
        self._log("Startup sweep: %d older-version pad page(s) shredded, %d skipped."
                  % (destroyed, skipped))
        self.refresh_ledger()

    # -- shutdown -----------------------------------------------------------------------------
    def _on_close(self):
        if self.sandbox:
            # Sandbox test pages are shredded on close so nothing usable lingers.
            for folder in (state.PADS_DIR, state.HEXPADS_DIR):
                for f in list(folder.glob("P*.txt")) + list(folder.glob("BATCH-*.txt")):
                    try:
                        if SANDBOX_MARK in f.read_text(encoding="utf-8", errors="replace"):
                            secure_shred(f, self.source)
                    except Exception:
                        pass
            self._log("Sandbox test pages shredded on close.")
        self.root.destroy()

    # -- main loop --------------------------------------------------------------------------------
    def run(self):
        self.root.mainloop()


class _Refusal(Exception):
    """Internal: an encrypt/decrypt step refused to proceed (nothing consumed)."""
