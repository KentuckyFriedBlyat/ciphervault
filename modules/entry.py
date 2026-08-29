"""_banner() and main(): argument parsing, workspace provisioning, bootstrap, GUI launch."""

from pathlib import Path
import os
import sys
from . import state
from .compat import messagebox, simpledialog, tk
from config.config import APP_NAME, PRODUCT_LINE, VERSION, CALIBRATION_ENABLED, TUNING_COMPLETE
from .app import VaultApplication
from .bootstrap import EnvironmentBootstrap
from .crypto import CryptoEngine
from .noise import SandboxNoiseSource, SdrNoiseSource
from .selfcheck import run_selfcheck
from .state import provision_dirs

def _banner():
    print("=" * 64)
    print(" %s v%s - %s" % (APP_NAME, VERSION, PRODUCT_LINE))
    print(" RTL-SDR atmospheric noise OTP | Hex mode (primary) + Printable (fallback)")
    print("=" * 64)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    sandbox = "--sandbox" in argv
    selftest = "--selftest" in argv
    hexgen = "--hex" in argv
    fix_dvb = "--fix-dvb" in argv
    no_sweep = "--no-sweep" in argv
    dry_run = "--dry-run" in argv
    gen_only = None
    operator = None
    station = None
    panic_trigger = False
    panic_hash = None
    for i, a in enumerate(argv):
        if a == "--generate" and i + 1 < len(argv) and argv[i + 1].isdigit():
            gen_only = int(argv[i + 1])
        elif a == "--operator" and i + 1 < len(argv):
            operator = argv[i + 1]
        elif a == "--station" and i + 1 < len(argv):
            station = argv[i + 1]
        elif a == "--panic" and i + 1 < len(argv):
            # --panic HASH - triggers panic if HASH matches configured trigger
            panic_trigger = True
            panic_hash = argv[i + 1]
        elif a == "--panic-hash" and i + 1 < len(argv):
            # --panic-hash HASH - sets the trigger hash for external scripts
            panic_hash = argv[i + 1]

    if selftest:
        print("SELF CHECK: %s" % ("PASS" if run_selfcheck() else "FAIL"))
        return 0
    
    # Version flag
    if "--version" in argv:
        from config.config import VERSION
        print("CipherVault v%s" % VERSION)
        return 0
    
    # Verify mode: check all pads in a directory
    verify_path = None
    for i, a in enumerate(argv):
        if a == "--verify" and i + 1 < len(argv):
            verify_path = argv[i + 1]
    if verify_path:
        from modules.crypto import CryptoEngine
        p = Path(verify_path)
        if not p.exists():
            print("  [FAIL] Path does not exist: %s" % verify_path)
            return 1
        if not p.is_dir():
            print("  [FAIL] Path is not a directory: %s" % verify_path)
            return 1
        
        print("Verifying pads in: %s" % verify_path)
        ok_count = 0
        fail_count = 0
        for f in p.glob("P*.txt"):
            ok, reason = CryptoEngine.verify_page(f)
            if ok:
                ok_count += 1
                print("  [ OK ] %s" % f.name)
            else:
                fail_count += 1
                print("  [FAIL] %s: %s" % (f.name, reason))
        
        print("")
        print("Results: %d OK, %d FAILED, %d TOTAL" % (ok_count, fail_count, ok_count + fail_count))
        return 0 if fail_count == 0 else 1
    
    _banner()
    
    # Verify config checksum
    try:
        import hashlib
        config_path = Path(__file__).resolve().parent.parent / "config" / "config.py"
        if config_path.exists():
            config_hash = hashlib.sha256(config_path.read_bytes()).hexdigest()
            from config.config import CONFIG_CHECKSUM
            if CONFIG_CHECKSUM != "PLACEHOLDER_CHECKSUM" and config_hash != CONFIG_CHECKSUM:
                print("  [FAIL] Config checksum mismatch!")
                print("  Expected: %s" % CONFIG_CHECKSUM)
                print("  Actual:   %s" % config_hash)
                print("  Config may be corrupted or tampered with.")
                print("  Refusing to continue for security reasons.")
                return 1
    except Exception as e:
        print("  [WARN] Could not verify config checksum: %s" % e)
    
    # Set operator/station IDs if provided via command-line
    if operator:
        from config.config import OPERATOR_ID, STATION_ID
        import config.config as cfg
        cfg.OPERATOR_ID = operator
        cfg.STATION_ID = station
        print("  [ OK ] Operator: %s, Station: %s" % (operator, station or "<default>"))
    
    # Check for panic trigger (command-line or environment variable)
    panic_env = os.environ.get("CIPHERVAULT_PANIC", "")
    if panic_trigger and panic_hash:
        # Command-line trigger
        if panic_hash == "TRIGGER_PANIC":
            print("  [PANIC] Triggered by command-line - initiating panic reset")
            app = VaultApplication(source=SandboxNoiseSource())
            app._execute_panic_reset()
            print("  [ OK ] Panic reset complete - program reset to factory defaults")
            return 0
    elif panic_env == "TRIGGER_PANIC":
        # Environment variable trigger
        print("  [PANIC] Triggered by environment variable - initiating panic reset")
        app = VaultApplication(source=SandboxNoiseSource())
        app._execute_panic_reset()
        print("  [ OK ] Panic reset complete - program reset to factory defaults")
        return 0
    
    ws = os.environ.get("CIPHERVAULT_HOME") or str(Path(__file__).resolve().parent.parent)
    provision_dirs(ws)
    print("  [ OK ] workspace tree provisioned: Manual Pads/ HexPads/ Cipher/ Clear/ audit/ certificates/ under %s"
          % state.WORKSPACE)

    # 1. System binary check (explicit alert + install terminal + clean re-exec)
    if not EnvironmentBootstrap.check_binaries():
        print("")
        print("Halting: environment is not compliant yet.")
        return 1

    # 1.5. Udev rule setup (non-fatal: tool works without it, but rule
    # prevents DVB driver hijack at boot on dedicated stations).
    # Only checks if a dongle is present. Uses cached state from config/config.py
    # to avoid re-checking on every run.
    EnvironmentBootstrap.ensure_udev_rule()

    # 2. Kernel TV (DVB) driver lock gate. Detects by default and prints
    # the exact release command; changes nothing on the system unless the
    # operator consents (--fix-dvb, or 'y' at the prompt). Even then it
    # only unbinds this dongle's one USB interface - no modules unloaded,
    # no /etc files touched, other tuners and SDR programs unaffected.
    EnvironmentBootstrap.dvb_gate(auto_fix=fix_dvb)

    if gen_only is not None:
        if dry_run:
            print("[DRY RUN] Would generate %d %s pads" % (gen_only, "hex" if hexgen else "printable"))
            print("[DRY RUN] No actual generation or capture performed.")
            return 0
        src = SandboxNoiseSource() if sandbox else SdrNoiseSource()
        try:
            CryptoEngine.trigger_generation(n_pads=gen_only,
                                            kind="hex" if hexgen else "printable",
                                            source=src,
                                            auto_sweep=not no_sweep)
        except Exception as e:
            print("  [FAIL] %s" % e)
            return 1
        return 0

    # 3. Dynamic tkinter bootstrap (install terminal + clean re-exec if needed)
    if not EnvironmentBootstrap.ensure_tkinter():
        print("")
        print("Halting: GUI toolkit unavailable.")
        return 1
    if tk is None or simpledialog is None:
        print("Halting: GUI toolkit still unavailable after bootstrap.")
        return 1

    # 3.5. Calibration (find frequency limits, only if not already done)
    from .noise import SdrNoiseSource as _SdrNoiseSource
    if CALIBRATION_ENABLED and not TUNING_COMPLETE:
        try:
            src = _SdrNoiseSource()
            src.calibrate(log=print)
        except Exception as e:
            print("  [WARN] calibration failed: %s - continuing with defaults" % e)

    # 4. USB bus hardware ping (honest: a TV-locked dongle reports as NOT usable)
    found, detail = EnvironmentBootstrap.ping_dongle()
    if found:
        print("  [ OK ] dongle ping: %s" % detail)
    else:
        print("  [WARN] %s" % detail)

    # 5. Launch the GUI application
    src = SandboxNoiseSource() if sandbox else SdrNoiseSource()
    app = VaultApplication(source=src, sandbox=sandbox)
    if not found and not sandbox:
        messagebox.showwarning(
            "No RTL-SDR dongle detected",
            detail + "\n\nYou can still use decryption with pad pages generated "
            "elsewhere. Pad generation will be unavailable until a dongle is "
            "connected and verified.")
    app.run()
    return 0
