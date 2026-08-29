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
    gen_only = None
    for i, a in enumerate(argv):
        if a == "--generate" and i + 1 < len(argv) and argv[i + 1].isdigit():
            gen_only = int(argv[i + 1])

    if selftest:
        print("SELF CHECK: %s" % ("PASS" if run_selfcheck() else "FAIL"))
        return 0

    _banner()
    ws = os.environ.get("CIPHERVAULT_HOME") or str(Path(__file__).resolve().parent.parent)
    provision_dirs(ws)
    print("  [ OK ] workspace tree provisioned: Manual Pads/ HexPads/ Cipher/ Clear/ audit/ under %s"
          % state.WORKSPACE)

    # 1. System binary check (explicit alert + install terminal + clean re-exec)
    if not EnvironmentBootstrap.check_binaries():
        print("")
        print("Halting: environment is not compliant yet.")
        return 1

    # 1.5. Udev rule setup (non-fatal: tool works without it, but rule
    # prevents DVB driver hijack at boot on dedicated stations).
    EnvironmentBootstrap.ensure_udev_rule()

    # 2. Kernel TV (DVB) driver lock gate. Detects by default and prints
    # the exact release command; changes nothing on the system unless the
    # operator consents (--fix-dvb, or 'y' at the prompt). Even then it
    # only unbinds this dongle's one USB interface - no modules unloaded,
    # no /etc files touched, other tuners and SDR programs unaffected.
    EnvironmentBootstrap.dvb_gate(auto_fix=fix_dvb)

    if gen_only is not None:
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
