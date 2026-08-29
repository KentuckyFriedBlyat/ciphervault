"""Environment bootstrap: binary checks, tkinter install + re-exec, dongle ping."""

import glob
import os
import shutil
import subprocess
import sys
from pathlib import Path
from config.config import APP_NAME, REQUIRED_BINARIES, RTL_USB_IDS

class EnvironmentBootstrap:
    """Startup checks: system binaries, tkinter, USB dongle ping.

    When something is missing the bootstrap opens an active terminal window
    matching the host environment and runs elevated package installation for
    the detected distro package manager - explaining clearly WHY the sudo
    password is being requested - then re-executes this script for a clean
    pass.
    """

    TERMINALS = ("kitty", "alacritty", "gnome-terminal", "konsole", "xterm")
    REEXEC_FLAG = "CIPHERVAULT_REEXEC"
    NO_AUTOINSTALL_FLAG = "CIPHERVAULT_NO_AUTOINSTALL"

    # tool -> package, per distro family (ported from the original setup tool)
    PKG_MAP = {
        "apt":    {"awk": "mawk", "rtl_sdr": "rtl-sdr"},
        "dnf":    {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
        "pacman": {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
        "zypper": {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
    }
    TK_PKG = {
        "apt": "python3-tk",
        "dnf": "python3-tkinter",
        "pacman": "tk",
        "zypper": "python-tk",
    }

    @staticmethod
    def detect_pkg_manager():
        for exe, name in (("apt-get", "apt"), ("dnf", "dnf"),
                          ("pacman", "pacman"), ("zypper", "zypper")):
            if shutil.which(exe):
                return name
        return None

    @classmethod
    def missing_binaries(cls):
        return [b for b in REQUIRED_BINARIES if not shutil.which(b)]

    @classmethod
    def packages_for(cls, missing, mgr):
        base = cls.PKG_MAP.get(mgr, {})
        pkgs = []
        for tool in missing:
            pkg = base.get(tool, "coreutils")
            if pkg not in pkgs:
                pkgs.append(pkg)
        return pkgs

    @staticmethod
    def install_command(mgr, pkgs):
        joined = " ".join(pkgs)
        if mgr == "apt":
            return "sudo apt-get update -qq && sudo apt-get install -y %s" % joined
        if mgr == "dnf":
            return "sudo dnf install -y %s" % joined
        if mgr == "pacman":
            return "sudo pacman -S --noconfirm %s" % joined
        if mgr == "zypper":
            return "sudo zypper --non-interactive install %s" % joined
        return None

    @staticmethod
    def find_terminal():
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            return None
        for t in EnvironmentBootstrap.TERMINALS:
            if shutil.which(t):
                return t
        return None

    @staticmethod
    def _run_in_terminal(term, title, body):
        """Open `body` in the detected terminal window and wait for it.
        Returns True if the window ran, False if it could not be opened."""
        if term == "kitty":
            argv = [term, "sh", "-c", body]
        elif term == "alacritty":
            argv = [term, "-t", title, "-e", "sh", "-c", body]
        elif term == "gnome-terminal":
            argv = [term, "--title", title, "--wait", "--", "bash", "-c", body]
        elif term == "konsole":
            argv = [term, "--title", title, "-e", "bash", "-c", body]
        else:  # xterm
            argv = [term, "-T", title, "-hold", "-e", "bash", "-c", body]
        try:
            subprocess.run(argv, check=False)
            return True
        except OSError:
            return False

    @classmethod
    def launch_install_terminal(cls, mgr, pkgs, what):
        """Open a terminal window that explains exactly why administrator
        privileges are needed, runs the elevated install command for the
        detected distro package manager, and holds open afterwards.
        Returns True if the terminal was launched."""
        cmd = cls.install_command(mgr, pkgs)
        if not cmd:
            return False
        term = cls.find_terminal()
        if not term:
            return False
        body = (
            "echo '================================================================'\n"
            "echo ' %s - Core Privacy System : environment setup'\n"
            "echo ''\n"
            "echo ' This program checked your machine and found missing pieces:\n"
            "echo '   %s\n"
            "echo ''\n"
            "echo ' Installing them requires administrator privileges, so the\n"
            "echo ' next prompt will ask for YOUR user password (sudo). It is\n"
            "echo ' used ONLY to install the packages listed above - nothing\n"
            "echo ' else runs. This is normal first-run setup.\n"
            "echo '================================================================'\n"
            "sleep 2\n"
            "%s\n"
            "\necho ''\necho '--- Install pass finished. Press Enter to close this window.'\n"
            "read -r _" % (APP_NAME, ", ".join(pkgs), cmd)
        )
        return cls._run_in_terminal(term, "%s setup" % APP_NAME, body)

    @staticmethod
    def reexec():
        """Clean script re-execution pass after an install terminal."""
        os.execv(sys.executable,
                 [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:])

    # -- system binary check -------------------------------------------------
    @classmethod
    def check_binaries(cls):
        """Exhaustive startup check of every required CLI dependency.

        Missing tools -> explicit terminal alert. If a GUI terminal is
        available the bootstrap opens it to run the elevated install for
        the detected package manager (with a plain-language explanation of
        why the password is needed), then re-executes for a clean pass;
        otherwise (or on a second failing pass) it halts with instructions.
        """
        missing = cls.missing_binaries()
        if not missing:
            print("  [ OK ] all required system binaries present")
            return True
        mgr = cls.detect_pkg_manager()
        print("  [FAIL] missing system binaries: %s" % ", ".join(missing))
        if mgr is None:
            print("")
            print("No supported package manager found (apt, dnf, pacman, or zypper).")
            print("Install the rtl-sdr userspace package and coreutils by whatever")
            print("method your distro provides, then re-run this program.")
            return False
        pkgs = cls.packages_for(missing, mgr)
        cmd = cls.install_command(mgr, pkgs)
        print("")
        print("Detected package manager: %s" % mgr)
        print("Packages needed:          %s" % ", ".join(pkgs))
        print("Install command:          %s" % cmd)
        if os.environ.get(cls.NO_AUTOINSTALL_FLAG):
            print("Auto-install disabled (%s). Run the command above, then re-run."
                  % cls.NO_AUTOINSTALL_FLAG)
            return False
        if not cls.find_terminal():
            print("")
            print("No GUI terminal window available to run the install automatically.")
            print("Run the command above in a terminal, then re-run this program.")
            return False
        if os.environ.get(cls.REEXEC_FLAG):
            print("")
            print("Still missing after an install pass - halting. Fix the install")
            print("(the machine may be offline or the package name may differ on")
            print("this distro), then re-run this program.")
            return False
        print("")
        print("Opening a terminal window to install the missing packages.")
        print("That window will explain why it asks for your sudo password.")
        cls.launch_install_terminal(mgr, pkgs, "system tools")
        os.environ[cls.REEXEC_FLAG] = "1"
        cls.reexec()
        return False      # not reached: reexec replaces the process

    # -- dynamic tkinter bootstrap -------------------------------------------
    @classmethod
    def ensure_tkinter(cls):
        """Check that 'tkinter' is importable; if not, open a terminal window
        that installs it with sudo for the detected package manager (with an
        explanation of why), then re-execute this script for a clean pass."""
        try:
            import tkinter  # noqa: F401
            print("  [ OK ] tkinter available in this Python environment")
            return True
        except ImportError:
            pass
        mgr = cls.detect_pkg_manager()
        if mgr is None or mgr not in cls.TK_PKG:
            print("  [FAIL] tkinter is missing and no supported package manager was")
            print("         found to install it. Install python3-tk through your")
            print("         distro's normal method, then re-run this program.")
            return False
        pkg = cls.TK_PKG[mgr]
        cmd = cls.install_command(mgr, [pkg])
        print("  [WARN] tkinter missing - install command: %s" % cmd)
        if os.environ.get(cls.NO_AUTOINSTALL_FLAG):
            print("Auto-install disabled (%s). Run the command above, then re-run."
                  % cls.NO_AUTOINSTALL_FLAG)
            return False
        if not cls.find_terminal():
            print("No GUI terminal window available to install tkinter automatically.")
            print("Run the command above in a terminal, then re-run this program.")
            return False
        if os.environ.get(cls.REEXEC_FLAG):
            print("tkinter still missing after an install pass - halting.")
            return False
        print("Opening a terminal window to install tkinter (it will explain")
        print("why the sudo password is requested).")
        cls.launch_install_terminal(mgr, [pkg], "GUI toolkit (tkinter)")
        os.environ[cls.REEXEC_FLAG] = "1"
        cls.reexec()
        return False      # not reached: reexec replaces the process

    # -- udev rule setup for DVB driver override -----------------------------
    UDEV_RULE_FILE = "99-rtlsdr.rules"
    UDEV_RULES_DIR = "/etc/udev/rules.d"

    @classmethod
    def check_udev_rule(cls):
        """Check if the CipherVault udev rule is installed.

        Returns True if the rule file exists in /etc/udev/rules.d/ and
        contains the expected CipherVault identifier.
        """
        rule_path = os.path.join(cls.UDEV_RULES_DIR, cls.UDEV_RULE_FILE)
        if not os.path.exists(rule_path):
            return False
        try:
            with open(rule_path, "r") as f:
                content = f.read()
            return "CipherVault" in content and "0bda" in content
        except (IOError, OSError):
            return False

    @classmethod
    def check_dongle_present(cls, devdir="/dev"):
        """Check if an RTL-SDR dongle is present on the system bus.

        Looks for USB devices with our known vendor/product IDs.
        Works whether or not the DVB driver is bound (udev rule may prevent binding).
        Returns (present, detail) tuple.
        """
        # Scan USB bus for matching devices
        usb_devices = sorted(Path("/sys/bus/usb/devices").glob("[0-9]*-[0-9]*"))
        
        for device_path in usb_devices:
            try:
                vendor_path = device_path / "idVendor"
                product_path = device_path / "idProduct"
                
                if vendor_path.exists() and product_path.exists():
                    vendor = vendor_path.read_text().strip()
                    product = product_path.read_text().strip()
                    
                    if vendor == "0bda" and product in ("2837", "2838", "2839"):
                        return True, "RTL-SDR dongle present"
            except Exception:
                continue
        
        return False, "No matching RTL-SDR dongle found on USB bus"

    @classmethod
    def _save_udev_state(cls, installed):
        """Save udev check state to config/config.py."""
        import re as _re

        config_path = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            "..", "config", "config.py"
        )
        config_path = os.path.normpath(config_path)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (IOError, OSError):
            return False

        # Add udev state if not present
        if "UDEV_CHECKED" not in content:
            content += "\n# Udev rule check state (auto-set on first run)\n"
            content += "UDEV_CHECKED = False\n"
            content += "UDEV_INSTALLED = False\n"

        # Update the values
        content = _re.sub(
            r"UDEV_CHECKED\s*=\s*False",
            "UDEV_CHECKED = True",
            content
        )
        content = _re.sub(
            r"UDEV_INSTALLED\s*=\s*False",
            "UDEV_INSTALLED = %s" % installed,
            content
        )

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except (IOError, OSError):
            return False

    @classmethod
    def ensure_udev_rule(cls):
        """Check and install the udev rule if missing.

        Only checks if a dongle is present. If no dongle, skips the check.
        Saves state to config/config.py to avoid re-checking on subsequent runs.
        This is non-fatal: if it fails, the tool still works (per-session
        DVB release via --fix-dvb or manual unbind).
        """
        from config.config import UDEV_CHECKED, UDEV_INSTALLED

        # Check if dongle is present
        dongle_present, _ = cls.check_dongle_present()
        if not dongle_present:
            # No dongle - skip udev check (decrypt works without dongle)
            return True

        # If we've already checked, just return the cached state
        if UDEV_CHECKED:
            if UDEV_INSTALLED:
                print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
                return True
            else:
                print("  [INFO] udev rule not installed - DVB driver may hijack dongle at boot")
                print("         Use --fix-dvb at startup or run 'sudo udevadm control --reload-rules' after")
                print("         manually installing config/%s to /etc/udev/rules.d/" % cls.UDEV_RULE_FILE)
                return True  # non-fatal: continue

        # First run: check and install if needed
        if cls.check_udev_rule():
            cls._save_udev_state(True)
            print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
            return True

        if cls.setup_udev_rule():
            cls._save_udev_state(True)
            print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
            return True

        # Non-fatal: the tool can still work with per-session unbind
        cls._save_udev_state(False)
        print("  [INFO] udev rule not installed - DVB driver may hijack dongle at boot")
        print("         Use --fix-dvb at startup or run 'sudo udevadm control --reload-rules' after")
        print("         manually installing config/%s to /etc/udev/rules.d/" % cls.UDEV_RULE_FILE)
        return True  # non-fatal: continue

    @classmethod
    def setup_udev_rule(cls):
        """Install the CipherVault udev rule to prevent DVB driver hijack.

        Copies the rule file to /etc/udev/rules.d/ with sudo, then reloads
        udev. Running as root: copies directly. Not root: opens terminal
        with explanation and sudo prompt.

        Returns True if the rule is installed after this call.
        """
        rule_path = os.path.join(cls.UDEV_RULES_DIR, cls.UDEV_RULE_FILE)
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", cls.UDEV_RULE_FILE)
        src = os.path.normpath(src)

        if cls.check_udev_rule():
            return True

        if hasattr(os, "geteuid") and os.geteuid() == 0:
            # Running as root: copy directly
            try:
                shutil.copy2(src, rule_path)
                subprocess.run(["udevadm", "control", "--reload-rules"], check=False)
                subprocess.run(["udevadm", "trigger"], check=False)
                return cls.check_udev_rule()
            except (IOError, OSError, shutil.Error) as e:
                print("  [FAIL] could not install udev rule: %s" % e)
                return False

        # Not root: open terminal with explanation
        term = cls.find_terminal()
        if not term:
            print("  [WARN] udev rule not installed and no terminal available.")
            print("         Copy config/%s to /etc/udev/rules.d/ manually." % cls.UDEV_RULE_FILE)
            print("         Then run: sudo udevadm control --reload-rules")
            return False

        body = (
            "echo '================================================================'\n"
            "echo ' %s - Core Privacy System : udev rule setup'\n"
            "echo ''\n"
            "echo ' The Linux kernel grabs RTL-SDR dongles with its built-in TV'\n"
            "echo ' tuner driver at boot. This prevents noise capture until the'\n"
            "echo ' driver is released per-session. The udev rule below tells'\n"
            "echo ' udev to ignore these specific dongles for the DVB subsystem'\n"
            "echo ' at boot - the driver is still loaded, other DVB devices keep'\n"
            "echo ' working, but YOUR dongle stays free for rtl_sdr.'\n"
            "echo ''\n"
            "echo ' What happens next (and nothing else):'\n"
            "echo '   1. The rule file is copied to /etc/udev/rules.d/ (requires sudo)'\n"
            "echo '   2. udev reloads its rules (requires sudo)'\n"
            "echo '   3. The current dongle state is triggered to apply the new rule'\n"
            "echo ''\n"
            "echo ' The next prompt asks for YOUR user password (sudo), used ONLY for'\n"
            "echo ' the copy and reload commands above - nothing else runs. This is'\n"
            "echo ' normal first-run setup.'\n"
            "echo '================================================================'\n"
            "sleep 2\n"
            "sudo cp %s %s/\n"
            "sudo udevadm control --reload-rules\n"
            "sudo udevadm trigger\n"
            "\necho ''\n"
            "echo '--- udev rule installed. Press Enter to close this window.'\n"
            "read -r _" % (APP_NAME, src, cls.UDEV_RULES_DIR)
        )
        if not cls._run_in_terminal(term, "%s udev setup" % APP_NAME, body):
            return False
        os.environ[cls.REEXEC_FLAG] = "1"
        cls.reexec()
        return False      # not reached: reexec replaces the process

    @classmethod
    def ensure_udev_rule(cls):
        """Check and install the udev rule if missing.

        This is non-fatal: if it fails, the tool still works (per-session
        DVB release via --fix-dvb or manual unbind). But on dedicated pad
        stations, having the rule installed is the cleanest setup.
        """
        if cls.check_udev_rule():
            print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
            return True
        if cls.setup_udev_rule():
            print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
            return True
        # Non-fatal: the tool can still work with per-session unbind
        print("  [INFO] udev rule not installed - DVB driver may hijack dongle at boot")
        print("         Use --fix-dvb at startup or run 'sudo udevadm control --reload-rules' after")
        print("         manually installing config/%s to /etc/udev/rules.d/" % cls.UDEV_RULE_FILE)
        return True      # non-fatal: continue

    # -- kernel TV driver (DVB) lock: detect + opt-in release -----------------
    @classmethod
    def _adapter_usb_info(cls, devdir="/dev", sysroot="/sys"):
        """Map each /dev/dvb/adapterN to the USB device behind it.

        Read-only walk of /dev and /sys: adapter -> frontend0/device (the USB
        interface the DVB driver bound) -> up the tree to the device object
        holding idVendor/idProduct, plus the driver currently bound to that
        interface. Returns a list of dicts:
        {"adapter", "iface", "vendor", "product", "driver"}. Adapters whose
        chain cannot be resolved are skipped (they are not our hardware).
        This function changes nothing on the system."""
        out = []
        for name in sorted(os.path.basename(a)
                           for a in glob.glob(os.path.join(devdir, "dvb", "adapter*"))):
            resolved = os.path.realpath(
                os.path.join(sysroot, "class", "dvb", name,
                             "frontend0", "device"))
            # idVendor/idProduct live on the USB device object; frontend0/device
            # normally points at its interface, so walk up a few levels until
            # found (robust across kernel sysfs layouts).
            vendor = product = None
            d = resolved
            for _ in range(4):
                try:
                    with open(os.path.join(d, "idVendor")) as f:
                        vendor = f.read().strip().lower()
                    with open(os.path.join(d, "idProduct")) as f:
                        product = f.read().strip().lower()
                    break
                except OSError:
                    parent = os.path.dirname(d)
                    if parent == d:
                        break
                    d = parent
            if not vendor:
                continue
            driver = None
            iface_id = os.path.basename(resolved.rstrip(os.sep))
            for drv in glob.glob(os.path.join(sysroot, "bus", "usb", "drivers", "*")):
                if os.path.exists(os.path.join(drv, iface_id)):
                    driver = os.path.basename(drv)
                    break
            out.append({"adapter": name, "iface": iface_id, "vendor": vendor,
                        "product": product, "driver": driver})
        return out

    @classmethod
    def find_dvb_hijack(cls, devdir="/dev", sysroot="/sys"):
        """Return the DVB adapters that are ACTUALLY holding an RTL-SDR dongle.

        Detection only - it reads /dev and /sys and changes nothing. A module
        merely being loaded (what 'lsmod' shows) is NOT a conflict: this
        reports only dongles whose own USB interface is bound to a kernel TV
        driver right now, so other tuners or SDR programs sharing the same
        modules (dvb_usb_v2, r820t, ...) are never mistaken for a problem.
        """
        return [i for i in cls._adapter_usb_info(devdir, sysroot)
                if (i["vendor"], i["product"]) in RTL_USB_IDS and i["driver"]]

    @staticmethod
    def unbind_command(info):
        """The single surgical command that releases THIS dongle from the DVB
        driver: it unbinds just this one USB interface. No kernel modules are
        unloaded (other tuners keep working) and no file under /etc is
        written or touched - the state is fully reversible."""
        return ("echo '%s' | sudo tee /sys/bus/usb/drivers/%s/unbind"
                % (info["iface"], info["driver"]))

    @classmethod
    def release_dvb_hijack(cls, infos):
        """Release the listed dongle(s) from the kernel TV driver.

        Running as root: performs the unbind directly in-process and verifies.
        Not root: opens the usual explanation terminal window (it says exactly
        why sudo is requested), runs the unbind there, then re-executes this
        program for a clean pass. Returns True when this process can continue
        with the device released."""
        cmds = [cls.unbind_command(i) for i in infos]
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            for c in cmds:
                subprocess.run(["sh", "-c", c.replace("sudo ", "")], check=False)
            return not cls.find_dvb_hijack()
        body = (
            "echo '================================================================'\n"
            "echo ' %s - Core Privacy System : hardware lock release'\n"
            "echo ''\n"
            "echo ' The Linux kernel grabbed your SDR dongle with its built-in TV'\n"
            "echo ' tuner driver, and while that lock is held the noise capture'\n"
            "echo ' cannot open the device. You just confirmed you want it released.'\n"
            "echo ''\n"
            "echo ' What happens next (and nothing else): the dongle's single USB'\n"
            "echo ' interface is unbound from the TV driver. NO modules are unloaded,'\n"
            "echo ' NO files in /etc are written, and any other tuner or SDR program'\n"
            "echo ' on this machine keeps working. Re-plugging the dongle later'\n"
            "echo ' re-arms the lock; README.md explains the optional permanent fix.'\n"
            "echo ''\n"
            "echo ' The next prompt asks for YOUR user password (sudo), used ONLY for'\n"
            "echo ' the unbind command below - nothing else runs. This is normal.'\n"
            "echo '================================================================'\n"
            "sleep 2\n"
            "%s\n"
            "\necho ''\necho '--- Lock released. Press Enter to close this window.'\n"
            "read -r _" % (APP_NAME, "\n".join(cmds))
        )
        term = cls.find_terminal()
        if not term:
            return False
        if not cls._run_in_terminal(term, "%s hardware lock release" % APP_NAME, body):
            return False
        os.environ[cls.REEXEC_FLAG] = "1"
        cls.reexec()
        return False      # not reached: reexec replaces the process

    @classmethod
    def dvb_gate(cls, auto_fix=False):
        """Startup gate for the kernel TV driver lock (AUDIT-05).

        Default behavior is DETECTION plus clear instructions only: this tool
        does not rewrite /etc and does not unload shared kernel modules on its
        own. The release step runs only on explicit operator consent - via
        --fix-dvb, or by answering 'y' to the prompt - and even then it
        unbinds just this dongle's one USB interface (reversible; other
        tuners are untouched). Returns True when capture is possible.
        """
        hits = cls.find_dvb_hijack()
        if not hits:
            print("  [ OK ] kernel TV (DVB) driver is not holding the RTL-SDR dongle")
            return True
        for h in hits:
            print("  [WARN] %s: RTL-SDR dongle (%s:%s) is locked by kernel TV "
                  "driver '%s'" % (h["adapter"], h["vendor"], h["product"], h["driver"]))
        print("")
        print("The Linux kernel grabbed the dongle with its built-in TV tuner driver")
        print("at boot. While that lock is held, rtl_sdr cannot open the device and")
        print("every capture batch fails immediately. Pad decryption still works;")
        print("pad generation will not, until the lock is released.")
        print("")
        print("To release it yourself (reversible - no system files are changed):")
        for h in hits:
            print("   %s" % cls.unbind_command(h))
        print("  ...then re-run this program. Re-plugging the dongle later re-arms")
        print("  the lock; if you want it gone permanently, see the optional note")
        print("  in README.md (an operator decision - this tool does not do it).")
        if auto_fix:
            pass                                   # --fix-dvb: explicit consent
        elif sys.stdin.isatty():
            try:
                ans = input("\nRelease the lock now? A terminal window will explain "
                            "the sudo step. [y/N] ").strip().lower()
            except EOFError:
                ans = ""
            if ans not in ("y", "yes"):
                print("  [SKIP] continuing - decryption works; generation needs the "
                      "lock released first.")
                return False
        else:
            print("  [SKIP] non-interactive session - run the command above yourself,")
            print("         or re-run with --fix-dvb to let the tool do it.")
            return False
        if os.environ.get(cls.REEXEC_FLAG):
            print("")
            print("  [FAIL] lock still held after a previous release pass - halting")
            print("         (the tool will not retry automatically). Run the command")
            print("         above in a terminal yourself, then re-run this program.")
            return False
        if cls.release_dvb_hijack(hits):
            print("  [ OK ] dongle released from the kernel TV driver - continuing.")
            return True
        print("")
        print("  [FAIL] could not release the lock automatically - run the command")
        print("         above in a terminal, then re-run this program.")
        return False

    # -- USB bus hardware ping ------------------------------------------------
    @classmethod
    def ping_dongle(cls, devdir="/dev"):
        """Verify an RTL-SDR dongle is on the system bus AND usable by
        userspace capture. A /dev/dvb/adapter* entry only counts against us
        when it is one of OUR dongles locked by the kernel TV driver (that
        state means rtl_sdr cannot open the device); real TV tuners are
        ignored. The final word is a clean 'rtl_test -t' exit.
        Returns (found, detail)."""
        adapters = sorted(glob.glob(os.path.join(devdir, "dvb", "adapter*")))
        if adapters:
            locked = cls.find_dvb_hijack(devdir)
            if locked:
                names = ", ".join(i["adapter"] for i in locked)
                return False, ("dongle present but locked by the kernel TV driver "
                               "(%s) - rtl_sdr cannot open it until released; see "
                               "the DVB gate output above or re-run with --fix-dvb"
                               % names)
            # Adapters exist but none is our RTL dongle (e.g. a real TV
            # tuner): fall through to rtl_test for the actual verdict.
        if shutil.which("rtl_test"):
            try:
                r = subprocess.run(["rtl_test", "-t"], capture_output=True, timeout=20)
                if r.returncode == 0:
                    return True, "rtl_test -t exited cleanly"
            except Exception:
                pass
        return False, ("no RTL-SDR dongle detected (no /dev/dvb/adapter* device and "
                       "rtl_test failed). Checklist: 1. Is the dongle plugged in? Try "
                       "a different USB port. 2. Long cable or unpowered hub? Use a "
                       "short cable directly to the machine, or a powered hub. 3. Was "
                       "it recognized? Re-plug and look for 'rtlsdr' in your system "
                       "log (journalctl -k | grep rtlsdr). 4. After fixing, re-run.")
