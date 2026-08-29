#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
 CipherVault - Core Privacy System (Standalone Workspace)
 Version 1.3.2-GUI   |   Standalone application, Python 3
=============================================================================

 A field-deployable one-time-pad workspace for secure communications in
 offline or infrastructure-constrained environments. Pad material is generated
 exclusively from atmospheric noise captured with an RTL-SDR dongle. Finished
 pads travel between stations on thumbdrives; every page carries a SHA3-256
 fingerprint so the receiving station can verify a pad before it is ever used,
 and consumed pages are shredded in place.

 What this script does on first run:
   1. Checks your system for missing dependencies (coreutils, rtl-sdr,
      python3-tk, tkinterdnd2).
   2. Opens a terminal window that explains WHY it needs your sudo password.
   3. Installs whatever is missing for your distro (apt / dnf / pacman / zypper).
   4. Re-executes itself for a clean pass.
   5. Launches the GUI.

 After the first run, just run it again - everything is already installed.

 Usage:
   python3 ciphervault.py             # full install + GUI (default)
   python3 ciphervault.py --selftest  # RAM-only self check: PASS/FAIL
   python3 ciphervault.py --generate 5 [--hex]   # headless generation
   python3 ciphervault.py --sandbox   # sandbox noise source (TEST ONLY)
   python3 ciphervault.py --no-sweep  # hard-fail on dead/overloaded front end
   python3 ciphervault.py --fix-dvb   # release dongle from kernel TV driver

 Supported distros: Mint, Debian, Ubuntu, Arch, Fedora/RHEL/CentOS, openSUSE.
=============================================================================
"""

import os
import sys
import shutil
import subprocess

# Ensure the project root is on sys.path so the modules/ package is findable
# regardless of where this script is invoked from.
_project_root = os.path.dirname(os.path.abspath(__file__))
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

# ---------------------------------------------------------------------------
# Dependency detection + installation
# ---------------------------------------------------------------------------

# System binaries required by the program (all checked at runtime).
REQUIRED_BINARIES = [
    "awk", "od", "sort", "uniq", "fold", "cut", "tr", "wc",
    "timeout", "dd", "sha256sum", "sha3sum", "shred", "rtl_sdr",
]

# Python packages required by the GUI.
REQUIRED_PYTHON_PKGS = ["tkinterdnd2"]

# Package manager -> package name mapping for missing system binaries.
PKG_MAP = {
    "apt":    {"awk": "mawk", "rtl_sdr": "rtl-sdr"},
    "dnf":    {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
    "pacman": {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
    "zypper": {"awk": "gawk", "rtl_sdr": "rtl-sdr"},
}

# Package manager -> python3-tk package name.
TK_PKG = {
    "apt": "python3-tk",
    "dnf": "python3-tkinter",
    "pacman": "tk",
    "zypper": "python-tk",
}

# Terminal emulators to try (in order of preference).
TERMINALS = ("kitty", "alacritty", "gnome-terminal", "konsole", "xterm")

APP_NAME = "CipherVault"
REEXEC_FLAG = "CIPHERVAULT_REEXEC"
NO_AUTOINSTALL_FLAG = "CIPHERVAULT_NO_AUTOINSTALL"


def detect_pkg_manager():
    """Detect the system package manager. Returns name or None."""
    for exe, name in (("apt-get", "apt"), ("dnf", "dnf"),
                      ("pacman", "pacman"), ("zypper", "zypper")):
        if shutil.which(exe):
            return name
    return None


def missing_binaries():
    """Return list of missing required system binaries."""
    return [b for b in REQUIRED_BINARIES if not shutil.which(b)]


def packages_for(missing, mgr):
    """Map missing tools to distro package names."""
    base = PKG_MAP.get(mgr, {})
    pkgs = []
    for tool in missing:
        pkg = base.get(tool, "coreutils")
        if pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs


def install_command(mgr, pkgs):
    """Build the install command for the detected package manager."""
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


def find_terminal():
    """Find an available terminal emulator."""
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return None
    for t in TERMINALS:
        if shutil.which(t):
            return t
    return None


def run_in_terminal(term, title, body):
    """Open a terminal window with the given body text and command."""
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


def launch_install_terminal(mgr, pkgs, what):
    """Open a terminal explaining the install and running it with sudo."""
    cmd = install_command(mgr, pkgs)
    if not cmd:
        return False
    term = find_terminal()
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
    return run_in_terminal(term, "%s setup" % APP_NAME, body)


def reexec():
    """Re-execute this script for a clean pass after installation."""
    os.execv(sys.executable,
             [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:])


def install_python_packages():
    """Install missing Python packages via pip (no sudo needed for user install)."""
    missing = []
    for pkg in REQUIRED_PYTHON_PKGS:
        try:
            __import__(pkg.replace("-", "_"))
        except ImportError:
            missing.append(pkg)
    if not missing:
        return True
    print("  [INFO] Installing Python packages: %s" % ", ".join(missing))
    
    # Check for PEP 668 externally-managed-environment
    # If detected, use --break-system-packages flag
    pip_args = [sys.executable, "-m", "pip", "install", "--user"]
    try:
        result = subprocess.run(
            pip_args + missing,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return True
        
        # Check if it's a PEP 668 error
        if "externally-managed-environment" in result.stderr:
            print("  [INFO] Detected externally-managed Python environment (PEP 668)")
            print("  [INFO] Retrying with --break-system-packages flag...")
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", "--user", "--break-system-packages"] + missing,
                check=True
            )
            return True
        else:
            raise subprocess.CalledProcessError(result.returncode, pip_args + missing)
    except subprocess.CalledProcessError:
        print("  [WARN] Could not install Python packages automatically.")
        print("         Run: pip3 install --user %s" % " ".join(missing))
        return False


def install_system_dependencies():
    """Check and install missing system dependencies."""
    missing = missing_binaries()
    if not missing:
        print("  [ OK ] all required system binaries present")
        return True

    mgr = detect_pkg_manager()
    print("  [FAIL] missing system binaries: %s" % ", ".join(missing))
    if mgr is None:
        print("")
        print("No supported package manager found (apt, dnf, pacman, or zypper).")
        print("Install the rtl-sdr userspace package and coreutils by whatever")
        print("method your distro provides, then re-run this program.")
        return False

    pkgs = packages_for(missing, mgr)
    cmd = install_command(mgr, pkgs)
    print("")
    print("Detected package manager: %s" % mgr)
    print("Packages needed:          %s" % ", ".join(pkgs))
    print("Install command:          %s" % cmd)

    if os.environ.get(NO_AUTOINSTALL_FLAG):
        print("Auto-install disabled (%s). Run the command above, then re-run."
              % NO_AUTOINSTALL_FLAG)
        return False

    if not find_terminal():
        print("")
        print("No GUI terminal window available to run the install automatically.")
        print("Run the command above in a terminal, then re-run this program.")
        return False

    if os.environ.get(REEXEC_FLAG):
        print("")
        print("Still missing after an install pass - halting. Fix the install")
        print("(the machine may be offline or the package name may differ on")
        print("this distro), then re-run this program.")
        return False

    print("")
    print("Opening a terminal window to install the missing packages.")
    print("That window will explain why it asks for your sudo password.")
    launch_install_terminal(mgr, pkgs, "system tools")
    os.environ[REEXEC_FLAG] = "1"
    reexec()
    return False  # not reached: reexec replaces the process


def install_tkinter():
    """Check and install tkinter if missing."""
    try:
        import tkinter
        print("  [ OK ] tkinter available in this Python environment")
        return True
    except ImportError:
        pass

    mgr = detect_pkg_manager()
    if mgr is None or mgr not in TK_PKG:
        print("  [FAIL] tkinter is missing and no supported package manager was")
        print("         found to install it. Install python3-tk through your")
        print("         distro's normal method, then re-run this program.")
        return False

    pkg = TK_PKG[mgr]
    cmd = install_command(mgr, [pkg])
    print("  [WARN] tkinter missing - install command: %s" % cmd)

    if os.environ.get(NO_AUTOINSTALL_FLAG):
        print("Auto-install disabled (%s). Run the command above, then re-run."
              % NO_AUTOINSTALL_FLAG)
        return False

    if not find_terminal():
        print("No GUI terminal window available to install tkinter automatically.")
        print("Run the command above in a terminal, then re-run this program.")
        return False

    if os.environ.get(REEXEC_FLAG):
        print("tkinter still missing after an install pass - halting.")
        return False

    print("Opening a terminal window to install tkinter (it will explain")
    print("why the sudo password is requested).")
    launch_install_terminal(mgr, [pkg], "GUI toolkit (tkinter)")
    os.environ[REEXEC_FLAG] = "1"
    reexec()
    return False  # not reached: reexec replaces the process


def setup_udev_rule():
    """Install the udev rule to prevent DVB driver hijack at boot.

    Non-fatal: the tool works without it, but the rule is cleaner for
    dedicated stations. Copies config/99-rtlsdr.rules to /etc/udev/rules.d/
    with sudo, then reloads udev.
    """
    rule_path = "/etc/udev/rules.d/99-rtlsdr.rules"
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "config", "99-rtlsdr.rules")

    # Check if already installed
    if os.path.exists(rule_path):
        try:
            with open(rule_path, "r") as f:
                content = f.read()
            if "CipherVault" in content and "0bda" in content:
                print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
                return True
        except (IOError, OSError):
            pass

    # Running as root: copy directly
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            shutil.copy2(src, rule_path)
            subprocess.run(["udevadm", "control", "--reload-rules"], check=False)
            subprocess.run(["udevadm", "trigger"], check=False)
            print("  [ OK ] udev rule installed - DVB driver will not hijack dongle at boot")
            return True
        except (IOError, OSError, shutil.Error) as e:
            print("  [FAIL] could not install udev rule: %s" % e)
            return False

    # Not root: open terminal with explanation
    term = find_terminal()
    if not term:
        print("  [WARN] udev rule not installed and no terminal available.")
        print("         Copy config/99-rtlsdr.rules to /etc/udev/rules.d/ manually.")
        print("         Then run: sudo udevadm control --reload-rules")
        return True  # non-fatal

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
        "read -r _" % (APP_NAME, src, "/etc/udev/rules.d")
    )
    if not run_in_terminal(term, "%s udev setup" % APP_NAME, body):
        return False
    os.environ[REEXEC_FLAG] = "1"
    reexec()
    return False  # not reached: reexec replaces the process


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------

def main():
    """First-run setup: install dependencies, then launch the program."""
    
    # If we've already been re-executed, skip the install phase
    if os.environ.get(REEXEC_FLAG):
        print("=" * 64)
        print(" %s v1.3.2-GUI - Core Privacy System (Standalone Workspace)" % APP_NAME)
        print(" (re-exec pass - skipping install)")
        print("=" * 64)
    else:
        print("=" * 64)
        print(" %s v1.3.2-GUI - Core Privacy System (Standalone Workspace)" % APP_NAME)
        print(" Installing dependencies...")
        print("=" * 64)

        # 1. Install system dependencies (requires sudo for package install)
        if not install_system_dependencies():
            return 1

        # 2. Install Python packages (tkinterdnd2 for drag & drop)
        if not install_python_packages():
            print("  [WARN] Python packages may need manual installation.")

        # 3. Check tkinter
        if not install_tkinter():
            return 1

        # 4. Udev rule setup (non-fatal: tool works without it)
        setup_udev_rule()

        # 5. All dependencies installed - re-exec for clean pass
        os.environ[REEXEC_FLAG] = "1"
        reexec()
        return 0  # not reached
    
    # 5. Launch the GUI (either after install or on re-exec pass)
    from modules.entry import main as real_main
    return real_main()


if __name__ == "__main__":
    # If --selftest or other flags are passed, delegate to the real entry point
    if "--selftest" in sys.argv or "--generate" in sys.argv or "--sandbox" in sys.argv:
        from modules.entry import main as real_main
        sys.exit(real_main())

    # Otherwise: install dependencies then launch
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        sys.exit(130)
