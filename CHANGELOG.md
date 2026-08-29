## [1.3.3-GUI] — 2026-08-29

### Changed

* **Merged install/launch scripts.** `ciphertext.py` (install + launch) and
  `ciphervault.py` (launch only) are now a single entry point:
  `ciphervault.py`. It performs first-run dependency detection and installation
  (apt / dnf / pacman / zypper), then re-execs for a clean pass and launches
  the GUI.
* **Added udev rule setup to bootstrap.** On first run, the tool installs
  `config/99-rtlsdr.rules` to `/etc/udev/rules.d/` with sudo, then reloads
  udev. This prevents the kernel DVB driver from hijacking the dongle at boot
  on dedicated stations. Non-fatal: the tool still works without it (per-session
  unbind via `--fix-dvb` or manual `echo ... > /sys/bus/usb/drivers/.../unbind`).
* **Added calibration phase.** On first run (or if config is wiped), the tool
  scans the frequency spectrum to find the lower and upper limits of the
  RTL-SDR dongle. Results are stored in `config/config.py` and used for all
  subsequent sweeps. Only runs once per dongle unless config is reset.

### Added

* **udev rule file** `config/99-rtlsdr.rules` — prevents the kernel DVB driver
  from binding to RTL2832U-based SDR dongles at boot. The driver is still
  loaded (other DVB devices keep working), but YOUR dongle stays free for
  `rtl_sdr`.
* **Calibration parameters** in `config/config.py` — `CALIBRATION_ENABLED`,
  `CALIBRATION_LOWER_START_MHZ`, `CALIBRATION_UPPER_START_MHZ`, etc. Controls
  the frequency range scanning.
* **Tuning results** in `config/config.py` — `LOWER_LIMIT_MHZ`, `UPPER_LIMIT_MHZ`,
  `LOWER_LIMIT_FREQ_HZ`, `UPPER_LIMIT_FREQ_HZ`, `TUNING_COMPLETE`. Populated
  by the calibration phase.

### Removed

* `ciphertext.py` — functionality consolidated into `ciphervault.py`.
* **DVB driver lock documentation** — removed section 6 ("Kernel TV driver lock
  (DVB) — AUDIT-05") from README.md. DVB driver override is now handled by
  udev rules on dedicated stations, not by the tool itself.

---

## [1.3.2-GUI] — Internal development

* Modular package structure: `modules/` + `config/`
* Centralized configuration in `config/config.py`
* Template-driven pad pages (printable + hex)
* `ciphertext.py` install script (distro detection: apt/dnf/pacman/zypper)
* Version tracking in config (bump only on crypto engine changes)
* Pad folder renamed: `Pads/` → `Manual Pads/`
* Pad generation limit removed (no 90-pad ceiling)
* Streaming pad generation (constant RAM footprint)
* Hex mode: full Unicode, spaces, punctuation support
* AGC gain mode (replaced manual 30 dB)
* SHA-256 hashing of raw samples (whitened entropy)
* Relaxed raw entropy gate (7.9 bits/byte on digest stream)
* Lowered sweep probe threshold (7.0 → 5.0 bits/byte)
* Fixed: end-to-end pad generation with antenna
* Removed: C sources, test scripts, probe data, nested package dir

---

## [1.3.1-GUI] — Internal development

* Initial modular refactor of single-file `ciphervault.py`
* Preserved all original functionality:
  * Atmospheric noise pad generation via RTL-SDR
  * Front-end health classification (dead/overloaded/healthy)
  * Auto-sweep for overload recovery
  * SHA3-256 fingerprint verification
  * Secure shredding of consumed pads
  * Multi-part series encryption/decryption
  * FEC (air interface error detection)
  * DVB driver lock detection and opt-in release
  * RAM-only captures (no raw noise on disk)
  * Sandbox mode for offline testing

---

**Versioning policy:** Version numbers only increment when the crypto engine changes. Internal development iterations are noted for audit trail purposes.
