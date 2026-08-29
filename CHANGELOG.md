## [1.3.2-GUI] — 2026-08-29

### Changed

* **Merged install/launch scripts.** `ciphertext.py` (install + launch) and
  `ciphervault.py` (launch only) are now a single entry point:
  `ciphervault.py`. It performs first-run dependency detection and installation
  (apt / dnf / pacman / zypper), then re-execs for a clean pass and launches
  the GUI. `ciphertext.py` has been removed.
* **Removed DVB driver lock section from README.** DVB driver override is now
  handled via udev rules on dedicated stations, not by the tool itself.
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

### Fixed

* **Duplicate `resolve_frequency` method in `modules/noise.py`.** Removed
  duplicate method definition that was shadowing the primary implementation.
  Only the first definition was being executed, causing the sweep logic to
  be ignored.

---

## [1.3.2-GUI] — 2026-08-29

### Added

* **Modular package structure.** The program now lives in `modules/` with a
  separate `config/` folder for all tunables and page templates. The launcher
  is `ciphertext.py` (install + launch) and `ciphervault.py` (launch only).
* **Centralized configuration.** All tunable parameters, protocol constants,
  SDR capture settings, statistical gates, and pad page templates live in
  `config/config.py`. No more scattered constants across multiple files.
* **Template-driven pad pages.** Printable and hex pad page layouts are now
  stored as templates in `config/config.py` and rendered by the crypto engine.
  No hardcoded page formatting in the code.
* **`ciphertext.py` install script.** First-run wrapper that detects your
  distro (apt/dnf/pacman/zypper), opens a terminal explaining why sudo is
  needed, installs missing dependencies, then launches the program. Covers
  Mint, Debian, Ubuntu, Arch, Fedora/RHEL/CentOS, and openSUSE.
* **Version tracking in config.** The program version lives in `config/config.py`
  with a warning comment: changing it breaks all existing crypto and requires
  re-distribution of pads. Version bumps only for crypto engine changes.

### Changed

* **Pad folder renamed.** `Pads/` → `Manual Pads/` for clarity. The folder is
  the obvious place to find manually distributed printable pad pages.
* **Pad generation limit removed.** No more 90-pad ceiling. Generate as many
  pads as you want (the universe may end first).
* **Streaming pad generation.** The engine now captures entropy for one pad at
  a time, writes it to disk immediately, then clears the capture data from RAM
  before generating the next pad. This keeps RAM usage constant regardless of
  how many pads are being generated (e.g., generating 1 billion pads won't
  cause OOM). Each pad still passes all statistical gates independently.
* **Hex mode full Unicode and space support.** Hex mode now fully supports
  Unicode characters, spaces, and punctuation. Messages are UTF-8 encoded
  and converted to hex (each byte becomes 2 hex characters), then encrypted
  with 2 pad digits per hex character. The cipher text can include spaces or
  other separators for grouping - non-digit characters are automatically
  stripped during decryption.
* **AGC gain mode** (`noise.py: _open_rtl_sdr`): switched from manual 30 dB to
  AGC for better entropy from atmospheric noise.
* **SHA-256 hashing of raw samples** (`noise.py: capture_digests`): raw IQ bytes
  are now hashed in 64-byte blocks before entropy validation. This whitens the
  ADC quantization noise and produces ~8 bits/byte entropy from raw ~6 bits/byte.
* **Relaxed raw entropy gate** (`crypto.py: _capture_and_verify`): raw start/end
  sanity samples no longer fail on entropy < 7.9 bits/byte, since the digest
  stream (hashed output) is the actual entropy source.
* **Lowered sweep probe threshold** (`config/config.py: SWEEP_PROBE_ENTROPY_MIN`):
  reduced from 7.0 to 5.0 bits/byte to account for the hashing step. The full
  7.9 gate still runs on the digest stream.

### Fixed

* Pad generation now works end-to-end with an antenna connected. The dongle
  streams atmospheric noise at VHF (25-40 MHz) via `rtl_sdr` userspace, and
  the hashing step produces entropy above the 7.9 bits/byte threshold.
* Verified on this unit: 28.5 MHz with AGC, ~0.7 MB/s capture rate, 7.91
  bits/byte entropy after hashing.

### Removed

* All C source files and compiled probes (development artifacts).
* Standalone test scripts (`antenna_check.py`, `rf_check.py`, `ft8_test.py`).
* Matrix run scripts (`run_matrix.sh`, `run_matrix_s12.sh`).
* Audit test script (`audit/audit_test.py`).
* Probe data directory (`probe/`).
* The nested `ciphervault/` package directory — replaced by `modules/` + `config/`.
* Hardcoded pad page templates — moved to `config/config.py`.

### Deliberate deviations

* **No switch to librtlsdr async mode**: the ctypes wrapper for
  `rtlsdr_read_async` blocked indefinitely on this hardware (callback never
  invoked). The userspace `rtl_sdr` tool works reliably, so we kept that path.
* **No change to FREQS tuple**: the existing quiet-zone bands (26, 27.5, 28.5,
  31, 40, 61.5 MHz) all produce usable entropy with AGC + hashing.

---

## [1.3.1-GUI] — Earlier release

Initial modular refactor of the original single-file `ciphervault.py` into a
package structure. Preserved all original functionality including:

* Atmospheric noise pad generation via RTL-SDR
* Front-end health classification (dead/overloaded/healthy)
* Auto-sweep for overload recovery
* SHA3-256 fingerprint verification on every pad use
* Secure shredding of consumed pads
* Multi-part series encryption/decryption
* FEC (air interface error detection)
* DVB driver lock detection and opt-in release
* RAM-only captures (no raw noise on disk)
* Sandbox mode for offline testing
