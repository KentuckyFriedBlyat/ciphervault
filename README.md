# CipherVault — One-Time Pad Workspace

**Version 1.3.2-GUI** · Python 3 · Linux

A field-deployable one-time-pad workspace for secure communications in
offline or infrastructure-constrained environments. Pad material is generated
exclusively from **atmospheric noise captured with an RTL-SDR dongle** — no
PRNG and no OS entropy ever touch key material. Finished pads travel between
stations on thumbdrives; every page carries a SHA3-256 fingerprint so the
receiving station can verify a pad before it is ever used, and consumed pages
are shredded in place.

---

## 1. What it does

### HEX (primary)
Full Unicode in / out — any language, punctuation, emoji, spaces. Message is
UTF-8 → hex; each hex character consumes two pad digits through a fixed code
map (0-9 → 00-09, A-F → 10-15). Simplified page: number grid + checksum only.

**Capacity:** 127 bytes of any text per page

**Cipher text format:** Decryption accepts cipher text with or without
spaces/separators — non-digit characters are automatically stripped. This makes
it easier to work with cipher text that was transmitted in groups (e.g.,
"85422 44931 94682...").

**Where it lives:** `HexPads/`

### Printable (fallback)
Human-decodable pages with a per-page random substitution table over
`a-z0-9`, printable for offline manual use.

**Capacity:** 255 A-Z/0-9 chars per page

**Where it lives:** `Manual Pads/`

### Multi-part long messages
With "split across multiple pads" enabled, a message longer than one page's
capacity is split; each part burns its own pad page and reserves its first two
characters for the part number (the transmission header carries the series
flag plus total part count — 48-digit prefix instead of 45). The receiver
**refuses to decrypt a series unless all parts are present** — nothing is
consumed on an incomplete drop. Multi-part output is saved to a file in the
working directory that can be dragged back into the program at the receiving
station for batch processing.

### Streaming generation (low RAM footprint)
Pad generation captures entropy for one pad at a time, writes it to disk
immediately, then clears the capture data from RAM before generating the next
pad. This keeps RAM usage constant regardless of how many pads are being
generated — generating 1 billion pads won't cause OOM. Each pad still passes
all statistical gates independently.

### Front-end health gate and auto-sweep
Before any capture is accepted as an entropy source, the tool probes the tuned
coordinate with a short sample and classifies the front end: *dead* (no RF
reaching the mixer — antenna/coax), *overloaded* (front end clipping — too
much signal), or healthy. If the spot is not healthy, the tool slowly sweeps
upward from 25 MHz in 250 kHz steps until it finds a clean spot. Three
consecutive dead spots stop the run with an antenna/coax diagnosis (no
frequency rotation fixes a disconnected antenna); overload persisting across
the whole sweep halts the run with advice to add a 10–20 dB attenuator or
lower `GAIN`. A clipped front end is never mistaken for "infinite entropy" —
its presence is measured, not assumed. Run with `--no-sweep` to hard-fail
instead of sweeping.

---

## 2. Running

```bash
python3 ciphervault.py                # GUI (default; hex mode primary)
python3 ciphervault.py --selftest     # RAM-only self check: PASS/FAIL
python3 ciphervault.py --generate 5   # headless: generate 5 printable pads
python3 ciphervault.py --generate 5 --hex   # headless: hex pads
python3 ciphervault.py --sandbox      # sandbox noise source (TEST ONLY)
python3 ciphervault.py --no-sweep     # hard-fail on dead/overloaded front end
python3 ciphervault.py --fix-dvb      # release dongle from kernel TV driver
python3 ciphervault.py --dry-run      # show what would be done without executing
python3 ciphervault.py --verify DIR   # verify all pads in directory
python3 ciphervault.py --version      # show version
python3 ciphervault.py --operator NAME --station ID  # set operator/station IDs
```

**GUI Settings:** The GUI includes an Operator / Station ID section with text
fields and a "Persist in config" checkbox. When checked and the window is
closed, the IDs are saved to `config/config.py` and will be used for all
subsequent pad generations.

**PANIC Button:** A red "PANIC" button is located in the top-right corner of
the GUI. Clicking it triggers a two-step confirmation dialog:

1. **Warning Dialog** - Explains that all sensitive data will be destroyed
2. **Final Confirmation** - Asks "Are you absolutely sure?"

If confirmed, the program immediately:
- **Consumes pad material** as entropy for the secure wipe
- Shreds operator/station IDs using pad-derived entropy
- Destroys all files in `audit/` using pad entropy
- Destroys all files in `Clear/` using pad entropy
- Destroys all files in `Cipher/` using pad entropy
- Resets `config/config.py` to factory defaults

The pad material is hashed and used as the wipe pattern instead of random
data, making the secure wipe more cryptographically robust. Both the pads
and sensitive data are destroyed simultaneously.

This immediately resets the program to a clean state. Use this when you
suspect compromise or need to quickly clear sensitive data from the system.

**Script Hook for Panic Trigger:**

External scripts can trigger the panic reset via:

```bash
# Command-line trigger
python3 ciphervault.py --panic TRIGGER_PANIC

# Environment variable trigger
CIPHERVAULT_PANIC=TRIGGER_PANIC python3 ciphervault.py

# Helper script
CIPHERVAULT_PANIC=TRIGGER_PANIC python3 panic_trigger.py
```

This allows automation of panic triggers based on system events like:
- Failed login attempts
- Intrusion detection system alerts
- Network security policies
- Custom security scripts

Example automation script:
```bash
#!/bin/bash
# Trigger panic on 3 failed login attempts
FAILED_ATTEMPTS=0
while true; do
    if ! ssh user@host "echo test" 2>/dev/null; then
        FAILED_ATTEMPTS=$((FAILED_ATTEMPTS + 1))
        if [ $FAILED_ATTEMPTS -ge 3 ]; then
            echo "Too many failed attempts - triggering panic"
            CIPHERVAULT_PANIC=TRIGGER_PANIC python3 /path/to/ciphervault.py
            exit 1
        fi
    else
        FAILED_ATTEMPTS=0
    fi
    sleep 60
done
```

Copy `ciphervault.py` **and** the adjacent `modules/` and `config/` folders to
the machine. The workspace tree is created next to the launcher:

```
Manual Pads/   printable one-time pad pages (fallback mode key material)
HexPads/       simplified hex-mode pad pages (primary mode key material)
Cipher/        outbound transmission payloads (single + multi-part series)
Clear/         decrypted clear-text copies (destroy when done)
audit/         batch records, failed captures, and operational logs
```

---

## 3. Security model

- **Only the RTL-SDR bus is a randomness source** for pad material. The
  `random` and `secrets` modules are not imported anywhere. A clearly labelled
  sandbox mode exists for offline testing; its pages carry a stamped marker
  and are refused by the encrypt/decrypt paths for any other use.

- **Capture-frequency wobble:** every batch is tuned at a non-deterministic
  offset of up to ±500 kHz from its base quiet-zone band, derived from live
  host thermal state mixed with nanosecond timing. The coordinate is recorded
  in the batch file for operator audit; it selects tuning only — never key
  material.

- **Captures live and die in RAM.** Sanity samples are read into memory and
  tested in memory; the main capture streams 256 KB chunks from the dongle
  straight into SHA-256 digests held in RAM. No raw noise byte ever touches
  disk.

- **Every pad page carries a SHA3-256 fingerprint** of the whole page (every
  byte and blank space, field zeroed during computation). Encryption *and*
  decryption recompute it on every run and refuse any page that differs —
  refused pages are quarantined, never consumed. This is what makes thumbdrive
  transport safe: verify before you trust.

- **Consumed pad files are securely shredded** (multi-pass randomized
  overwrite + fsync + unlink) before the tool reports success.

- **Forward Error Correction (FEC)** for over-the-air transmission. FEC is
  a fixed, public, deterministic encoding of OTP ciphertext that adds
  redundancy for error detection and correction. It is explicitly designed
  for transmission modes that don't have built-in error correction — such as
  Morse (CW), phone (SSB/AM/FM), or other analog/digital modes where bit
  errors can occur during transmission. FEC frames use the format
  `FECv1 <space-separated 4-char groups>` and add 8x expansion to the
  ciphertext for robustness.

- **Operator/Station ID tracking** for accountability. Audit logs include
  operator and station identification. IDs can be persisted in config or
  cleared with secure overwrite to prevent forensic recovery.

- **Panic button for immediate cleanup.** Red "PANIC" button in the GUI
  triggers a two-step confirmation dialog. When confirmed, the program:
  - Securely shreds operator/station IDs with multipass wipe
  - Destroys all files in `audit/`, `Clear/`, and `Cipher/` folders
  - Resets `config/config.py` to factory defaults
  - Uses pad material as entropy for the secure wipe pattern
  This immediately resets the program to a clean state. Use this when you
  suspect compromise or need to quickly clear sensitive data from the system.

- **Script hooks for automated panic triggers.** External scripts can
  trigger the panic reset via:
  - Command-line: `python3 ciphervault.py --panic TRIGGER_PANIC`
  - Environment variable: `CIPHERVAULT_PANIC=TRIGGER_PANIC python3 ciphervault.py`
  - Helper script: `CIPHERVAULT_PANIC=TRIGGER_PANIC python3 panic_trigger.py`
  This allows automation of panic triggers based on system events like
  failed login attempts, intrusion detection, or other security policies.

---

## 4. DVB driver override (udev rule)

At boot, the Linux kernel grabs RTL-SDR dongles with its built-in TV tuner
driver (`dvb_usb_rtl28xxu`). While that lock is held, `rtl_sdr` cannot open
the device. Pad **decryption still works**; pad **generation does not**, until
the lock is released.

**How this tool handles it — udev rule on dedicated stations.**

- On first run, the tool installs `config/99-rtlsdr.rules` to
  `/etc/udev/rules.d/` with sudo, then reloads udev. The rule tells udev to
  ignore RTL2832U-based dongles for the DVB subsystem at boot — the driver is
  still loaded (other DVB devices keep working), but YOUR dongle stays free
  for `rtl_sdr`.

- The udev setup is **non-fatal**: if it fails (no sudo, no terminal, etc.),
  the tool still works. You can release the lock per-session with `--fix-dvb`
  or manually:

```bash
echo '1-1:1.0' | sudo tee /sys/bus/usb/drivers/dvb_usb_rtl28xxu/unbind
```

- The rule matches USB IDs `0bda:283[789]` (RTL2832U family). If you run a
  less common rtl-sdr-supported stick, add its ID to the rule.

**Known dongles.** Recognition uses the USB IDs in `config/config.py`
(`RTL_USB_IDS`: RTL2832U `0bda:2838`, plus `2837`/`2839`).

---

## 5. Calibration (frequency range scanning)

RTL-SDR dongles vary in their usable frequency range. This tool calibrates the
dongle on first run (or if the config is wiped) to find the lower and upper
frequency limits, then stores the results in `config/config.py`.

**How it works:**

- Starts at ~26 MHz and scans downward in 500 kHz steps until it finds a
  frequency with sufficient entropy (≥ 5.0 bits/byte).
- Starts at ~220 MHz and scans upward in 500 kHz steps until it finds a
  frequency with sufficient entropy (≥ 5.0 bits/byte).
- Stores `LOWER_LIMIT_MHZ`, `UPPER_LIMIT_MHZ`, `LOWER_LIMIT_FREQ_HZ`,
  `UPPER_LIMIT_FREQ_HZ`, and `TUNING_COMPLETE` in `config/config.py`.
- Only runs once per dongle unless the config is reset.

**Calibration parameters** (in `config/config.py`):

- `CALIBRATION_ENABLED` — toggle calibration on/off
- `CALIBRATION_LOWER_START_MHZ` — start frequency for lower limit scan
- `CALIBRATION_LOWER_STEP_KHZ` — step size for lower limit scan
- `CALIBRATION_LOWER_ENTROPY_MIN` — minimum entropy to accept a frequency
- `CALIBRATION_UPPER_START_MHZ` — start frequency for upper limit scan
- `CALIBRATION_UPPER_STEP_KHZ` — step size for upper limit scan
- `CALIBRATION_UPPER_ENTROPY_MIN` — minimum entropy to accept a frequency
- `CALIBRATION_DEAD_STREAK_MAX` — consecutive dead probes to abort early

**If calibration fails:** the tool falls back to default frequency ranges
(26 MHz lower, 40 MHz upper) and continues. You can reset calibration by
setting `TUNING_COMPLETE = False` in `config/config.py` and restarting.

**Why this matters:** subsequent sweeps use the calibrated range, so they
cover the full usable spectrum of your dongle instead of just the default
25-40 MHz window. This is especially important for dongles that work above
40 MHz.

---

## 6. Field notes (pad logistics)

1. Generate at a station with a verified dongle (`--selftest`, then watch the
   dongle ping line). Statistical gates (Shannon entropy ≥ 7.9 bits/byte,
   chi-square on bytes and digits) are applied to every capture batch; failed
   batches are re-captured up to 3 times at rotated quiet-zone frequencies.

2. Copy finished pages to the thumbdrive. Each page's fingerprint line is the
   integrity check — the receiving station re-verifies it automatically on
   first use, and any mismatch quarantines the page.

3. One pad page = one use. The tool shreds consumed pages; do not "save a copy
   just in case" — a reused OTP destroys the confidentiality of both messages.

---

## 7. Self check

```bash
python3 ciphervault.py --selftest     # RAM-only: PASS/FAIL, touches no disk
```

Runs the crypto round-trip, chunking invariants, and fingerprint logic
entirely in memory. Use it after moving the tool to a new machine.

---

## 8. Troubleshooting

| Symptom | Meaning / action |
|---|---|
| Dongle ping fails: "no RTL-SDR dongle detected" | Check port/cable (short cable, direct or powered hub), re-plug, then `journalctl -k \| grep rtlsdr`. |
| `front-end probe ... dead` at batch start | No RF reaching the mixer — check antenna, coax, and the SMA connection on the dongle; sweeping frequencies cannot fix this. |
| `slowly sweeping upward from 25 MHz...` | Normal recovery: the tuned spot was unusable (dead or overloaded); the tool is hunting for a clean coordinate. |
| `front end OVERLOADED ... (clipping)` | A strong local signal is saturating the front end — add a 10–20 dB attenuator or lower `GAIN` in `config/config.py`, then re-run. |
| Capture batch fails mid-run | The tool re-captures up to 3 times at rotated frequencies; persistent failure usually means RF environment or dongle lock — re-run §5 and the startup ping. |
| Page refused on use | Fingerprint mismatch → page quarantined. Do not force it; regenerate/re-copy from the source station. |
| `Halting: environment is not compliant yet` | The install pass ran but a package name differs on your distro — run the printed command manually, then re-run. |

---

## 9. Versioning policy

**Version numbers only increment when the crypto engine changes.**

The version stamp embedded in every pad page is a security boundary — it
prevents cross-contamination between different program revisions. Changing
the version number means:

- All existing pad pages become "obsolete" and will be shredded on startup
  sweep unless manually preserved.
- New pad pages MUST be generated and physically distributed to every
  receiving station. Thumbdrives with old pads become useless.

**What does NOT require a version bump:**

- UI changes, bug fixes, and feature additions
- New configuration options or tuning parameters
- Changes to pad page templates or formatting
- Installation script improvements

**What DOES require a version bump:**

- Changes to the cryptographic algorithm or key derivation
- Changes to the entropy capture or validation logic
- Changes to the fingerprint or verification mechanism
- Any modification that would invalidate previously-generated pads

This policy ensures that operators only need to re-distribute pads when the
security model itself changes, not for every improvement to the tool.

See `config/config.py` for the authoritative version and detailed reasoning.
