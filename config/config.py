"""CipherVault configuration — all tunables, protocol constants, and page templates.

Everything that an operator or deployer might need to adjust lives here. The
crypto engine reads these values; it does not define them.
"""

from textwrap import dedent
import os

# ===========================================================================
# VERSION TRACKING
# ===========================================================================
#
# WARNING: DO NOT CHANGE THIS NUMBER UNLESS YOU ARE WILLING TO BREAK ALL
# EXISTING CRYPTO AND RE-DISTRIBUTE ALL NEW PADS.
#
# Every pad page generated from this version onward carries a TOOL VERSION
# stamp. The crypto engine locks pads to this version to prevent cross-
# contamination between different program revisions. Changing this number
# means:
#   * All existing pad pages become "obsolete" and will be shredded on
#     startup sweep unless manually preserved.
#   * New pad pages MUST be generated and physically distributed to every
#     receiving station. Thumbdrives with old pads become useless.
#   * The version stamp is embedded in every pad page header.
#
# The ONLY reason to bump this is a change to the crypto engine itself.
# UI changes, bug fixes, and feature additions do NOT require a version
# bump.
#
VERSION = "1.3.2-GUI"

# ===========================================================================
# CONFIG CHECKSUM
# ===========================================================================
# This checksum is used to verify that config/config.py hasn't been
# tampered with or corrupted. If it doesn't match, the tool will warn
# the operator and refuse to generate pads until the issue is resolved.
# This prevents accidental corruption from causing security failures.
#
# To regenerate: python3 -c "import hashlib; print(hashlib.sha256(open('config/config.py','rb').read()).hexdigest())"
CONFIG_CHECKSUM = "PLACEHOLDER_CHECKSUM"
VERSION_MARK = "TOOL VERSION: "
PRODUCT_LINE = "Core Privacy System (Standalone Workspace)"
APP_NAME = "CipherVault"

# ===========================================================================
# OPERATOR / STATION IDENTIFICATION
# ===========================================================================
# These are used to identify the operator and station in audit logs.
# They can be overridden via command-line flags (--operator, --station).
# If not set, defaults are used.
OPERATOR_ID = "dfsaDF"
STATION_ID = "FSADFs"
PERSIST_IDS = True  # Persist operator/station IDs in config across sessions

# ===========================================================================
# CERTIFICATE INTEGRITY
# ===========================================================================
# SHA-256 hash of loaded certificate for integrity verification.
# Calculated when certificate is loaded and compared at startup.
# If hash doesn't match, certificate has been tampered with.
CERTIFICATE_SHA256 = None  # Populated at runtime when certificate is loaded

# ===========================================================================
# CERTIFICATE INTEGRITY
# ===========================================================================
# SHA-256 hash of loaded certificate for integrity verification.
# Calculated when certificate is loaded and compared at startup.
# If hash doesn't match, certificate has been tampered with.
CERTIFICATE_SHA256 = None  # Populated at runtime when certificate is loaded

# ===========================================================================
# CERTIFICATE INTEGRITY
# ===========================================================================
# SHA-256 hash of loaded certificate for integrity verification.
# Calculated when certificate is loaded and compared at startup.
# If hash doesn't match, certificate has been tampered with.
CERTIFICATE_SHA256 = None  # Populated at runtime when certificate is loaded

# ===========================================================================
# CERTIFICATE INTEGRITY
# ===========================================================================
# SHA-256 hash of loaded certificate for integrity verification.
# Calculated when certificate is loaded and compared at startup.
# If hash doesn't match, certificate has been tampered with.
CERTIFICATE_SHA256 = None  # Populated at runtime when certificate is loaded

# ===========================================================================
# CAPACITY & PAGE STRUCTURE
# ===========================================================================
MAX_MSG_CHARS = 255                 # max characters per message
DIGITS_PER_PAD = MAX_MSG_CHARS * 2  # 510 digits per page
COLS = 30                           # grid columns (30 x 17 rows = 510)
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"

# Hex mode (primary): fixed code map, no per-page table needed.
HEXCHARS = "0123456789ABCDEF"
HEX_CODE = {c: "%02d" % i for i, c in enumerate(HEXCHARS)}
HEX_INV = {i: c for i, c in enumerate(HEXCHARS)}

# Capacity budget:
PRINTABLE_CAP = MAX_MSG_CHARS                 # 255 chars per printable page
HEX_CAP_BYTES = DIGITS_PER_PAD // 4           # 127 bytes per hex page
SERIES_PART_OVERHEAD = 2                      # reserved chars per part
PRINTABLE_PART_CAP = PRINTABLE_CAP - SERIES_PART_OVERHEAD   # 253
HEX_PART_CAP_BYTES = (HEX_CAP_BYTES - SERIES_PART_OVERHEAD) // 2   # 62
MAX_PARTS = 99                                # 2-digit total field in header
SERIES_FLAG = "1"                             # multipart flag digit
HEADER_LEN = 45                               # identification prefix length
HDR_SALT = "universal-otp-hdr-v1"             # fixed constant, shared by both ends

# ===========================================================================
# SDR CAPTURE PARAMETERS
# ===========================================================================
GAIN = 30                                   # manual gain dB (doctrine range 20-40, no AGC)
RATE = 1000000                              # sample rate: 1 Msps = 2 MB/s raw
MAX_RETRIES = 3                             # automatic re-captures per run
FREQS = (26000000, 27500000, 28500000, 31000000, 40000000, 61500000)

# Front-end health classification (raw int8 IQ over USB; byte 128 == sample 0):
DEAD_ZERO_FRAC = 0.50        # >50% of samples at DC => no RF reaching the mixer
CLIP_OVERLOAD_FRAC = 0.05    # >5% of samples pinned to ADC rails => front-end overload

# Auto-sweep (overload recovery):
SWEEP_START_MHZ = 25.0
SWEEP_STEP_KHZ = 250
SWEEP_MAX_MHZ = 40.0
SWEEP_PROBE_BYTES = 512 * 1024
SWEEP_PROBE_ENTROPY_MIN = 5.0
SWEEP_DEAD_STREAK_MAX = 3

# Calibration/tuning parameters
CALIBRATION_ENABLED = True
CALIBRATION_LOWER_START_MHZ = 26.0
CALIBRATION_LOWER_STEP_KHZ = 500
CALIBRATION_LOWER_ENTROPY_MIN = 5.0
CALIBRATION_UPPER_START_MHZ = 220.0  # RTL2832U max is ~220 MHz
CALIBRATION_UPPER_STEP_KHZ = 500
CALIBRATION_UPPER_ENTROPY_MIN = 5.0
CALIBRATION_DEAD_STREAK_MAX = 3

# Tuning results (populated by calibration)
LOWER_LIMIT_MHZ = 26.0
UPPER_LIMIT_MHZ = 229.5
LOWER_LIMIT_FREQ_HZ = 26000000
UPPER_LIMIT_FREQ_HZ = 229500000
TUNING_COMPLETE = True

# Udev rule check state (auto-set on first run)
UDEV_CHECKED = False
UDEV_INSTALLED = False

SAMPLE_BYTES = 5898240              # 5.9 MB sanity sample (held in RAM only)
BLOCK_SIZE = 262144                 # 256 KB digest block

# ===========================================================================
# STATISTICAL GATES
# ===========================================================================
BYTE_ENTROPY_MIN = 7.9              # bits/byte, Shannon entropy floor
BYTE_CHISQ_CRIT = 293.2             # chi-square critical value, df=255
DIGIT_CHISQ_CRIT = 16.92            # chi-square critical value, df=9

# ===========================================================================
# SYSTEM REQUIREMENTS
# ===========================================================================
REQUIRED_BINARIES = [
    "awk", "od", "sort", "uniq", "fold", "cut", "tr", "wc",
    "timeout", "dd", "sha256sum", "sha3sum", "shred", "rtl_sdr",
]

# Known RTL-SDR dongle USB IDs (vendor, product), as reported by sysfs
# (4-digit lowercase hex).
RTL_USB_IDS = (
    ("0bda", "2838"),   # RTL2832U (the standard SDR dongle)
    ("0bda", "2837"),
    ("0bda", "2839"),
)

# ===========================================================================
# MARKERS
# ===========================================================================
SANDBOX_MARK = "MODE: SANDBOX TEST - NOT OPERATIONAL KEY MATERIAL"
BANNER_PRINTABLE = "CIPHERVAULT ONE-TIME PAD - ATMOSPHERIC NOISE (SDR) - SINGLE USE ONLY"
BANNER_HEX = "CIPHERVAULT HEX PAD - ATMOSPHERIC NOISE (SDR) - SINGLE USE ONLY"
FP_MARK = "PAGE FINGERPRINT (SHA3-256): "

# ===========================================================================
# PAD PAGE TEMPLATES
# ===========================================================================
#
# These templates define the layout of every pad page. The crypto engine
# fills in the placeholders with generated data. Templates are read by
# format_pad_page() and format_hex_pad_page() in crypto.py.
#
# Placeholders use {name} syntax. The engine calls template.format(**data)
# to produce the final page text.
#

# Printable (fallback) pad page template
PRINTABLE_TEMPLATE = dedent("""\
================================================================
 {banner}
 Batch {batchid}  |  Pad {pad} of {n_pads}  |  Method: SDR  |  Generated: {datestr}
 TOOL VERSION: {version}
================================================================

SUBSTITUTION TABLE - THIS PAGE ONLY (assigned at random at generation):
 {line1}
 {line2}
 {line3}

PAD GRID - {digits_per_pad} digits. Covers up to {printable_cap} characters (2 digits per character).
 Read left to right, top to bottom. C01 is the first digit of row R01.
        [C01-C05] [C06-C10] [C11-C15] [C16-C20] [C21-C25] [C26-C30]
{grid_rows}

----------------------------------------------------------------
MESSAGE FORM - one message per page. Then burn the page.

STEP 1  PLAINTEXT (letters and digits only, no spaces or punctuation, max {printable_cap}):
 {u72}
 {u72}
 {u72}
STEP 2  ENCODED - two digits per character from the table at top of page:
 {u72}
 {u72}
 {u72}
STEP 3  PAD DIGITS - from the grid above, starting at C01 of R01:
 {u72}
 {u72}
STEP 4  RESULT - encrypt: (step 2 + step 3) mod 10 per digit.
         decrypt: (cipher - pad) mod 10; if negative, add 10.
 {u72}
 {u72}
STEP 5  TRANSMISSION - send STEP 4 only, in groups of five:
 {u72}
 {u72}

HOW TO USE (read once):
 ENCRYPT: fill steps 1-5. Each character (letter or digit) becomes
 two digits from the table; add each digit to the next pad digit
 mod 10; send step 5.
 DECRYPT: write the received cipher in STEP 4 (groups of five),
 read pad digits in STEP 3 from C01 of R01, subtract mod 10
 (add 10 if negative) to get STEP 2; translate each digit pair
 back to a letter or digit with the table. That is your message.
 EXAMPLE (this page's table; the pad digits shown are illustrative -
 real work always reads pad digits from the grid):
   letter a here = {perm0_10d}, letter b here = {perm1_10d}
   encode "ab"   ->   {a1}{a2}  {b1}{b2}
   pad (example)      ->   5   9   2   3
   cipher = (e+p)%10 ->   {a1p5}   {a2p9}   {b1p2}   {b2p3}
----------------------------------------------------------------
FOOTER - fill in by hand before use; both stations verify, then burn:
 Digit count: {digits_per_pad}   Date: {datestr}   Operator: ______________
 Batch ID: {batchid}   Method: SDR
 {fp_mark}{fp_zeroed}
 (auto field - stamped by the generator; the send and receive tools
 verify it on every run. If verification fails the page is refused and
 quarantined. Do not edit this page after generation.)
 RULES: whole page only | single use | before encrypting check pad
 digits remaining >= 2 x character count | on transmission error
 retransmit on fresh cells (never reuse) | burn after use.
{sandbox_line}
================================================================""")

# Hex (primary) pad page template
HEX_TEMPLATE = dedent("""\
================================================================
 {banner}
 Batch {batchid}  |  Pad {pad} of {n_pads}  |  Method: SDR  |  Generated: {datestr}
 TOOL VERSION: {version}
================================================================

PAD GRID - {digits_per_pad} digits. Hex mode: fixed code map 0-9 -> 00-09, A-F -> 10-15.
 One page covers {hex_cap_bytes} bytes of any Unicode text ({hex_cap_bytes_2x} hex chars).
 Read left to right, top to bottom. C01 is the first digit of row R01.
        [C01-C05] [C06-C10] [C11-C15] [C16-C20] [C21-C25] [C26-C30]
{grid_rows}

----------------------------------------------------------------
 RULES: whole page only | single use | burn after both stations
 verify consumption. Do not edit this page after generation.
{sandbox_line}
 {fp_mark}{fp_zeroed}
 (auto field - stamped by the generator; verified on every run.)
================================================================""")

# ===========================================================================
# BOOTSTRAP / INSTALLER CONFIG
# ===========================================================================
TERMINALS = ("kitty", "alacritty", "gnome-terminal", "konsole", "xterm")
REEXEC_FLAG = "CIPHERVAULT_REEXEC"
NO_AUTOINSTALL_FLAG = "CIPHERVAULT_NO_AUTOINSTALL"

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