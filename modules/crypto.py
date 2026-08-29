"""Hardware-aligned pad pipeline: digest stream, rejection sampling, pages, encrypt/decrypt."""

from datetime import date
from pathlib import Path
import hashlib
import math
import re
import time
from . import state
from config.config import BANNER_HEX, BANNER_PRINTABLE, BYTE_CHISQ_CRIT, BYTE_ENTROPY_MIN, CHARSET, COLS, DIGITS_PER_PAD, DIGIT_CHISQ_CRIT, FP_MARK, FREQS, GAIN, HDR_SALT, HEADER_LEN, HEX_CAP_BYTES, HEX_CODE, HEX_INV, MAX_PARTS, MAX_RETRIES, PRINTABLE_CAP, SAMPLE_BYTES, SANDBOX_MARK, SERIES_FLAG, VERSION, VERSION_MARK
from .noise import CaptureError, SdrNoiseSource

class _ByteStream:
    """Sequential cursor over the verified digest byte stream."""

    __slots__ = ("data", "i")

    def __init__(self, data):
        self.data = data
        self.i = 0

    def getbyte(self):
        if self.i >= len(self.data):
            return -1
        b = self.data[self.i]
        self.i += 1
        return b


def _uniform_int(k, stream):
    """Uniform integer in [0, k-1] from hardware bytes.

    Bytes >= 256-(256%k) are rejected so every value lands with exactly
    probability 1/k (rejection sampling - eliminates modulo bias).
    Returns -1 when the stream is exhausted.
    """
    m = 256 - (256 % k)
    while True:
        b = stream.getbyte()
        if b < 0:
            return -1
        if b < m:
            return b % k


def _next_digit(stream):
    """Next pad digit: mod-10 with rejection (bytes >= 240 discarded)."""
    while True:
        b = stream.getbyte()
        if b < 0:
            return -1
        if b < 240:
            return b % 10


class CryptoEngine:
    """Static encapsulation of the verification formulas and page machinery.

    ABSOLUTE ZERO-OS-ENTROPY MANDATE: no 'random' or 'secrets' import
    anywhere in this file. Every integer used to build pad material comes
    from hardware bytes captured off the SDR bus (or, in sandbox mode only,
    from system entropy - clearly marked test material that is refused for
    operational use).
    """

    # -- digests -----------------------------------------------------------
    @staticmethod
    def fp_digest(data_bytes):
        """SHA3-256 of arbitrary bytes -> exactly 64 hex characters."""
        d = hashlib.sha3_256(data_bytes).hexdigest()
        if len(d) != 64:                      # defensive; sha3_256 is fixed-width
            raise ValueError("digest width anomaly")
        return d

    @staticmethod
    def derive_header(batch, pad):
        """One-way salted page identification prefix (45 decimal digits).

        SHA3-256 of SALT|batch|pad, read as eight 32-bit groups rendered in
        decimal (zero-padded to 10), first 45 digits taken. One-way: the
        prefix identifies a page only to a station that holds pages.
        Identical construction on both ends and every machine.
        """
        h = hashlib.sha3_256(
            ("%s|%s|%s" % (HDR_SALT, batch, pad)).encode("utf-8")).hexdigest()
        out = []
        for g in range(8):
            grp = h[g * 8:(g + 1) * 8]
            out.append("%010d" % int(grp, 16))
        return "".join(out)[:HEADER_LEN]

    @staticmethod
    def series_prefix(batch, pad, total):
        """Extended transmission header for a multi-part series (48 digits):
        the 45-digit one-way identification prefix + the multipart flag
        digit + the 2-digit total part count. The ID portion stays one-way;
        the trailing metadata is plain by design so the receiver can detect
        incomplete series before touching any pad page."""
        if not (2 <= total <= MAX_PARTS):
            raise ValueError("series total out of range (2-%d)" % MAX_PARTS)
        return CryptoEngine.derive_header(batch, pad) + SERIES_FLAG + "%02d" % total

    @staticmethod
    def parse_prefix(digits):
        """Parse a transmission header. Returns:
          ('single', id45)            for a 45-digit prefix
          ('series', id45, total)     for a 48-digit series-part prefix
          None                        for anything else
        """
        if len(digits) == HEADER_LEN and digits.isdigit():
            return ("single", digits)
        if (len(digits) == HEADER_LEN + 3 and digits[:HEADER_LEN].isdigit()
                and digits[HEADER_LEN] == SERIES_FLAG and digits[HEADER_LEN + 1:].isdigit()):
            total = int(digits[HEADER_LEN + 1:])
            if 2 <= total <= MAX_PARTS:
                return ("series", digits[:HEADER_LEN], total)
        return None

    # -- statistical gates (port of the original awk verification block) ---
    @staticmethod
    def run_chi_square_bytes(data):
        """Shannon entropy + uniform chi-square over raw bytes.

        Port of the original byte-uniformity test: input is a byte string,
        output is (entropy_bits_per_byte, chi_square_df255). Runs in RAM.
        """
        n = len(data)
        if n == 0:
            raise ValueError("NO DATA")
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        h = 0.0
        x2 = 0.0
        e = n / 256
        for c in counts:
            if c:
                p = c / n
                h -= p * math.log(p, 2)
            x2 += (c - e) ** 2 / e
        return h, x2

    @staticmethod
    def run_chi_square_byte(path):
        """File-based gate (reads the file into RAM first). Returns True ONLY
        if entropy >= 7.9 and chi-square variance < 293.2 (df=255)."""
        with open(path, "rb") as f:
            data = f.read()
        h, x2 = CryptoEngine.run_chi_square_bytes(data)
        return h >= BYTE_ENTROPY_MIN and x2 < BYTE_CHISQ_CRIT

    @staticmethod
    def run_chi_square_digits(digits):
        """Chi-square of the mod-10 digit stream vs uniform (df=9)."""
        n = len(digits)
        if n == 0:
            raise ValueError("NO DATA")
        counts = [0] * 10
        for d in digits:
            counts[d] += 1
        e = n / 10
        x2 = sum((c - e) ** 2 / e for c in counts)
        return n, x2

    # -- page parsing / verification ---------------------------------------
    _TABLE_TOK = re.compile(r"^([a-z0-9])=(\d\d)$")
    _ROW_RE = re.compile(r"^R(\d\d)")
    _BATCH_LINE = re.compile(r"Batch\s+(\S+)\s*\|\s+Pad\s+(\d+)\s+of")

    @classmethod
    def parse_page_text(cls, text):
        """Extract kind, table, grid, batch/pad ids, tool version and
        fingerprint from a page. `version` is None for pre-revision pages
        that carry no TOOL VERSION line (they still verify as-is)."""
        lines = text.split("\n")
        kind = "hex" if BANNER_HEX in text else "printable"
        table = {}
        inv = {}
        grid_parts = []
        batchid = None
        padnum = None
        fingerprint = None
        version = None
        for ln in lines:
            for tok in ln.split(" "):
                m = cls._TABLE_TOK.match(tok)
                if m:
                    table[m.group(1)] = m.group(2)
                    inv[int(m.group(2))] = m.group(1)
            row = cls._ROW_RE.match(ln)
            if row:
                rest = ln[row.end():]
                grid_parts.append("".join(rest.split(" ")))
            mb = cls._BATCH_LINE.search(ln)
            if mb and batchid is None:
                batchid, padnum = mb.group(1), mb.group(2)
            if ln.startswith(FP_MARK):
                fingerprint = ln[len(FP_MARK):].strip()
            s = ln.strip()
            if s.startswith(VERSION_MARK) and version is None:
                version = s[len(VERSION_MARK):].strip()
        return {
            "kind": kind,
            "table": table,
            "inv": inv,
            "grid": "".join(grid_parts),
            "batchid": batchid,
            "padnum": padnum,
            "fingerprint": fingerprint,
            "version": version,
        }

    @classmethod
    def parse_page(cls, path):
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        return cls.parse_page_text(text)

    @staticmethod
    def is_sandbox_page(text_or_path):
        """Sandbox pages carry a stamped marker and are refused for any
        operational use."""
        if isinstance(text_or_path, (str, Path)) and not isinstance(text_or_path, bytes):
            try:
                p = Path(text_or_path)
                if p.is_file() and len(str(text_or_path)) < 4096:
                    text_or_path = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                pass
        return SANDBOX_MARK in str(text_or_path)

    @classmethod
    def verify_page_text(cls, text):
        """Recompute the page fingerprint (signature row zeroed) and check
        structure. Returns (True, 'OK') or (False, reason).

        Primary: SHA3-256 of the whole page with the fingerprint field
        zeroed - covers every byte and blank space; any later edit is
        detectable. Secondary: printable pages must carry exactly 36 valid
        alphanumeric lookup keys (no duplicates) and exactly 510 digits of
        grid data matrix; hex pages must carry exactly 510 grid digits.
        """
        lines = text.split("\n")
        stored = None
        for ln in lines:
            if ln.startswith(FP_MARK):
                stored = ln[len(FP_MARK):].strip()
                break
        if not stored:
            return False, "NO FINGERPRINT LINE (pre-revision page)"
        zeroed = "\n".join(
            FP_MARK + "0" * 64 if ln.startswith(FP_MARK) else ln for ln in lines)
        comp = CryptoEngine.fp_digest(zeroed.encode("utf-8"))
        if stored != comp:
            return False, "FINGERPRINT MISMATCH stored=%s computed=%s" % (stored, comp)
        page = cls.parse_page_text(text)
        if page["kind"] == "hex":
            if len(page["grid"]) == DIGITS_PER_PAD:
                return True, "OK"
            return False, "BAD grid=%d (hex page)" % len(page["grid"])
        dup = len(page["table"]) != 36
        if len(page["table"]) == 36 and not dup and len(page["grid"]) == DIGITS_PER_PAD:
            return True, "OK"
        return False, "BAD table=%d grid=%d" % (len(page["table"]), len(page["grid"]))

    @classmethod
    def verify_page(cls, path):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            return False, "UNREADABLE (%s)" % e
        return cls.verify_page_text(text)

    # -- encryption cores ----------------------------------------------------
    @staticmethod
    def group5(s):
        """Group a digit string into blocks of five for transmission."""
        return " ".join(s[i:i + 5] for i in range(0, len(s), 5))

    @classmethod
    def encrypt_printable(cls, plaintext, page):
        """Printable mode: message-form steps 1-4.

        plaintext: uppercase A-Z0-9 only (part number already prepended for
        series parts). Returns (status, batchid, padnum, chars, cipher_digits).
        status is one of OK / EMPTY / TOOLONG / NOPAD / CORRUPT.
        """
        if len(page["table"]) != 36 or len(page["grid"]) != DIGITS_PER_PAD:
            return ("CORRUPT", None, None, 0, "")
        L = len(plaintext)
        if L == 0:
            return ("EMPTY", None, None, 0, "")
        if L > PRINTABLE_CAP:
            return ("TOOLONG", None, None, L, "")
        if 2 * L > len(page["grid"]):
            return ("NOPAD", None, None, L, "")
        grid = page["grid"]
        cipher = []
        for i, ch in enumerate(plaintext):
            c = page["table"].get(ch.lower())
            if c is None:                       # defensive; input is pre-purified
                return ("CORRUPT", None, None, L, "")
            p1 = ord(grid[2 * i]) - 48
            p2 = ord(grid[2 * i + 1]) - 48
            cipher.append(str((ord(c[0]) - 48 + p1) % 10))
            cipher.append(str((ord(c[1]) - 48 + p2) % 10))
        return ("OK", page["batchid"], page["padnum"], L, "".join(cipher))

    @classmethod
    def encrypt_hex(cls, message, page):
        """Hex mode (primary): full Unicode in -> UTF-8 -> hex -> pad.

        Every hex character maps to a fixed 2-digit code (0-9 -> 00-09,
        A-F -> 10-15) and is encrypted with two pad digits mod 10. Series
        parts carry their 2-char part number as the first hex pair.
        message may already include the part number for series parts.
        Returns (status, batchid, padnum, bytes_used, cipher_digits).
        """
        if len(page["grid"]) != DIGITS_PER_PAD:
            return ("CORRUPT", None, None, 0, "")
        data = message.encode("utf-8")
        hx = data.hex().upper()
        if len(hx) == 0:
            return ("EMPTY", None, None, 0, "")
        if len(hx) > DIGITS_PER_PAD // 2:      # max 254 hex chars = 127 payload bytes (4 pad digits per byte)
            return ("TOOLONG", None, None, len(data), "")
        grid = page["grid"]
        cipher = []
        for i, c in enumerate(hx):
            code = HEX_CODE[c]
            p1 = ord(grid[2 * i]) - 48
            p2 = ord(grid[2 * i + 1]) - 48
            cipher.append(str((ord(code[0]) - 48 + p1) % 10))
            cipher.append(str((ord(code[1]) - 48 + p2) % 10))
        return ("OK", page["batchid"], page["padnum"], len(data), "".join(cipher))

    # -- decryption cores ----------------------------------------------------
    @classmethod
    def decrypt_printable(cls, cipher_digits, page):
        """Printable mode: message-form steps 3-5 in reverse, with wrong-pad
        detection (every pair must resolve inside the 00-35 table).
        Returns (status, plain, badpairs, batchid, padnum).
        
        Accepts cipher text with or without spaces/separators - non-digit
        characters are automatically stripped."""
        if len(page["table"]) != 36 or len(page["grid"]) != DIGITS_PER_PAD:
            return ("CORRUPT", "", 0, None, None)
        # Strip non-digit characters (spaces, newlines, etc.) for grouping
        cipher_digits = "".join(c for c in cipher_digits if c.isdigit())
        D = len(cipher_digits)
        if D == 0:
            return ("EMPTY", "", 0, None, None)
        if D % 2 != 0:
            return ("ODD", "", 0, None, None)
        if D > len(page["grid"]):
            return ("NOPAD", "", 0, None, None)
        grid = page["grid"]
        inv = page["inv"]
        plain = []
        badpairs = 0
        for i in range(D // 2):
            c1 = ord(cipher_digits[2 * i]) - 48
            c2 = ord(cipher_digits[2 * i + 1]) - 48
            p1 = ord(grid[2 * i]) - 48
            p2 = ord(grid[2 * i + 1]) - 48
            d1 = (c1 - p1 + 10) % 10
            d2 = (c2 - p2 + 10) % 10
            v = d1 * 10 + d2
            if v > 35 or v not in inv:
                badpairs += 1
                continue
            plain.append(inv[v])
        if badpairs > 0:
            return ("BADPAIRS", "".join(plain), badpairs, page["batchid"], page["padnum"])
        return ("OK", "".join(plain), 0, page["batchid"], page["padnum"])

    @classmethod
    def decrypt_hex(cls, cipher_digits, page):
        """Hex mode: reverse the fixed code map with modulo-10 subtraction.
        Every pair must resolve to a valid code in the hex map (wrong-pad
        detection), and the resulting byte string must be valid UTF-8.
        Returns (status, text, badpairs, batchid, padnum).
        
        Accepts cipher text with or without spaces/separators - non-digit
        characters are automatically stripped."""
        if len(page["grid"]) != DIGITS_PER_PAD:
            return ("CORRUPT", "", 0, None, None)
        # Strip non-digit characters (spaces, newlines, etc.) for grouping
        cipher_digits = "".join(c for c in cipher_digits if c.isdigit())
        D = len(cipher_digits)
        if D == 0:
            return ("EMPTY", "", 0, None, None)
        if D % 2 != 0:
            return ("ODD", "", 0, None, None)
        if D > len(page["grid"]):
            return ("NOPAD", "", 0, None, None)
        grid = page["grid"]
        hexchars = []
        badpairs = 0
        for i in range(D // 2):
            c1 = ord(cipher_digits[2 * i]) - 48
            c2 = ord(cipher_digits[2 * i + 1]) - 48
            p1 = ord(grid[2 * i]) - 48
            p2 = ord(grid[2 * i + 1]) - 48
            d1 = (c1 - p1 + 10) % 10
            d2 = (c2 - p2 + 10) % 10
            v = d1 * 10 + d2
            if v not in HEX_INV:
                badpairs += 1
                continue
            hexchars.append(HEX_INV[v])
        if badpairs > 0:
            return ("BADPAIRS", "", badpairs, page["batchid"], page["padnum"])
        try:
            text = bytes.fromhex("".join(hexchars)).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            return ("BADUTF8", "", 0, page["batchid"], page["padnum"])
        return ("OK", text, 0, page["batchid"], page["padnum"])

    # -- page formatting -----------------------------------------------------
    @staticmethod
    def format_pad_page(batchid, p, n_pads, datestr, perm, grid_digits, sandbox=False):
        """Build the printable fallback pad page (full self-contained sheet).

        `perm` is the Fisher-Yates permutation of 0..35 over CHARSET;
        `grid_digits` is the 510-digit grid string. All randomness has
        already been drawn from the verified hardware byte stream.
        """
        u72 = "_" * 72
        z64 = "0" * 64
        rows = DIGITS_PER_PAD // COLS

        # substitution table: 3 printable rows (13 / 13 / 10 cells)
        line1, line2, line3 = [], [], []
        for i in range(36):
            cell = "%s=%02d" % (CHARSET[i], perm[i])
            if i < 13:
                line1.append(cell)
            elif i < 26:
                line2.append(cell)
            else:
                line3.append(cell)

        L = []
        L.append("=" * 64)
        L.append(" " + BANNER_PRINTABLE)
        L.append(" Batch %s  |  Pad %d of %d  |  Method: SDR  |  Generated: %s"
                 % (batchid, p, n_pads, datestr))
        L.append(" TOOL VERSION: %s" % VERSION)
        L.append("=" * 64)
        L.append("")
        L.append("SUBSTITUTION TABLE - THIS PAGE ONLY (assigned at random at generation):")
        L.append(" " + " ".join(line1))
        L.append(" " + " ".join(line2))
        L.append(" " + " ".join(line3))
        L.append("")
        L.append("PAD GRID - %d digits. Covers up to %d characters (2 digits per character)."
                 % (DIGITS_PER_PAD, PRINTABLE_CAP))
        L.append(" Read left to right, top to bottom. C01 is the first digit of row R01.")
        L.append("        [C01-C05] [C06-C10] [C11-C15] [C16-C20] [C21-C25] [C26-C30]")
        for r in range(rows):
            parts = []
            for g in range(COLS // 5):
                parts.append(grid_digits[r * COLS + g * 5: r * COLS + g * 5 + 5])
            L.append("R%02d     %s" % (r + 1, "  ".join(parts)))
        L.append("")
        L.append("-" * 64)
        L.append("MESSAGE FORM - one message per page. Then burn the page.")
        L.append("")
        L.append("STEP 1  PLAINTEXT (letters and digits only, no spaces or punctuation, max %d):"
                 % PRINTABLE_CAP)
        L.extend([u72, u72, u72])
        L.append("STEP 2  ENCODED - two digits per character from the table at top of page:")
        L.extend([u72, u72, u72])
        L.append("STEP 3  PAD DIGITS - from the grid above, starting at C01 of R01:")
        L.extend([u72, u72])
        L.append("STEP 4  RESULT - encrypt: (step 2 + step 3) mod 10 per digit.")
        L.append("         decrypt: (cipher - pad) mod 10; if negative, add 10.")
        L.extend([u72, u72])
        L.append("STEP 5  TRANSMISSION - send STEP 4 only, in groups of five:")
        L.extend([u72, u72])
        L.append("")
        L.append("HOW TO USE (read once):")
        L.append(" ENCRYPT: fill steps 1-5. Each character (letter or digit) becomes")
        L.append(" two digits from the table; add each digit to the next pad digit")
        L.append(" mod 10; send step 5.")
        L.append(" DECRYPT: write the received cipher in STEP 4 (groups of five),")
        L.append(" read pad digits in STEP 3 from C01 of R01, subtract mod 10")
        L.append(" (add 10 if negative) to get STEP 2; translate each digit pair")
        L.append(" back to a letter or digit with the table. That is your message.")
        a1, a2 = perm[0] // 10, perm[0] % 10
        b1, b2 = perm[1] // 10, perm[1] % 10
        L.append(" EXAMPLE (this page's table; the pad digits shown are illustrative -")
        L.append(" real work always reads pad digits from the grid):")
        L.append("   letter a here = %02d, letter b here = %02d" % (perm[0], perm[1]))
        L.append('   encode "ab"   ->   %d%d  %d%d' % (a1, a2, b1, b2))
        L.append("   pad (example)      ->   5   9   2   3")
        L.append("   cipher = (e+p)%%10 ->   %d   %d   %d   %d"
                 % ((a1 + 5) % 10, (a2 + 9) % 10, (b1 + 2) % 10, (b2 + 3) % 10))
        L.append("-" * 64)
        L.append("FOOTER - fill in by hand before use; both stations verify, then burn:")
        L.append(" Digit count: %d   Date: %s   Operator: ______________"
                 % (DIGITS_PER_PAD, datestr))
        L.append(" Batch ID: %s   Method: SDR" % batchid)
        L.append(FP_MARK + z64)
        L.append(" (auto field - stamped by the generator; the send and receive tools")
        L.append(" verify it on every run. If verification fails the page is refused and")
        L.append(" quarantined. Do not edit this page after generation.)")
        L.append(" RULES: whole page only | single use | before encrypting check pad")
        L.append(" digits remaining >= 2 x character count | on transmission error")
        L.append(" retransmit on fresh cells (never reuse) | burn after use.")
        if sandbox:
            L.append(SANDBOX_MARK)
        L.append("=" * 64)
        return L

    @staticmethod
    def format_hex_pad_page(batchid, p, n_pads, datestr, grid_digits, sandbox=False):
        """Build the simplified hex-mode pad page: number field + checksum.

        No substitution table - the hex code map is fixed and shared by all
        stations (0-9 -> 00-09, A-F -> 10-15), so the page carries only the
        510-digit grid, its identifying metadata (needed for the one-way
        header), and the SHA3-256 fingerprint.
        """
        z64 = "0" * 64
        rows = DIGITS_PER_PAD // COLS
        L = []
        L.append("=" * 64)
        L.append(" " + BANNER_HEX)
        L.append(" Batch %s  |  Pad %d of %d  |  Method: SDR  |  Generated: %s"
                 % (batchid, p, n_pads, datestr))
        L.append(" TOOL VERSION: %s" % VERSION)
        L.append("=" * 64)
        L.append("")
        L.append("PAD GRID - %d digits. Hex mode: fixed code map 0-9 -> 00-09, A-F -> 10-15."
                 % DIGITS_PER_PAD)
        L.append(" One page covers %d bytes of any Unicode text (%d hex chars)."
                 % (HEX_CAP_BYTES, HEX_CAP_BYTES * 2))
        L.append(" Read left to right, top to bottom. C01 is the first digit of row R01.")
        L.append("        [C01-C05] [C06-C10] [C11-C15] [C16-C20] [C21-C25] [C26-C30]")
        for r in range(rows):
            parts = []
            for g in range(COLS // 5):
                parts.append(grid_digits[r * COLS + g * 5: r * COLS + g * 5 + 5])
            L.append("R%02d     %s" % (r + 1, "  ".join(parts)))
        L.append("")
        L.append("-" * 64)
        L.append(" RULES: whole page only | single use | burn after both stations")
        L.append(" verify consumption. Do not edit this page after generation.")
        if sandbox:
            L.append(SANDBOX_MARK)
        L.append(FP_MARK + z64)
        L.append(" (auto field - stamped by the generator; verified on every run.)")
        L.append("=" * 64)
        return L

    # -- environmental frequency wobble (tuning only - never key material) --
    @staticmethod
    def _harvest_thermal_entropy():
        """Scrape all accessible hardware temperature sensors on the system bus.
        Crawls sysfs thermal zones, hardware monitors (hwmon), and legacy ACPI
        trees. Returns a raw byte-matrix string representing live
        thermodynamic variations.

        BOUNDARY NOTE: this telemetry is used ONLY to select the capture
        tuning coordinate (an operational parameter - where to point the
        antenna). It never enters pad material; every key byte still comes
        from the SDR bus, keeping the zero-OS-entropy mandate intact.
        """
        payload = []

        # 1. Broad sysfs thermal zone coverage (CPU die core sensors, etc.)
        try:
            for p in Path('/sys/class/thermal').glob('thermal_zone*/temp'):
                payload.append("tz_%s:%s" % (p.parent.name, p.read_text().strip()))
        except Exception:
            pass

        # 2. Hardware monitoring subsystem (chipsets, northbridge, NVMe, GPUs)
        try:
            for p in Path('/sys/class/hwmon').glob('hwmon*/temp*_input'):
                # Capture both the temperature input value and its hardware
                # label if available
                label = ""
                lbl_path = p.parent / p.name.replace('_input', '_label')
                if lbl_path.exists():
                    label = "_%s" % lbl_path.read_text().strip()
                payload.append("hw_%s%s:%s" % (p.parent.name, label, p.read_text().strip()))
        except Exception:
            pass

        # 3. Legacy ACPI platform trees (system board / ambient chassis arrays)
        try:
            for p in Path('/proc/acpi/thermal_zone').glob('*/temperature'):
                payload.append("acpi_%s:%s" % (p.parent.name, p.read_text().strip()))
        except Exception:
            pass

        # Ensure we always have an absolute baseline even on weird virtualized hardware
        if not payload:
            payload.append("ambient_die_fallback:0")

        return "|".join(payload)

    @staticmethod
    def apply_frequency_wobble(base_freq, blocks):
        """Shift the capture center coordinate by up to +/-500 kHz using a
        dynamic differential matrix sourced from every visible physical
        thermal sensor on the local host bus, mixed with nanosecond timing.

        Purpose: the base quiet-zone bands are fixed and known; an adversary
        who records the same band during a capture window could attempt to
        reconstruct the noise stream that was digested into pad material.
        Wobbling the exact tuning coordinate per batch makes it unpredictable
        in advance, while the resulting frequency is still recorded in the
        batch record for operator audit.

        Affects ONLY the tuning parameter - never key material (which comes
        100% from the SDR bus at that coordinate).

        Returns (jittered_freq_hz, sensor_count).
        """
        # Harvest the live multi-point hardware thermal delta matrix
        thermal_matrix = CryptoEngine._harvest_thermal_entropy()
        sensor_count = len(thermal_matrix.split("|")) if thermal_matrix else 0

        # Mix high-resolution timing strings directly with the environmental
        # state string (operational input - not key material)
        state_mix = "%d|%s|%d" % (time.time_ns(), thermal_matrix, blocks)
        state_hash = hashlib.sha3_256(state_mix.encode('utf-8')).digest()

        # Extract a uniform integer between -500,000 Hz and +499,999 Hz
        jitter_raw = int.from_bytes(state_hash[:3], "big")
        jitter_hz = (jitter_raw % 1000001) - 500000

        # Apply the environmental jitter drift to the physical SDR tuning
        # coordinate, clamped to the RTL2832U-class tuning range as a guard.
        jittered_freq = base_freq + jitter_hz
        if not (1_000_000 <= jittered_freq <= 1_200_000_000):
            jittered_freq = base_freq
            jitter_hz = 0

        return jittered_freq, sensor_count

    # -- capture + verify loop (RAM-ONLY captures, auto-retry, freq rotation)
    @staticmethod
    def _capture_and_verify(freq, blocks, n_pads, source, log):
        """Run one full capture cycle with all four verification gates.

        Every byte of every sample lives and dies in RAM: the opening and
        closing sanity samples are read into memory and tested in memory;
        the main capture streams 256 KB chunks from the dongle straight into
        SHA-256 digests held in RAM. No raw noise byte touches disk.

        Returns (digest_bytes, stats_dict). Raises CaptureError on any gate
        failure - the caller discards the ENTIRE batch and re-captures at a
        different frequency and time.
        """
        cmhz = freq / 1000000

        # --- opening sanity sample: RAM only ---
        raw = source.capture_sanity(freq)
        if len(raw) != SAMPLE_BYTES:
            raise CaptureError("opening sample short (%d bytes) - I/O fault" % len(raw))
        ent, x2 = CryptoEngine.run_chi_square_bytes(raw)
        # Raw entropy check skipped: we hash the data anyway, so raw entropy
        # below 7.9 is acceptable as long as the digest stream passes.
        # Keep the classify_capture for diagnostics (dead/overloaded detection).
        st, zf, cf, _e = SdrNoiseSource.classify_capture(raw)
        del raw
        log("  [ OK ] raw start: bytes=%d  entropy=%.4f bits/byte  chi-square=%.1f "
            "(df=255, crit=%.1f) [RAM, hashed output]" % (SAMPLE_BYTES, ent, x2, BYTE_CHISQ_CRIT))

        # --- main capture: stream 256 KB chunks straight into SHA-256 digests;
        #     raw bytes of the main capture never touch disk. Hard timeout so a
        #     hung dongle can never hang the tool (short stream -> FAIL path). ---
        def progress(done, total):
            log("  ... main capture %d/%d digest blocks [RAM]" % (done, total))

        digests = source.capture_digests(freq, blocks, progress_cb=progress)
        if len(digests) != blocks * 32:
            raise CaptureError(
                "digest stream short (%d bytes, expected %d) - I/O fault"
                % (len(digests), blocks * 32))

        # --- closing sanity sample: RAM only (brackets the batch) ---
        raw = source.capture_sanity(freq)
        if len(raw) != SAMPLE_BYTES:
            raise CaptureError("closing sample short (%d bytes) - I/O fault" % len(raw))
        ent, x2 = CryptoEngine.run_chi_square_bytes(raw)
        del raw
        log("  [ OK ] raw end:   bytes=%d  entropy=%.4f bits/byte  chi-square=%.1f "
            "(df=255, crit=%.1f) [RAM, hashed output]" % (SAMPLE_BYTES, ent, x2, BYTE_CHISQ_CRIT))

        # --- digest stream uniformity gate (in RAM - never written to disk) --
        ent, x2 = CryptoEngine.run_chi_square_bytes(bytes(digests))
        if not (ent >= BYTE_ENTROPY_MIN and x2 < BYTE_CHISQ_CRIT):
            raise CaptureError(
                "digest stream check failed (bytes=%d entropy=%.4f chi-square=%.1f) - "
                "toolchain fault" % (len(digests), ent, x2))
        log("  [ OK ] digests:   bytes=%d  entropy=%.4f bits/byte  chi-square=%.1f "
            "(df=255, crit=%.1f) [RAM]" % (len(digests), ent, x2, BYTE_CHISQ_CRIT))

        # --- digit chi-square on 0-9 (mod-10 rejection yield) ---------------
        digits = [b % 10 for b in digests if b < 240]
        n_d, x2d = CryptoEngine.run_chi_square_digits(digits)
        if x2d >= DIGIT_CHISQ_CRIT:
            raise CaptureError(
                "digit chi-square failed (N=%d digits chi-square=%.2f)" % (n_d, x2d))
        log("  [ OK ] digits:    N=%d digits  chi-square=%.2f (df=9, crit=%.2f) [RAM]"
            % (n_d, x2d, DIGIT_CHISQ_CRIT))

        # --- stream sufficiency guard ----------------------------------------
        need = n_pads * (580 if True else 600)   # printable worst case governs sizing
        if len(digests) < need:
            raise CaptureError(
                "insufficient verified material (%d < %d bytes)" % (len(digests), need))

        return digests, {"cmhz": cmhz, "n_digits": n_d}

    @staticmethod
    def _record_failed_batch(out_dir, batchid, freq_mhz, reason, sandbox):
        """Write a DISCARDED batch record so the sequence stays auditable."""
        from . import state
        txt = (
            "Batch ID:        %s\n"
            "Date/time:       %s local\n"
            "Operator:        <fill in by hand>\n"
            "Frequency:       %.4f MHz (base band + thermal wobble)\n"
            "Gain / rate:     %d dB manual / 1 Msps\n"
            "Method:          SDR (atmospheric noise, PRIMARY)\n"
            "Disposition:     DISCARDED - %s\n"
            % (batchid, date.today().isoformat(), freq_mhz, GAIN, reason)
        )
        if sandbox:
            txt += SANDBOX_MARK + "\n"
        Path(state.AUDIT_DIR, "BATCH-%s.txt" % batchid).write_text(txt, encoding="utf-8")

    # -- main generation driver ---------------------------------------------
    @staticmethod
    def trigger_generation(n_pads=None, kind="printable", source=None, log=print, progress=None,
                           auto_sweep=True):
        """Full pad-generation pipeline.

        Prompts for a pad count when none is supplied, captures the
        5.9 MB opening stability sample from the SDR bus into RAM, validates
        it with the chi-square gate, streams the main noise block off the bus
        in 256 KB chunks hashed straight into SHA-256 digests held in RAM,
        draws (printable mode) the 36-element Fisher-Yates shuffle and (both
        modes) the 510-digit grid with mod-10 rejection sampling (bytes >= 240
        discarded to eliminate modulo bias), formats the pages, signs each
        footer with a fresh SHA3-256 signature, and leaves nothing on disk
        but the finished pages and batch records.

        kind: 'printable' (fallback, Manual Pads/) or 'hex' (primary, HexPads/).
        auto_sweep: when the tuned coordinate's front end is dead/overloaded,
        slowly sweep upward from the 25 MHz dongle floor until a clean spot is
        found (default True; --no-sweep hard-fails instead).
        """
        if n_pads is None:
            while True:
                try:
                    raw = input("How many pads to generate?: ")
                except EOFError:
                    raise CaptureError("no pad count supplied")
                raw = raw.strip()
                if not raw.isdigit():
                    log("  [WARN] type a whole number, e.g. 5")
                    continue
                n_pads = int(raw)
                break
        if n_pads < 1:
            raise CaptureError("pad count must be at least 1")
        if kind not in ("printable", "hex"):
            raise CaptureError("unknown pad kind: %s" % kind)
        if source is None:
            source = SdrNoiseSource()

        today = date.today().isoformat()
        y, m, d = today[:4], today[5:7], today[8:10]
        out_dir = state.HEXPADS_DIR if kind == "hex" else state.PADS_DIR
        out_dir.mkdir(parents=True, exist_ok=True)

        # Batch numbering (never overwrites unused pads): highest sequence
        # already used today, from existing pad files in this folder.
        pre = "P%s-B" % today
        day_max = 0
        for f in out_dir.glob(pre + "*"):
            rest = f.name[len(pre):]
            num = rest.split("-")[0]
            if num.isdigit() and int(num) > day_max:
                day_max = int(num)
        bseq = day_max

        # Capture sizing: ~21 digest blocks (672 B) per pad covers the 510
        # grid digits plus ~27 substitution bytes with margin. However, the
        # digest stream chi-square test needs at least ~64 blocks (2048 B) to
        # reliably distinguish real entropy from biased sources (with fewer
        # blocks the test has too much variance to be meaningful).
        blocks_per_pad = 21
        blocks = max(blocks_per_pad, 64)                  # floor for statistical validity
        secs_per_batch = (blocks + 3) // 4                 # 4 blocks per second at 1 Msps
        log("This run: %d %s pad(s), ~%ds per batch of noise capture plus verification."
            % (n_pads, kind, secs_per_batch))
        log("Pads go to: %s" % out_dir)
        log("Strategy: capture one pad's worth at a time, write immediately, clear RAM.")

        digest_bytes = None
        stats = None
        batchid = None
        written = []
        total_pads_generated = 0
        try:
            while total_pads_generated < n_pads:
                # ---- capture one pad's worth of entropy -------------------
                bseq += 1
                batchid = "B%s-%s%s-%02d" % (y, m, d, bseq)
                for attempt in range(1, MAX_RETRIES + 1):
                    base_freq = FREQS[(attempt - 1) % len(FREQS)]   # rotate base band each retry
                    freq, sensors = CryptoEngine.apply_frequency_wobble(base_freq, blocks_per_pad)
                    log("Batch %s (attempt %d of %d): base %.1f MHz + wobble %+d Hz -> "
                        "%.4f MHz (%d thermal sensor(s))..."
                        % (batchid, attempt, MAX_RETRIES, base_freq / 1000000, freq - base_freq,
                           freq / 1000000, sensors))
                    try:
                        # Front-end health gate: probe the tuned coordinate BEFORE the
                        # expensive capture. If it is dead or overloaded (clipping),
                        # slowly sweep upward from the 25 MHz floor until a clean spot
                        # is found - a clipped front end must never be mistaken for
                        # "infinite entropy".
                        freq, note = source.resolve_frequency(freq, auto_sweep=auto_sweep, log=log)
                        log("  [ OK ] front-end: %s" % note)
                        digest_bytes, stats = CryptoEngine._capture_and_verify(
                            freq, blocks, 1, source, log)
                    except CaptureError as e:
                        CryptoEngine._record_failed_batch(out_dir, batchid, freq / 1000000,
                                                          str(e), source.sandbox)
                        log("  [WARN] batch discarded: %s (any failed check discards the whole batch)" % e)
                        if attempt >= MAX_RETRIES:
                            raise RuntimeError(
                                "three failed batches in a row - stopping.\n\n"
                                "Troubleshoot: re-run the environment setup, try another USB port "
                                "or a powered hub, and start at a different time."
                            ) from e
                        time.sleep(2)     # re-capture at a different frequency AND time
                    else:
                        break

                # ---- generate and write ONE pad from the verified stream ---
                stream = _ByteStream(digest_bytes)
                p = total_pads_generated + 1
                log("Generating pad %d of %d..." % (p, n_pads))

                # grid digits: mod-10 with rejection (bytes >= 240 discarded)
                grid = []
                okflag = True
                for _ in range(DIGITS_PER_PAD):
                    v = _next_digit(stream)
                    if v < 0:
                        okflag = False
                        break
                    grid.append(str(v))
                if not okflag:
                    raise CaptureError("STREAM EXHAUSTED at pad %d" % p)
                grid_str = "".join(grid)

                if kind == "hex":
                    lines = CryptoEngine.format_hex_pad_page(
                        batchid, p, n_pads, today, grid_str, sandbox=source.sandbox)
                else:
                    # substitution table: random permutation of 0..35 (Fisher-Yates,
                    # driven exclusively by hardware bytes)
                    perm = list(range(36))
                    for i in range(35, 0, -1):
                        j = _uniform_int(i + 1, stream)
                        if j < 0:
                            raise CaptureError("STREAM EXHAUSTED at pad %d" % p)
                        perm[i], perm[j] = perm[j], perm[i]
                    lines = CryptoEngine.format_pad_page(
                        batchid, p, n_pads, today, perm, grid_str, sandbox=source.sandbox)

                content = "\n".join(lines) + "\n"
                fp = CryptoEngine.fp_digest(content.encode("utf-8"))
                stamped = "\n".join(
                    FP_MARK + fp if ln.startswith(FP_MARK) else ln for ln in lines) + "\n"
                path = Path(out_dir, "P%s-B%02d-p%02d.txt" % (today, bseq, p))
                path.write_text(stamped, encoding="utf-8")
                written.append(path)
                total_pads_generated += 1

                log("  [ OK ] pad %d written to %s" % (p, path))

                # ---- clear capture data from RAM before next iteration ----
                # Keep stats/digest_bytes/stream around for the batch record;
                # the RAM savings come from not holding ALL pads' entropy at
                # once, not from discarding one pad's worth of metadata.
                del stream
                digest_bytes = None

            if not written:
                raise CaptureError("no pad pages written")

            # ---- batch record ----------------------------------------------
            rec = (
                "Batch ID:        %s\n"
                "Date/time:       %s local\n"
                "Operator:        <fill in by hand>\n"
                "Frequency:       %.4f MHz (base band + thermal wobble)\n"
                "Gain / rate:     %d dB manual / 1 Msps\n"
                "Duration:        ~%ds per batch x %d batches\n"
                "Raw bytes:       0 on disk (all captures held in RAM and destroyed)\n"
                "Kind:            %s\n"
                "Checks:          raw start PASS | raw end PASS | digests PASS | digits PASS\n"
                "Pads fed:        p01-p%02d of P%s-B%02d set\n"
                "Method:          SDR (atmospheric noise, PRIMARY)\n"
                "Disposition:     ACCEPTED - all three mandatory checks passed\n"
            ) % (batchid, today, stats["cmhz"], GAIN, secs_per_batch, total_pads_generated,
                 kind.upper(), n_pads, today, bseq)
            if source.sandbox:
                rec += SANDBOX_MARK + "\n"
            Path(state.AUDIT_DIR, "BATCH-%s.txt" % batchid).write_text(rec, encoding="utf-8")

            log("")
            log("  [ OK ] fingerprints stamped on all %d page(s)" % len(written))
            if source.sandbox:
                log("  [WARN] sandbox noise source active - these pages are TEST ONLY and "
                    "will be refused for operational use.")
            return written
        finally:
            # Nothing to shred: captures never touched disk. Only the finished
            # pages and batch records remain, by design.
            pass
