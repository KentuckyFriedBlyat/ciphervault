"""RAM-only self check (fixture builder + run_selfcheck)."""

from datetime import date
from pathlib import Path
import hashlib
import os
import tempfile
from config.config import BYTE_CHISQ_CRIT, BYTE_ENTROPY_MIN, DIGITS_PER_PAD, FP_MARK, PRINTABLE_PART_CAP, SANDBOX_MARK
from .crypto import CryptoEngine, _ByteStream, _next_digit, _uniform_int
from .shred import secure_shred

def _selfcheck_fixture():
    """Deterministic 64 KB byte fixture built from SHA3-256 of counters.

    Used instead of live randomness so the self check is a stable PASS/FAIL
    signal about the code paths, not about today's noise quality.
    """
    out = bytearray()
    for i in range(2048):
        out.extend(hashlib.sha3_256(b"cipher_vault_selfcheck_fixture_%d" % i).digest())
    return bytes(out)


def _build_test_page(kind, fixture, batchid, p, sandbox=False, seed=0):
    """Build a fully stamped test page entirely in RAM (no disk writes).

    `seed` rotates the fixture so distinct pages get distinct grids/tables.
    """
    off = (seed * 997) % len(fixture)
    data = fixture[off:] + fixture[:off]
    stream = _ByteStream(data)
    grid = []
    for _ in range(DIGITS_PER_PAD):
        v = _next_digit(stream)
        if v < 0:
            raise RuntimeError("fixture exhausted")
        grid.append(str(v))
    grid_str = "".join(grid)
    today = date.today().isoformat()
    if kind == "hex":
        lines = CryptoEngine.format_hex_pad_page(batchid, p, 1, today, grid_str,
                                                 sandbox=sandbox)
    else:
        perm = list(range(36))
        for i in range(35, 0, -1):
            j = _uniform_int(i + 1, stream)
            if j < 0:
                raise RuntimeError("fixture exhausted")
            perm[i], perm[j] = perm[j], perm[i]
        lines = CryptoEngine.format_pad_page(batchid, p, 1, today, perm, grid_str,
                                             sandbox=sandbox)
    content = "\n".join(lines) + "\n"
    fp = CryptoEngine.fp_digest(content.encode("utf-8"))
    return "\n".join(
        FP_MARK + fp if ln.startswith(FP_MARK) else ln for ln in lines) + "\n"


def run_selfcheck():
    """RAM-only self check. Returns True (PASS) or False (FAIL).

    Everything runs in memory: pages are built and verified as strings, the
    round trips happen on in-RAM data, and the single wiper probe file is
    created in the system temp area and shredded immediately. Nothing is
    written to the program's working directory, and nothing survives.
    """
    try:
        fixture = _selfcheck_fixture()

        # 1. statistical gate functions (accept uniform, reject constant)
        ent, x2 = CryptoEngine.run_chi_square_bytes(fixture)
        if not (ent >= BYTE_ENTROPY_MIN and x2 < BYTE_CHISQ_CRIT):
            return False
        ent_c, x2_c = CryptoEngine.run_chi_square_bytes(bytes(65536))
        if ent_c >= BYTE_ENTROPY_MIN and x2_c < BYTE_CHISQ_CRIT:
            return False

        # 2. printable page: build in RAM, verify fingerprint + structure
        ptxt = _build_test_page("printable", fixture, "BSELF-TEST-01", 1)
        ok, _r = CryptoEngine.verify_page_text(ptxt)
        if not ok:
            return False

        # 3. tamper detection: one flipped character must break the fingerprint
        flip = len(ptxt) // 2
        bad = ptxt[:flip] + ("a" if ptxt[flip] != "a" else "b") + ptxt[flip + 1:]
        ok, reason = CryptoEngine.verify_page_text(bad)
        if ok or "MISMATCH" not in reason:
            return False

        # 4. printable round trip
        pageA = CryptoEngine.parse_page_text(ptxt)
        msg = "CIPHERVAULT123ROUNTRIP"
        st, _b, _p, _c, cipher_digits = CryptoEngine.encrypt_printable(msg, pageA)
        if st != "OK":
            return False
        st2, plain, bp, _b2, _p2 = CryptoEngine.decrypt_printable(cipher_digits, pageA)
        if not (st2 == "OK" and plain.upper() == msg):
            return False

        # 5. hex page + full-Unicode round trip (multi-language + emoji)
        htxt = _build_test_page("hex", fixture, "BSELF-TEST-02", 1, seed=1)
        ok, _r = CryptoEngine.verify_page_text(htxt)
        if not ok:
            return False
        pageH = CryptoEngine.parse_page_text(htxt)
        uni = "H\u00e9llo w\u00f6rld \u2014 \u65e5\u672c\u8a9e \u043f\u0440\u0438\u0432\u0435\u0442 " \
              "\U0001F680\U0001F525 100% ok"
        st, _b, _p, nbytes, cipher_digits = CryptoEngine.encrypt_hex(uni, pageH)
        if st != "OK" or nbytes != len(uni.encode("utf-8")):
            return False
        st2, back, bp, _b2, _p2 = CryptoEngine.decrypt_hex(cipher_digits, pageH)
        if not (st2 == "OK" and back == uni):
            return False

        # 6. wrong-pad detection in both modes
        pageB = CryptoEngine.parse_page_text(
            _build_test_page("printable", fixture, "BSELF-TEST-04", 1, seed=3))
        # printable tables cover all of 00-35: a wrong pad yields garbage OK or
        # BADPAIRS - both defined behaviors; the status must be one of them.
        st3, _pl, bp3, _b3, _p3 = CryptoEngine.decrypt_printable(cipher_digits, pageB)
        if not (st3 in ("OK", "BADPAIRS")):
            return False
        # hex mode has strong detection: codes > 15 are invalid, so a wrong pad
        # grid almost certainly trips BADPAIRS.
        st4, _pl4, bp4, _b4, _p4 = CryptoEngine.decrypt_hex(cipher_digits, pageA)
        if not (st4 == "BADPAIRS" and bp4 > 0):
            return False

        # 7. sandbox pages are inherently refused for operational use
        sxtxt = _build_test_page("hex", fixture, "BSELF-TEST-03", 1, sandbox=True, seed=2)
        if not CryptoEngine.is_sandbox_page(sxtxt):
            return False
        if SANDBOX_MARK not in sxtxt:
            return False

        # 8. series split / reassembly logic (2-char part numbers, flag+total header)
        long_msg = "CIPHERVAULT" * 60          # 780 chars -> 3 printable parts
        n_parts = -(-len(long_msg) // PRINTABLE_PART_CAP)
        if n_parts != 3:
            return False
        headers = []
        ciphers = []
        for i in range(n_parts):
            chunk = long_msg[i * PRINTABLE_PART_CAP:(i + 1) * PRINTABLE_PART_CAP]
            payload = "%02d" % (i + 1) + chunk
            pg = _build_test_page("printable", fixture, "BSELF-TEST-S%d" % (i + 1), 1, seed=10 + i)
            pageS = CryptoEngine.parse_page_text(pg)
            st, bid, pnum, _c, cd = CryptoEngine.encrypt_printable(payload, pageS)
            if st != "OK":
                return False
            headers.append(CryptoEngine.series_prefix(bid, pnum, n_parts))
            ciphers.append(cd)
        for i in range(n_parts):
            info = CryptoEngine.parse_prefix(headers[i])
            if info is None or info[0] != "series" or info[2] != n_parts:
                return False
        assembled = []
        for i in range(n_parts):
            st, back, bp, _b, _p = CryptoEngine.decrypt_printable(ciphers[i],
                                                                  CryptoEngine.parse_page_text(
                                                                      _build_test_page(
                                                                          "printable",
                                                                          fixture,
                                                                          "BSELF-TEST-S%d" % (i + 1),
                                                                          1, seed=10 + i)))
            if st != "OK":
                return False
            pnum = int(back[:2])
            if pnum != i + 1:
                return False
            assembled.append(back[2:].upper())
        if "".join(assembled) != long_msg:
            return False

        # 8b. environmental frequency wobble: harvest non-empty, offset bounded
        matrix = CryptoEngine._harvest_thermal_entropy()
        if not matrix:
            return False
        wf, sensors = CryptoEngine.apply_frequency_wobble(21000000, 64)
        if sensors < 1 or not (abs(wf - 21000000) <= 500000):
            return False

        # 9. wiper probe: one small file in system temp, shredded immediately
        probe = Path(tempfile.gettempdir()) / ("cv_selfcheck_probe_%d.txt" % os.getpid())
        try:
            probe.write_bytes(os.urandom(4096))
            secure_shred(probe)
            if probe.exists():
                return False
        finally:
            if probe.exists():
                probe.unlink()

        # 10. FEC (air interface only): round-trip + error injection
        from .import fec
        sample = "123456789012345678901234567890123456789|ABCDEF0123\n"
        frame = fec.encode(sample)
        if not frame.startswith(fec.MARKER + " "):
            return False
        if len(frame.split()) != 1 + 2 * len(sample):
            return False
        if fec.decode(frame) != sample:
            return False
        toks = frame.split()
        for victim in (1, len(toks) // 2, len(toks) - 1):
            g = list(toks[victim])
            g[0] = fec.ALPHABET[(fec.ALPHABET.index(g[0]) + 1) % 16]
            bad = list(toks)
            bad[victim] = "".join(g)
            try:
                fec.decode(" ".join(bad))
                return False
            except ValueError:
                pass
        try:
            fec.decode(frame[:-2] + ("00" if frame[-2:] != "00" else "11"))
            return False
        except ValueError:
            pass
        try:
            fec.decode(sample)  # no marker -> must refuse
            return False
        except ValueError:
            pass

        return True
    except Exception:
        return False
