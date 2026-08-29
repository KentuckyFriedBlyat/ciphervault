"""Forward Error Correction (FEC) for over-the-air transmission only.

Air interfaces (JS8Call / VARA-HF / VarAC-style chat links) corrupt bits;
USB distribution of pads stays SHA-fingerprint-protected and does NOT use
this module (SUBTASK 7, v1.4.0-dev).

Mechanism (rotated 4-symbol groups, no new crypto):
- Every character of the transmittable string is first mapped to two hex
  digits (fixed public byte mapping: format(ord(ch), '02X')), then each hex
  digit of value b becomes a 4-char group: ALPHABET[(b + j) % 16] for
  j = 0..3. The rotation breaks naive repeated-symbol grouping by an
  eavesdropper.
- Frame format: 'FECv1 <space-separated 4-char groups>'.
- Distinct valid groups differ in all 4 positions (Hamming distance 4), so
  up to 3 corrupted characters inside any one group are always rejected; a
  group can only silently decode as another value if all 4 of its characters
  are replaced by exactly the other group's characters.
- decode() returns the original text ONLY if every group passes the
  agreement check; any mismatch raises ValueError. No partial acceptance and
  no symbol-level correction - a transmission must be exact or it is not
  used (same policy as SHA-verified pads). This is error DETECTION for the
  air interface, not correction; message redundancy lives elsewhere.
- FEC is a fixed, public, deterministic encoding of OTP ciphertext: it adds
  no key material and does not weaken information-theoretic security (any
  deterministic public transformation of a one-time-pad ciphertext preserves
  its security). It is the air interface's error tolerance, nothing else.
- Pad size on USB is UNCHANGED; only the transmitted text grows (8x).
"""

ALPHABET = "0123456789ABCDEF"
MARKER = "FECv1"
MAX_TEXT_CHARS = 60_000  # transmittable string limit; keeps frames manageable for JS8Call/VARA segmentation


def encode(text: str) -> str:
    """Encode a transmittable string into an FECv1 frame (8x expansion)."""
    if not text or len(text) > MAX_TEXT_CHARS:
        raise ValueError(
            "bad length %d (need 1..%d)" % (len(text), MAX_TEXT_CHARS))
    if any(ord(ch) > 0xFF for ch in text):
        raise ValueError("non-Latin-1 character in transmittable string")
    hexs = "".join(format(ord(ch), "02X") for ch in text)
    groups = []
    for ch in hexs:
        b = ALPHABET.index(ch)
        groups.append("".join(ALPHABET[(b + j) % 16] for j in range(4)))
    return MARKER + " " + " ".join(groups)


def decode(frame: str) -> str:
    """Decode an FECv1 frame back to the original text; ValueError on ANY mismatch."""
    t = frame.strip()
    if not (t.startswith(MARKER + " ") or t == MARKER):
        raise ValueError("missing FECv1 marker")
    body = t[len(MARKER):].strip()
    if not body:
        raise ValueError("empty frame")
    tokens = body.split()
    if len(tokens) % 2 != 0:
        raise ValueError("odd number of groups (%d)" % len(tokens))
    hexs = []
    for i, tok in enumerate(tokens):
        if len(tok) != 4 or any(c not in ALPHABET for c in tok.upper()):
            raise ValueError("bad group %r at position %d" % (tok, i))
        tok = tok.upper()
        b = ALPHABET.index(tok[0])
        if any(tok[j] != ALPHABET[(b + j) % 16] for j in range(1, 4)):
            raise ValueError("group %r at position %d fails 4x agreement" % (tok, i))
        hexs.append(tok[0])
    return bytes.fromhex("".join(hexs)).decode("latin-1")
