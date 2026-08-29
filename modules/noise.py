"""Noise sources: live RTL-SDR capture (RAM only) and the offline sandbox stand-in."""

import hashlib
import math
import os
import subprocess
import time
from collections import Counter
from .compat import select
from config.config import (BLOCK_SIZE, CLIP_OVERLOAD_FRAC, DEAD_ZERO_FRAC,
                                   FREQS, GAIN, RATE, SAMPLE_BYTES, SWEEP_DEAD_STREAK_MAX,
                                   SWEEP_MAX_MHZ, SWEEP_PROBE_BYTES, SWEEP_PROBE_ENTROPY_MIN,
                                   SWEEP_START_MHZ, SWEEP_STEP_KHZ)

class CaptureError(Exception):
    """Raised when a noise capture or one of its verification gates fails."""


class SdrNoiseSource:
    """True-hardware noise source: streams raw IQ bytes off the RTL-SDR bus.

    Hardened capture discipline: NOTHING from a capture touches disk.
      * sanity samples are read into memory and tested in memory;
      * the main capture streams 256 KB chunks from the dongle straight into
        SHA-256 digests held in RAM - only one chunk plus the digest
        accumulator ever exist at once;
      * rtl_sdr's stderr is captured through a pipe and inspected in RAM.
    """

    sandbox = False

    def __init__(self, workdir=None):
        self.workdir = None          # deliberately unused: no capture files

    # -- low-level: exactly n bytes from a non-blocking pipe, hard deadline -
    def _read_exact(self, fd, n, deadline):
        buf = bytearray()
        while len(buf) < n:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise CaptureError("capture timed out (dongle hung or too slow)")
            ready, _, _ = select.select([fd], [], [], min(remaining, 1.0))
            if not ready:
                continue
            try:
                chunk = os.read(fd, min(65536, n - len(buf)))
            except BlockingIOError:
                continue
            if not chunk:
                raise CaptureError("rtl_sdr stream ended early")
            buf.extend(chunk)
        return bytes(buf)

    # -- low-level: open rtl_sdr on a frequency; returns (proc, nonblocking fd)
    def _open_rtl_sdr(self, freq):
        if select is None:
            raise CaptureError("select module unavailable - cannot guard capture timeouts")
        # The trailing "-" is rtl_sdr's documented way of writing samples to
        # stdout; without it the binary prints its usage text and exits, so
        # the pipe closes empty and every capture fails (AUDIT-06).
        # Use AGC for best entropy from atmospheric noise.
        cmd = ["rtl_sdr", "-f", str(freq), "-s", str(RATE), "-"]
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            raise CaptureError("rtl_sdr executable not found on this system")
        fd = proc.stdout.fileno()
        os.set_blocking(fd, False)
        return proc, fd

    @staticmethod
    def _reap(proc):
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    # -- low-level: raw bytes + stderr, all in RAM ---------------------------
    def _raw_capture(self, freq, nbytes, deadline_secs):
        proc, fd = self._open_rtl_sdr(freq)
        try:
            data = self._read_exact(fd, nbytes, time.monotonic() + deadline_secs)
        finally:
            self._reap(proc)
        err = b""
        try:
            if proc.stderr is not None:
                err = proc.stderr.read() or b""
        except Exception:
            pass
        return data, err

    # -- front-end health classification (RAM only) --------------------------
    @staticmethod
    def classify_capture(data):
        """Classify a raw IQ byte stream for front-end health.

        int8 IQ over the USB bus: byte 128 == sample 0, so mass at 127/128 is a
        DEAD/FLAT receiver (no RF reaching the mixer), while bytes 0 and 255 are
        the true ADC rails - mass there means the front end is OVERLOADED
        (clipping). A healthy capture has few samples at either extreme.

        Returns (state, zero_frac, clip_frac, entropy) with state one of
        {'ok', 'dead', 'overloaded'}.
        """
        n = len(data)
        counts = Counter(data)
        zero_frac = (counts.get(127, 0) + counts.get(128, 0)) / n
        clip_frac = (counts.get(0, 0) + counts.get(255, 0)) / n
        ent = -sum((c / n) * math.log(c / n, 2) for c in counts.values())
        if zero_frac > DEAD_ZERO_FRAC:
            state = 'dead'
        elif clip_frac > CLIP_OVERLOAD_FRAC:
            state = 'overloaded'
        else:
            state = 'ok'
        return state, zero_frac, clip_frac, ent

    def probe_frequency(self, freq):
        """Short RAM-only capture at `freq` for front-end health classification."""
        data, _err = self._raw_capture(freq, SWEEP_PROBE_BYTES, deadline_secs=8.0)
        return SdrNoiseSource.classify_capture(data)

    def resolve_frequency(self, base_freq, auto_sweep=True, log=print):
        """Pick a capture frequency whose front end is actually healthy.

        Probes `base_freq` first (a short RAM-only sample). If the front end is
        DEAD or OVERLOADED there - or the spectrum has too little spread - it
        sweeps from the calibrated lower frequency limit to the upper limit in
        250 kHz steps until a clean spot is found. Uses the frequency range
        determined by the calibration phase (LOWER_LIMIT_FREQ_HZ to
        UPPER_LIMIT_FREQ_HZ) so the sweep stays within the dongle's operational
        range. Consecutive dead probes abort early: no frequency rotation fixes
        an antenna/coax problem.

        Returns (freq_hz, note). Raises CaptureError when no usable spot exists.
        """
        state, zf, cf, ent = self.probe_frequency(base_freq)
        log("  front-end probe %.4f MHz: %s (zero-centered=%.2f rail-clip=%.2f entropy=%.2f)"
            % (base_freq / 1e6, state, zf, cf, ent))
        if state == 'ok' and ent >= SWEEP_PROBE_ENTROPY_MIN:
            return base_freq, "healthy at tuned coordinate"

        reason = {'dead': 'no RF reaching the mixer',
                  'overloaded': 'front end OVERLOADED (clipping)',
                  'ok': 'too little spectral spread'}[state]
        if not auto_sweep:
            raise CaptureError("front end %s at %.4f MHz - auto-sweep disabled" % (reason, base_freq / 1e6))

        # Use calibrated frequency range if available, otherwise fall back to defaults
        from config.config import LOWER_LIMIT_FREQ_HZ, UPPER_LIMIT_FREQ_HZ
        if LOWER_LIMIT_FREQ_HZ is None:
            lo = int(SWEEP_START_MHZ * 1e6)
        else:
            lo = LOWER_LIMIT_FREQ_HZ
        if UPPER_LIMIT_FREQ_HZ is None:
            hi = int(SWEEP_MAX_MHZ * 1e6)
        else:
            hi = UPPER_LIMIT_FREQ_HZ
        
        # Validate sweep range
        if lo >= hi:
            raise CaptureError(
                "Invalid sweep range: LOWER_LIMIT_FREQ_HZ (%d) >= UPPER_LIMIT_FREQ_HZ (%d) - "
                "calibration may be corrupted, resetting to defaults" % (lo, hi))
        
        step = int(SWEEP_STEP_KHZ * 1000)

        log("  [WARN] %s - sweeping from %.1f MHz to %.1f MHz in %d kHz steps..."
            % (reason, lo / 1e6, hi / 1e6, SWEEP_STEP_KHZ))

        freq = lo
        dead_streak = 0
        saw_overload = False
        probes = 0
        while freq <= hi:
            if freq != base_freq:   # already probed above
                st, zf2, cf2, ent2 = self.probe_frequency(freq)
                probes += 1
                log("    sweep %.3f MHz: %s (zero-centered=%.2f rail-clip=%.2f entropy=%.2f)"
                    % (freq / 1e6, st, zf2, cf2, ent2))
                if st == 'dead':
                    dead_streak += 1
                    if dead_streak >= SWEEP_DEAD_STREAK_MAX:
                        raise CaptureError("front end dead at every probed frequency - "
                                           "antenna/coax/USB problem, not a frequency problem")
                else:
                    dead_streak = 0
                if st == 'overloaded':
                    saw_overload = True
                elif ent2 >= SWEEP_PROBE_ENTROPY_MIN:
                    return freq, "clean spot found at %.3f MHz (swept from %.1f MHz)" % (freq / 1e6, lo / 1e6)
            freq += step

        if saw_overload:
            raise CaptureError("no usable frequency in %.1f-%.1f MHz: overload persists across the "
                               "whole sweep - add a 10-20 dB attenuator or lower GAIN and retry"
                               % (lo / 1e6, hi / 1e6))
        raise CaptureError("no usable frequency in %.1f-%.1f MHz (%d probes) - every spot was "
                           "dead or too structured" % (lo / 1e6, hi / 1e6, probes))

    # -- sanity sample: captured into RAM only -------------------------------
    def capture_sanity(self, freq):
        """Return SAMPLE_BYTES of raw noise in memory. Raises CaptureError."""
        data, _err = self._raw_capture(freq, SAMPLE_BYTES, deadline_secs=12.0)
        return data

    # -- main capture: 256 KB chunks straight into SHA-256 digests (RAM) -----
    def capture_digests(self, freq, blocks, progress_cb=None):
        """Stream `blocks` 256 KB chunks from the dongle and hash each one as
        it arrives; only one chunk plus the digest accumulator live in RAM.
        Returns a bytearray of `blocks` * 32 digest bytes. Raises CaptureError."""
        secs = (blocks + 3) // 4                 # 4 blocks per second at 1 Msps
        deadline = time.monotonic() + secs * 3 + 60   # hard timeout: a hung dongle can never hang the tool
        proc, fd = self._open_rtl_sdr(freq)
        digests = bytearray()
        try:
            for i in range(blocks):
                block = self._read_exact(fd, BLOCK_SIZE, deadline)
                digests.extend(hashlib.sha256(block).digest())
                if progress_cb and (i % 8 == 0 or i == blocks - 1):
                    progress_cb(i + 1, blocks)
        finally:
            self._reap(proc)
        # I/O fault guard: a batch that showed read errors is discarded (in RAM)
        err = b""
        try:
            if proc.stderr is not None:
                err = proc.stderr.read() or b""
        except Exception:
            pass
        if b"error" in err.lower():
            raise CaptureError("rtl_sdr reported I/O errors mid-capture")
        return digests

    # -- wipe material for secure_shred (SDR first, system entropy fallback)
    def wipe_bytes(self, n):
        try:
            data, _err = self._raw_capture(FREQS[0], max(n, 65536), deadline_secs=8.0)
            if len(data) >= n:
                return data[:n]
        except Exception:
            pass
        return os.urandom(n)

    # -- calibration: find lower and upper frequency limits ------------------
    @staticmethod
    def _write_calibration(lower_mhz, upper_mhz, lower_freq_hz, upper_freq_hz):
        """Persist calibration results to config/config.py.

        Updates the module-level variables so subsequent runs use the
        calibrated range instead of falling back to defaults.
        """
        import re as _re
        import os as _os

        # Find config/config.py relative to this file
        config_path = _os.path.join(
            _os.path.dirname(_os.path.abspath(__file__)),
            "..", "config", "config.py"
        )
        config_path = _os.path.normpath(config_path)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                content = f.read()
        except (IOError, OSError) as e:
            return False

        # Replace the calibration values
        content = _re.sub(
            r"LOWER_LIMIT_MHZ\s*=\s*None",
            f"LOWER_LIMIT_MHZ = {lower_mhz}",
            content
        )
        content = _re.sub(
            r"UPPER_LIMIT_MHZ\s*=\s*None",
            f"UPPER_LIMIT_MHZ = {upper_mhz}",
            content
        )
        content = _re.sub(
            r"LOWER_LIMIT_FREQ_HZ\s*=\s*None",
            f"LOWER_LIMIT_FREQ_HZ = {lower_freq_hz}",
            content
        )
        content = _re.sub(
            r"UPPER_LIMIT_FREQ_HZ\s*=\s*None",
            f"UPPER_LIMIT_FREQ_HZ = {upper_freq_hz}",
            content
        )
        content = _re.sub(
            r"TUNING_COMPLETE\s*=\s*False",
            "TUNING_COMPLETE = True",
            content
        )

        try:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(content)
            return True
        except (IOError, OSError):
            return False

    def calibrate(self, log=print):
        """Calibrate the RTL-SDR dongle to find its usable frequency range.

        Scans downward from CALIBRATION_LOWER_START_MHZ to find where the
        device's receive edge is (where it stops working), and scans upward
        from CALIBRATION_UPPER_START_MHZ to find the upper receive edge.
        Stores results in config.

        Only runs if CALIBRATION_ENABLED is True and TUNING_COMPLETE is False.

        Returns True if calibration succeeded, False otherwise.
        """
        from config.config import (
            CALIBRATION_ENABLED, CALIBRATION_LOWER_START_MHZ,
            CALIBRATION_LOWER_STEP_KHZ, CALIBRATION_LOWER_ENTROPY_MIN,
            CALIBRATION_UPPER_START_MHZ, CALIBRATION_UPPER_STEP_KHZ,
            CALIBRATION_UPPER_ENTROPY_MIN, CALIBRATION_DEAD_STREAK_MAX,
            LOWER_LIMIT_MHZ, UPPER_LIMIT_MHZ, LOWER_LIMIT_FREQ_HZ,
            UPPER_LIMIT_FREQ_HZ, TUNING_COMPLETE
        )

        if not CALIBRATION_ENABLED or TUNING_COMPLETE:
            log("  [ OK ] calibration already complete")
            return True

        log("  [INFO] starting RTL-SDR calibration...")

        # -- Lower limit: tune down from ~26 MHz to find where it stops working
        log("  [CAL] scanning downward from %.1f MHz to find lower receive edge..."
            % CALIBRATION_LOWER_START_MHZ)
        lo_start = int(CALIBRATION_LOWER_START_MHZ * 1e6)
        lo_step = int(CALIBRATION_LOWER_STEP_KHZ * 1000)
        lo_ent_min = CALIBRATION_LOWER_ENTROPY_MIN
        lo_dead_streak = 0
        lo_freq = lo_start
        lo_found = False

        while lo_freq >= 10_000_000:  # 10 MHz floor
            st, zf, cf, ent = self.probe_frequency(lo_freq)
            log("    cal %.3f MHz: %s (zero-centered=%.2f rail-clip=%.2f entropy=%.2f)"
                % (lo_freq / 1e6, st, zf, cf, ent))
            if st == 'dead':
                lo_dead_streak += 1
                if lo_dead_streak >= CALIBRATION_DEAD_STREAK_MAX:
                    # Device stopped working - this is the lower receive edge
                    lo_found = True
                    LOWER_LIMIT_MHZ = (lo_freq + lo_step) / 1e6  # last good frequency
                    LOWER_LIMIT_FREQ_HZ = int(LOWER_LIMIT_MHZ * 1e6)
                    log("  [CAL] lower receive edge found: %.3f MHz (stopped working at %.3f MHz)"
                        % (LOWER_LIMIT_MHZ, lo_freq / 1e6))
                    break
            elif ent >= lo_ent_min:
                lo_found = True
                LOWER_LIMIT_MHZ = lo_freq / 1e6
                LOWER_LIMIT_FREQ_HZ = lo_freq
                log("  [CAL] lower receive edge found: %.3f MHz" % LOWER_LIMIT_MHZ)
                break
            lo_freq -= lo_step

        if not lo_found:
            log("  [WARN] could not find lower receive edge - using default 26 MHz")
            LOWER_LIMIT_MHZ = 26.0
            LOWER_LIMIT_FREQ_HZ = 26_000_000

        # -- Upper limit: tune up from ~220 MHz to find where it stops working
        log("  [CAL] scanning upward from %.1f MHz to find upper receive edge..."
            % CALIBRATION_UPPER_START_MHZ)
        up_start = int(CALIBRATION_UPPER_START_MHZ * 1e6)
        up_step = int(CALIBRATION_UPPER_STEP_KHZ * 1000)
        up_ent_min = CALIBRATION_UPPER_ENTROPY_MIN
        up_dead_streak = 0
        up_freq = up_start
        up_found = False

        while up_freq <= 300_000_000:  # 300 MHz ceiling
            st, zf, cf, ent = self.probe_frequency(up_freq)
            log("    cal %.3f MHz: %s (zero-centered=%.2f rail-clip=%.2f entropy=%.2f)"
                % (up_freq / 1e6, st, zf, cf, ent))
            if st == 'dead':
                up_dead_streak += 1
                if up_dead_streak >= CALIBRATION_DEAD_STREAK_MAX:
                    # Device stopped working - this is the upper receive edge
                    up_found = True
                    UPPER_LIMIT_MHZ = (up_freq - up_step) / 1e6  # last good frequency
                    UPPER_LIMIT_FREQ_HZ = int(UPPER_LIMIT_MHZ * 1e6)
                    log("  [CAL] upper receive edge found: %.3f MHz (stopped working at %.3f MHz)"
                        % (UPPER_LIMIT_MHZ, up_freq / 1e6))
                    break
            elif ent >= up_ent_min:
                up_found = True
                UPPER_LIMIT_MHZ = up_freq / 1e6
                UPPER_LIMIT_FREQ_HZ = up_freq
                log("  [CAL] upper receive edge found: %.3f MHz" % UPPER_LIMIT_MHZ)
                break
            up_freq += up_step

        if not up_found:
            log("  [WARN] could not find upper receive edge - using default 220 MHz")
            UPPER_LIMIT_MHZ = 220.0
            UPPER_LIMIT_FREQ_HZ = 220_000_000

        # Validate: lower must be less than upper, and both must be positive
        if LOWER_LIMIT_MHZ < 0 or UPPER_LIMIT_MHZ < 0 or LOWER_LIMIT_MHZ >= UPPER_LIMIT_MHZ:
            log("  [WARN] calibration produced invalid range (%.1f - %.1f MHz) - keeping previous config"
                % (LOWER_LIMIT_MHZ, UPPER_LIMIT_MHZ))
            return False

        # Persist results to config/config.py
        self._write_calibration(LOWER_LIMIT_MHZ, UPPER_LIMIT_MHZ,
                                LOWER_LIMIT_FREQ_HZ, UPPER_LIMIT_FREQ_HZ)

        TUNING_COMPLETE = True
        log("  [CAL] calibration complete: %.1f - %.1f MHz" % (LOWER_LIMIT_MHZ, UPPER_LIMIT_MHZ))
        return True


class SandboxNoiseSource:
    """TEST-ONLY noise source for offline development and self-tests.

    Uses system entropy in place of the dongle so the pipeline can be
    exercised on machines without RTL-SDR hardware. Pages produced under this
    source are stamped with SANDBOX_MARK and are inherently refused by the
    encrypt and decrypt paths - they are NOT operational key material.
    """

    sandbox = True

    def __init__(self, workdir=None):
        self.workdir = None          # deliberately unused: no capture files

    def capture_sanity(self, freq):
        return os.urandom(SAMPLE_BYTES)

    def capture_digests(self, freq, blocks, progress_cb=None):
        digests = bytearray()
        for i in range(blocks):
            digests.extend(hashlib.sha256(os.urandom(BLOCK_SIZE)).digest())
            if progress_cb and (i % 8 == 0 or i == blocks - 1):
                progress_cb(i + 1, blocks)
        return digests

    def resolve_frequency(self, base_freq, auto_sweep=True, log=print):
        """Sandbox has no RF front end - nothing to probe or sweep."""
        return base_freq, "sandbox: no RF front end to probe"

    def wipe_bytes(self, n):
        return os.urandom(n)
