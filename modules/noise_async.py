"""Async noise source: librtlsdr direct calls via ctypes for streaming."""

import ctypes
import ctypes.util
import hashlib
import math
import os
import signal
import threading
import time
from collections import Counter
from config.config import (BLOCK_SIZE, CLIP_OVERLOAD_FRAC, DEAD_ZERO_FRAC,
                                   FREQS, GAIN, RATE, SAMPLE_BYTES, SWEEP_DEAD_STREAK_MAX,
                                   SWEEP_MAX_MHZ, SWEEP_PROBE_BYTES, SWEEP_PROBE_ENTROPY_MIN,
                                   SWEEP_START_MHZ, SWEEP_STEP_KHZ)

# Load librtlsdr
_librtlsdr = ctypes.CDLL(ctypes.util.find_library("rtlsdr"))

# Define types
rtlsdr_dev_t = ctypes.c_void_p

# Callback type: void (*)(unsigned char *buf, uint32_t len, void *ctx)
rtlsdr_read_async_cb_t = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint32, ctypes.c_void_p)

# Function signatures
_librtlsdr.rtlsdr_open.restype = ctypes.c_int
_librtlsdr.rtlsdr_open.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_uint]

_librtlsdr.rtlsdr_close.restype = None
_librtlsdr.rtlsdr_close.argtypes = [rtlsdr_dev_t]

_librtlsdr.rtlsdr_set_sample_rate.restype = ctypes.c_int
_librtlsdr.rtlsdr_set_sample_rate.argtypes = [rtlsdr_dev_t, ctypes.c_ulong]

_librtlsdr.rtlsdr_set_center_freq.restype = ctypes.c_int
_librtlsdr.rtlsdr_set_center_freq.argtypes = [rtlsdr_dev_t, ctypes.c_ulong]

_librtlsdr.rtlsdr_set_tuner_gain_mode.restype = ctypes.c_int
_librtlsdr.rtlsdr_set_tuner_gain_mode.argtypes = [rtlsdr_dev_t, ctypes.c_int]

_librtlsdr.rtlsdr_set_tuner_gain.restype = ctypes.c_int
_librtlsdr.rtlsdr_set_tuner_gain.argtypes = [rtlsdr_dev_t, ctypes.c_int]

_librtlsdr.rtlsdr_read_async.restype = ctypes.c_int
_librtlsdr.rtlsdr_read_async.argtypes = [rtlsdr_dev_t, rtlsdr_read_async_cb_t, ctypes.c_void_p, ctypes.c_uint32, ctypes.c_uint32]

_librtlsdr.rtlsdr_cancel_async.restype = ctypes.c_int
_librtlsdr.rtlsdr_cancel_async.argtypes = [rtlsdr_dev_t]

_librtlsdr.rtlsdr_wait_async.restype = ctypes.c_int
_librtlsdr.rtlsdr_wait_async.argtypes = [rtlsdr_dev_t, rtlsdr_read_async_cb_t, ctypes.c_void_p]


class CaptureError(Exception):
    """Raised when a noise capture or one of its verification gates fails."""


class SdrNoiseSourceAsync:
    """Async noise source using librtlsdr direct calls."""

    sandbox = False

    def __init__(self):
        self.dev = None
        self._samples = bytearray()
        self._lock = threading.Lock()

    def _open_device(self, index=0):
        """Open the RTL-SDR device."""
        dev_ptr = ctypes.c_void_p()
        rc = _librtlsdr.rtlsdr_open(ctypes.byref(dev_ptr), index)
        if rc != 0:
            raise CaptureError(f"rtlsdr_open failed: {rc}")
        return dev_ptr.value

    def _close_device(self, dev):
        """Close the device (may hang on wedged dongle)."""
        try:
            _librtlsdr.rtlsdr_close(dev)
        except Exception as e:
            # If close hangs or fails, just leak the handle
            pass

    def _set_params(self, dev, freq_hz, gain_db=None):
        """Set sample rate, frequency, and gain with I2C retry."""
        # Sample rate
        rc = _librtlsdr.rtlsdr_set_sample_rate(dev, RATE)
        if rc != 0:
            raise CaptureError(f"set_sample_rate failed: {rc}")

        # Frequency
        rc = _librtlsdr.rtlsdr_set_center_freq(dev, freq_hz)
        if rc != 0:
            raise CaptureError(f"set_center_freq failed: {rc}")

        # Gain - use AGC for best entropy
        rc = _librtlsdr.rtlsdr_set_tuner_gain_mode(dev, 0)  # AGC
        if rc != 0:
            raise CaptureError(f"set_tuner_gain_mode (AGC) failed: {rc}")

    def _callback(self, buf, length, ctx):
        """Callback for async reads."""
        data = ctypes.cast(buf, ctypes.POINTER(ctypes.c_uint8 * length)).contents
        with self._lock:
            self._samples.extend(data)

    def capture_sync(self, freq_hz, nbytes, gain_db=None):
        """Capture nbytes of samples using async mode.

        Returns the captured data as bytes.
        """
        self._samples = bytearray()

        dev = self._open_device()
        try:
            self._set_params(dev, freq_hz, gain_db)

            # Start async read
            cb = rtlsdr_read_async_cb_t(self._callback)
            rc = _librtlsdr.rtlsdr_read_async(dev, cb, None, 0, 0)
            if rc != 0:
                raise CaptureError(f"rtlsdr_read_async failed: {rc}")

            # Wait for enough data or timeout
            target_time = time.monotonic() + nbytes // (RATE // 2)  # ~2 MB/s
            while len(self._samples) < nbytes and time.monotonic() < target_time + 5:
                time.sleep(0.01)

            # Cancel async read
            _librtlsdr.rtlsdr_cancel_async(dev)

            if len(self._samples) < nbytes:
                raise CaptureError(f"insufficient data: {len(self._samples)} < {nbytes}")

            return bytes(self._samples[:nbytes])

        finally:
            # Leak the handle on error to avoid close hanging
            try:
                self._close_device(dev)
            except:
                pass

    def capture_hashed(self, freq_hz, nbytes, block_size=1024):
        """Capture and hash raw samples for whitenening.

        Returns hashed data with ~8 bits/byte entropy.
        """
        raw_data = self.capture_sync(freq_hz, nbytes * 4)  # Need 4x raw data for 1x hashed output
        
        # Hash in blocks
        hash_blocks = []
        for i in range(0, len(raw_data) - block_size, block_size):
            block = raw_data[i:i+block_size]
            h = hashlib.sha256(block).digest()
            hash_blocks.append(h)
        
        return b''.join(hash_blocks)[:nbytes]

    def probe_frequency(self, freq_hz):
        """Short probe for front-end health classification."""
        data = self.capture_sync(freq_hz, SWEEP_PROBE_BYTES)
        return self.classify_capture(data)

    @staticmethod
    def classify_capture(data):
        """Classify a raw IQ byte stream for front-end health."""
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

    def resolve_frequency(self, base_freq, auto_sweep=True, log=print):
        """Pick a capture frequency whose front end is actually healthy."""
        state, zf, cf, ent = self.probe_frequency(base_freq)
        log(f"  front-end probe {base_freq / 1e6:.4f} MHz: {state} (zero-centered={zf:.2f} rail-clip={cf:.2f} entropy={ent:.2f})")
        if state == 'ok' and ent >= SWEEP_PROBE_ENTROPY_MIN:
            return base_freq, "healthy at tuned coordinate"

        reason = {'dead': 'no RF reaching the mixer',
                  'overloaded': 'front end OVERLOADED (clipping)',
                  'ok': 'too little spectral spread'}[state]
        if not auto_sweep:
            raise CaptureError(f"front end {reason} at {base_freq / 1e6:.4f} MHz - auto-sweep disabled")

        log(f"  [WARN] {reason} - slowly sweeping upward from {SWEEP_START_MHZ:.0f} MHz in {SWEEP_STEP_KHZ} kHz steps...")
        lo = int(SWEEP_START_MHZ * 1e6)
        if base_freq <= int(SWEEP_MAX_MHZ * 1e6):
            hi = int(SWEEP_MAX_MHZ * 1e6)
        else:
            lo, hi = int(base_freq - 1_000_000), int(base_freq + 1_000_000)
        step = int(SWEEP_STEP_KHZ * 1000)

        freq = lo
        dead_streak = 0
        saw_overload = False
        probes = 0
        while freq <= hi:
            if freq != base_freq:
                st, zf2, cf2, ent2 = self.probe_frequency(freq)
                probes += 1
                log(f"    sweep {freq / 1e6:.3f} MHz: {st} (zero-centered={zf2:.2f} rail-clip={cf2:.2f} entropy={ent2:.2f})")
                if st == 'dead':
                    dead_streak += 1
                    if dead_streak >= SWEEP_DEAD_STREAK_MAX:
                        raise CaptureError("front end dead at every probed frequency - antenna/coax/USB problem, not a frequency problem")
                else:
                    dead_streak = 0
                if st == 'overloaded':
                    saw_overload = True
                elif ent2 >= SWEEP_PROBE_ENTROPY_MIN:
                    return freq, f"clean spot found at {freq / 1e6:.3f} MHz (swept from {lo / 1e6:.1f} MHz)"
            freq += step

        if saw_overload:
            raise CaptureError(f"no usable frequency in {lo / 1e6:.0f}-{hi / 1e6:.0f} MHz: overload persists across the whole sweep - add a 10-20 dB attenuator or lower GAIN and retry")
        raise CaptureError(f"no usable frequency in {lo / 1e6:.0f}-{hi / 1e6:.0f} MHz ({probes} probes) - every spot was dead or too structured")

    def capture_sanity(self, freq):
        """Return SAMPLE_BYTES of raw noise in memory."""
        return self.capture_hashed(freq, SAMPLE_BYTES)


class SandboxNoiseSourceAsync:
    """TEST-ONLY noise source for offline development."""

    sandbox = True

    def __init__(self):
        pass

    def capture_sanity(self, freq):
        return os.urandom(SAMPLE_BYTES)

    def capture_sync(self, freq, nbytes):
        return os.urandom(nbytes)

    def probe_frequency(self, freq):
        return 'ok', 0.0, 0.0, 7.99

    def resolve_frequency(self, base_freq, auto_sweep=True, log=print):
        return base_freq, "sandbox: no RF front end to probe"
