"""
SDR Radio Suite – Hardware Abstraction Layer
Supports RTL-SDR via rtl_sdr subprocess, SoapySDR as bonus.
"""
import os
import subprocess
import threading
import time
import numpy as np
import signal


def _kill_stale():
    for proc_name in ("rtl_sdr", "rtl_fm", "rtl_power", "rtl_tcp"):
        subprocess.run(["pkill", "-9", proc_name], capture_output=True)
    time.sleep(0.3)


def detect_sdr():
    try:
        import SoapySDR
        results = SoapySDR.Device.enumerate()
        if results:
            label = results[0].get("label", results[0].get("driver", "SoapySDR"))
            return True, label, "soapy"
    except Exception:
        pass
    try:
        r = subprocess.run(
            ["rtl_test", "-t"], capture_output=True, text=True, timeout=5,
        )
        combined = r.stdout + r.stderr
        if "Found" in combined or "RTL28" in combined or "RTL-SDR" in combined or "R82" in combined or "R828" in combined:
            label = "RTL-SDR"
            if "R828D" in combined or "Blog V4" in combined:
                label = "RTL-SDR V4"
            elif "R820T" in combined:
                label = "RTL-SDR"
            return True, label, "rtlsdr"
    except FileNotFoundError:
        pass
    except Exception:
        pass
    # Try rtl_433 detection (works with V4 when rtl_test doesn't)
    try:
        r = subprocess.run(
            ["rtl_433", "-F", "null", "-T", "0"], capture_output=True, text=True, timeout=5,
        )
        combined = r.stdout + r.stderr
        if "Found" in combined or "RTL" in combined or "SDR" in combined:
            label = "RTL-SDR (via rtl_433)"
            return True, label, "rtlsdr"
    except Exception:
        pass
    # Fallback: check if USB device is present even without drivers
    try:
        r = subprocess.run(["lsusb"], capture_output=True, text=True, timeout=3)
        if "0bda:2838" in r.stdout or "0bda:2832" in r.stdout:
            return False, "RTL-SDR detected but drivers not working", "none"
    except Exception:
        pass
    return False, "No SDR found", "none"


def compute_fft(iq, fft_size=256):
    if len(iq) < fft_size:
        iq = np.pad(iq, (0, fft_size - len(iq)))
    iq = iq[:fft_size]
    window = np.hanning(fft_size)
    windowed = iq * window
    spectrum = np.fft.fftshift(np.fft.fft(windowed))
    mag = np.abs(spectrum) / fft_size
    db = 20 * np.log10(mag + 1e-10)
    return db


class SDRDevice:
    def __init__(self):
        self._proc = None
        self._thread = None
        self._lock = threading.Lock()
        self._buf = bytearray()
        self._buf_max = 32768
        self._running = False
        self._freq = 0
        self._sample_rate = 2_048_000
        self._gain = 30
        self._backend = "none"
        self._soapy_dev = None
        self._soapy_stream = None
        self._rec_file = None
        self._rec_lock = threading.Lock()
        self._signal_db = -100.0

    def start(self, freq_hz, sample_rate=2_048_000, gain=30, backend="auto"):
        self.stop()
        _kill_stale()
        self._freq = freq_hz
        self._sample_rate = sample_rate
        self._gain = gain
        self._running = True

        if backend == "auto":
            _, _, backend = detect_sdr()

        self._backend = backend
        if backend == "soapy":
            self._start_soapy()
        elif backend == "rtlsdr":
            self._start_rtlsdr()
        else:
            self._running = False
            return False
        return True

    def _start_rtlsdr(self):
        cmd = [
            "rtl_sdr", "-f", str(self._freq), "-s", str(self._sample_rate),
            "-g", str(self._gain), "-",
        ]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        self._thread = threading.Thread(target=self._reader_rtlsdr, daemon=True)
        self._thread.start()

    def _reader_rtlsdr(self):
        while self._running and self._proc and self._proc.poll() is None:
            try:
                chunk = self._proc.stdout.read(4096)
                if not chunk:
                    break
                with self._lock:
                    self._buf.extend(chunk)
                    if len(self._buf) > self._buf_max:
                        self._buf = self._buf[-self._buf_max:]
                with self._rec_lock:
                    if self._rec_file:
                        self._rec_file.write(chunk)
            except Exception:
                break

    def _start_soapy(self):
        try:
            import SoapySDR
            self._soapy_dev = SoapySDR.Device()
            self._soapy_dev.setSampleRate(SoapySDR.SOAPY_SDR_RX, 0, self._sample_rate)
            self._soapy_dev.setFrequency(SoapySDR.SOAPY_SDR_RX, 0, self._freq)
            if self._gain > 0:
                self._soapy_dev.setGainMode(SoapySDR.SOAPY_SDR_RX, 0, False)
                self._soapy_dev.setGain(SoapySDR.SOAPY_SDR_RX, 0, self._gain)
            else:
                self._soapy_dev.setGainMode(SoapySDR.SOAPY_SDR_RX, 0, True)
            self._soapy_stream = self._soapy_dev.setupStream(SoapySDR.SOAPY_SDR_RX, SoapySDR.SOAPY_SDR_CF32)
            self._soapy_dev.activateStream(self._soapy_stream)
            self._thread = threading.Thread(target=self._reader_soapy, daemon=True)
            self._thread.start()
        except Exception:
            self._running = False

    def _reader_soapy(self):
        import SoapySDR
        buf = np.zeros(4096, dtype=np.complex64)
        while self._running:
            try:
                sr = self._soapy_dev.readStream(self._soapy_stream, [buf], len(buf))
                if sr.ret > 0:
                    raw = buf[:sr.ret].tobytes()
                    with self._lock:
                        self._buf.extend(raw)
                        if len(self._buf) > self._buf_max:
                            self._buf = self._buf[-self._buf_max:]
                    with self._rec_lock:
                        if self._rec_file:
                            self._rec_file.write(raw)
            except Exception:
                break

    def stop(self):
        self._running = False
        self.stop_recording()
        if self._proc:
            try:
                os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            except Exception:
                pass
            self._proc = None
        if self._soapy_stream and self._soapy_dev:
            try:
                self._soapy_dev.deactivateStream(self._soapy_stream)
                self._soapy_dev.closeStream(self._soapy_stream)
            except Exception:
                pass
            self._soapy_stream = None
            self._soapy_dev = None
        if self._thread:
            self._thread.join(timeout=2)
            self._thread = None
        with self._lock:
            self._buf.clear()

    def set_freq(self, freq_hz):
        self._freq = freq_hz
        if self._backend == "soapy" and self._soapy_dev:
            try:
                import SoapySDR
                self._soapy_dev.setFrequency(SoapySDR.SOAPY_SDR_RX, 0, freq_hz)
            except Exception:
                pass
        elif self._backend == "rtlsdr" and self._running:
            self.start(freq_hz, self._sample_rate, self._gain, "rtlsdr")

    def set_gain(self, gain):
        self._gain = gain
        if self._soapy_dev:
            try:
                import SoapySDR
                self._soapy_dev.setGain(SoapySDR.SOAPY_SDR_RX, 0, gain)
            except Exception:
                pass

    def get_iq_block(self, n_samples=1024):
        with self._lock:
            if self._backend == "soapy":
                needed = n_samples * 8
                if len(self._buf) < needed:
                    return np.zeros(n_samples, dtype=np.complex64)
                raw = bytes(self._buf[-needed:])
                return np.frombuffer(raw, dtype=np.complex64)
            else:
                needed = n_samples * 2
                if len(self._buf) < needed:
                    return np.zeros(n_samples, dtype=np.complex64)
                raw = bytes(self._buf[-needed:])
                uint8 = np.frombuffer(raw, dtype=np.uint8)
                floats = (uint8.astype(np.float32) - 127.5) / 127.5
                return floats[0::2] + 1j * floats[1::2]

    def get_signal_db(self):
        iq = self.get_iq_block(256)
        rms = np.sqrt(np.mean(np.abs(iq) ** 2))
        return 20 * np.log10(rms + 1e-10)

    def start_recording(self, path):
        self.stop_recording()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with self._rec_lock:
            self._rec_file = open(path, "wb")

    def stop_recording(self):
        with self._rec_lock:
            if self._rec_file:
                self._rec_file.close()
                self._rec_file = None

    @property
    def is_running(self):
        return self._running

    @property
    def freq(self):
        return self._freq

    @property
    def sample_rate(self):
        return self._sample_rate


def start_fm_audio(freq_hz, device="default"):
    _kill_stale()
    cmd = (
        f"rtl_fm -f {freq_hz} -M wbfm -s 200000 -r 48000 -g 20 - "
        f"| aplay -D {device} -f S16_LE -r 48000 -c 1 -q"
    )
    return subprocess.Popen(
        cmd, shell=True, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid,
    )


def stop_fm_audio(proc):
    if proc:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
    _kill_stale()
