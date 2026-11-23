#!/usr/bin/env python3
"""Bench splice-mending kit (Scottie 1) - event fallback for QSSTV.

  python3 tape_splice_HTH26-SUV.py <SENTBOX.WAV> --bands [out.png]
      decode the frame; report the margin mark of each stored row-band
      and write the scrambled picture (out.png)
  python3 tape_splice_HTH26-SUV.py <SENTBOX.WAV> --order 9,3,0,... [out.png]
      decode, then re-splice: mended band order[i] takes stored slot i
      - and write the mended picture. --order must be all sixteen
      digits 0..15, comma-separated.

Finds the standard calibration sequence (1900 Hz leader / 1200 Hz
break / 1900 Hz leader), reads and VERIFIES the VIS code (60 =
Scottie 1), then decodes the frame (standard Scottie 1: a starting
sync, then per line sep G sep B sync sep R, each scan 320 px x
0.432 ms = 138.24 ms, 9 ms syncs, 1.5 ms separators) and writes the
PNG.
Pure numpy + PIL. Exits 1 with a clear message on: wrong PCM format,
stereo input, wrong sample rate, missing/short calibration, an
unrecognised VIS code, or a file too short to hold a frame.

The kit does NOT know the band order and will not search for it: the
bench ledger on the sleeve is the evidence - align the picture's own
rows and marks until the card runs true. (16! orders - guessing is
not a strategy.)
"""
import sys
import wave

import numpy as np

F_BLACK, F_WHITE = 1500.0, 2300.0
SYNC_F, SEP_F = 1200.0, 1500.0
SEP_MS, SYNC_MS, SCAN_MS = 1.5, 9.0, 138.24
W, H = 320, 256
PXP = SCAN_MS / W
BANDS = 16
BAND_H = H // BANDS
# the mark geometry the bench burns: right margin, four 2-row cells
MARK_X0, MARK_X1 = 306, 318
MARK_CELL_ROWS = (1, 5, 9, 13)


def die(msg):
    print("tape_splice: %s" % msg, file=sys.stderr)
    sys.exit(1)


def load_pcm(path):
    try:
        w = wave.open(path, "rb")
    except Exception as exc:                             # noqa: BLE001
        die("cannot open %s as WAV (%s)" % (path, exc))
    nch, sw, fr = w.getnchannels(), w.getsampwidth(), w.getframerate()
    if nch != 1 or sw != 2 or fr != 44100:
        die("need 16-bit mono 44.1 kHz PCM (got ch=%d sw=%d rate=%d)"
            % (nch, sw, fr))
    sig = np.frombuffer(w.readframes(w.getnframes()),
                        dtype="<i2").astype(np.float64) / 32768.0
    w.close()
    return sig


def find_leader(sig):
    """The calibration leader: longest sustained 1900 Hz run."""
    step = 2205                            # 50 ms bins
    tref = np.arange(step) / 44100.0
    rs = np.sin(2 * np.pi * 1900.0 * tref)
    rc = np.cos(2 * np.pi * 1900.0 * tref)
    nbins = int((len(sig) - step) // step)
    if nbins < 2:
        die("file too short to hold an SSTV frame")
    scores = np.empty(nbins)
    for i in range(nbins):
        i0 = int(round(i * step))
        seg = sig[i0:i0 + step]
        scores[i] = abs(np.dot(seg, rs) + 1j * np.dot(seg, rc)) / step
    strong = scores > 0.35
    best_len = best_start = run_len = run_start = 0
    for i, s in enumerate(strong):
        if s:
            if run_len == 0:
                run_start = i
            run_len += 1
            if run_len > best_len:
                best_len, best_start = run_len, run_start
        else:
            run_len = 0
    if best_len < 5:                       # < 250 ms of leader
        die("no SSTV calibration leader found (is this the SENTBOX wav?)")
    return int(round(best_start * step))


def decode(wav_path):
    sig = load_pcm(wav_path)
    vox = find_leader(sig)

    def hilbert_phase(x):
        N = len(x)
        Xf = np.fft.fft(x)
        h = np.zeros(N)
        h[0] = 1
        if N % 2 == 0:
            h[N // 2] = 1
            h[1:N // 2] = 2
        else:
            h[1:(N + 1) // 2] = 2
        return np.unwrap(np.angle(np.fft.ifft(Xf * h)))

    s0 = vox
    s1 = int(vox + 112.0 * 44100)
    if s1 > len(sig):
        die("file too short to hold a frame after the leader")
    ph = hilbert_phase(sig[s0:s1])
    inst = np.diff(ph) * 44100.0 / (2 * np.pi)
    k = np.ones(19) / 19.0
    inst = np.convolve(inst, k, mode="same")

    # verify the VIS code (60 = Scottie 1) before trusting the frame
    def mean_freq(t0_ms, dur_ms):
        i0 = int(round(44100.0 * t0_ms / 1000.0))
        i1 = int(round(44100.0 * (t0_ms + dur_ms) / 1000.0))
        return inst[i0:i1].mean()

    vis_t = 300.0 + 10.0 + 300.0 + 30.0   # leader|break|leader|start bit
    bits = []
    for i in range(7):
        f = mean_freq(vis_t + i * 30.0, 30.0)
        bits.append(1 if abs(f - 1100.0) < abs(f - 1300.0) else 0)
    vis = sum(b << i for i, b in enumerate(bits))
    if vis != 60:
        die("VIS code %d is not Scottie 1 (60)" % vis)

    img = np.zeros((H, W, 3), dtype=np.uint8)
    t = 610.0 + 10 * 30.0                 # through calibration + VIS

    def sample(ms):
        sp = int(round(44100.0 * ms / 1000.0))
        v = (inst[sp:sp + 19].mean() - F_BLACK) / (F_WHITE - F_BLACK) * 255
        return int(np.clip(v, 0, 255))

    t += SYNC_MS                          # starting sync pulse
    for y in range(H):
        for ch in (1, 2, 0):              # G, B, then sync + R
            if ch == 0:
                t += SYNC_MS
            t += SEP_MS
            for x in range(W):
                img[y, x, ch] = sample(t)
                t += PXP
    return img


def band_mark(img, band):
    """Read the mark burned into a stored band's margin (right edge).

    Presence-per-cell over four 2-row tick cells: a cell counts as
    set when its margin pixels average dark. This mirrors the burn
    geometry exactly, so decode noise cannot slide a mark by one.
    """
    v = 0
    for c in range(4):
        y0 = band * BAND_H + MARK_CELL_ROWS[c]
        cell = img[y0:y0 + 2, MARK_X0:MARK_X1].mean()
        if cell < 128:
            v |= 1 << c
    return "%x" % v


def save(img, out_path):
    from PIL import Image
    Image.fromarray(img).save(out_path)
    print("wrote %s" % out_path)


def main():
    args = sys.argv[1:]
    if len(args) < 2 or args[0] in ("-h", "--help"):
        print(__doc__)
        sys.exit(1)
    wav_path, mode = args[0], args[1]
    rest = args[2:]
    out = rest[-1] if rest else wav_path.rsplit(".", 1)[0] + ".png"

    img = decode(wav_path)

    if mode == "--bands":
        print("stored bands, top to bottom (slot: mark):")
        for slot in range(BANDS):
            print("  slot %2d: mark %s" % (slot, band_mark(img, slot)))
        save(img, out)
        print("the picture is splice-scrambled - mend it with --order")
        return

    if mode == "--order":
        if not rest or "," not in rest[0]:
            die("--order needs all sixteen digits 0..%d, comma-separated"
                % (BANDS - 1))
        try:
            order = [int(t) for t in rest[0].split(",")]
        except ValueError:
            die("--order needs digits 0..%d, comma-separated" % (BANDS - 1))
        if sorted(order) != list(range(BANDS)):
            die("--order needs all sixteen digits 0..%d, comma-separated"
                % (BANDS - 1))
        out = rest[1] if len(rest) > 1 else out
        mended = np.empty_like(img)
        for slot in range(BANDS):
            mended[order[slot] * BAND_H:(order[slot] + 1) * BAND_H] = \
                img[slot * BAND_H:(slot + 1) * BAND_H]
        save(mended, out)
        return

    die("unknown mode %r (use --bands or --order N,N,...)" % mode)


if __name__ == "__main__":
    main()
