"""
analysis.py  -  Comparison, X-ray and detection (steganalysis)
--------------------------------------------------------------
compare()        How different are the original and the stego image?
                 (pixels changed, max colour change, PSNR)
bit_plane()      "X-ray": show one bit of every colour value as black/white.
                 Bit 7 shows the picture's shapes; bit 0 looks like noise -
                 that is where secrets live.
diff_map()       Highlights exactly which pixels were changed.
statistical_scan RS analysis (Fridrich, Goljan & Du, 2001): estimates what
                 share of the image carries hidden LSB data, without knowing
                 any password or even which tool was used.
"""

import math

import numpy as np
from PIL import Image

PREVIEW_MAX = 1200


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------
def compare(cover, stego):
    a = np.asarray(cover, dtype=np.int16)[..., :3]
    b = np.asarray(stego, dtype=np.int16)[..., :3]
    diff = a - b
    changed_values = int(np.count_nonzero(diff))
    changed_pixels = int(np.count_nonzero(np.any(diff != 0, axis=2)))
    total_pixels = a.shape[0] * a.shape[1]
    mse = float(np.mean(diff.astype(np.float64) ** 2))
    psnr = float("inf") if mse == 0 else 10 * math.log10(255 ** 2 / mse)
    return {
        "changed_pixels": changed_pixels,
        "changed_values": changed_values,
        "total_pixels": total_pixels,
        "changed_percent": round(100 * changed_pixels / total_pixels, 4) if total_pixels else 0,
        "max_change": int(np.abs(diff).max()) if diff.size else 0,
        "psnr": None if math.isinf(psnr) else round(psnr, 2),
    }


# ---------------------------------------------------------------------------
# Previews
# ---------------------------------------------------------------------------
def _scale_for(w, h, max_side=PREVIEW_MAX):
    s = max(w, h)
    return 1 if s <= max_side else math.ceil(s / max_side)


def preview(img, max_side=PREVIEW_MAX):
    """A smaller copy for showing in the browser."""
    img = img.convert("RGBA") if img.mode == "RGBA" else img.convert("RGB")
    k = _scale_for(img.width, img.height, max_side)
    if k == 1:
        return img
    return img.resize((max(1, img.width // k), max(1, img.height // k)), Image.LANCZOS)


def small_array(img, max_side=PREVIEW_MAX):
    """Nearest-neighbour downscale (keeps exact pixel values, needed for bit planes)."""
    arr = np.asarray(img, dtype=np.uint8)[..., :3]
    k = _scale_for(arr.shape[1], arr.shape[0], max_side)
    return arr[::k, ::k] if k > 1 else arr


def bit_plane(arr_small, bit=0, channel="all"):
    """Black/white (or coloured) image of one bit plane."""
    bit = int(bit)
    if not 0 <= bit <= 7:
        raise ValueError("bit must be 0-7")
    planes = ((arr_small >> bit) & 1).astype(np.uint8) * 255
    if channel in ("r", "g", "b"):
        c = "rgb".index(channel)
        return Image.fromarray(np.repeat(planes[..., c:c + 1], 3, axis=2), "RGB")
    return Image.fromarray(planes, "RGB")


def diff_map(cover, stego, max_side=PREVIEW_MAX):
    """White pixels = changed. Uses max-pooling so tiny changes stay visible."""
    a = np.asarray(cover, dtype=np.uint8)[..., :3]
    b = np.asarray(stego, dtype=np.uint8)[..., :3]
    changed = np.any(a != b, axis=2)
    h, w = changed.shape
    k = _scale_for(w, h, max_side)
    if k > 1:
        hh, ww = (h // k) * k, (w // k) * k
        changed = changed[:hh, :ww].reshape(hh // k, k, ww // k, k).max(axis=(1, 3))
    out = np.zeros(changed.shape + (3,), dtype=np.uint8)
    out[...] = (24, 24, 28)
    out[changed] = (255, 214, 10)
    return Image.fromarray(out, "RGB")


# ---------------------------------------------------------------------------
# RS analysis (Fridrich, Goljan & Du, 2001)
# ---------------------------------------------------------------------------
# Pixels are taken in groups of 4 along each row. "Smoothness" of a group is
# the sum of differences between neighbours. We flip the LSBs of the middle
# two pixels in two different ways and count how often the group becomes
# rougher (Regular) or smoother (Singular). In a natural image both flips
# behave the same; hiding random bits breaks that balance in a predictable
# way, which lets us ESTIMATE how much of the image carries hidden data.

def _smoothness(groups):
    return np.abs(np.diff(groups, axis=-1)).sum(axis=-1)


def _rs_counts(channel):
    a = channel.astype(np.int16)
    h, w = a.shape
    w4 = (w // 4) * 4
    if h == 0 or w4 == 0:
        return None
    g = a[:, :w4].reshape(h, w4 // 4, 4)
    f0 = _smoothness(g)
    pos = g.copy()
    pos[..., 1:3] ^= 1                                   # F1 :  2k <-> 2k+1
    neg = g.copy()
    neg[..., 1:3] = ((neg[..., 1:3] + 1) ^ 1) - 1        # F-1: 2k-1 <-> 2k
    fp, fn = _smoothness(pos), _smoothness(neg)
    return np.array([np.count_nonzero(fp > f0), np.count_nonzero(fp < f0),
                     np.count_nonzero(fn > f0), np.count_nonzero(fn < f0), f0.size], dtype=np.float64)


def rs_estimate(img):
    """Estimated fraction (0-1) of colour values that carry hidden bits."""
    arr = np.asarray(img, dtype=np.uint8)[..., :3]
    normal = np.zeros(5)
    flipped = np.zeros(5)
    for c in range(3):
        ch = arr[..., c]
        a, b = _rs_counts(ch), _rs_counts(ch ^ 1)
        if a is None:
            return None
        normal += a
        flipped += b
    n = normal[4]
    if n == 0:
        return None
    rm, sm, rn, sn = normal[:4] / n
    rm1, sm1, rn1, sn1 = flipped[:4] / n
    d0, d1 = rm - sm, rm1 - sm1
    dn0, dn1 = rn - sn, rn1 - sn1
    qa = 2 * (d1 + d0)
    qb = dn0 - dn1 - d1 - 3 * d0
    qc = d0 - dn0
    if abs(qa) < 1e-12:
        if abs(qb) < 1e-12:
            return 0.0
        x = -qc / qb
    else:
        disc = qb * qb - 4 * qa * qc
        if disc < 0:
            return 0.0
        roots = [(-qb + math.sqrt(disc)) / (2 * qa), (-qb - math.sqrt(disc)) / (2 * qa)]
        x = min(roots, key=abs)
    if abs(x - 0.5) < 1e-12:
        return 1.0
    return max(0.0, min(1.0, x / (x - 0.5)))


def statistical_scan(img):
    """RS analysis turned into a verdict the UI can show."""
    arr = np.asarray(img, dtype=np.uint8)
    w, h = arr.shape[1], arr.shape[0]
    if w < 16 or h < 4:
        return {"verdict": "too_small", "rate": None, "estimated_bytes": 0}
    rate = rs_estimate(img)
    if rate is None:
        return {"verdict": "too_small", "rate": None, "estimated_bytes": 0}
    if rate >= 0.30:
        verdict = "likely"
    elif rate >= 0.20:
        verdict = "possible"
    else:
        verdict = "unlikely"
    est = int(rate * w * h * 3 / 8) if verdict != "unlikely" else 0
    return {"verdict": verdict, "rate": round(float(rate), 4), "estimated_bytes": est}
