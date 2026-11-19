"""
sample.py  -  Generates a sample landscape photo (for demos without a photo).
Smooth sky gradient with a sun, three mountain ranges and a lake, with a
little grain on the land so it behaves like a real photo for the detector.
"""

import numpy as np
from PIL import Image


def make_sample(width=1600, height=1000, seed=7):
    rng = np.random.default_rng(seed)
    y, x = np.mgrid[0:height, 0:width].astype(np.float64)
    t = y / height

    # Sky: deep blue at the top to warm peach at the horizon
    top, horizon = np.array([38, 70, 140.0]), np.array([250, 196, 160.0])
    img = top[None, None, :] * (1 - t[..., None]) + horizon[None, None, :] * t[..., None]

    # Sun with a soft glow
    cx, cy, r = width * 0.68, height * 0.42, height * 0.07
    d = np.hypot(x - cx, y - cy)
    glow = np.exp(-((d / (r * 4)) ** 2))[..., None]
    img = img * (1 - 0.35 * glow) + np.array([255, 236, 200.0]) * 0.35 * glow
    img[d < r] = [255, 244, 222]

    land = np.zeros((height, width), dtype=bool)

    # Mountain ranges (back to front)
    ranges = [
        (0.52, 0.06, 0.004, [126, 112, 158.0]),
        (0.60, 0.07, 0.006, [86, 82, 128.0]),
        (0.70, 0.05, 0.009, [48, 56, 92.0]),
    ]
    for base, amp, freq, color in ranges:
        phase = rng.uniform(0, 6.28)
        ridge = height * (base - amp * (np.sin(x[0] * freq + phase) * 0.6 +
                                       np.sin(x[0] * freq * 2.7 + phase * 1.3) * 0.3 +
                                       np.sin(x[0] * freq * 6.1) * 0.1))
        mask = y >= ridge[None, :]
        land |= mask
        shade = (1 - 0.25 * ((y - ridge[None, :]) / height))[..., None]
        img = np.where(mask[..., None], np.array(color) * shade, img)

    # Lake with a darker reflection of the sky
    lake = y > height * 0.8
    img[lake] = img[lake] * 0.55 + np.array([60, 90, 140.0]) * 0.45

    # Grain on the land only. The sky stays perfectly smooth, like a digital
    # illustration, so the Pixel X-ray clearly shows where data gets hidden.
    img += rng.normal(0, 3.0, img.shape) * land[..., None]
    return Image.fromarray(np.clip(img, 0, 255).astype(np.uint8), "RGB")
