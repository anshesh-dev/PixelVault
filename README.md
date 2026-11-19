# 🔐 PixelVault — Hide Secrets Inside Images

PixelVault is a steganography tool: it hides a text message or a whole file **inside a photo**.
The photo looks exactly the same, but carries an encrypted secret that only PixelVault (and the
right password) can reveal. It also includes a **detector** that finds hidden data in images,
which covers the forensics side of the same problem.

Runs as a local website (`http://localhost:8000`) with an Apple-style glass interface.
Everything happens on your own computer, and no image is ever uploaded to the internet.

---

## ✨ Features

| # | Feature | What it does |
|---|---------|--------------|
| 1 | **Hide** | Hide a message inside any photo (PNG, JPG, BMP, WebP). Download the result as PNG |
| 2 | **Extract** | Open a PixelVault photo and read the hidden message |
| 3 | **Password lock** | AES-256-GCM encryption, key derived with PBKDF2-SHA256 (200,000 rounds) |
| 4 | **Capacity meter** | Live bar showing how much of the photo your secret uses |
| 5 | **Before / after** | Drag-to-compare slider, changed-pixel map, and quality stats (pixels changed, max change ±1, PSNR) |
| 6 | **Hide files** | Hide any file (PDF, image, zip…); the original filename is kept |
| 7 | **Friendly errors** | Wrong password, no secret, damaged image, JPG warning, too big for the photo |
| 8 | **Drag & drop · paste · copy** | Drop or paste images, one-click copy of the revealed message |
| 9 | **Pixel X-ray** | Bit-plane viewer (bit 7 → bit 0, per colour channel) |
| 10 | **Detector** | Signature scan (certain) + RS steganalysis (statistical estimate, no password needed) |
| 11 | **Self-destruct** | Read once, or lock forever after N wrong passwords |
| 12 | **Learn** | Step-by-step animation of one letter being hidden in three pixels |

Also included: Hindi/emoji support, automatic compression, light and dark mode, a built-in sample photo,
mobile layout, and "Reset demo data".

## 🧠 How it works

**LSB steganography.** Every pixel has Red, Green and Blue values (0–255, 8 bits each). PixelVault
replaces only the **last bit** of each value with one bit of the secret, which changes each colour by at most
1/255, below what the human eye can notice. Bits are written from the top-left pixel onwards; the
transparency channel is never touched.

**Payload format**
```
HEADER (22 bytes)
  magic "PXV1" (4) | flags (1) | random id (8) | max wrong attempts (1) | body length (4) | CRC32 (4)
BODY
  with password : salt (16) | nonce (12) | AES-256-GCM ciphertext + tag (16)
  without       : content
CONTENT (zlib-compressed when smaller)
  kind: text/file (1) | name length (2) | name | data
```
- The **CRC32** detects images that were edited or re-compressed.
- The header is passed to AES-GCM as **associated data**, so nobody can switch off the
  self-destruct flags without breaking decryption.
- **Capacity** = width × height × 3 / 8 − 22 bytes (a 12 MP photo holds about 4.5 MB).

**Self-destruct.** Each secret carries a random 8-byte id. A local registry
(`pixelvault_state.json`) records ids that were read once or locked after too many wrong passwords,
and PixelVault refuses to open them again.

**Detector**
- *Signature scan*: looks for a valid PixelVault header and checksum. If it finds one, it reports
  size, encryption and self-destruct status without revealing anything.
- *RS analysis* (Fridrich, Goljan & Du, 2001): flips LSBs in groups of pixels in two ways and
  measures how "smoothness" changes. Hidden random data breaks a natural balance, which lets the
  tool **estimate the share of the image carrying hidden data**, even for other LSB tools.

## 🚀 How to run (Windows)

Double-click **`run.bat`**. The first run creates a virtual environment and installs the
requirements (internet needed once). Your browser then opens `http://localhost:8000`.
Keep the black window open while using PixelVault.

Manual:
```bash
pip install -r requirements.txt
python app.py
```

## ✅ Tests

```bash
python tests.py
```
34 automated tests cover: text/Hindi/emoji round-trips, compression, password, wrong/missing
password, tamper-proof flags, capacity limits, file hiding, JPG destruction, edited-image detection,
transparency, palette/grayscale images, self-destruct (read-once and attempt lock), X-ray,
the detector, every API endpoint, filename sanitising and security headers.

## 🎬 Demo script

1. **Hide**: click *Use a sample*, type a message, set a password, turn on *Self-destruct*, press **Hide secret**.
2. Drag the **compare slider**: no visible difference. Show the stats (±1/255, PSNR > 50 dB).
3. Open **Pixel X-ray**: the smooth sky shows stripes in the original and noise where data is hidden.
4. **Test it in Extract**: try a wrong password (shake + warning), then the right one, and watch the message type out.
5. Extract again: **"This secret is gone"** (self-destruct).
6. **Scan it with Detect**: signature found, plus the RS estimate compared to the actual size.
7. **Learn**: play the animation of the letter "H" hiding in three pixels.

## 🔒 Security notes

- AES-256-GCM with a random salt and nonce for every secret; PBKDF2-SHA256, 200,000 iterations
- Server listens on `127.0.0.1` only, with a strict Content-Security-Policy, no framing, and no-sniff
- All text from images is shown as plain text (never HTML); extracted files are always downloads
- Upload size and image size limits (64 MB / 40 megapixels) and decompression-bomb protection

## ⚠️ Limitations

- **Share the PNG as a file.** WhatsApp, Instagram, screenshots, editing or saving as JPG destroy the secret.
- Self-destruct is enforced by PixelVault's registry. The data in the image stays encrypted,
  so without the password it remains unreadable anyway.
- RS analysis is a statistical estimate: very small secrets are undetectable (that is LSB's
  strength), and it can read high on smooth digital images.

## 🧰 Tech stack

Python 3 · Flask · Pillow · NumPy · cryptography (AES-GCM, PBKDF2) · HTML / CSS / JavaScript (no frameworks)

## 📁 Structure

```
PixelVault/
├── app.py               # Flask server + JSON API
├── static/index.html    # Glass UI: Hide · Extract · Detect · Learn
├── src/
│   ├── stego.py         # LSB embedding, payload format, AES-GCM, errors
│   ├── analysis.py      # Comparison stats, X-ray bit planes, RS steganalysis
│   ├── registry.py      # Self-destruct registry
│   └── sample.py        # Built-in sample photo
├── tests.py             # 34 automated tests
├── run.bat              # Windows one-click launcher
└── requirements.txt
```

---
**Author:** Anshesh · Major Project · Department of Computer Science and Engineering
