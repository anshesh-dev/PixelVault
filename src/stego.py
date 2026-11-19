"""
stego.py  -  PixelVault core engine
-----------------------------------
Hides a text message or a whole file inside an image using LSB
(Least Significant Bit) steganography, and extracts it again.

How the data is stored
    Every pixel has three colour values (Red, Green, Blue), each 0-255.
    We overwrite only the LAST bit of each value with one bit of our data.
    That changes a colour by at most 1/255, which the human eye cannot see.
    Bits are written in order: pixel (0,0) R, G, B, then pixel (0,1) R, G, B ...
    The alpha (transparency) channel is never touched.

Payload layout (the bytes that get hidden)
    HEADER (22 bytes)
        magic        4  b"PXV1"  - lets us recognise PixelVault data
        flags        1  bit0 encrypted, bit1 compressed, bit2 read-once
        payload_id   8  random id, used by the self-destruct registry
        max_attempts 1  wrong passwords allowed before lock (0 = unlimited)
        body_length  4  number of body bytes that follow
        crc32        4  checksum of the body, detects corruption
    BODY
        encrypted:   salt(16) | nonce(12) | AES-256-GCM ciphertext + tag(16)
        plain:       the content bytes
    CONTENT (before compression / encryption)
        kind 1 (0 = text, 1 = file) | name_length 2 | name | data

Security
    Key derivation : PBKDF2-HMAC-SHA256, 200,000 iterations, random 16-byte salt
    Encryption     : AES-256-GCM (confidentiality + integrity)
    The header is bound to the ciphertext as "associated data", so nobody can
    flip the read-once flag or the attempt limit without breaking decryption.
"""

import io
import os
import struct
import zlib

import numpy as np
from PIL import Image, ImageOps
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"PXV1"
HEADER_FMT = "!4sB8sBII"
HEADER_SIZE = struct.calcsize(HEADER_FMT)          # 22 bytes
FLAG_ENCRYPTED = 0x01
FLAG_COMPRESSED = 0x02
FLAG_READ_ONCE = 0x04

KIND_TEXT = 0
KIND_FILE = 1

SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
CRYPTO_OVERHEAD = SALT_SIZE + NONCE_SIZE + TAG_SIZE  # 44 bytes
KDF_ITERATIONS = 200_000

MAX_PIXELS = 40_000_000          # refuse images above 40 megapixels
MAX_NAME_BYTES = 255
Image.MAX_IMAGE_PIXELS = MAX_PIXELS


# ---------------------------------------------------------------------------
# Errors (each has a machine-readable code for the API)
# ---------------------------------------------------------------------------
class StegoError(Exception):
    code = "error"

    def __init__(self, message, **extra):
        super().__init__(message)
        self.message = message
        self.extra = extra


class ImageError(StegoError):
    code = "bad_image"


class CapacityError(StegoError):
    code = "too_big"


class NoPayloadError(StegoError):
    code = "no_payload"


class CorruptedError(StegoError):
    code = "corrupted"


class NeedPasswordError(StegoError):
    code = "need_password"


class WrongPasswordError(StegoError):
    code = "wrong_password"


# ---------------------------------------------------------------------------
# Image helpers
# ---------------------------------------------------------------------------
def load_image(data, for_hiding=False):
    """
    Open image bytes and return (PIL image in RGB or RGBA, info dict).
    for_hiding=True also applies the camera's rotation (EXIF) so the result
    isn't sideways - never done when extracting, as it would move the bits.
    """
    try:
        img = Image.open(io.BytesIO(data))
        fmt = (img.format or "").upper()
        frames = getattr(img, "n_frames", 1)
        img.load()
    except Image.DecompressionBombError:
        raise ImageError("This image is too large. The limit is 40 megapixels.")
    except Exception:
        raise ImageError("This file isn't an image we can read. Try PNG, JPG, BMP or WebP.")

    if img.width * img.height > MAX_PIXELS:
        raise ImageError("This image is too large. The limit is 40 megapixels.")

    warnings = []
    if for_hiding:
        img = ImageOps.exif_transpose(img)
        if fmt in ("JPEG", "JPG", "WEBP", "HEIF", "AVIF"):
            warnings.append("The result is saved as PNG. A lossy format like JPG would destroy the hidden data.")
        if frames > 1:
            warnings.append("Only the first frame of this animated image is used.")

    has_alpha = img.mode in ("RGBA", "LA", "PA") or (img.mode == "P" and "transparency" in img.info)
    target = "RGBA" if has_alpha else "RGB"
    if img.mode != target:
        if img.mode in ("I;16", "I;16B", "I;16L", "I"):
            # 16-bit images: scale down to 8 bits per channel first
            arr = np.array(img, dtype=np.float64)
            img = Image.fromarray(np.clip(arr / 257.0, 0, 255).astype(np.uint8), "L")
        img = img.convert(target)

    info = {"width": img.width, "height": img.height, "format": fmt or "UNKNOWN",
            "mode": target, "warnings": warnings}
    return img, info


def capacity_bytes(width, height):
    """How many payload bytes (after the header) an image can hold."""
    return max(0, (width * height * 3) // 8 - HEADER_SIZE)


def content_overhead(name_len=0, encrypted=False):
    """Bytes added around the user's data (worst case, without compression)."""
    return 3 + name_len + (CRYPTO_OVERHEAD if encrypted else 0)


def _rgb_view(img):
    arr = np.array(img, dtype=np.uint8)
    return arr, arr[..., :3]


# ---------------------------------------------------------------------------
# Crypto helpers
# ---------------------------------------------------------------------------
def _derive_key(password, salt):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=KDF_ITERATIONS)
    return kdf.derive(password.encode("utf-8"))


def _pack_content(kind, name, data):
    name_b = (name or "").encode("utf-8")[:MAX_NAME_BYTES]
    return struct.pack("!BH", kind, len(name_b)) + name_b + data


def _unpack_content(raw):
    if len(raw) < 3:
        raise CorruptedError("The hidden data is damaged.")
    kind, name_len = struct.unpack("!BH", raw[:3])
    if kind not in (KIND_TEXT, KIND_FILE) or len(raw) < 3 + name_len:
        raise CorruptedError("The hidden data is damaged.")
    name = raw[3:3 + name_len].decode("utf-8", errors="replace")
    return kind, name, raw[3 + name_len:]


# ---------------------------------------------------------------------------
# Build / parse payload
# ---------------------------------------------------------------------------
def build_payload(kind, data, name="", password=None, read_once=False, max_attempts=0):
    if password is not None and password == "":
        password = None
    if (read_once or max_attempts) and not password:
        raise StegoError("Self-destruct options need a password.")
    if not 0 <= int(max_attempts) <= 20:
        raise StegoError("Wrong-password limit must be between 1 and 20.")

    content = _pack_content(kind, name, data)
    flags = 0
    packed = zlib.compress(content, 9)
    if len(packed) < len(content):
        content, flags = packed, flags | FLAG_COMPRESSED
    if read_once:
        flags |= FLAG_READ_ONCE
    payload_id = os.urandom(8)

    if password:
        flags |= FLAG_ENCRYPTED
        aad = struct.pack("!4sB8sB", MAGIC, flags, payload_id, int(max_attempts))
        salt, nonce = os.urandom(SALT_SIZE), os.urandom(NONCE_SIZE)
        body = salt + nonce + AESGCM(_derive_key(password, salt)).encrypt(nonce, content, aad)
    else:
        body = content

    header = struct.pack(HEADER_FMT, MAGIC, flags, payload_id, int(max_attempts),
                         len(body), zlib.crc32(body) & 0xFFFFFFFF)
    return header + body, {"id": payload_id.hex(), "flags": flags}


def parse_header(raw):
    magic, flags, pid, max_attempts, length, crc = struct.unpack(HEADER_FMT, raw[:HEADER_SIZE])
    return {"magic": magic, "flags": flags, "id": pid.hex(), "id_bytes": pid,
            "max_attempts": max_attempts, "length": length, "crc": crc,
            "encrypted": bool(flags & FLAG_ENCRYPTED),
            "compressed": bool(flags & FLAG_COMPRESSED),
            "read_once": bool(flags & FLAG_READ_ONCE)}


def decrypt_body(header, body, password):
    """Turn the body back into (kind, name, data). Raises on a wrong password."""
    if header["encrypted"]:
        if not password:
            raise NeedPasswordError("This secret is locked. Enter the password to open it.")
        salt, nonce, ct = body[:SALT_SIZE], body[SALT_SIZE:SALT_SIZE + NONCE_SIZE], body[SALT_SIZE + NONCE_SIZE:]
        aad = struct.pack("!4sB8sB", MAGIC, header["flags"], header["id_bytes"], header["max_attempts"])
        try:
            content = AESGCM(_derive_key(password, salt)).decrypt(nonce, ct, aad)
        except InvalidTag:
            raise WrongPasswordError("That password is wrong.")
    else:
        content = body
    if header["compressed"]:
        try:
            content = zlib.decompress(content)
        except zlib.error:
            raise CorruptedError("The hidden data is damaged.")
    return _unpack_content(content)


# ---------------------------------------------------------------------------
# Embed / read bits
# ---------------------------------------------------------------------------
def embed(img, payload):
    """Write payload bytes into the LSBs of the image. Returns a new image."""
    arr, rgb = _rgb_view(img)
    flat = rgb.reshape(-1).copy()
    bits = np.unpackbits(np.frombuffer(payload, dtype=np.uint8))
    if bits.size > flat.size:
        need = len(payload) - HEADER_SIZE
        have = capacity_bytes(img.width, img.height)
        raise CapacityError(f"This image can hold {have:,} bytes, but the secret needs {need:,}. "
                            f"Use a bigger image or a shorter message.", need=need, have=have)
    flat[:bits.size] = (flat[:bits.size] & 0xFE) | bits
    out = arr.copy()
    out[..., :3] = flat.reshape(rgb.shape)
    return Image.fromarray(out, img.mode)


def read_bytes(img, n_bytes, offset_bytes=0):
    _, rgb = _rgb_view(img)
    flat = rgb.reshape(-1)
    start, stop = offset_bytes * 8, (offset_bytes + n_bytes) * 8
    if stop > flat.size:
        raise NoPayloadError("No hidden PixelVault data was found in this image.")
    return np.packbits(flat[start:stop] & 1).tobytes()


def read_payload(img):
    """Find and validate a PixelVault payload. Returns (header, body)."""
    if img.width * img.height * 3 < HEADER_SIZE * 8:
        raise NoPayloadError("No hidden PixelVault data was found in this image.")
    header = parse_header(read_bytes(img, HEADER_SIZE))
    if header["magic"] != MAGIC:
        raise NoPayloadError("No hidden PixelVault data was found in this image.")
    if header["length"] > capacity_bytes(img.width, img.height):
        raise CorruptedError("The hidden data is damaged or incomplete.")
    body = read_bytes(img, header["length"], HEADER_SIZE)
    if zlib.crc32(body) & 0xFFFFFFFF != header["crc"]:
        raise CorruptedError("The hidden data is damaged. Was the image edited, resized or compressed?")
    return header, body


# ---------------------------------------------------------------------------
# High level API
# ---------------------------------------------------------------------------
def to_png(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG", optimize=False, compress_level=6)
    return buf.getvalue()


def hide(image_bytes, kind, data, name="", password=None, read_once=False, max_attempts=0):
    """
    Hide text (kind=KIND_TEXT, data=utf-8 bytes) or a file (kind=KIND_FILE)
    inside an image. Returns a dict with the stego image and details.
    """
    if not data:
        raise StegoError("There's nothing to hide yet.")
    cover, info = load_image(image_bytes, for_hiding=True)
    payload, meta = build_payload(kind, data, name, password, read_once, max_attempts)
    stego = embed(cover, payload)
    return {
        "cover": cover, "stego": stego, "png": to_png(stego), "info": info,
        "payload_bytes": len(payload), "capacity": capacity_bytes(cover.width, cover.height),
        "id": meta["id"], "encrypted": bool(meta["flags"] & FLAG_ENCRYPTED),
        "compressed": bool(meta["flags"] & FLAG_COMPRESSED),
    }


def extract(image_bytes, password=None):
    """Read and decrypt the hidden content. Returns dict(kind, name, data, header)."""
    img, _ = load_image(image_bytes)
    header, body = read_payload(img)
    kind, name, data = decrypt_body(header, body, password)
    return {"kind": kind, "name": name, "data": data, "header": header}
