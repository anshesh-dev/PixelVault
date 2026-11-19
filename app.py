"""
app.py  -  PixelVault web server (Flask)
----------------------------------------
Runs a local website at http://localhost:8000 and a small JSON API that the
page (static/index.html) talks to. Images are processed in memory on this
computer only - nothing is sent to the internet.

Run:   python app.py
"""

import io
import os
import re
import secrets
import sys
import threading
import time
from collections import OrderedDict

from flask import Flask, Response, jsonify, request, send_from_directory

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from src import stego, analysis                    # noqa: E402
from src.registry import Registry                  # noqa: E402
from src.sample import make_sample                 # noqa: E402

STATIC_DIR = os.path.join(HERE, "static")
PORT = int(os.environ.get("PORT", 8000))

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024        # 64 MB per request
registry = Registry(os.path.join(HERE, "pixelvault_state.json"))


# ---------------------------------------------------------------------------
# Small in-memory caches (results live only while the server runs)
# ---------------------------------------------------------------------------
class LRU:
    def __init__(self, size):
        self.size, self.items, self.lock = size, OrderedDict(), threading.Lock()

    def put(self, value):
        token = secrets.token_urlsafe(12)
        with self.lock:
            self.items[token] = value
            while len(self.items) > self.size:
                self.items.popitem(last=False)
        return token

    def get(self, token):
        with self.lock:
            item = self.items.get(token)
            if item is not None:
                self.items.move_to_end(token)
            return item

    def pop(self, token):
        with self.lock:
            return self.items.pop(token, None)

    def clear(self):
        with self.lock:
            self.items.clear()


results = LRU(8)      # hide results: cover + stego images
scans = LRU(8)        # detect uploads
files = LRU(16)       # extracted files waiting to be downloaded


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def fail(code, message, status=400, **extra):
    return jsonify({"ok": False, "code": code, "message": message, **extra}), status


def safe_name(name, default="file"):
    name = os.path.basename((name or "").replace("\\", "/")).strip()
    name = re.sub(r"[^\w.\- ()\[\]]+", "_", name, flags=re.UNICODE).strip(" .")
    return (name or default)[:120]


def png_response(img_or_bytes, download_name=None):
    data = img_or_bytes if isinstance(img_or_bytes, bytes) else stego.to_png(img_or_bytes)
    headers = {}
    if download_name:
        headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
    return Response(data, mimetype="image/png", headers=headers)


def read_upload(field="image"):
    f = request.files.get(field)
    if not f or not f.filename:
        raise stego.StegoError("Please choose an image first.")
    data = f.read()
    if not data:
        raise stego.StegoError("That file is empty.")
    return data, f.filename


def human(n):
    for unit in ("bytes", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:,.0f} {unit}" if unit == "bytes" else f"{n:,.1f} {unit}"
        n /= 1024


@app.errorhandler(stego.StegoError)
def on_stego_error(e):
    return fail(e.code, e.message, **e.extra)


@app.errorhandler(413)
def on_too_large(_):
    return fail("too_large", "That upload is too big. The limit is 64 MB.", 413)


@app.errorhandler(500)
def on_server_error(_):
    return fail("server_error", "Something went wrong on our side. Please try again.", 500)


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' blob: data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; base-uri 'none'")
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Permissions-Policy"] = "microphone=(self)"
    return resp


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/present")
def present():
    return send_from_directory(STATIC_DIR, "present.html")


@app.route("/present/<path:name>")
def present_asset(name):
    return send_from_directory(os.path.join(STATIC_DIR, "present"), name)


@app.route("/api/health")
def health():
    return jsonify({"ok": True, "app": "PixelVault"})


@app.route("/api/sample.png")
def sample():
    return png_response(make_sample(), "pixelvault-sample.png")


# ---------------------------------------------------------------------------
# Inspect: size, capacity and warnings for a chosen image
# ---------------------------------------------------------------------------
@app.route("/api/inspect", methods=["POST"])
def inspect():
    data, _ = read_upload()
    img, info = stego.load_image(data, for_hiding=True)
    cap = stego.capacity_bytes(img.width, img.height)
    return jsonify({"ok": True, **info, "capacity": cap, "capacity_human": human(cap),
                    "overhead_plain": stego.content_overhead(0, False),
                    "overhead_encrypted": stego.content_overhead(0, True)})


# ---------------------------------------------------------------------------
# Hide
# ---------------------------------------------------------------------------
@app.route("/api/hide", methods=["POST"])
def hide():
    image_bytes, image_name = read_upload()
    mode = request.form.get("mode", "text")
    password = request.form.get("password") or None
    read_once = request.form.get("read_once") == "1"
    try:
        max_attempts = int(request.form.get("max_attempts") or 0)
    except ValueError:
        return fail("bad_input", "Wrong-password limit must be a number.")

    if mode == "file":
        f = request.files.get("secret_file")
        if not f or not f.filename:
            return fail("bad_input", "Choose a file to hide.")
        data, name, kind = f.read(), safe_name(f.filename, "secret.bin"), stego.KIND_FILE
        if not data:
            return fail("bad_input", "That file is empty.")
    else:
        text = request.form.get("text", "")
        if not text.strip():
            return fail("bad_input", "Write a message to hide.")
        data, name, kind = text.encode("utf-8"), "", stego.KIND_TEXT

    t0 = time.perf_counter()
    res = stego.hide(image_bytes, kind, data, name, password, read_once, max_attempts)
    stats = analysis.compare(res["cover"], res["stego"])
    stem = os.path.splitext(safe_name(image_name, "image"))[0]
    token = results.put({"cover": res["cover"], "stego": res["stego"], "png": res["png"],
                         "filename": f"{stem}-hidden.png", "previews": {},
                         "small": {}})
    return jsonify({
        "ok": True, "token": token, "filename": f"{stem}-hidden.png",
        "width": res["info"]["width"], "height": res["info"]["height"],
        "warnings": res["info"]["warnings"],
        "payload_bytes": res["payload_bytes"], "capacity": res["capacity"],
        "used_percent": round(100 * (res["payload_bytes"] - stego.HEADER_SIZE) / max(1, res["capacity"]), 3),
        "secret_bytes": len(data), "encrypted": res["encrypted"], "compressed": res["compressed"],
        "read_once": read_once, "max_attempts": max_attempts, "kind": "file" if kind else "text",
        "png_bytes": len(res["png"]), "png_human": human(len(res["png"])),
        "stats": stats, "seconds": round(time.perf_counter() - t0, 2),
    })


def _result(token):
    r = results.get(token)
    if r is None:
        raise stego.StegoError("This result has expired. Please hide the message again.")
    return r


@app.route("/api/result/<token>/download")
def result_download(token):
    r = _result(token)
    return png_response(r["png"], r["filename"])


@app.route("/api/result/<token>/<which>.png")
def result_image(token, which):
    r = _result(token)
    if which not in ("original", "stego", "diff"):
        return fail("not_found", "Unknown image.", 404)
    if which not in r["previews"]:
        if which == "diff":
            r["previews"][which] = stego.to_png(analysis.diff_map(r["cover"], r["stego"]))
        else:
            src = r["cover"] if which == "original" else r["stego"]
            r["previews"][which] = stego.to_png(analysis.preview(src))
    return png_response(r["previews"][which])


@app.route("/api/result/<token>/xray")
def result_xray(token):
    r = _result(token)
    which = request.args.get("which", "stego")
    src = r["cover"] if which == "original" else r["stego"]
    if which not in r["small"]:
        r["small"][which] = analysis.small_array(src)
    return _xray(r["small"][which])


def _xray(small):
    try:
        bit = int(request.args.get("bit", 0))
    except ValueError:
        bit = 0
    channel = request.args.get("channel", "all")
    if channel not in ("all", "r", "g", "b") or not 0 <= bit <= 7:
        return fail("bad_input", "Bit must be 0-7 and channel all, r, g or b.")
    return png_response(analysis.bit_plane(small, bit, channel))


# ---------------------------------------------------------------------------
# Extract (with self-destruct rules)
# ---------------------------------------------------------------------------
DESTROYED_MSG = {
    "read": "This secret was set to self-destruct after one reading, and it has already been read.",
    "locked": "This secret has been locked forever after too many wrong passwords.",
}


@app.route("/api/extract", methods=["POST"])
def extract():
    image_bytes, _ = read_upload()
    password = request.form.get("password") or None
    img, info = stego.load_image(image_bytes)
    try:
        header, body = stego.read_payload(img)
    except stego.NoPayloadError as e:
        hint = ""
        if info["format"] in ("JPEG", "JPG", "WEBP"):
            hint = " This is a JPG/WebP file. Compression destroys hidden data, so use the original PNG."
        return fail(e.code, e.message + hint)

    pid, max_attempts = header["id"], header["max_attempts"]
    meta = {"encrypted": header["encrypted"], "read_once": header["read_once"], "max_attempts": max_attempts}
    st = registry.status(pid)
    if st["destroyed"]:
        return fail("destroyed", DESTROYED_MSG.get(st["reason"], DESTROYED_MSG["read"]), **meta)

    try:
        kind, name, data = stego.decrypt_body(header, body, password)
    except stego.NeedPasswordError as e:
        left = max(0, max_attempts - st["attempts"]) if max_attempts else None
        return fail(e.code, e.message, attempts_left=left, **meta)
    except stego.WrongPasswordError as e:
        left, destroyed = registry.record_failure(pid, max_attempts)
        if destroyed:
            return fail("destroyed", DESTROYED_MSG["locked"], **meta)
        return fail(e.code, e.message, attempts_left=left, **meta)

    destroyed_now = False
    if header["read_once"]:
        registry.destroy(pid, "read")
        destroyed_now = True

    out = {"ok": True, **meta, "destroyed_now": destroyed_now, "compressed": header["compressed"]}
    if kind == stego.KIND_TEXT:
        out.update(kind="text", text=data.decode("utf-8", errors="replace"), size=len(data))
    else:
        fname = safe_name(name, "hidden-file.bin")
        out.update(kind="file", name=fname, size=len(data), size_human=human(len(data)),
                   token=files.put({"name": fname, "data": data, "once": destroyed_now}))
    return jsonify(out)


@app.route("/api/file/<token>")
def file_download(token):
    item = files.get(token)
    if item is None:
        return fail("expired", "This download has expired. Extract the file again.", 404)
    if item["once"]:
        files.pop(token)
    return Response(item["data"], mimetype="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{item["name"]}"'})


# ---------------------------------------------------------------------------
# Detect (signature scan + RS steganalysis) and X-ray for any image
# ---------------------------------------------------------------------------
@app.route("/api/detect", methods=["POST"])
def detect():
    image_bytes, name = read_upload()
    img, info = stego.load_image(image_bytes)
    cap = stego.capacity_bytes(img.width, img.height)

    signature = None
    try:
        header, body = stego.read_payload(img)
        st = registry.status(header["id"])
        signature = {
            "found": True, "encrypted": header["encrypted"], "compressed": header["compressed"],
            "read_once": header["read_once"], "max_attempts": header["max_attempts"],
            "payload_bytes": header["length"] + stego.HEADER_SIZE,
            "payload_human": human(header["length"] + stego.HEADER_SIZE),
            "percent_of_image": round(100 * (header["length"] + stego.HEADER_SIZE) * 8 / (img.width * img.height * 3), 3),
            "destroyed": st["destroyed"], "destroyed_reason": st["reason"], "wrong_attempts": st["attempts"],
        }
    except stego.CorruptedError:
        signature = {"found": False, "damaged": True}
    except stego.NoPayloadError:
        signature = {"found": False, "damaged": False}

    stats = analysis.statistical_scan(img)
    if stats.get("estimated_bytes"):
        stats["estimated_human"] = human(stats["estimated_bytes"])
    token = scans.put({"img": img, "small": analysis.small_array(img), "preview": None})
    return jsonify({"ok": True, "token": token, "name": safe_name(name, "image"),
                    "width": img.width, "height": img.height, "format": info["format"],
                    "capacity": cap, "capacity_human": human(cap),
                    "signature": signature, "stats": stats,
                    "lossy": info["format"] in ("JPEG", "JPG", "WEBP")})


def _scan(token):
    s = scans.get(token)
    if s is None:
        raise stego.StegoError("This scan has expired. Please upload the image again.")
    return s


@app.route("/api/scan/<token>/preview.png")
def scan_preview(token):
    s = _scan(token)
    if s["preview"] is None:
        s["preview"] = stego.to_png(analysis.preview(s["img"]))
    return png_response(s["preview"])


@app.route("/api/scan/<token>/xray")
def scan_xray(token):
    return _xray(_scan(token)["small"])


# ---------------------------------------------------------------------------
# Reset demo data
# ---------------------------------------------------------------------------
@app.route("/api/reset", methods=["POST"])
def reset():
    registry.reset()
    results.clear()
    scans.clear()
    files.clear()
    return jsonify({"ok": True})


if __name__ == "__main__":
    print(f"\n  PixelVault is running at  http://localhost:{PORT}\n  Keep this window open. Press Ctrl+C to stop.\n")
    app.run(host="127.0.0.1", port=PORT, debug=False, threaded=True)
