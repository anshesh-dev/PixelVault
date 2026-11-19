"""
tests.py  -  Automated tests for every PixelVault feature
---------------------------------------------------------
Run:   python tests.py
"""

import io
import os
import sys
import tempfile
import unittest

import numpy as np
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from src import stego, analysis                 # noqa: E402
from src.registry import Registry               # noqa: E402
from src.sample import make_sample              # noqa: E402


def png_bytes(img):
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def jpg_bytes(img):
    buf = io.BytesIO()
    img.convert("RGB").save(buf, format="JPEG", quality=90)
    return buf.getvalue()


SAMPLE = make_sample(800, 500)
SAMPLE_PNG = png_bytes(SAMPLE)


class CoreTests(unittest.TestCase):
    # ---- 1. Hide + 2. Extract ------------------------------------------------
    def test_text_roundtrip(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"Meet me at 5 pm")
        out = stego.extract(r["png"])
        self.assertEqual(out["kind"], stego.KIND_TEXT)
        self.assertEqual(out["data"], b"Meet me at 5 pm")

    def test_unicode_hindi_emoji(self):
        msg = "नमस्ते दुनिया 🔐 Hinglish: kal milte hai!".encode("utf-8")
        out = stego.extract(stego.hide(SAMPLE_PNG, stego.KIND_TEXT, msg)["png"])
        self.assertEqual(out["data"].decode("utf-8"), msg.decode("utf-8"))

    def test_long_text_is_compressed(self):
        msg = ("All work and no play. " * 2000).encode()
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, msg)
        self.assertTrue(r["compressed"])
        self.assertLess(r["payload_bytes"], len(msg))
        self.assertEqual(stego.extract(r["png"])["data"], msg)

    # ---- 3. Password (AES-256-GCM) ------------------------------------------
    def test_password_roundtrip(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"top secret", password="hunter2")
        self.assertTrue(r["encrypted"])
        self.assertEqual(stego.extract(r["png"], "hunter2")["data"], b"top secret")

    def test_wrong_password(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"top secret", password="hunter2")
        with self.assertRaises(stego.WrongPasswordError):
            stego.extract(r["png"], "wrong")

    def test_missing_password(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"top secret", password="hunter2")
        with self.assertRaises(stego.NeedPasswordError):
            stego.extract(r["png"])

    def test_ciphertext_hides_plaintext(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"PLAINTEXT-MARKER" * 4, password="pw")
        img, _ = stego.load_image(r["png"])
        _, body = stego.read_payload(img)
        self.assertNotIn(b"PLAINTEXT-MARKER", body)

    def test_flags_are_tamper_proof(self):
        """Removing the read-once flag from the header must break decryption."""
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"x", password="pw", read_once=True)
        img, _ = stego.load_image(r["png"])
        header, body = stego.read_payload(img)
        header["flags"] &= ~stego.FLAG_READ_ONCE
        with self.assertRaises(stego.WrongPasswordError):
            stego.decrypt_body(header, body, "pw")

    # ---- 4. Capacity ----------------------------------------------------------
    def test_capacity_formula(self):
        self.assertEqual(stego.capacity_bytes(100, 100), 100 * 100 * 3 // 8 - stego.HEADER_SIZE)

    def test_too_big_rejected(self):
        tiny = png_bytes(Image.new("RGB", (20, 20), (90, 90, 90)))
        with self.assertRaises(stego.CapacityError):
            stego.hide(tiny, stego.KIND_TEXT, os.urandom(500))

    def test_fill_to_exact_capacity(self):
        img = make_sample(120, 80)
        cap = stego.capacity_bytes(120, 80)
        data = os.urandom(cap - stego.content_overhead(len("a.bin")))
        r = stego.hide(png_bytes(img), stego.KIND_FILE, data, "a.bin")
        self.assertEqual(stego.extract(r["png"])["data"], data)

    # ---- 5. Comparison --------------------------------------------------------
    def test_invisible_changes(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, os.urandom(4000).hex().encode())
        c = analysis.compare(r["cover"], r["stego"])
        self.assertEqual(c["max_change"], 1)
        self.assertGreater(c["psnr"], 50)
        self.assertGreater(c["changed_pixels"], 0)

    # ---- 6. Files ---------------------------------------------------------------
    def test_file_roundtrip_with_name(self):
        data = os.urandom(3000)
        r = stego.hide(SAMPLE_PNG, stego.KIND_FILE, data, "report.pdf", password="pw")
        out = stego.extract(r["png"], "pw")
        self.assertEqual((out["kind"], out["name"], out["data"]), (stego.KIND_FILE, "report.pdf", data))

    # ---- 7. Errors ----------------------------------------------------------------
    def test_clean_image_has_no_payload(self):
        with self.assertRaises(stego.NoPayloadError):
            stego.extract(SAMPLE_PNG)

    def test_not_an_image(self):
        with self.assertRaises(stego.ImageError):
            stego.extract(b"this is not an image")

    def test_jpeg_destroys_data(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"hello")
        recompressed = jpg_bytes(Image.open(io.BytesIO(r["png"])))
        with self.assertRaises((stego.NoPayloadError, stego.CorruptedError)):
            stego.extract(recompressed)

    def test_edited_image_detected_as_corrupted(self):
        r = stego.hide(SAMPLE_PNG, stego.KIND_TEXT, os.urandom(2000).hex().encode())
        arr = np.array(Image.open(io.BytesIO(r["png"])))
        arr[0, 200:260, :] ^= 1                     # flip some hidden bits
        with self.assertRaises(stego.CorruptedError):
            stego.extract(png_bytes(Image.fromarray(arr)))

    def test_empty_secret(self):
        with self.assertRaises(stego.StegoError):
            stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"")

    def test_self_destruct_needs_password(self):
        with self.assertRaises(stego.StegoError):
            stego.hide(SAMPLE_PNG, stego.KIND_TEXT, b"x", read_once=True)

    # ---- Image formats -----------------------------------------------------------
    def test_jpeg_input_gives_png_output(self):
        r = stego.hide(jpg_bytes(SAMPLE), stego.KIND_TEXT, b"from a jpg")
        self.assertTrue(r["png"].startswith(b"\x89PNG"))
        self.assertTrue(r["info"]["warnings"])
        self.assertEqual(stego.extract(r["png"])["data"], b"from a jpg")

    def test_transparency_is_preserved(self):
        rgba = Image.new("RGBA", (200, 120), (10, 120, 200, 0))
        rgba.paste((250, 80, 40, 255), (40, 30, 160, 90))
        r = stego.hide(png_bytes(rgba), stego.KIND_TEXT, b"alpha ok")
        out_img = Image.open(io.BytesIO(r["png"]))
        self.assertEqual(out_img.mode, "RGBA")
        self.assertTrue(np.array_equal(np.array(out_img)[..., 3], np.array(rgba)[..., 3]))
        self.assertEqual(stego.extract(r["png"])["data"], b"alpha ok")

    def test_palette_and_grayscale_images(self):
        for mode in ("P", "L"):
            img = SAMPLE.convert(mode)
            r = stego.hide(png_bytes(img), stego.KIND_TEXT, b"mode " + mode.encode())
            self.assertEqual(stego.extract(r["png"])["data"], b"mode " + mode.encode())


class RegistryTests(unittest.TestCase):
    # ---- 11. Self-destruct --------------------------------------------------
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)
        self.reg = Registry(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_lock_after_attempts(self):
        self.assertEqual(self.reg.record_failure("abc", 3), (2, False))
        self.assertEqual(self.reg.record_failure("abc", 3), (1, False))
        self.assertEqual(self.reg.record_failure("abc", 3), (0, True))
        self.assertTrue(self.reg.status("abc")["destroyed"])

    def test_destroy_persists(self):
        self.reg.destroy("xyz", "read")
        self.assertTrue(Registry(self.path).status("xyz")["destroyed"])


class AnalysisTests(unittest.TestCase):
    # ---- 9. X-ray + 10. Detector --------------------------------------------
    def test_bit_planes(self):
        small = analysis.small_array(SAMPLE)
        for bit in (0, 7):
            img = analysis.bit_plane(small, bit)
            self.assertEqual(img.size, (small.shape[1], small.shape[0]))
        with self.assertRaises(ValueError):
            analysis.bit_plane(small, 8)

    @staticmethod
    def camera_photo():
        """Sample landscape with sensor noise everywhere, like a real camera photo."""
        rng = np.random.default_rng(3)
        arr = np.asarray(SAMPLE, dtype=np.float64) + rng.normal(0, 3, (500, 800, 3))
        return Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8))

    def test_detector_estimate_on_camera_photo(self):
        photo = self.camera_photo()
        self.assertEqual(analysis.statistical_scan(photo)["verdict"], "unlikely")
        cap = stego.capacity_bytes(*photo.size)
        for share in (0.4, 0.7):
            r = stego.hide(png_bytes(photo), stego.KIND_FILE, os.urandom(int(cap * share)), "x", password="pw")
            hidden = analysis.statistical_scan(r["stego"])
            self.assertEqual(hidden["verdict"], "likely")
            self.assertAlmostEqual(hidden["rate"], share, delta=0.12)

    def test_detector_verdict_on_smooth_sample(self):
        self.assertEqual(analysis.statistical_scan(SAMPLE)["verdict"], "unlikely")
        cap = stego.capacity_bytes(*SAMPLE.size)
        r = stego.hide(SAMPLE_PNG, stego.KIND_FILE, os.urandom(int(cap * 0.7)), "x", password="pw")
        self.assertEqual(analysis.statistical_scan(r["stego"])["verdict"], "likely")


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import app as app_module
        cls.app_module = app_module
        fd, cls.state = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(cls.state)
        app_module.registry = Registry(cls.state)
        cls.c = app_module.app.test_client()

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.state):
            os.remove(cls.state)

    def post(self, url, image, **form):
        data = {"image": (io.BytesIO(image), "photo.png"), **form}
        return self.c.post(url, data=data, content_type="multipart/form-data")

    def hide(self, **form):
        r = self.post("/api/hide", SAMPLE_PNG, **form)
        self.assertEqual(r.status_code, 200, r.get_json())
        j = r.get_json()
        return j, self.c.get(f"/api/result/{j['token']}/download").data

    def test_full_text_flow(self):
        j, png = self.hide(mode="text", text="hello api", password="pw")
        self.assertTrue(j["encrypted"])
        for which in ("original", "stego", "diff"):
            self.assertEqual(self.c.get(f"/api/result/{j['token']}/{which}.png").status_code, 200)
        self.assertEqual(self.c.get(f"/api/result/{j['token']}/xray?bit=0").status_code, 200)
        r = self.post("/api/extract", png, password="pw").get_json()
        self.assertEqual((r["kind"], r["text"]), ("text", "hello api"))

    def test_read_once(self):
        _, png = self.hide(mode="text", text="burn after reading", password="pw", read_once="1")
        self.assertTrue(self.post("/api/extract", png, password="pw").get_json()["destroyed_now"])
        r = self.post("/api/extract", png, password="pw")
        self.assertEqual(r.get_json()["code"], "destroyed")

    def test_attempt_limit(self):
        _, png = self.hide(mode="text", text="x", password="pw", max_attempts="2")
        r1 = self.post("/api/extract", png, password="a").get_json()
        self.assertEqual((r1["code"], r1["attempts_left"]), ("wrong_password", 1))
        r2 = self.post("/api/extract", png, password="b").get_json()
        self.assertEqual(r2["code"], "destroyed")
        r3 = self.post("/api/extract", png, password="pw").get_json()
        self.assertEqual(r3["code"], "destroyed")

    def test_file_flow(self):
        data = {"image": (io.BytesIO(SAMPLE_PNG), "p.png"), "mode": "file",
                "secret_file": (io.BytesIO(b"%PDF-1.4 demo"), "../../evil name.pdf")}
        j = self.c.post("/api/hide", data=data, content_type="multipart/form-data").get_json()
        png = self.c.get(f"/api/result/{j['token']}/download").data
        r = self.post("/api/extract", png).get_json()
        self.assertEqual(r["kind"], "file")
        self.assertNotIn("/", r["name"])
        dl = self.c.get(f"/api/file/{r['token']}")
        self.assertEqual(dl.data, b"%PDF-1.4 demo")
        self.assertEqual(dl.mimetype, "application/octet-stream")

    def test_detect(self):
        _, png = self.hide(mode="text", text="find me", password="pw", read_once="1")
        j = self.post("/api/detect", png).get_json()
        self.assertTrue(j["signature"]["found"])
        self.assertTrue(j["signature"]["read_once"])
        self.assertEqual(self.c.get(f"/api/scan/{j['token']}/xray?bit=3&channel=g").status_code, 200)
        clean = self.post("/api/detect", SAMPLE_PNG).get_json()
        self.assertFalse(clean["signature"]["found"])
        self.assertEqual(clean["stats"]["verdict"], "unlikely")

    def test_errors_are_friendly(self):
        r = self.post("/api/extract", b"not an image")
        self.assertEqual((r.status_code, r.get_json()["code"]), (400, "bad_image"))
        r = self.post("/api/hide", SAMPLE_PNG, mode="text", text="   ")
        self.assertEqual(r.get_json()["code"], "bad_input")
        r = self.c.get("/api/result/nope/xray")
        self.assertEqual(r.status_code, 400)

    def test_security_headers(self):
        r = self.c.get("/api/health")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")


if __name__ == "__main__":
    import warnings
    warnings.simplefilter("ignore", ResourceWarning)
    unittest.main(verbosity=2)
