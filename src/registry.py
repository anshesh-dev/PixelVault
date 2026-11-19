"""
registry.py  -  Self-destruct registry
--------------------------------------
Every hidden secret carries a random 8-byte id. This small JSON "registry"
remembers, per id:
    - how many wrong passwords were tried
    - whether the secret has been destroyed (read once, or locked)

PixelVault refuses to open a destroyed secret again. The data in the image
stays encrypted, so without the password nobody can read it anyway.
"""

import json
import os
import threading
from datetime import datetime


class Registry:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self.data = {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                self.data = json.load(f)
        except (OSError, ValueError):
            self.data = {}

    def _save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2)
        os.replace(tmp, self.path)

    def status(self, pid):
        with self.lock:
            rec = self.data.get(pid, {})
            return {"attempts": rec.get("attempts", 0), "destroyed": rec.get("destroyed", False),
                    "reason": rec.get("reason")}

    def record_failure(self, pid, max_attempts):
        """Count a wrong password. Returns (attempts_left or None, destroyed_now)."""
        with self.lock:
            rec = self.data.setdefault(pid, {"attempts": 0, "destroyed": False})
            rec["attempts"] += 1
            destroyed = False
            if max_attempts and rec["attempts"] >= max_attempts:
                rec.update(destroyed=True, reason="locked", at=datetime.now().isoformat(timespec="seconds"))
                destroyed = True
            self._save()
            left = max(0, max_attempts - rec["attempts"]) if max_attempts else None
            return left, destroyed

    def destroy(self, pid, reason="read"):
        with self.lock:
            rec = self.data.setdefault(pid, {"attempts": 0})
            rec.update(destroyed=True, reason=reason, at=datetime.now().isoformat(timespec="seconds"))
            self._save()

    def reset(self):
        with self.lock:
            self.data = {}
            self._save()
