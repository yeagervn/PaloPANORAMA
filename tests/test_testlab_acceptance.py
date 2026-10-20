# -*- coding: utf-8 -*-
"""
Noi `testlab/run_all_features.py` vao bo test chung: chay toan bo kich ban nghiem
thu (3 tab, qua PANORAMA gia lap) nhu 1 test case duy nhat.

Nho vay `python -m unittest discover -s tests` bao phu CA phan logic LAN phan goi
API that (qua HTTPS, cert tu ky) - thu ma unit test thuan tuy khong cham toi.

Tu dong SKIP neu thieu 'cryptography' (khong sinh duoc cert) hoac khong bind
duoc cong - de khong lam do bo test tren may khong co dieu kien.
"""

import os
import socket
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUNNER = os.path.join(ROOT, "testlab", "run_all_features.py")


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class TestTestlabAcceptance(unittest.TestCase):
    def test_toan_bo_tinh_nang_qua_firewall_gia_lap(self):
        if not os.path.exists(RUNNER):
            self.skipTest("khong tim thay testlab/run_all_features.py")
        try:
            import cryptography  # noqa: F401
        except ImportError:
            self.skipTest("thieu 'cryptography' - khong sinh duoc cert cho mock HTTPS")

        proc = subprocess.run(
            [sys.executable, RUNNER, "--auto", "--port", str(_free_port())],
            cwd=ROOT, capture_output=True, text=True, timeout=300)
        out = proc.stdout + proc.stderr
        if proc.returncode != 0:
            fails = [ln for ln in out.splitlines() if "[FAIL]" in ln]
            self.fail("testlab FAIL:\n  " + "\n  ".join(fails or out.splitlines()[-25:]))
        self.assertIn("PASS", out)
        total = [ln for ln in out.splitlines() if "TONG KET" in ln]
        print("\n    [testlab] " + (total[0].strip() if total else "OK"))


if __name__ == "__main__":
    unittest.main()
