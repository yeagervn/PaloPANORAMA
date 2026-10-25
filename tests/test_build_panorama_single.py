# -*- coding: utf-8 -*-
"""
Bo sinh ban gop 1 file (`tools/build_panorama_single.py`) phai:

  1. Idempotent - chay 2 lan ra y het.
  2. KHONG gay khi phan `main` cua file single bi sua tay. Logic main
     (build_app, on_close, APP_TITLE...) CHI ton tai trong
     PaloPANORAMA_single.py, nen sua no la viec hop le. Cac buoc trong
     `_migrate_main()` so khop chuoi y nguyen; neu chi dua vao "new in text"
     de biet "da migrate roi" thi 1 ban sua tay hop le se lam build no
     AssertionError. Da gap that o repo ban Firewall standalone.
  3. Tu sinh lai duoc `on_close()` dang goi shutdown() cho CA 3 tab, ke ca khi
     file single dang o dang CU (chi shutdown 2 tab) -> khong bao gio phai sua
     tay file gop.
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import build_panorama_single as builder  # noqa: E402

TARGET = os.path.join(ROOT, "PaloPANORAMA_single.py")

OLD_ON_CLOSE = """        # Huy moi tac vu Search/Connect dang chay o tab CHECK IP (co
        # cancel_event, dung threading) truoc khi dong cua so - tab CHECK
        # RULE khong dung co che cancel_event nen khong can xu ly gi them.
        try:
            tab_check_ip.shutdown()
        except Exception:
            pass
        try:
            tab_check_audit.shutdown()
        except Exception:
            pass
        root.destroy()"""

NEW_ON_CLOSE_MARK = "for tab in (tab_check_rule, tab_check_ip, tab_check_audit)"


class TestReplaceHelper(unittest.TestCase):
    def test_raises_when_anchor_missing(self):
        with self.assertRaises(AssertionError):
            builder._replace("khong co gi", "ANCHOR", "MOI")

    def test_skips_when_new_already_there(self):
        text = "da co MOI roi"
        self.assertEqual(builder._replace(text, "ANCHOR", "MOI"), text)

    def test_done_if_accepts_several_markers(self):
        text = "ban sua tay dung DANG_MOI"
        self.assertEqual(
            builder._replace(text, "ANCHOR", "MOI", done_if=("DANG_CU", "DANG_MOI")), text)
        with self.assertRaises(AssertionError):
            builder._replace("khong co dang nao", "ANCHOR", "MOI",
                             done_if=("DANG_CU", "DANG_MOI"))


class TestBuild(unittest.TestCase):
    def setUp(self):
        with open(TARGET, "r", encoding="utf-8") as f:
            self._original = f.read()
        self.addCleanup(self._restore)

    def _restore(self):
        with open(TARGET, "w", encoding="utf-8") as f:
            f.write(self._original)

    def test_rebuild_is_idempotent(self):
        builder.build()
        with open(TARGET, "r", encoding="utf-8") as f:
            once = f.read()
        builder.build()
        with open(TARGET, "r", encoding="utf-8") as f:
            twice = f.read()
        self.assertEqual(once, twice, "build() khong idempotent")

    def test_on_close_shuts_down_all_three_tabs(self):
        with open(TARGET, "r", encoding="utf-8") as f:
            text = f.read()
        self.assertIn(NEW_ON_CLOSE_MARK, text,
                      "on_close() phai shutdown() ca 3 tab")

    def test_regenerates_on_close_from_old_form(self):
        """Ha file single ve dang CU -> build phai tu sinh lai dang moi."""
        downgraded = self._original.replace(
            self._original[self._original.index("        # Huy moi tac vu dang chay o CA 3 tab"):
                           self._original.index("        root.destroy()",
                                                self._original.index("def on_close():"))
                           + len("        root.destroy()")],
            OLD_ON_CLOSE)
        self.assertNotIn(NEW_ON_CLOSE_MARK, downgraded, "khong ha duoc ve dang cu")
        with open(TARGET, "w", encoding="utf-8") as f:
            f.write(downgraded)

        builder.build()
        with open(TARGET, "r", encoding="utf-8") as f:
            rebuilt = f.read()
        self.assertIn(NEW_ON_CLOSE_MARK, rebuilt,
                      "build() khong tu sinh lai on_close() dang 3 tab")

    def test_survives_hand_edited_main(self):
        edited = self._original.replace(
            '    root.protocol("WM_DELETE_WINDOW", on_close)',
            '    # chu thich them tay cua nguoi bao tri\n'
            '    root.protocol("WM_DELETE_WINDOW", on_close)')
        self.assertNotEqual(edited, self._original)
        with open(TARGET, "w", encoding="utf-8") as f:
            f.write(edited)
        builder.build()        # khong duoc nem AssertionError
        with open(TARGET, "r", encoding="utf-8") as f:
            rebuilt = f.read()
        self.assertIn("chu thich them tay cua nguoi bao tri", rebuilt,
                      "build() da xoa mat phan sua tay o main")


if __name__ == "__main__":
    unittest.main(verbosity=2)
