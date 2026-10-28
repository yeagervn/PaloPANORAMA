# -*- coding: utf-8 -*-
"""
E2E GUI tab CHECK AUDIT: lai THAT giao dien tren FIREWALL GIA LAP cua testlab.

Cung ly do voi tests/test_gui_e2e_check_ip.py: testlab goi thang cac ham
detector/exporter, KHONG di qua tang GUI. Bug that da tim thay o tab CHECK IP
bang dung cach nay (worker thread cham vao widget -> Export NAT hong hoan toan
trong khi testlab van 48/48 PASS).

Phu o day:
  * Connect -> do danh sach VSYS -> mo khoa nut Check.
  * Tick ca 3 tinh nang (shadow / disabled / overly permissive) -> Check ->
    bang ket qua co dong, nut Export/Import duoc mo dung luc.
  * Bo tick het -> Check phai canh bao, khong duoc treo UI.
  * Export ra file va mo lai doi chieu.
  * D6: TUYET DOI khong goi commit o bat ky duong nao.

Tu skip neu may khong co python3-tk hoac khong co DISPLAY (dung xvfb-run).
"""

import os
import shutil
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MOCK_PORT = 18479


def _tk_ready():
    try:
        import tkinter as tk
    except Exception as exc:
        return None, f"khong co tkinter ({exc})"
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        return None, "khong co DISPLAY (chay qua xvfb-run)"
    try:
        r = tk.Tk()
        r.destroy()
    except Exception as exc:
        return None, f"khong mo duoc Tk: {exc}"
    return tk, ""


class _NoDialogs:
    def __init__(self, gui_mod):
        self.mod = gui_mod
        self.saved = {}
        self.calls = []

    def __enter__(self):
        for name, ret in (("showinfo", None), ("showwarning", None),
                          ("showerror", None), ("askyesno", False)):
            self.saved[name] = getattr(self.mod.messagebox, name)
            setattr(self.mod.messagebox, name,
                    (lambda *a, _n=name, _r=ret, **k: (self.calls.append((_n, a)), _r)[1]))
        return self

    def __exit__(self, *exc):
        for name, fn in self.saved.items():
            setattr(self.mod.messagebox, name, fn)
        return False


class TestCheckAuditGuiEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tk, why = _tk_ready()
        if tk is None:
            raise unittest.SkipTest(why)
        cls.tk = tk

        from testlab.run_all_features import auto_mock

        cls._mock_ctx = auto_mock(MOCK_PORT)
        cls.host = cls._mock_ctx.__enter__()

        from check_audit_pan.core import OUTPUT_DIR

        cls.out_dir = OUTPUT_DIR

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_mock_ctx"):
            cls._mock_ctx.__exit__(None, None, None)

    def setUp(self):
        self._before = set(os.listdir(self.out_dir)) if os.path.isdir(self.out_dir) else set()
        self.addCleanup(self._cleanup_output)

    def _cleanup_output(self):
        if not os.path.isdir(self.out_dir):
            return
        for name in set(os.listdir(self.out_dir)) - self._before:
            path = os.path.join(self.out_dir, name)
            try:
                os.remove(path) if os.path.isfile(path) else shutil.rmtree(path)
            except OSError:
                pass

    @staticmethod
    def _teardown_tk(app, root):
        import gc

        import threading

        try:
            app.shutdown()          # bat cancel_event -> worker se dung som
        except Exception:
            pass

        # CHO worker thread ket thuc TRUOC khi buong tham chieu. Neu xoa
        # __dict__ trong luc worker con chay, no se nem AttributeError khi goi
        # self._log() - loi cua TEST chu khong phai cua tool.
        deadline = time.time() + 5
        while time.time() < deadline:
            alive = [t for t in threading.enumerate()
                     if t is not threading.main_thread() and t.is_alive()]
            if not alive:
                break
            time.sleep(0.05)

        try:
            root.destroy()
        except Exception:
            pass
        # Buong het tham chieu Tk ngay tren main thread roi gom rac: tk.Variable
        # bi GC sau khi interpreter Tcl da bien mat se lam Tcl abort ca tien
        # trinh ("Tcl_AsyncDelete: async handler deleted by the wrong thread").
        app.__dict__.clear()
        gc.collect()

    def _pump(self, root, predicate, timeout=90, label=""):
        end = time.time() + timeout
        while time.time() < end:
            root.update()
            if predicate():
                return True
            time.sleep(0.05)
        self.fail(f"Qua {timeout}s van chua: {label}")

    def _new_app(self):
        from check_audit_pan.gui import App

        root = self.tk.Tk()
        root.withdraw()
        app = App(root)
        app.pack(fill="both", expand=True)
        root.update_idletasks()
        self.addCleanup(self._teardown_tk, app, root)
        return root, app

    def _connect(self, root, app):
        app.ent_host.delete(0, "end")
        app.ent_host.insert(0, self.host)
        app.ent_apikey.delete(0, "end")
        app.ent_apikey.insert(0, "testlab")
        app.var_verify_ssl.set(False)
        self.assertEqual(str(app.btn_check.cget("state")), "disabled",
                         "chua Connect ma nut Check da bat")
        app._on_connect()
        self._pump(root, lambda: str(app.btn_check.cget("state")) == "normal",
                   label="ket noi xong va mo khoa nut Check")

    # ---------------------------------------------------------------- tests
    def test_check_all_three_features_then_export(self):
        import check_audit_pan.gui as gui_mod

        root, app = self._new_app()
        with _NoDialogs(gui_mod) as dialogs:
            self._connect(root, app)
            self.assertTrue(app.cmb_dg.cget("values"), "khong lay duoc danh sach Device-Group")

            app.var_shadow.set(True)
            app.var_disabled.set(True)
            app.var_overly.set(True)

            app._on_check()
            self._pump(root, lambda: str(app.btn_check.cget("state")) == "normal",
                       label="Check chay xong")

            rows = app.tree.get_children()
            self.assertTrue(rows, "Check xong ma bang ket qua trong ron")
            kinds = {app.tree.item(r, "values")[0] for r in rows}
            self.assertTrue(kinds, "khong doc duoc cot loai phat hien")

            self.assertEqual(str(app.btn_export.cget("state")), "normal",
                             "co ket qua ma nut Export van khoa")

            app._on_open_output = lambda *a, **k: None
            app._on_export()
            self._pump(root, lambda: bool(set(os.listdir(self.out_dir)) - self._before),
                       timeout=30, label="sinh file Export")

        new_files = sorted(set(os.listdir(self.out_dir)) - self._before)
        xlsx = [f for f in new_files if f.endswith(".xlsx")]
        self.assertTrue(xlsx, f"khong co file .xlsx nao trong {new_files}")

        import openpyxl

        wb = openpyxl.load_workbook(os.path.join(self.out_dir, xlsx[0]))
        ws = wb[wb.sheetnames[0]]
        self.assertGreater(ws.max_row, 1, "file Export rong")
        headers = [c.value for c in next(ws.iter_rows(min_row=1, max_row=1))]
        for col in ("Name Rule", "Source IP", "Dest IP", "Port"):
            self.assertIn(col, headers, f"thieu cot nen tang D7: {col} (dang co {headers})")
        wb.close()
        self.assertTrue(dialogs.calls, "Export xong khong bao cho nguoi dung")

    def test_check_with_no_feature_selected_warns_and_keeps_ui(self):
        import check_audit_pan.gui as gui_mod

        root, app = self._new_app()
        with _NoDialogs(gui_mod) as dialogs:
            self._connect(root, app)
            # Bo tick HET - ke ca muc moi them. Them mot loai check ma quen
            # dong bo o day thi test nay xanh gia (van con 1 muc duoc tick nen
            # tool khong he canh bao gi).
            app.var_shadow.set(False)
            app.var_disabled.set(False)
            app.var_overly.set(False)
            app.var_target_sai.set(False)
            self.assertEqual(app._selected_types(), [],
                             "con muc check nao do van dang duoc tick")

            app._on_check()
            root.update()
            self._pump(root, lambda: str(app.btn_check.cget("state")) == "normal",
                       timeout=30, label="UI khong bi ket")
        self.assertTrue(dialogs.calls, "bo tick het ma khong canh bao gi")

    def test_never_calls_commit_anywhere(self):
        """D6 (locked): tuyet doi khong goi commit o bat ky dau trong codebase."""
        import glob
        import re

        offenders = []
        pat = re.compile(r"type\s*=\s*commit|<commit>|action\s*=\s*commit", re.I)
        for path in glob.glob(os.path.join(ROOT, "check_audit_pan", "*.py")):
            with open(path, encoding="utf-8") as f:
                for i, line in enumerate(f, 1):
                    if pat.search(line):
                        offenders.append(f"{os.path.basename(path)}:{i} {line.strip()[:70]}")
        self.assertEqual(offenders, [], "D6 bi vi pham:\n  " + "\n  ".join(offenders))


if __name__ == "__main__":
    unittest.main(verbosity=2)
