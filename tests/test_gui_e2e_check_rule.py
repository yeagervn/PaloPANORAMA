# -*- coding: utf-8 -*-
"""
E2E GUI tab CHECK RULE: lai THAT giao dien tren FIREWALL GIA LAP cua testlab.

Khep lai not khoang trong "GUI that: CHUA kiem chung" cua PHAN 0.2 cho tab cuoi
cung. Phu:
  * Load Config tu thiet bi -> nut Check dung duoc, rulebase da nap.
  * Che do "Nhap tay": them dong -> Check -> ra ket qua, KHONG sinh file.
  * Che do "Chon file": chay file mau cua testlab -> sinh dung 1 file
    Result_*.xlsx canh file input, va "Browse Output" duoc mo khoa.
  * Dong cua so giua chung: worker khong duoc nem loi (dung lop bug
    "main thread is not in main loop" da sua ngay 2026-10-22).

Tu skip neu may khong co python3-tk hoac khong co DISPLAY (dung xvfb-run).
"""

import os
import shutil
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

MOCK_PORT = 18480


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


class TestCheckRuleGuiEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tk, why = _tk_ready()
        if tk is None:
            raise unittest.SkipTest(why)
        cls.tk = tk
        from testlab.run_all_features import auto_mock

        cls._mock_ctx = auto_mock(MOCK_PORT)
        cls.host = cls._mock_ctx.__enter__()

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "_mock_ctx"):
            cls._mock_ctx.__exit__(None, None, None)

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

    def _pump(self, root, predicate, timeout=120, label=""):
        end = time.time() + timeout
        while time.time() < end:
            root.update()
            if predicate():
                return True
            time.sleep(0.05)
        self.fail(f"Qua {timeout}s van chua: {label}")

    def _new_app(self):
        from check_rule_pan.gui import PANOSCheckerGUI

        root = self.tk.Tk()
        root.withdraw()
        app = PANOSCheckerGUI(root)
        app.pack(fill="both", expand=True)
        root.update_idletasks()
        self.addCleanup(self._teardown_tk, app, root)
        return root, app

    def _log_text(self, app):
        return app.log_text.get("1.0", "end")

    def _load_config(self, root, app):
        app.mgmt_ip_var.set(self.host)
        app.api_key_var.set("testlab")
        app._start_load_config()
        self._pump(root, lambda: app.rule_infos is not None, label="nap xong running-config")
        self.assertTrue(app.rule_infos, "nap config xong nhung rulebase rong")

    # ---------------------------------------------------------------- tests
    def test_load_config_from_device(self):
        import check_rule_pan.gui as gui_mod

        root, app = self._new_app()
        with _NoDialogs(gui_mod) as dialogs:
            self._load_config(root, app)
            self._pump(root, lambda: any(n == "showinfo" for n, _ in dialogs.calls),
                       timeout=30, label="bao nap config thanh cong")
        self.assertIn("Nạp thành công", self._log_text(app))

    def test_manual_mode_prints_result_without_writing_file(self):
        import check_rule_pan.gui as gui_mod

        root, app = self._new_app()
        with tempfile.TemporaryDirectory() as tmp:
            with _NoDialogs(gui_mod) as dialogs:
                self._load_config(root, app)
                app.input_mode_var.set("manual")
                app._toggle_mode()
                app.tree.insert("", "end", values=("10.1.1.5", "10.2.2.5", "443"))

                app._start_check()
                self._pump(root,
                           lambda: "KẾT QUẢ KIỂM TRA TRỰC TIẾP" in self._log_text(app),
                           label="chay xong che do nhap tay")
                self._pump(root,
                           lambda: any(a and "Test Policy Match" in str(a[0])
                                       for n, a in dialogs.calls if n == "showinfo"),
                           timeout=30, label="hien bang ket qua")

            log = self._log_text(app)
            self.assertIn("Dòng 1: Status [", log)
            self.assertEqual(os.listdir(tmp), [], "che do nhap tay khong duoc sinh file")

    def test_file_mode_exports_result_next_to_input(self):
        import check_rule_pan.gui as gui_mod

        sample = os.path.join(ROOT, "testlab", "samples", "request_check_rule.xlsx")
        self.assertTrue(os.path.exists(sample), f"thieu file mau: {sample}")

        with tempfile.TemporaryDirectory() as tmp:
            work = os.path.join(tmp, "request_check_rule.xlsx")
            shutil.copy(sample, work)

            root, app = self._new_app()
            with _NoDialogs(gui_mod):
                self._load_config(root, app)
                app.input_mode_var.set("file")
                app._toggle_mode()
                app.req_file_var.set(work)
                app._open_path = lambda *a, **k: None       # khong mo file manager

                app._start_check()
                self._pump(root,
                           lambda: any(f.startswith("Result_") for f in os.listdir(tmp)),
                           label="sinh file Result_*.xlsx")

                # MOI viec cham vao UI phai nam TRONG khoi _NoDialogs. Worker
                # xep hop thoai vao hang doi _ui; neu pump hang doi do SAU khi
                # da bo patch messagebox thi dialog THAT bat len va treo vinh
                # vien (test dung, tool khong sai).
                self._pump(root,
                           lambda: str(app.browse_output_btn.cget("state")) == "normal",
                           timeout=30, label="mo khoa nut Browse Output")

            results = [f for f in os.listdir(tmp) if f.startswith("Result_")]
            self.assertEqual(len(results), 1, f"ky vong dung 1 file ket qua, co {results}")

            import openpyxl

            wb = openpyxl.load_workbook(os.path.join(tmp, results[0]))
            ws = wb[wb.sheetnames[0]]
            self.assertGreater(ws.max_row, 1, "file ket qua rong")
            wb.close()
            self.assertEqual(os.path.dirname(app.last_output_path), tmp,
                             "file ket qua phai nam canh file input")

    def test_close_window_while_checking_is_silent(self):
        """Dong cua so giua chung: khong duoc nem RuntimeError tu worker."""
        import check_rule_pan.gui as gui_mod

        root, app = self._new_app()
        with _NoDialogs(gui_mod):
            self._load_config(root, app)
            app.input_mode_var.set("manual")
            app._toggle_mode()
            for i in range(5):
                app.tree.insert("", "end", values=(f"10.1.1.{i + 1}", "10.2.2.5", "443"))

            app._start_check()
            root.update()
            app.shutdown()          # dung nhu Suite lam trong on_close()
            root.update()

        # worker con chay tiep vai nhip roi moi thay cancel_event
        time.sleep(0.5)
        app._log("sau khi dong")
        app._ui(lambda: None)


if __name__ == "__main__":
    unittest.main(verbosity=2)
