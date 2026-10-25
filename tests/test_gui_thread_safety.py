# -*- coding: utf-8 -*-
"""
Tkinter KHONG thread-safe: moi thao tac cham vao widget/hop thoai PHAI chay
tren main thread. Worker thread chi duoc day viec qua queue.

Bug that da gap (2026-10-22): tab CHECK RULE goi thang messagebox.showinfo()/
showerror() va self.after(0, ...) tu trong worker thread. Hau qua:

  * Dong cua so Suite trong luc dang chay Check ->
    RuntimeError: main thread is not in main loop
    nem ra trong worker thread. Ban .exe dong goi --noconsole thi thread chet
    am tham, nguoi dung khong thay gi.
  * 2 tab con lai (CHECK IP, CHECK AUDIT) khong dinh - chung dung dung mau
    queue -> _poll_queue tu dau.

Nhom test 1 (STATIC) chay duoc o moi noi, KHONG can python3-tk.
Nhom test 2 (RUNTIME) can Tk + DISPLAY, tu skip neu thieu.
"""

import ast
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUI_FILES = ["check_rule_pan/gui.py", "check_ip_pan/gui.py", "check_audit_pan/gui.py"]

# Nhung module chi duoc dung tren main thread
UI_MODULES = {"messagebox", "filedialog", "simpledialog", "colorchooser"}

# Method lam THAY DOI widget - goi tu worker thread la sai.
# Da gap that (2026-10-22): check_ip goi self.lbl_progress.config() trong
# _run_nat_pipeline() -> Export NAT hong hoan toan khi chay qua GUI, trong khi
# testlab goi thang pipeline nen 48/48 van PASS.
WIDGET_MUTATORS = {"config", "configure", "insert", "delete", "see",
                   "selection_set", "heading", "column"}

# DOC gia tri tu widget / tk.Variable cung la 1 loi goi vao Tcl, khong chi ghi.
# Da gap that (2026-10-22): check_rule doc self.req_file_var.get() trong
# _worker() -> no dung luc chuan bi xuat Excel, mat trang ca luot chay.
WIDGET_READERS = {"get", "set", "curselection", "cget"}

# Quy uoc dat ten cua 3 tab: tien to/hau to nao la widget hoac tk.Variable.
TK_ATTR_PREFIXES = ("var_", "ent_", "txt_", "cmb_", "cbo_", "lbl_", "chk_",
                    "spn_", "btn_", "tree", "progress", "log_text")


def _looks_like_tk_attr(name):
    return name.endswith("_var") or any(
        name == p or name.startswith(p) for p in TK_ATTR_PREFIXES)


def _thread_target_names(tree):
    """Ten cac ham duoc truyen lam target= cho threading.Thread(...)."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "Thread":
            for kw in node.keywords:
                if kw.arg == "target":
                    val = kw.value
                    name = getattr(val, "id", None) or getattr(val, "attr", None)
                    if name:
                        names.add(name)
    return names


# Cac ham "hoan lai": doi so callable truyen vao day se do MAIN THREAD chay,
# nen cham vao Tk ben trong la HOP LE.
DEFERRERS = {"_ui", "after", "after_idle", "put", "put_nowait"}


def _deferred_callables(func_node):
    """id() cua cac lambda/def duoc truyen lam doi so cho 1 ham "hoan lai".

    `self._ui(lambda: messagebox.showinfo(...))` la CACH DUNG DUNG - lambda do
    chay tren main thread. Phai loai no ra khoi ket qua quet, neu khong test se
    bao nham chinh ban va.
    """
    deferred = set()
    for sub in ast.walk(func_node):
        if not isinstance(sub, ast.Call):
            continue
        name = getattr(sub.func, "attr", None) or getattr(sub.func, "id", None)
        if name not in DEFERRERS:
            continue
        for arg in list(sub.args) + [kw.value for kw in sub.keywords]:
            if isinstance(arg, (ast.Lambda, ast.FunctionDef)):
                deferred.add(id(arg))
    return deferred


def _calls_inside(func_node):
    """(lineno, 'owner.attr') cua moi loi goi <owner>.<attr>() CHAY NGAY trong ham.

    Khong di vao than cac callable da duoc hoan lai cho main thread.
    """
    deferred = _deferred_callables(func_node)
    out = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Lambda, ast.FunctionDef)) and id(child) in deferred:
                continue                      # chay tren main thread -> bo qua
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                owner = (getattr(child.func.value, "id", None)
                         or getattr(child.func.value, "attr", None))
                if owner:
                    out.append((child.lineno, f"{owner}.{child.func.attr}"))
            visit(child)

    visit(func_node)
    return out


def _widget_assigns_inside(func_node):
    """Cac phep gan dang self.<widget>[...] = ... CHAY NGAY trong ham.

    `widget['values'] = x` la __setitem__ -> configure(), tuc 1 loi goi vao
    Tcl y het .config(). Bo quet chi soi LOI GOI HAM se bo lot han mau nay -
    da gap that o check_rule_pan: self.cmb_dg['values'] = dg_list trong worker
    lam hong ca buoc Load Config.
    """
    deferred = _deferred_callables(func_node)
    out = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Lambda, ast.FunctionDef)) and id(child) in deferred:
                continue
            if isinstance(child, ast.Assign):
                for tgt in child.targets:
                    if (isinstance(tgt, ast.Subscript) and isinstance(tgt.value, ast.Attribute)
                            and getattr(tgt.value.value, "id", None) == "self"
                            and _looks_like_tk_attr(tgt.value.attr)):
                        # Chi tinh khi ten thuoc tinh dung quy uoc widget cua 3 tab -
                        # `self.rule_by_key[k] = v` la dict thuong, khong lien quan Tk.
                        out.append((child.lineno, f"self.{tgt.value.attr}[...] ="))
            visit(child)

    visit(func_node)
    return out


def _widget_calls_inside(func_node):
    """Cac loi goi dang self.<widget>.<method>() CHAY NGAY trong ham.

    Bat ca 2 chieu: GHI vao widget (config/insert/...) va DOC tu widget hoac
    tk.Variable (get/set/cget) - ca hai deu la loi goi vao Tcl.
    """
    deferred = _deferred_callables(func_node)
    out = []

    def visit(node):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.Lambda, ast.FunctionDef)) and id(child) in deferred:
                continue
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                owner = child.func.value
                if isinstance(owner, ast.Attribute) and getattr(owner.value, "id", None) == "self":
                    attr = child.func.attr
                    if attr in WIDGET_MUTATORS or (
                            attr in WIDGET_READERS and _looks_like_tk_attr(owner.attr)):
                        out.append((child.lineno, f"self.{owner.attr}.{attr}"))
            visit(child)

    visit(func_node)
    return out


class TestNoUiCallFromWorkerThread(unittest.TestCase):
    """Khong file gui.py nao duoc cham vao Tk tu trong worker thread."""

    def _audit(self, path):
        with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
            src = f.read()
        tree = ast.parse(src)
        # LUU Y: nhieu ham LONG NHAU trung ten (moi _start_xxx deu co 1 ham
        # con ten `_worker`). Dung dict {ten: node} thi chi giu lai cai CUOI
        # cung -> bo lot het cac ham _worker con lai. Phai giu DANH SACH.
        all_funcs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]
        funcs = {}
        for n in all_funcs:
            funcs.setdefault(n.name, n)

        # Khong chi ham duoc truyen lam target=, ma CA cac ham ma no goi toi:
        # loi that nam o _run_nat_pipeline(), duoc _run_all_worker() goi.
        reach = {n for n in _thread_target_names(tree) if n}
        self.assertTrue(reach, f"{path}: khong tim thay worker thread nao de kiem tra")
        changed = True
        while changed:
            changed = False
            for name in list(reach):
                fn = funcs.get(name)
                if fn is None:
                    continue
                for sub in ast.walk(fn):
                    if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                            and getattr(sub.func.value, "id", None) == "self"
                            and sub.func.attr in funcs and sub.func.attr not in reach):
                        reach.add(sub.func.attr)
                        changed = True

        bad = []
        for node in all_funcs:
            name = node.name
            if name not in reach:
                continue
            for lineno, call in _calls_inside(node):
                owner, attr = call.split(".", 1)
                if owner in UI_MODULES:
                    bad.append(f"{path}:{lineno} {call}() trong {name}()")
                if owner == "self" and attr == "after":
                    bad.append(f"{path}:{lineno} self.after() trong {name}()")
            for lineno, widget_call in _widget_calls_inside(node):
                bad.append(f"{path}:{lineno} {widget_call}() trong {name}()")
            for lineno, assign in _widget_assigns_inside(node):
                bad.append(f"{path}:{lineno} {assign} trong {name}()")
        return bad

    def test_no_dialog_or_after_from_worker(self):
        bad = []
        for path in GUI_FILES:
            bad.extend(self._audit(path))
        self.assertEqual(
            bad, [],
            "Goi Tk tu worker thread (phai day qua queue, vd self._ui(...) hoac "
            "self.msg_queue.put((...))):\n  "
            + "\n  ".join(bad))

    def test_every_tab_has_shutdown(self):
        """Suite goi shutdown() cho ca 3 tab khi dong cua so."""
        for path in GUI_FILES:
            with open(os.path.join(ROOT, path), "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
            names = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
            self.assertIn("shutdown", names, f"{path} thieu shutdown()")

    def test_suite_calls_shutdown_on_all_tabs(self):
        with open(os.path.join(ROOT, "PaloPANORAMA_single.py"), "r", encoding="utf-8") as f:
            text = f.read()
        start = text.index("def on_close():")
        body = text[start:text.index("root.destroy()", start)]
        # Chap nhan ca 2 dang hop le: goi rieng tung tab, hoac 1 vong for.
        looped = "for tab in (tab_check_rule, tab_check_ip, tab_check_audit)" in body
        for tab in ("tab_check_rule", "tab_check_ip", "tab_check_audit"):
            called = looped or f"{tab}.shutdown()" in body
            self.assertTrue(called, f"on_close() khong goi shutdown() cho {tab}:\n{body}")


def _release_tk(app):
    """Buong het tham chieu Tk ngay tren main thread rồi gom rac.

    tk.Variable.__del__ goi vao Tcl; neu no chay sau khi interpreter da bi huy
    (hoac tu thread GC) thi Tcl abort ca tien trinh bang
    "Tcl_AsyncDelete: async handler deleted by the wrong thread".
    """
    import gc

    try:
        app.__dict__.clear()
    except Exception:
        pass
    gc.collect()


def _tk_ready():
    try:
        import tkinter as tk
    except Exception as exc:
        return None, f"khong co tkinter ({exc})"
    if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
        return None, "khong co DISPLAY (chay qua xvfb-run)"
    try:
        root = tk.Tk()
        root.destroy()
    except Exception as exc:
        return None, f"khong mo duoc Tk: {exc}"
    return tk, ""


class TestCloseWhileWorkerRunning(unittest.TestCase):
    """Dong cua so giua chung: worker con day viec ve UI cung khong duoc nem loi."""

    @classmethod
    def setUpClass(cls):
        tk, why = _tk_ready()
        if tk is None:
            raise unittest.SkipTest(why)
        cls.tk = tk

    def _each_tab(self):
        from check_audit_pan.gui import App as AuditApp
        from check_ip_pan.gui import App as IpApp
        from check_rule_pan.gui import PANOSCheckerGUI

        return [("CHECK RULE", PANOSCheckerGUI), ("CHECK IP", IpApp), ("CHECK AUDIT", AuditApp)]

    def test_ui_call_after_shutdown_is_silent(self):
        for label, cls in self._each_tab():
            with self.subTest(tab=label):
                root = self.tk.Tk()
                root.withdraw()
                app = cls(root)
                app.pack()
                root.update_idletasks()

                app.shutdown()          # dung nhu Suite lam trong on_close()
                root.destroy()

                # Worker thread "cham chan" van con day viec ve UI sau khi dong
                app._log("log sau khi dong cua so")
                if hasattr(app, "_ui"):
                    app._ui(lambda: None)
                if hasattr(app, "q"):
                    app.q.put(("log", "sau khi dong"))
                _release_tk(app)

    def test_shutdown_sets_cancel_event(self):
        for label, cls in self._each_tab():
            with self.subTest(tab=label):
                root = self.tk.Tk()
                root.withdraw()
                app = cls(root)
                app.pack()
                self.assertFalse(app.cancel_event.is_set())
                app.shutdown()
                self.assertTrue(app.cancel_event.is_set(),
                                f"{label}: shutdown() phai bat cancel_event")
                root.destroy()
                _release_tk(app)


if __name__ == "__main__":
    unittest.main(verbosity=2)
