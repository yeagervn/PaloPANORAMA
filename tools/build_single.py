#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/build_single.py - Sinh lai `PaloRuleSearchSuite_single.py` (ban gop 1
file duy nhat) tu 3 package DOC LAP o root repo: check_rule/, check_ip/ va
check_audit/ + logic main dung san trong file single Hien tai.

File single KHONG bao gio sua tay logic: bend duoi chi doc lat file dang co,
thay the DUNG 3 bang:
  1. _EMBEDDED_PACKAGES_ZIP_B64  -> nen zip moi (check_rule + check_ip +
     check_audit) roi base64.
  2. Tep zip finder (sys.meta_path) -> bo sung root "check_audit".
  3. Phan main (import + tab thu 3 "CHECK AUDIT" + APP_TITLE + on_close
     shutdown + docstring) -> cap nhat len dung 3 tab.

Cach chay: tu ROOT repo:  `python tools/build_single.py`
Kiem tra sau khi build: `python -m py_compile PaloRuleSearchSuite_single.py`
"""

import base64
import io
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "PaloRuleSearchSuite_single.py"
PKG_NAMES = ["check_rule", "check_ip", "check_audit"]


def _pkg_files():
    """[(arc_name, bytes)] cua tat ca *.py trong 3 package (ban rieng o root)."""
    named = {}
    for pkg in PKG_NAMES:
        for p in sorted((ROOT / pkg).glob("*.py")):
            named[f"{pkg}/{p.name}"] = p.read_bytes()
    return named


def _make_zip_b64_lines():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in _pkg_files().items():
            # Pin date_time co dinh + nho danh ZD: neu de mac dinh, writestr ghi
            # thoi diem hien tai vao tung entry -> zip doi theo giay -> mat tinh
            # idempotent; ZipInfo() luc tao mac dinh la ZIP_STORED -> phong to file.
            zinfo = zipfile.ZipInfo(arc)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.date_time = (1980, 1, 1, 0, 0, 0)
            zf.writestr(zinfo, data)
    encoded = base64.b64encode(buf.getvalue()).decode("ascii")
    return [encoded[i:i + 90] for i in range(0, len(encoded), 90)]


def _blob_block(lines):
    body = "\n".join('    "' + ln + '"' for ln in lines)
    return "_EMBEDDED_PACKAGES_ZIP_B64 = (\n" + body + "\n)\n"


def _collect_external_imports():
    """Top-level import BÊN NGOÀI (không relative, không thuộc 3 package) trong
    toàn bộ source 3 package — để PyInstaller "nhìn thấy" và đóng gói đủ khi
    build .exe từ file single (không nhìn xuyên qua chuỗi base64)."""
    import ast

    roots = set()
    for pkg in PKG_NAMES:
        for p in sorted((ROOT / pkg).glob("*.py")):
            tree = ast.parse(p.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        roots.add(a.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        roots.add(node.module.split(".")[0])
    for own in PKG_NAMES:
        roots.discard(own)
    return sorted(roots)


_OPEN_IMPORTS_HEADER = """# ============================================================================
# KHOI IMPORT "LO THIEN" (khong nam trong chuoi base64 nhung ben duoi) - TU
# DONG SINH boi tools/build_single.py (ham _collect_external_imports) bang
# cach quet AST toan bo 3 package. Muc dich DUY NHAT: de PyInstaller "nhin
# thay" duoc cac thu vien ngoai khi phan tich tinh va tu dong dong goi vao
# file .exe. Ban than cac dong import nay vo hai/du thua o goc do runtime binh
# thuong (cac module check_rule/check_ip/check_audit nhung ben duoi van tu
# import lai dung nhung gi ho can) - CHI phuc vu cho buoc build .exe. KHONG
# XOA khoi nay khi build .exe bang PyInstaller --onefile, neu khong se gap lai
# loi "ModuleNotFoundError" luc chay .exe.
"""


def _open_imports_block():
    body = "\n".join(f"import {mod}" for mod in _collect_external_imports())
    return _OPEN_IMPORTS_HEADER + body


def _replace(text, old, new):
    if new in text:
        # Idempotent: buoc nay da duoc ap dung tu lan build truoc -> bo qua.
        return text
    count = text.count(old)
    if count == 1:
        return text.replace(old, new)
    raise AssertionError(
        f"Anchored `{old!r}` xuat hien {count} lan (can DUNG 1, va gia tri moi "
        f"`{new!r}` chua ton tai san). File goc co the da thay doi - hay kiem "
        "tra lai tools/build_single.py.")


def build():
    text = TARGET.read_text(encoding="utf-8")

    # 0) Cap nhat khoi "open imports" (PyInstaller) tu scan AST cua 3 package.
    #    Idempotent vi block duoc sinh determinis-tic - thay the theo ranh gioi
    #    dong divider phia tren anchor "# KHOI IMPORT" VA vung nguoc len tu
    #    marker `_EMBEDDED_PACKAGES_ZIP_B64 = (`.
    anchor_ki = text.find('# KHOI IMPORT "LO THIEN"')
    if anchor_ki == -1:
        raise AssertionError(
            "Khong tim thay anchor '# KHOI IMPORT' trong file single - "
            "file goc co the da thay doi, hay kiem tra lai tools/build_single.py.")
    line_start = text.rfind("\n", 0, anchor_ki) + 1
    div = line_start
    prev_line_end = text.rfind("\n", 0, line_start - 1) + 1
    prev_line = text[prev_line_end:line_start].strip()
    if prev_line.startswith("#") and prev_line.lstrip("#").strip().startswith("==="):
        div = prev_line_end
    blob_marker = text.index("_EMBEDDED_PACKAGES_ZIP_B64 = (", anchor_ki)
    text = text[:div] + _open_imports_block() + "\n" + text[blob_marker:]

    # 1) Thay base64 zip moi chua ca 3 package.
    start_marker = "_EMBEDDED_PACKAGES_ZIP_B64 = (\n"
    start = text.index(start_marker)
    close = text.index("\n)\n", start) + len("\n)\n")
    text = text[:start] + _blob_block(_make_zip_b64_lines()) + text[close:]

    # 2) Them root "check_audit" vao zip finder.
    text = _replace(
        text,
        'sys.meta_path.insert(0, _ZipBytesFinder(zf, {"check_rule", "check_ip"}))',
        'sys.meta_path.insert(0, _ZipBytesFinder(zf, {"check_rule", "check_ip", "check_audit"}))')
    text = _replace(
        text,
        'self._roots = package_roots  # {"check_rule", "check_ip"}',
        'self._roots = package_roots  # {"check_rule", "check_ip", "check_audit"}')

    # =====================================================================
    # 3) Cap nhat phan main/docstring: 2 tab -> 3 tab (CHECK AUDIT).
    # =====================================================================
    # 3a. Header docstring cua file single.
    text = _replace(text, "tu 2 package DOC LAP", "tu 3 package DOC LAP")
    text = _replace(
        text,
        "check_ip/ (tool CHECK IP) + main.py.",
        "check_ip/ (tool CHECK IP) va check_audit/ (tool CHECK AUDIT) + main logic.")
    text = _replace(
        text,
        "roi chay lai `python build_single_file.py` de sinh lai file",
        "roi chay lai `python tools/build_single.py` de sinh lai file")
    text = _replace(
        text,
        "Co che: 2 package check_rule/ va check_ip/ duoc nen",
        "Co che: 3 package check_rule/, check_ip/ va check_audit/ duoc nen")
    text = _replace(text, "chuan cua Python -> 2 tool VAN", "chuan cua Python -> 3 tool VAN")

    # 3b. Docstring main body.
    text = _replace(text, "ttk.Notebook 2 tab len tren", "ttk.Notebook 3 tab len tren")
    text = _replace(text, "GIAO DIEN GOC cua 2 tool doc lap", "GIAO DIEN GOC cua 3 tool doc lap")
    text = _replace(text, "vao 2 tab do:", "vao 3 tab do:")
    text = _replace(
        text,
        "lien quan toi 1 danh sach IP)\n",
        'lien quan toi 1 danh sach IP)\n'
        '    Tab "CHECK AUDIT" -> check_audit.gui.App               (tool #3: kiem tra\n'
        '                          Shadow / Disabled / Overly Permissive Rules)\n')
    text = _replace(text, "luc con la 2 tool\n", "luc con la 3 tool\n")
    text = _replace(text, "rieng biet. 2 package", "rieng biet. 3 package")
    text = _replace(
        text,
        "pyinstaller --onefile --noconsole --name PaloRuleSearchSuite main.py",
        "pyinstaller --onefile --noconsole --name PaloRuleSearchSuite "
        "PaloRuleSearchSuite_single.py")
    text = _replace(
        text,
        "(Xem them build_single_file.py de sinh ban gop PaloRuleSearchSuite_single.py",
        "(Xem them tools/build_single.py de sinh ban gop PaloRuleSearchSuite_single.py")

    # 3c. Import App cua tool #3.
    text = _replace(
        text,
        "from check_ip.gui import App as CheckIPApp\n",
        "from check_ip.gui import App as CheckIPApp\nfrom check_audit.gui import App as CheckAuditApp\n")

    # 3d. APP_TITLE.
    text = _replace(
        text,
        'APP_TITLE = "PAN-OS Suite - Check Rule & Check IP"',
        'APP_TITLE = "PAN-OS Suite - Check Rule & Check IP & Check Audit"')

    # 3e. Docstring cua build_app + them Tab 3.
    text = _replace(text, "Dung Notebook 2 tab, moi tab", "Dung Notebook 3 tab, moi tab")
    text = _replace(
        text,
        "Tra ve (notebook, tab_check_rule, tab_check_ip) de noi goi",
        "Tra ve (notebook, tab_check_rule, tab_check_ip, tab_check_audit) de noi goi")
    text = _replace(
        text,
        '    notebook.add(tab_check_ip, text="CHECK IP")\n',
        '    notebook.add(tab_check_ip, text="CHECK IP")\n'
        "\n"
        '    # ---- Tab 3: CHECK AUDIT (tool #3 - nguyen ven, khong sua logic) ----\n'
        '    tab_check_audit = CheckAuditApp(notebook)\n'
        '    tab_check_audit.pack(fill="both", expand=True)\n'
        '    notebook.add(tab_check_audit, text="CHECK AUDIT")\n')

    # 3f. on_close: shutdown ca tab thu 3.
    text = _replace(
        text,
        "        try:\n"
        "            tab_check_ip.shutdown()\n"
        "        except Exception:\n"
        "            pass\n"
        "        root.destroy()",
        "        try:\n"
        "            tab_check_ip.shutdown()\n"
        "        except Exception:\n"
        "            pass\n"
        "        try:\n"
        "            tab_check_audit.shutdown()\n"
        "        except Exception:\n"
        "            pass\n"
        "        root.destroy()")

    # 3g. Tra ve ca 3 tab.
    text = _replace(
        text,
        "    return notebook, tab_check_rule, tab_check_ip",
        "    return notebook, tab_check_rule, tab_check_ip, tab_check_audit")

    TARGET.write_text(text, encoding="utf-8")
    print(f"OK: da sinh lai {TARGET.name} ({len(text)} ky tu, "
          f"zip {len(_pkg_files())} file py cua 3 package).")


def main():
    if not TARGET.exists():
        print(f"LOI: khong thay {TARGET}. Chay lenh nay tu ROOT repo.", file=sys.stderr)
        sys.exit(1)
    build()


if __name__ == "__main__":
    main()