#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/build_panorama_single.py - Sinh lai `PaloPANORAMA_single.py` (ban gop 1 file
duy nhat) tu 3 package DOC LAP o root repo: check_rule_pan/, check_ip_pan/ va
check_audit_pan/ + logic main dung san trong file single hien tai.

Viet lai 10/2026 - mo phong dung `tools/build_single.py` cua ban Firewall standalone
(da duoc kiem chung) de co 2 tinh chat BAT BUOC ma 2 script cu (`build_single.py` copy
nguyen tu ban firewall, va `rebuild_direct.py`) KHONG co:

  1. TU DONG SINH LAI KHOI "IMPORT LO THIEN" cho PyInstaller.
     3 package duoc nhung duoi dang chuoi base64 - PyInstaller phan tich TINH nen
     KHONG nhin xuyen qua chuoi do. Thu vien ngoai nao chi duoc import BEN TRONG
     package (vd `bisect` moi them vao detectors/resolver) se THIEU luc chay .exe
     ("ModuleNotFoundError"). Script cu chi thay the moi khoi base64 nen danh sach
     import lo thien bi DONG BANG tu lan sinh dau tien -> loi tiem an.
  2. IDEMPOTENT: chay bao nhieu lan cung ra file byte-giong-het (moi entry zip bi ep
     `date_time` co dinh), de dien diff/doi chieu giua cac lan build.

TEN PACKAGE TRONG ZIP = TEN THAT (`check_rule_pan`...), KHONG doi ten thanh
`check_rule` nhu script cu: file single khop dung voi cau truc repo, stack trace chi
dung module that, va khong the lan voi package cua ban Firewall standalone neu 2 ban
cung nam tren sys.path.

Chay tu ROOT repo:   python tools/build_panorama_single.py
Kiem tra:            python -m py_compile PaloPANORAMA_single.py
"""

import ast
import base64
import io
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "PaloPANORAMA_single.py"
PKG_NAMES = ["check_rule_pan", "check_ip_pan", "check_audit_pan"]


def _pkg_files():
    """{arc_name: bytes} cua tat ca *.py trong 3 package."""
    named = {}
    for pkg in PKG_NAMES:
        for p in sorted((ROOT / pkg).glob("*.py")):
            named[f"{pkg}/{p.name}"] = p.read_bytes()
    return named


def _make_zip_b64_lines():
    named = _pkg_files()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in named.items():
            zinfo = zipfile.ZipInfo(arc)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.date_time = (1980, 1, 1, 0, 0, 0)   # ep co dinh -> build idempotent
            zf.writestr(zinfo, data)
    enc = base64.b64encode(buf.getvalue()).decode()
    lines = [enc[i:i + 90] for i in range(0, len(enc), 90)]
    body = "\n".join('    "' + ln + '"' for ln in lines)
    return "_EMBEDDED_PACKAGES_ZIP_B64 = (\n" + body + "\n)\n", len(named), len(buf.getvalue())


def _collect_external_imports():
    """Top-level import BEN NGOAI (khong relative, khong thuoc 3 package) trong toan
    bo source 3 package - de PyInstaller nhin thay va dong goi du khi build .exe."""
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
# KHOI IMPORT "LO THIEN" (khong nam trong chuoi base64 ben duoi) - TU DONG SINH
# boi tools/build_panorama_single.py (ham _collect_external_imports) bang cach
# quet AST toan bo 3 package *_pan. Muc dich DUY NHAT: de PyInstaller "nhin
# thay" duoc cac thu vien ngoai khi phan tich tinh va tu dong dong goi vao file
# .exe. Ban than cac dong import nay vo hai/du thua o goc do runtime binh thuong
# - CHI phuc vu buoc build .exe. KHONG XOA khoi nay khi build bang PyInstaller
# --onefile, neu khong se gap lai loi "ModuleNotFoundError" luc chay .exe.
"""


def _open_imports_block():
    body = "\n".join(f"import {mod}" for mod in _collect_external_imports())
    return _OPEN_IMPORTS_HEADER + body


def _rendered() -> str:
    """Noi dung file single DUNG RA phai co, tinh tu source 3 package hien tai."""
    text = TARGET.read_text(encoding="utf-8")

    # 1) Sinh lai khoi "import lo thien" (quet AST 3 package).
    anchor = text.find('# KHOI IMPORT "LO THIEN"')
    if anchor == -1:
        raise AssertionError(
            "Khong tim thay anchor '# KHOI IMPORT \"LO THIEN\"' trong "
            f"{TARGET.name} - file goc co the da thay doi.")
    line_start = text.rfind("\n", 0, anchor) + 1
    div = line_start
    prev_end = text.rfind("\n", 0, line_start - 1) + 1
    prev_line = text[prev_end:line_start].strip()
    if prev_line.startswith("#") and prev_line.lstrip("#").strip().startswith("==="):
        div = prev_end
    blob_marker = text.index("_EMBEDDED_PACKAGES_ZIP_B64 = (", anchor)
    text = text[:div] + _open_imports_block() + "\n" + text[blob_marker:]

    # 2) Thay khoi base64 bang zip moi cua 3 package.
    blob, n_files, zip_bytes = _make_zip_b64_lines()
    start = text.index("_EMBEDDED_PACKAGES_ZIP_B64 = (\n")
    close = text.index("\n)\n", start) + len("\n)\n")
    text = text[:start] + blob + text[close:]

    return text, n_files, zip_bytes


def build():
    text, n_files, zip_bytes = _rendered()
    TARGET.write_text(text, encoding="utf-8")

    import py_compile
    py_compile.compile(str(TARGET), doraise=True)
    print(f"OK: da sinh lai {TARGET.name} ({len(text)} ky tu, zip {n_files} file "
          f"py / {zip_bytes} bytes) tu 3 package: {', '.join(PKG_NAMES)}")
    print(f"    import lo thien: {', '.join(_collect_external_imports())}")


def check() -> int:
    """`--check`: KHONG ghi gi ca, chi xac nhan file single tren dia DA khop voi
    source 3 package. Dung cho pre-commit hook / CI theo quy tac V.4 (code va file
    single phai nam trong CUNG 1 commit) - truoc day tai lieu co nhac lenh nay
    nhung script khong he ho tro."""
    want, _n, _z = _rendered()
    have = TARGET.read_text(encoding="utf-8")
    if want == have:
        print(f"OK: {TARGET.name} da dong bo voi 3 package {', '.join(PKG_NAMES)}.")
        return 0
    print(f"LECH: {TARGET.name} KHONG khop source hien tai "
          f"(tren dia {len(have)} ky tu, dung ra {len(want)} ky tu).")
    print("      Chay `python tools/build_panorama_single.py` roi commit lai.")
    return 1


if __name__ == "__main__":
    import sys
    sys.exit(check() if "--check" in sys.argv else (build() or 0))
