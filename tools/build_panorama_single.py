#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/build_panorama_single.py - Sinh file PANORAMA Suite single (1 file duy nhất)
từ 3 package check_rule_pan / check_ip_pan / check_audit_pan.

Khác với tools/build_single.py (đóng gói bản Firewall standalone), file này:
 - Đọc source từ 3 package *_pan
 - Nhưng NHÚNG vào zip dưới tên chuẩn check_rule / check_ip / check_audit
   (map *_pan -> * ) để code main hiện có (from check_rule.gui import ...)
   hoạt động y hệt, không phải sửa main import.
 - Xuất ra file: PaloRuleSearchSuite_PANORAMA_single.py (giữ nguyên file gốc)
   với docstring + APP_TITLE cập nhật cho Panorama.

Cơ chế zip+base64+MetaPathFinder giữ nguyên (copy từ build_single.py).
Chạy: python tools/build_panorama_single.py  (từ ROOT repo)
Kiểm tra: python -m py_compile PaloRuleSearchSuite_PANORAMA_single.py
"""

import base64
import io
import sys
import zipfile
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "PaloRuleSearchSuite_single.py"
TARGET = ROOT / "PaloRuleSearchSuite_PANORAMA_single.py"

# map source package -> arc package (đổi tên khi nhúng)
PKG_MAP = {
    "check_rule_pan": "check_rule",
    "check_ip_pan": "check_ip",
    "check_audit_pan": "check_audit",
}

def _pkg_files():
    named = {}
    for src_pkg, arc_pkg in PKG_MAP.items():
        src_dir = ROOT / src_pkg
        if not src_dir.exists():
            print(f"WARN: thiếu {src_dir}, bỏ qua", file=sys.stderr)
            continue
        for p in sorted(src_dir.glob("*.py")):
            arc = f"{arc_pkg}/{p.name}"
            named[arc] = p.read_bytes()
    return named

def _make_zip_b64_lines():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in _pkg_files().items():
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
    roots = set()
    for src_pkg in PKG_MAP.keys():
        for p in sorted((ROOT / src_pkg).glob("*.py")):
            try:
                tree = ast.parse(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for a in node.names:
                        roots.add(a.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.level == 0 and node.module:
                        roots.add(node.module.split(".")[0])
    for own in ["check_rule", "check_ip", "check_audit", "check_rule_pan", "check_ip_pan", "check_audit_pan"]:
        roots.discard(own)
    return sorted(roots)

_OPEN_IMPORTS_HEADER = """# ============================================================================
# KHOI IMPORT "LO THIEN" (khong nam trong chuoi base64 nhung ben duoi) - TU
# DONG SINH boi tools/build_panorama_single.py (ham _collect_external_imports) bang
# cach quet AST toan bo 3 package PANORAMA. Muc dich DUY NHAT: de PyInstaller "nhin
# thay" duoc cac thu vien ngoai khi phan tich tinh va tu dong dong goi vao
# file .exe. Ban than cac dong import nay vo hai/du thua o goc do runtime binh
# thuong - CHI phuc vu cho buoc build .exe.
"""

def _open_imports_block():
    body = "\n".join(f"import {mod}" for mod in _collect_external_imports())
    return _OPEN_IMPORTS_HEADER + body

def build():
    if not TEMPLATE.exists():
        print(f"LOI: khong thay template {TEMPLATE}", file=sys.stderr)
        sys.exit(1)
    text = TEMPLATE.read_text(encoding="utf-8")

    # 0) Cập nhật khối open imports (scan từ pan packages)
    anchor_ki = text.find('# KHOI IMPORT "LO THIEN"')
    if anchor_ki == -1:
        raise AssertionError("Khong tim thay anchor '# KHOI IMPORT' trong template")
    line_start = text.rfind("\n", 0, anchor_ki) + 1
    div = line_start
    prev_line_end = text.rfind("\n", 0, line_start - 1) + 1
    prev_line = text[prev_line_end:line_start].strip()
    if prev_line.startswith("#") and prev_line.lstrip("#").strip().startswith("==="):
        div = prev_line_end
    blob_marker = text.index("_EMBEDDED_PACKAGES_ZIP_B64 = (", anchor_ki)
    text = text[:div] + _open_imports_block() + "\n" + text[blob_marker:]

    # 1) Thay zip base64 mới (pan content mapped to standard names)
    start_marker = "_EMBEDDED_PACKAGES_ZIP_B64 = (\n"
    start = text.index(start_marker)
    close = text.index("\n)\n", start) + len("\n)\n")
    text = text[:start] + _blob_block(_make_zip_b64_lines()) + text[close:]

    # 2) Đảm bảo zip finder vẫn là 3 roots chuẩn
    # (nếu template đã có đủ 3 thì idempotent, nếu chưa thì thêm)
    # Không cần đổi gì thêm vì arc names đã là check_rule/check_ip/check_audit

    # 3) Cập nhật docstring/header cho bản PANORAMA
    text = text.replace(
        "PaloRuleSearchSuite_single.py - BAN GOP 1 FILE DUY NHAT",
        "PaloRuleSearchSuite_PANORAMA_single.py - BAN GOP 1 FILE DUY NHAT (PANORAMA)"
    )
    # APP_TITLE nếu là bản firewall -> đổi thành panorama
    if 'APP_TITLE = "PAN-OS Suite - Check Rule & Check IP & Check Audit"' in text:
        text = text.replace(
            'APP_TITLE = "PAN-OS Suite - Check Rule & Check IP & Check Audit"',
            'APP_TITLE = "PAN-OS Suite (PANORAMA) - Check Rule & Check IP & Check Audit"'
        )
    # Thêm ghi chú Panorama vào docstring nếu chưa có
    if "bản PANORAMA" not in text[:2000]:
        text = text.replace(
            "va check_audit/ (tool CHECK AUDIT) + main logic.",
            "va check_audit/ (tool CHECK AUDIT) + main logic.\n# BAN NAY LA BAN PANORAMA: Panorama IP + Device Group + Target Serial, object thừa kế theo chuỗi DG, rulebase lắp ráp 6 bước 0.3."
        )

    TARGET.write_text(text, encoding="utf-8")
    print(f"OK: da sinh {TARGET.name} ({len(text)} ky tu) tu 3 package PANORAMA:")
    for src, arc in PKG_MAP.items():
        cnt = len(list((ROOT / src).glob("*.py")))
        print(f"  {src} -> {arc} ({cnt} files)")
    print(f"Zip entries: {len(_pkg_files())}")

def main():
    build()

if __name__ == "__main__":
    main()
