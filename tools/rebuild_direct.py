#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tools/rebuild_direct.py - Rebuild PaloPANORAMA_single.py trực tiếp từ 3 package *_pan
Không phụ thuộc template PaloRuleSearchSuite_single.py (đã đổi tên). Luôn sinh trực tiếp.
Dùng cho pre-commit hook và V.4 "luôn sinh trực tiếp ra file PaloPANORAMA_single.py"
"""
import base64, io, zipfile, re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "PaloPANORAMA_single.py"
PKG_MAP = {"check_rule_pan":"check_rule","check_ip_pan":"check_ip","check_audit_pan":"check_audit"}

def build():
    named = {}
    for src_pkg, arc_pkg in PKG_MAP.items():
        src_dir = ROOT / src_pkg
        for p in sorted(src_dir.glob("*.py")):
            arc = f"{arc_pkg}/{p.name}"
            named[arc] = p.read_bytes()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for arc, data in named.items():
            zinfo = zipfile.ZipInfo(arc)
            zinfo.compress_type = zipfile.ZIP_DEFLATED
            zinfo.date_time = (1980,1,1,0,0,0)
            zf.writestr(zinfo, data)
    enc = base64.b64encode(buf.getvalue()).decode()
    lines = [enc[i:i+90] for i in range(0, len(enc), 90)]
    text = TARGET.read_text(encoding="utf-8")
    start_marker = "_EMBEDDED_PACKAGES_ZIP_B64 = (\n"
    start = text.index(start_marker)
    close = text.index("\n)\n", start) + len("\n)\n")
    body = "\n".join('    "' + ln + '"' for ln in lines)
    blob = "_EMBEDDED_PACKAGES_ZIP_B64 = (\n" + body + "\n)\n"
    new = text[:start] + blob + text[close:]
    TARGET.write_text(new, encoding="utf-8")
    print(f"OK rebuilt {TARGET.name} ({len(new)} chars, {len(named)} files, zip {len(buf.getvalue())} bytes)")
    # CẤM đụng require.md từ 2026-09-02: chỉ update PaloPANORAMA_single.md (V.4)
    # require.md được đóng băng, không sync nữa
    # py_compile
    import py_compile
    py_compile.compile(str(TARGET), doraise=True)
    print("OK py_compile single")

if __name__ == "__main__":
    build()
