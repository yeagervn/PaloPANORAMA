# -*- coding: utf-8 -*-
import os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MD = os.path.join(ROOT, "PaloPANORAMA_single.md")

def test_md_has_v4():
    text = open(MD, encoding="utf-8").read()
    assert "V.4" in text, "MD missing V.4"
    assert "Quy tắc đồng bộ" in text
    assert "XIV" in text
    assert "2026-08-29" in text
    assert "Shadow" in text and "hit_count==0" in text or "hit_count" in text.lower() or "Disable" in text
    print("MD V.4 OK")
    # check single rebuilt recent (embedded zip contains pan_api)
    import base64, zipfile, io
    py = os.path.join(ROOT, "PaloPANORAMA_single.py")
    text = open(py, encoding="utf-8").read()
    import re
    m = re.search(r'_EMBEDDED_PACKAGES_ZIP_B64 = \(([^)]+)\)', text, re.S)
    assert m, "no embedded zip"
    b64 = "".join(re.findall(r'"([^"]+)"', m.group(0)))
    data = base64.b64decode(b64)
    zf = zipfile.ZipFile(io.BytesIO(data))
    names = zf.namelist()
    assert "check_audit/gui.py" in names
    content = zf.read("check_audit/pan_api.py").decode()
    assert "disable_rule_candidate" in content, "single zip not rebuilt"
    print("single contains disable OK via zip decode")

if __name__=="__main__":
    test_md_has_v4()
    print("MD sync test PASSED")
