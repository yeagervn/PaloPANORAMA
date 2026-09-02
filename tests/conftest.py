# -*- coding: utf-8 -*-
"""Hàm phụ trợ dùng chung cho toàn bộ test của check_audit: giúp chạy cả bằng
`python -m pytest tests/` lẫn `python -m unittest discover -s tests` từ root."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Alias cho Panorama: check_audit (standalone) -> check_audit_pan nếu không tồn tại
try:
    import check_audit  # noqa
except ImportError:
    try:
        import check_audit_pan as _pan
        import sys as _sys
        _sys.modules['check_audit'] = _pan
        # alias submodules
        for sub in ['core','resolver','detectors','excel_io','pan_api']:
            try:
                _mod = __import__(f'check_audit_pan.{sub}', fromlist=[sub])
                _sys.modules[f'check_audit.{sub}'] = _mod
            except ImportError:
                pass
    except ImportError:
        pass