# -*- coding: utf-8 -*-
"""Hàm phụ trợ dùng chung cho toàn bộ test của check_audit: giúp chạy cả bằng
`python -m pytest tests/` lẫn `python -m unittest discover -s tests` từ root."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))