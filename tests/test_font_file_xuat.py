# -*- coding: utf-8 -*-
"""
MOI file .xlsx tool xuat ra deu dung MOT font: Times New Roman.

Hai tab check_rule / check_audit dung font nay tu dau; rieng tab CHECK IP con
hai duong bi lech: sheet Security Rules ke thua font tu FILE TEMPLATE, con
sheet NAT / Object Where Used thi hardcode "Calibri" (va nhung `Font(...)`
khong dat `name` duoc openpyxl tu dien Calibri). Mot bo bao cao ma moi sheet
mot font thi nguoi nhan doc ra ngay la ghep tu nhieu cho.

Test duyet TUNG O cua TUNG SHEET chu khong chi kiem may bien font trong ma
nguon - vi dung cho de sai nhat la nhung o KHONG di qua bien nao ca (dong
tieu de lay nguyen style tu template).
"""

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import openpyxl

from check_ip_pan.excel_export import (OUT_FONT_NAME, export_combined_to_excel,
                                   export_nat_to_excel, export_to_excel,
                                   export_where_used_to_excel)
from check_ip_pan.resolver_engine import GroupResolver
from check_ip_pan.where_used import where_used_ip
from tests.test_check_ip_combined_export import (MATCH, _addr, _grp,
                                                 _nat_rules, _rules, _svc)


def _font_names(path):
    """Ten font cua MOI o co gia tri, trong MOI sheet."""
    wb = openpyxl.load_workbook(path)
    names = set()
    for ws in wb.worksheets:
        for row in ws.iter_rows():
            for cell in row:
                if cell.value is not None and cell.font is not None:
                    names.add(cell.font.name)
    wb.close()
    return names


class TestFontFileXuat(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="font_xuat_")
        self.addCleanup(shutil.rmtree, self.out, ignore_errors=True)

    def test_font_la_Times_New_Roman(self):
        self.assertEqual(OUT_FONT_NAME, "Times New Roman")

    def test_sheet_Security_Rules_khong_con_an_theo_template(self):
        p = export_to_excel(self.out, _rules(), MATCH,
                            GroupResolver(_addr(), _grp()), _svc(), {})
        self.assertEqual(_font_names(p), {OUT_FONT_NAME})

    def test_sheet_NAT(self):
        p = export_nat_to_excel(self.out, _nat_rules(),
                                GroupResolver(_addr(), _grp()), _svc(), {},
                                highlight_ips={"10.1.1.1"})
        self.assertEqual(_font_names(p), {OUT_FONT_NAME})

    def test_file_GOP_2_sheet(self):
        p = export_combined_to_excel(
            self.out, rules=_rules(), match_results=MATCH,
            resolver=GroupResolver(_addr(), _grp()),
            service_objects=_svc(), service_groups={},
            nat_rules=_nat_rules(), nat_resolver=GroupResolver(_addr(), _grp()),
            nat_service_objects=_svc(), nat_service_groups={})
        self.assertEqual(_font_names(p), {OUT_FONT_NAME})

    def test_sheet_Object_Where_Used(self):
        resolver = GroupResolver(_addr(), _grp())
        rep = where_used_ip("10.1.1.1", _addr(), _grp(), _rules(), resolver)
        p = export_where_used_to_excel(self.out, [rep])
        self.assertEqual(_font_names(p), {OUT_FONT_NAME})


if __name__ == "__main__":
    unittest.main(verbosity=2)
