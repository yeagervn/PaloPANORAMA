# -*- coding: utf-8 -*-
"""
Test cho thay doi 10/2026 (CHECK IP): khi 1 luot chay lam CA Check Rule LAN
Export NAT thi gop vao DUNG 1 file .xlsx co 2 sheet, thay vi sinh 2 file roi rac.

Nguyen tac BAT BUOC: template/dinh dang cua TUNG SHEET phai giu nguyen 100% so
voi file roi hien tai - test duoi day so sanh tung o (noi dung), font/mau/fill/
wrap, do rong cot va chieu cao dong giua 2 duong xuat.
Khong phu thuoc tkinter.
"""

import os
import shutil
import tempfile
import unittest

import openpyxl

from check_ip_pan.core import (SecurityRule, NatRule, AddressObject, AddressGroup,
                           ServiceObject, LogEntry)
from check_ip_pan.resolver_engine import GroupResolver
from check_ip_pan.excel_export import (export_to_excel, export_nat_to_excel,
                                    export_combined_to_excel,
                                    RULE_SHEET_TITLE, NAT_SHEET_TITLE)


def _addr():
    return {
        'H1': AddressObject('H1', 'ip-netmask', '10.1.1.1/32'),
        'H2': AddressObject('H2', 'ip-netmask', '10.1.1.2/32'),
        'R1': AddressObject('R1', 'ip-range', '10.2.2.10-10.2.2.20'),
    }


def _grp():
    return {'G1': AddressGroup('G1', 'static', members=['H1', 'H2'])}


def _svc():
    return {'tcp443': ServiceObject('tcp443', 'tcp', '443')}


def _rules():
    return [
        SecurityRule(index=1, name='Allow-Web', source=['G1'], destination=['R1'],
                     service=['tcp443'], application=['web-browsing'], action='allow',
                     from_zones=['trust'], to_zones=['untrust']),
        SecurityRule(index=2, name='Deny-All', source=['any'], destination=['any'],
                     service=['any'], application=['any'], action='deny', disabled=True),
    ]


def _nat_rules():
    return [
        NatRule(index=1, name='NAT-Out', source=['G1'], destination=['R1'],
                from_zones=['trust'], to_zones=['untrust'], service='any',
                src_xlate_type='dynamic-ip-and-port', src_xlate_interface='ethernet1/1'),
        NatRule(index=2, name='NAT-In', source=['any'], destination=['H1'],
                from_zones=['untrust'], to_zones=['trust'],
                dst_xlate_type='static', dst_xlate_address='H2', dst_xlate_port='8080'),
    ]


MATCH = {'10.1.1.1': [(1, 'source')]}


def _dump(ws):
    return [[c.value if (c.value is None or isinstance(c.value, (str, int, float, bool)))
             else str(c.value) for c in row] for row in ws.iter_rows()]


def _styles(ws):
    out = []
    for row in ws.iter_rows():
        for c in row:
            if c.value is not None:
                out.append((c.coordinate, c.font.b,
                            c.font.color.rgb if c.font.color else None,
                            c.fill.fgColor.rgb if (c.fill and c.fill.fgColor) else None,
                            c.alignment.wrap_text))
    return out


def _widths(ws):
    return {k: v.width for k, v in ws.column_dimensions.items()}


def _heights(ws):
    return {k: v.height for k, v in ws.row_dimensions.items()}


class TestCombinedExport(unittest.TestCase):
    def setUp(self):
        self.out = tempfile.mkdtemp(prefix="checkip_combined_")

    def tearDown(self):
        shutil.rmtree(self.out, ignore_errors=True)

    def _export_both_ways(self, log_entries=None, highlight=None, filt=None):
        """Xuat theo duong CU (2 file roi) va duong MOI (1 file 2 sheet)."""
        p_rule = export_to_excel(self.out, _rules(), MATCH, GroupResolver(_addr(), _grp()),
                                  _svc(), {}, log_entries=log_entries)
        p_nat = export_nat_to_excel(self.out, _nat_rules(), GroupResolver(_addr(), _grp()),
                                     _svc(), {}, highlight_ips=highlight, filter_ips=filt)
        p_comb = export_combined_to_excel(
            self.out, rules=_rules(), match_results=MATCH,
            resolver=GroupResolver(_addr(), _grp()),
            service_objects=_svc(), service_groups={},
            nat_rules=_nat_rules(), nat_resolver=GroupResolver(_addr(), _grp()),
            nat_service_objects=_svc(), nat_service_groups={},
            log_entries=log_entries, highlight_ips=highlight, filter_ips=filt)
        return p_rule, p_nat, p_comb

    def _assert_sheet_identical(self, ws_old, ws_new, label):
        self.assertEqual(_dump(ws_old), _dump(ws_new), label + ": noi dung khac")
        self.assertEqual(_styles(ws_old), _styles(ws_new), label + ": font/mau/fill/wrap khac")
        self.assertEqual(_widths(ws_old), _widths(ws_new), label + ": do rong cot khac")
        self.assertEqual(_heights(ws_old), _heights(ws_new), label + ": chieu cao dong khac")

    def test_dung_2_sheet_dung_ten(self):
        _, _, p_comb = self._export_both_ways(highlight={'10.1.1.1'})
        wb = openpyxl.load_workbook(p_comb)
        self.assertEqual(wb.sheetnames, [RULE_SHEET_TITLE, NAT_SHEET_TITLE])

    def test_chi_sinh_1_file_ten_rule_nat(self):
        _, _, p_comb = self._export_both_ways(highlight={'10.1.1.1'})
        self.assertTrue(os.path.basename(p_comb).startswith("rule_nat_"),
                        os.path.basename(p_comb))
        self.assertTrue(p_comb.endswith(".xlsx"))

    def test_che_do_search_doi_ten_file(self):
        _, _, p_comb = self._export_both_ways(filt={'10.1.1.1'})
        self.assertTrue(os.path.basename(p_comb).startswith("rule_nat_search_"),
                        os.path.basename(p_comb))

    def test_tung_sheet_giong_het_file_roi(self):
        p_rule, p_nat, p_comb = self._export_both_ways(highlight={'10.1.1.1'})
        wb_r = openpyxl.load_workbook(p_rule)
        wb_n = openpyxl.load_workbook(p_nat)
        wb_c = openpyxl.load_workbook(p_comb)
        self._assert_sheet_identical(wb_r.worksheets[0], wb_c[RULE_SHEET_TITLE], "Sheet Rule")
        self._assert_sheet_identical(wb_n[NAT_SHEET_TITLE], wb_c[NAT_SHEET_TITLE], "Sheet NAT")

    def test_giu_nguyen_khi_co_file_log_doi_chieu(self):
        """3 cot Log duoc chen them van phai y het file rule_*.xlsx roi."""
        logs = [LogEntry('10.1.1.1', '10.2.2.10', '443')]
        p_rule, _, p_comb = self._export_both_ways(log_entries=logs)
        wb_r = openpyxl.load_workbook(p_rule)
        wb_c = openpyxl.load_workbook(p_comb)
        self._assert_sheet_identical(wb_r.worksheets[0], wb_c[RULE_SHEET_TITLE],
                                      "Sheet Rule (co File Log)")
        # BAN PANORAMA (III.7): cot "Vi tri Rule" duoc chen NGAY SAU "Name Rule",
        # roi moi toi 3 cot Log doi chieu -> thu tu header khac ban Firewall standalone.
        headers = [c.value for c in wb_c[RULE_SHEET_TITLE][1]][:5]
        self.assertEqual(headers, ['Name Rule', 'Vi tri Rule',
                                    'Log Source IP', 'Log Dest IP', 'Log Port'])

    def test_search_mode_sheet_nat_van_giong_file_roi(self):
        p_rule, p_nat, p_comb = self._export_both_ways(filt={'10.1.1.1'})
        wb_n = openpyxl.load_workbook(p_nat)
        wb_c = openpyxl.load_workbook(p_comb)
        self._assert_sheet_identical(wb_n[NAT_SHEET_TITLE], wb_c[NAT_SHEET_TITLE],
                                      "Sheet NAT (Search)")

    def test_1_phan_thi_van_xuat_file_rieng_nhu_cu(self):
        """Chi Rule hoac chi NAT -> giu nguyen ten/file cu, khong doi gi."""
        p_rule = export_to_excel(self.out, _rules(), MATCH, GroupResolver(_addr(), _grp()),
                                  _svc(), {})
        self.assertTrue(os.path.basename(p_rule).startswith("rule_"))
        self.assertFalse(os.path.basename(p_rule).startswith("rule_nat"))
        self.assertEqual(openpyxl.load_workbook(p_rule).sheetnames, ["Sheet1"])

        p_nat = export_nat_to_excel(self.out, _nat_rules(), GroupResolver(_addr(), _grp()),
                                     _svc(), {})
        self.assertTrue(os.path.basename(p_nat).startswith("nat_"))
        self.assertEqual(openpyxl.load_workbook(p_nat).sheetnames, [NAT_SHEET_TITLE])


class TestGuiRoutingStatic(unittest.TestCase):
    """Doc source gui.py (khong can tkinter): worker phai dinh tuyen dung."""

    @classmethod
    def setUpClass(cls):
        import check_ip_pan
        with open(os.path.join(os.path.dirname(check_ip_pan.__file__), "gui.py"),
                  encoding="utf-8") as f:
            cls.src = f.read()

    def test_co_nhanh_gop_file(self):
        self.assertIn("export_combined_to_excel", self.src)
        self.assertIn('nat_is_csv = (plan.get("nat_format") == "csv")', self.src)
        self.assertIn("if rule_data and nat_data and not nat_is_csv:", self.src)

    def test_tach_pipeline_khoi_export(self):
        self.assertIn("_run_rule_pipeline", self.src)
        self.assertIn("_run_nat_pipeline", self.src)
        self.assertNotIn("_do_check_ip", self.src)
        self.assertNotIn("_do_export_nat", self.src)


if __name__ == "__main__":
    unittest.main()
