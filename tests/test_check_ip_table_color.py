# -*- coding: utf-8 -*-
"""
Luoi chan cho BANG KET QUA CO MAU cua tab CHECK IP.

HAI THU NGUOI VAN HANH BAO
==========================
1. "O khong lien quan (phia ben kia rule) chi con ten group/object" - ban
   10/2026 dau tien thu gon ca cum member con DUNG MOT CAI TEN. Doc mot dong
   rule ma chi thay "GRP-DC-SERVERS" thi khong tra loi duoc cau hoi ke tiep:
   "the dau ben kia la nhung IP nao?" - va lai phai mo thiet bi ra xem, dung
   viec ma tool phai lam thay.

2. "IP input mau xanh la, phan con lai mau do" - file Excel xuat ra da to mau
   nhu vay tu lau (`_runs_to_rich_text`), nhung bang TREN GIAO DIEN thi khong:
   ttk.Treeview chi to mau duoc ca mot dong. Mat mau la nguoi doc phai tu do
   mat so tung dong.

Nen bang tren giao dien doi sang widget Text, va toan bo phan tinh toan nam o
rows.py duoi dang ham thuan - test duoc o day, khong can mo cua so.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_ip_pan.core import AddressObject, AddressGroup, SecurityRule
from check_ip_pan.excel_export import _expand_entry_runs
from check_ip_pan.resolver_engine import GroupResolver
from check_ip_pan import rows as rowbuild

IP_TRA = "10.1.1.7"              # IP nguoi dung nhap
IP_KHAC = ("10.9.9.1", "10.9.9.2", "10.9.9.3")


def _host(name, ip):
    return AddressObject(name=name, kind="ip-netmask", raw_value=f"{ip}/32")


def _resolver():
    objs = {"H-TRA": _host("H-TRA", IP_TRA)}
    for i, ip in enumerate(IP_KHAC, 1):
        objs[f"H-KHAC-{i}"] = _host(f"H-KHAC-{i}", ip)
    groups = {
        "GRP-CO-IP": AddressGroup(name="GRP-CO-IP", kind="static",
                                  members=["H-TRA", "H-KHAC-1"]),
        "GRP-BEN-KIA": AddressGroup(name="GRP-BEN-KIA", kind="static",
                                    members=[f"H-KHAC-{i}" for i in (1, 2, 3)]),
    }
    return GroupResolver(objs, groups)


class TestOBenKiaVanBreakRaMember(unittest.TestCase):
    """Dung ca thu nhat nguoi van hanh bao."""

    def setUp(self):
        self.resolver = _resolver()
        self.target = {IP_TRA}

    def _runs(self, entry):
        return _expand_entry_runs(entry, self.resolver, self.target,
                                  filter_to_matched=True)

    def test_group_KHONG_lien_quan_van_hien_DU_member(self):
        runs = self._runs("GRP-BEN-KIA")
        text = "".join(t for _, t in runs)
        self.assertIn("GRP-BEN-KIA", text, "mat ten group")
        for ip in IP_KHAC:
            self.assertIn(ip, text, f"thu gon mat member {ip} cua o ben kia")

    def test_member_o_ben_kia_to_MAU_DO(self):
        kinds = {t: k for k, t in self._runs("GRP-BEN-KIA")}
        for ip in IP_KHAC:
            self.assertEqual(kinds.get(ip), "value",
                             f"{ip} khong phai 'value' (do) - sai mau")

    def test_group_CO_BAO_ip_tra_thi_chi_hien_dung_member_do(self):
        """Khong duoc sua qua tay: phia KHOP van phai gon - ten group + dung
        gia tri dang tra, khong keo ca danh sach member ra."""
        runs = self._runs("GRP-CO-IP")
        text = "".join(t for _, t in runs)
        self.assertIn("GRP-CO-IP", text)
        self.assertIn(IP_TRA, text)
        self.assertNotIn(IP_KHAC[0], text,
                         "o khop lai keo ca member khong lien quan ra")

    def test_ip_dang_tra_to_MAU_XANH_LA(self):
        kinds = {t: k for k, t in self._runs("GRP-CO-IP")}
        self.assertEqual(kinds.get(IP_TRA), "value_matched",
                         "IP input khong duoc to xanh la")

    def test_object_le_cung_dung_luat_mau(self):
        self.assertEqual({t: k for k, t in self._runs("H-TRA")}.get(IP_TRA),
                         "value_matched")
        self.assertEqual({t: k for k, t in self._runs("H-KHAC-1")}.get(IP_KHAC[0]),
                         "value")


class TestBangChuCoMau(unittest.TestCase):
    """Dung ca thu hai: bang tren giao dien phai mang theo mau."""

    def _display(self):
        resolver = _resolver()
        rule = SecurityRule(
            index=1, name="R-TEST", uuid="u1",
            from_zones=["trust"], to_zones=["untrust"],
            source=["GRP-CO-IP"], destination=["GRP-BEN-KIA"],
            application=["any"], service=["any"], action="allow", disabled=False)
        return rowbuild.rule_rows([rule], {IP_TRA: [(1, "source")]}, resolver,
                                  {}, {}, target_ips={IP_TRA})

    def test_dong_rule_mang_theo_runs_co_mau(self):
        row = self._display()[0]
        kinds = {t: k for cell in row["runs"] for k, t in cell}
        self.assertEqual(kinds.get(IP_TRA), "value_matched")
        self.assertEqual(kinds.get(IP_KHAC[1]), "value")

    def test_layout_dan_tag_mau_vao_dung_doan_chu(self):
        """Day moi la thu gui.py doc: `segments` kem tag. Mat buoc nay la bang
        van dung chu nhung TRANG LOP."""
        lines = rowbuild.layout(self._display())
        kinds = {t.strip(): k for ln in lines for k, t in ln["segments"] if t.strip()}
        self.assertEqual(kinds.get(IP_TRA), "value_matched",
                         "bang khong to xanh la IP dang tra")
        self.assertEqual(kinds.get(IP_KHAC[1]), "value",
                         "bang khong to do member phia ben kia")

    def test_cells_chu_tron_van_con_cho_ai_can(self):
        row = self._display()[0]
        self.assertEqual(row["cells"][0], "R-TEST")
        self.assertEqual(len(row["cells"]), rowbuild.NCOL)

    def test_layout_cac_dong_THANG_COT(self):
        display = rowbuild.section("rule") + self._display()
        lines = rowbuild.layout(display)
        widths = {sum(len(t) for _, t in ln["segments"]) for ln in lines}
        self.assertEqual(len(widths), 1, f"cac dong lech be ngang: {widths}")

    def test_layout_KHONG_cat_mat_chu_nao(self):
        """O dai thi xuong dong TRONG cot cua no, khong duoc cat cut."""
        text = rowbuild.layout_plain(self._display())
        for ip in (IP_TRA,) + IP_KHAC[1:]:
            self.assertIn(ip, text.replace("\n", " "), f"bang cat mat {ip}")

    def test_tag_ca_dong_dung_cho_tung_loai(self):
        self.assertEqual(rowbuild.row_tag({"kind": "section"}), "section")
        self.assertEqual(rowbuild.row_tag({"kind": "rule", "disabled": True}), "off")
        self.assertEqual(rowbuild.row_tag({"kind": "rule", "disabled": False}), "")
        self.assertEqual(rowbuild.row_tag({"kind": "log", "ok": False}), "no")

    def test_chi_dem_dong_DU_LIEU(self):
        self.assertFalse(rowbuild.is_data_row({"kind": "hdr"}))
        self.assertTrue(rowbuild.is_data_row({"kind": "rule"}))


class TestWrapRuns(unittest.TestCase):
    def test_giu_dung_loai_cua_tung_doan(self):
        runs = [("name", "GRP-A"), ("text", " ("), ("value_matched", "10.0.0.1"),
                ("text", ")")]
        lines = rowbuild.wrap_runs(runs, 10)
        kinds = {t: k for ln in lines for k, t in ln}
        self.assertEqual(kinds.get("10.0.0.1"), "value_matched")

    def test_khong_dong_nao_vuot_be_ngang(self):
        runs = [("value", "10.0.0.%d" % i) for i in range(1, 30)]
        for ln in rowbuild.wrap_runs(runs, 12):
            self.assertLessEqual(sum(len(t) for _, t in ln), 12)

    def test_tu_dai_hon_ca_cot_thi_cat_cung_chu_khong_pha_cot(self):
        lines = rowbuild.wrap_runs([("name", "A" * 40)], 10)
        self.assertEqual(len(lines), 4)
        self.assertEqual("".join(t for ln in lines for _, t in ln), "A" * 40)

    def test_o_rong_van_ra_dung_1_dong(self):
        self.assertEqual(rowbuild.wrap_runs([], 10), [[]])


if __name__ == "__main__":
    unittest.main(verbosity=2)
