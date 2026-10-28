# -*- coding: utf-8 -*-
"""
Bang ket qua: DUONG KE ngan cot, va KEO CO GIAN duoc tung cot.

Hai dau cach giua hai cot thi mat phai tu doan ranh gioi - voi o co noi dung
dai, xuong dong trong cot cua no, thi gan nhu khong doan duoc. Va be ngang co
dinh thi cot nao cung co luc qua chat hoac qua rong.

ttk.Treeview co san tro keo cot, nhung bang nay BAT BUOC la widget Text (chi
Text moi to mau duoc tung doan chu trong o). Nen phan keo phai tu lam: bang la
chu DEU nen "cot thu may" chi la phep dem ky tu.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_ip_pan import rows as rowbuild


class TestDuongKeNganCot(unittest.TestCase):
    def _hdr(self, widths=None):
        """DONG MAN HINH DAU TIEN cua dong tieu de cot.

        Tieu de dai hon be ngang cot thi no xuong dong TRONG cot cua no, nen
        chuoi tra ve co nhieu dong - moi dong deu co du duong ke. Lay dong dau
        de so vi tri ky tu cho dung.
        """
        kw = {"widths": widths} if widths else {}
        return rowbuild.layout_plain(
            [{"kind": "hdr", "cells": rowbuild.RULE_HEADERS}], **kw).splitlines()[0]

    def test_co_duong_ke_doc_that_su(self):
        self.assertEqual(self._hdr().count("│"), len(rowbuild.COL_WIDTHS) - 1)

    def test_vi_tri_duong_ke_khop_voi_chuoi_that(self):
        """`column_edges` phai noi DUNG ky tu so may, neu khong thi bam vao
        duong ke se khong bat duoc cot nao."""
        that = [i for i, ch in enumerate(self._hdr()) if ch == "│"]
        self.assertEqual(rowbuild.column_edges(), that)

    def test_doi_be_ngang_thi_duong_ke_di_theo(self):
        rong = [60] + list(rowbuild.COL_WIDTHS[1:])
        that = [i for i, ch in enumerate(self._hdr(rong)) if ch == "│"]
        self.assertEqual(rowbuild.column_edges(rong), that)
        self.assertEqual(that[0], 61)

    def test_moi_dong_van_THANG_COT_sau_khi_doi_be_ngang(self):
        rong = [8] + list(rowbuild.COL_WIDTHS[1:])
        display = rowbuild.section("rule") + [
            {"kind": "rule", "cells": tuple("x" * 30 for _ in rowbuild.COL_WIDTHS)}]
        be = {sum(len(t) for _k, t in ln["segments"])
              for ln in rowbuild.layout(display, widths=rong)}
        self.assertEqual(len(be), 1, f"cac dong lech be ngang: {be}")


if __name__ == "__main__":
    unittest.main(verbosity=2)


class TestThuGonTungMuc(unittest.TestCase):
    """Moi luot chay co the ra bon muc; muc nao dang khong quan tam thi van
    chiem cho va day muc can xem xuong duoi. Thu gon duoc la nguoi doc tu
    quyet cho nao can nhin - thay vi tool quyet thay."""

    def _display(self):
        return (rowbuild.section("rule")
                + [{"kind": "rule", "cells": tuple("x" for _ in rowbuild.COL_WIDTHS)}]
                + rowbuild.section("nat")
                + [{"kind": "nat", "cells": tuple("y" for _ in rowbuild.COL_WIDTHS)}])

    def test_mo_thi_hien_mui_ten_XUONG_va_du_dong(self):
        ra = rowbuild.ap_dung_thu_gon(self._display())
        self.assertEqual(len(ra), 6)
        self.assertTrue(rowbuild.layout_plain(ra).startswith(rowbuild.MUI_TEN_MO))

    def test_thu_gon_thi_MAT_dong_cua_muc_do_nhung_GIU_dong_tieu_de(self):
        d = self._display()
        ra = rowbuild.ap_dung_thu_gon(d, [rowbuild.khoa_muc(d[0])])
        chu = rowbuild.layout_plain(ra)
        self.assertTrue(chu.startswith(rowbuild.MUI_TEN_DONG), chu[:40])
        self.assertIn("SECURITY RULE", chu, "thu gon chu khong phai xoa dong tieu de")
        self.assertIn("NAT", chu, "thu gon muc nay lai an luon muc khac")
        self.assertEqual(len([r for r in ra if r["kind"] == "rule"]), 0)
        self.assertEqual(len([r for r in ra if r["kind"] == "nat"]), 1)

    def test_khoa_nho_theo_CHU_chu_khong_theo_chi_so_dong(self):
        a = rowbuild.khoa_muc(rowbuild.section("rule")[0])
        b = rowbuild.khoa_muc(rowbuild.section("rule")[0])
        self.assertEqual(a, b)
        self.assertNotEqual(a, rowbuild.khoa_muc(rowbuild.section("nat")[0]))

    def test_moi_dong_man_hinh_biet_no_tu_dong_ket_qua_nao(self):
        """GUI can no de biet nguoi dung vua bam vao tieu de muc nao."""
        lines = rowbuild.layout(rowbuild.ap_dung_thu_gon(self._display()))
        self.assertTrue(all("row" in ln for ln in lines))
        self.assertEqual(lines[0]["row"], 0)
        self.assertEqual(sorted({ln["row"] for ln in lines}), list(range(6)))
