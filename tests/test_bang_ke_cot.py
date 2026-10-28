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
