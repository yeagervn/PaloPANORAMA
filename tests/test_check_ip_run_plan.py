# -*- coding: utf-8 -*-
"""
Test cho thay doi 10/2026 (CHECK IP): gop nut "Check" (muc 3) + "Export NAT" thanh
1 NUT DUY NHAT "Check / Export", va siet lai phan kiem tra input.

Luat (dung yeu cau nguoi dung):
  - Muc 2/3 co du lieu  -> chay Check Rule. De trong -> BO QUA, khong phai loi.
  - Muc 4 duoc chon     -> chay Export NAT. De trong -> BO QUA, khong phai loi.
  - Nhap ca 2           -> chay CA HAI trong 1 luot.
  - Khong gi ca         -> chan lai + noi ro phai nhap gi.
  - O co chu nhung KHONG co IP hop le -> chan lai (khong im lang bo qua).

Test ham THUAN TUY core.build_run_plan()/describe_run_plan() nen KHONG can tkinter.
"""

import os
import tempfile
import unittest

from check_ip_pan.core import build_run_plan, describe_run_plan, DEFAULT_WORKERS


def plan_of(ip_text="", logfile="", nat_full=False, nat_ip_text="",
            nat_format="xlsx", workers=30, where_on=False, where_names=""):
    return build_run_plan(ip_text, logfile, nat_full, nat_ip_text, nat_format,
                          workers, where_on, where_names)


class TestOnlyRule(unittest.TestCase):
    def test_chi_muc_2_co_ip(self):
        plan, errors = plan_of(ip_text="10.1.1.1\n10.1.1.2")
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_rule"])
        self.assertFalse(plan["do_nat"])
        self.assertEqual(plan["valid_ips"], ["10.1.1.1", "10.1.1.2"])

    def test_chi_muc_3_co_file_log(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            plan, errors = plan_of(logfile=path)
            self.assertEqual(errors, [])
            self.assertTrue(plan["do_rule"])
            self.assertFalse(plan["do_nat"])
        finally:
            os.unlink(path)

    def test_range_o_muc_2_duoc_no_ra(self):
        plan, errors = plan_of(ip_text="10.1.1.1 - 10.1.1.4")
        self.assertEqual(errors, [])
        self.assertEqual(plan["valid_ips"],
                         ["10.1.1.1", "10.1.1.2", "10.1.1.3", "10.1.1.4"])


class TestOnlyNat(unittest.TestCase):
    def test_nat_full_khong_can_nhap_ip(self):
        plan, errors = plan_of(nat_full=True)
        self.assertEqual(errors, [])
        self.assertFalse(plan["do_rule"])
        self.assertTrue(plan["do_nat"])
        self.assertEqual(plan["nat_filter_ips"], [])

    def test_nat_search_co_ip(self):
        plan, errors = plan_of(nat_full=False, nat_ip_text="10.9.9.9")
        self.assertEqual(errors, [])
        self.assertFalse(plan["do_rule"])
        self.assertTrue(plan["do_nat"])
        self.assertEqual(plan["nat_filter_ips"], ["10.9.9.9"])
        self.assertEqual(plan["nat_highlight_ips"], [])

    def test_nat_full_co_ip_thi_ip_la_highlight(self):
        plan, errors = plan_of(nat_full=True, nat_ip_text="10.9.9.9")
        self.assertEqual(errors, [])
        self.assertEqual(plan["nat_highlight_ips"], ["10.9.9.9"])
        self.assertEqual(plan["nat_filter_ips"], [])


class TestBoth(unittest.TestCase):
    def test_nhap_ca_2_chay_ca_2(self):
        plan, errors = plan_of(ip_text="10.1.1.1", nat_full=False, nat_ip_text="10.9.9.9")
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_rule"])
        self.assertTrue(plan["do_nat"])

    def test_muc_2_va_nat_full(self):
        plan, errors = plan_of(ip_text="10.1.1.1", nat_full=True)
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_rule"] and plan["do_nat"])


class TestBlocked(unittest.TestCase):
    def test_khong_nhap_gi_ca(self):
        plan, errors = plan_of()
        self.assertTrue(errors)
        self.assertIn("Chua co gi de chay", errors[-1])
        self.assertFalse(plan["do_rule"])
        self.assertFalse(plan["do_nat"])

    def test_muc_2_co_chu_nhung_khong_ip_nao_hop_le(self):
        """Khong duoc im lang bo qua: nguoi dung dinh tim that nhung go sai."""
        plan, errors = plan_of(ip_text="abc\nxyz")
        self.assertTrue(any("Muc 2" in e for e in errors))

    def test_muc_4_co_chu_nhung_khong_ip_nao_hop_le(self):
        plan, errors = plan_of(nat_full=False, nat_ip_text="khong-phai-ip")
        self.assertTrue(any("Muc 4" in e for e in errors))

    def test_file_log_khong_ton_tai(self):
        plan, errors = plan_of(logfile="/khong/co/that/log.xlsx")
        self.assertTrue(any("Muc 3" in e and "khong tim thay" in e for e in errors))

    def test_file_log_sai_dinh_dang(self):
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
            path = f.name
        try:
            plan, errors = plan_of(logfile=path)
            self.assertTrue(any("Muc 3" in e and ".xlsx" in e for e in errors))
        finally:
            os.unlink(path)

    def test_ip_le_te_sai_van_chay_duoc(self):
        """Con IT NHAT 1 IP hop le -> van chay, dong sai chi ghi log."""
        plan, errors = plan_of(ip_text="10.1.1.1\nabc")
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_rule"])
        self.assertEqual(plan["valid_ips"], ["10.1.1.1"])
        self.assertEqual(plan["invalid_ips"], ["abc"])


class TestWorkerClamp(unittest.TestCase):
    def test_kep_trong_khoang_20_50(self):
        self.assertEqual(plan_of(nat_full=True, workers=5)[0]["worker_count"], 20)
        self.assertEqual(plan_of(nat_full=True, workers=999)[0]["worker_count"], 50)
        self.assertEqual(plan_of(nat_full=True, workers=37)[0]["worker_count"], 37)

    def test_gia_tri_rac_ve_mac_dinh(self):
        got = plan_of(nat_full=True, workers="abc")[0]["worker_count"]
        self.assertEqual(got, max(20, min(50, DEFAULT_WORKERS)))


class TestDescribe(unittest.TestCase):
    def test_mo_ta_tung_truong_hop(self):
        self.assertEqual(describe_run_plan(plan_of()[0]),
                         "Chua co gi de chay (xem muc 2/3/4/5)")
        self.assertEqual(describe_run_plan(plan_of(ip_text="10.1.1.1")[0]),
                         "Se chay: Check Rule (1 IP)")
        self.assertEqual(describe_run_plan(plan_of(nat_full=True)[0]),
                         "Se chay: Export NAT (Full)")
        self.assertEqual(
            describe_run_plan(plan_of(ip_text="10.1.1.1", nat_ip_text="10.9.9.9")[0]),
            "Se chay: Check Rule (1 IP) + Export NAT (Search 1 IP)")
        self.assertEqual(
            describe_run_plan(plan_of(ip_text="10.1.1.1", where_on=True)[0]),
            "Se chay: Check Rule (1 IP) + Check Object (1 IP)")
        self.assertEqual(
            describe_run_plan(plan_of(where_on=True, where_names="G-WEB")[0]),
            "Se chay: Check Object (1 ten object)")


class TestCheckObject(unittest.TestCase):
    """Muc 5 - Check Object (Where Used).

    Rang buoc chinh cua thiet ke: KHONG co o nhap IP thu hai. Muc 5 dung CHUNG
    danh sach IP cua muc 2, nen khong co duong nao de 2 o lech nhau roi nguoi
    doc so sai ket qua.
    """

    def test_dung_chung_danh_sach_IP_cua_muc_2(self):
        plan, errors = plan_of(ip_text="10.1.1.1\n10.1.1.2", where_on=True)
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_where"])
        self.assertEqual(plan["where_ips"], plan["valid_ips"])
        self.assertEqual(plan["where_ips"], ["10.1.1.1", "10.1.1.2"])

    def test_chay_duoc_voi_CHI_ten_object(self):
        plan, errors = plan_of(where_on=True, where_names="G-WEB, OBJ-DB")
        self.assertEqual(errors, [])
        self.assertTrue(plan["do_where"])
        self.assertFalse(plan["do_rule"])
        self.assertEqual(plan["where_names"], ["G-WEB", "OBJ-DB"])

    def test_tick_bat_ma_khong_co_gi_de_tra_thi_CHAN_LAI(self):
        """Tick roi bam Run ma lang le khong ra gi la loi te nhat cua giao dien:
        nguoi vua tick la dang mong no chay."""
        plan, errors = plan_of(where_on=True)
        self.assertFalse(plan["do_where"])
        self.assertTrue(any("Muc 5" in e for e in errors), errors)

    def test_khong_tick_thi_khong_chay_du_co_IP(self):
        plan, errors = plan_of(ip_text="10.1.1.1", where_on=False)
        self.assertEqual(errors, [])
        self.assertFalse(plan["do_where"])
        self.assertEqual(plan["where_ips"], [])

    def test_ten_object_khu_trung_lap_nhung_giu_thu_tu_go(self):
        plan, _ = plan_of(where_on=True, where_names="B, A, B, C")
        self.assertEqual(plan["where_names"], ["B", "A", "C"])

    def test_ten_object_GIU_NGUYEN_hoa_thuong(self):
        """Ten object cua PAN-OS phan biet hoa/thuong - ep chu thuong la tra
        nham object hoac bao 'khong tim thay' cho object co that."""
        plan, _ = plan_of(where_on=True, where_names="G-Web")
        self.assertEqual(plan["where_names"], ["G-Web"])

    def test_tach_duoc_ca_dau_phay_lan_xuong_dong(self):
        plan, _ = plan_of(where_on=True, where_names="A,B\nC;D")
        self.assertEqual(plan["where_names"], ["A", "B", "C", "D"])



if __name__ == "__main__":
    unittest.main()


class TestGuiWiringStatic(unittest.TestCase):
    """Kiem tra TINH (doc source, khong can tkinter): tab CHECK IP chi con DUNG 1
    nut chay, khong con sot tham chieu toi cap nut/handler cu."""

    @classmethod
    def setUpClass(cls):
        import check_ip_pan
        path = os.path.join(os.path.dirname(check_ip_pan.__file__), "gui.py")
        with open(path, encoding="utf-8") as f:
            cls.src = f.read()

    def test_chi_con_1_nut_chay(self):
        self.assertIn('text="Check / Export"', self.src)
        self.assertIn("command=self._on_run_all", self.src)
        # Nut "Check" rieng o muc 3 va nut "Export NAT" rieng da bi go bo
        self.assertNotIn('text="Check", command=', self.src)
        self.assertNotIn('text="Export NAT", command=', self.src)

    def test_khong_con_tham_chieu_cu(self):
        for stale in ("btn_check_ip", "btn_search", "_on_check_ip", "_on_export_nat",
                      "done_check_ip", "done_export_nat", "done_search",
                      "_finish_check_ip", "_finish_search"):
            self.assertNotIn(stale + "(", self.src, stale)
            self.assertNotIn("self." + stale, self.src, stale)

    def test_gui_khong_tu_chua_luat_quyet_dinh(self):
        """Luat phai nam o core.build_run_plan() de con unit-test duoc."""
        self.assertIn("build_run_plan", self.src)
        self.assertIn("describe_run_plan", self.src)
        self.assertNotIn('errors.append', self.src)
