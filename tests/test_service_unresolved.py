# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_service_unresolved.py). Luat nghiep vu 2 ban GIONG 100%
(PHAN 0) nen noi dung test giong 100%, chi doi ten package.
"""
"""
B3 (10/2026 - CHECK RULE): lo hong cung ho voi S1 nhung o phia SERVICE.

`ResolvedService` **khong co field `unresolved`** nao ca. Ba duong tra ve 0 PORT
ma khong danh dau gi: service/group **khong tim thay**, **circular reference**, va
service object co nhung **khong co dai port doc duoc**. Khac voi S1 (chi lech 1
huong), cho nay lech **CA HAI HUONG**:

  HUONG 1 (an toan, nhung sai): rule bi coi la IT PORT hon thuc te -> request bi
  bao thieu port -> tool khuyen "+ ADD PORT" cho mot port ma rule **da cho phep**.
  Admin them 1 port object trung lap vao rule. Khong cap quyen thua, nhung lam
  rulebase ban them va lan audit sau kho doc hon.

  HUONG 2 (NGUY HIEM): `_ports_covered_for_shadow()` duoc dung cho shadow-check va
  cho `_find_blocking_deny_rule()` (S5). Ham do CO Y coi `service=any` la "cover
  het" de **khong bo sot rui ro bi che khuat**. Nhung mot rule deny co service la
  group KHONG resolve duoc thi ra 0 port -> bi coi la "khong cover port nao" ->
  tool **BO SOT** canh bao "co deny chan truoc". Day la huong sai nguy hiem: admin
  tao rule moi, dat duoi mot deny ma tool khong he canh bao.

Ban va:
  - `ResolvedService` co `unresolved` + populate o ca 3 duong.
  - TOP1.1 "+ ADD PORT": service khong do duoc -> KHONG khuyen them port, bao cao
    tuong minh qua `untrusted_scope` (cung co che S1 da dung).
  - `_ports_covered_for_shadow()`: service khong do duoc -> coi nhu CO THE cover,
    y het cach no doi xu voi `is_any`, de khong bo sot rui ro.
"""

import unittest

from check_rule_pan.core import ServiceObject, ServiceGroup, SecurityRule, AddressObject, parse_ip_token
from check_rule_pan.resolver import GroupResolver, ServiceResolver, ResolvedService
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import (build_rule_infos, classify_row,
                                _ports_covered_for_shadow)
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter
import ipaddress


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC, DST = "10.1.1.1", "10.2.2.2"


def _objs():
    return {
        "H-S": AddressObject("H-S", "host", start=_ip(SRC), end=_ip(SRC), display=SRC),
        "H-D": AddressObject("H-D", "host", start=_ip(DST), end=_ip(DST), display=DST),
    }


def _row(port=443):
    return RequestRow(row_number=2, source_tokens=[parse_ip_token(SRC)],
                      dest_tokens=[parse_ip_token(DST)],
                      port_tokens=[(port, port, "tcp")], extra_values=[],
                      raw_source=SRC, raw_dest=DST, raw_port=str(port))


class TestResolvedServiceCoDanhDauUnresolved(unittest.TestCase):
    def test_service_khong_tim_thay(self):
        sr = ServiceResolver({}, {})
        r = sr.resolve_name("SVC-KHONG-TON-TAI")
        self.assertIn("SVC-KHONG-TON-TAI", r.unresolved,
                      "service khong tim thay phai bi danh dau, khong duoc im lang 0 port")

    def test_circular_reference(self):
        grps = {"SG-A": ServiceGroup("SG-A", members=["SG-B"]),
                "SG-B": ServiceGroup("SG-B", members=["SG-A"])}
        r = ServiceResolver({}, grps).resolve_name("SG-A")
        self.assertTrue(r.unresolved, "circular reference phai bi danh dau")

    def test_service_object_khong_co_dai_port_doc_duoc(self):
        objs = {"SVC-RONG": ServiceObject("SVC-RONG", "unknown", "", ranges=[])}
        r = ServiceResolver(objs, {}).resolve_name("SVC-RONG")
        self.assertIn("SVC-RONG", r.unresolved)

    def test_group_lan_truyen_unresolved_len_tren(self):
        objs = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        grps = {"SG": ServiceGroup("SG", members=["SVC-443", "SVC-THIEU"])}
        r = ServiceResolver(objs, grps).resolve_name("SG")
        self.assertIn("SVC-THIEU", r.unresolved,
                      "group phai mang theo unresolved cua member")
        self.assertTrue(r.covers("tcp", 443), "phan resolve duoc van phai dung")

    def test_service_sach_thi_khong_danh_dau_gi(self):
        objs = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        self.assertEqual(ServiceResolver(objs, {}).resolve_name("SVC-443").unresolved, set())


class TestHuong2_KhongBoSotDenyChanTruoc(unittest.TestCase):
    """Huong sai NGUY HIEM: bo sot canh bao "co deny chan truoc"."""

    def test_ports_covered_for_shadow_coi_unresolved_la_CO_THE_cover(self):
        r = ResolvedService()
        r.unresolved.add("SG-KHONG-DOC-DUOC")
        self.assertTrue(_ports_covered_for_shadow(r, [(443, 443, "tcp")]),
                        "service khong do duoc phai duoc coi la CO THE cover - y het "
                        "cach ham nay doi xu voi is_any - de khong bo sot rui ro")

    def test_van_khong_cover_khi_service_that_su_hep(self):
        """Doi chung: service doc duoc va KHONG chua port do thi van la khong cover."""
        objs = {"SVC-80": ServiceObject("SVC-80", "tcp", "80", ranges=[(80, 80)])}
        r = ServiceResolver(objs, {}).resolve_name("SVC-80")
        self.assertFalse(_ports_covered_for_shadow(r, [(443, 443, "tcp")]))

    def test_deny_co_service_group_khong_doc_duoc_VAN_duoc_canh_bao(self):
        """Kich ban that: rule deny dung service group ma parser khong doc duoc
        (vd group nam o vsys khac). Truoc ban va: tool im lang."""
        objs = _objs()
        deny = SecurityRule(index=1, name="R-DENY-SVC-THIEU", source=["any"],
                            destination=["any"], service=["SG-KHONG-CO"],
                            application=["any"], action="deny", disabled=False,
                            from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([deny], GroupResolver(objs, {}), ServiceResolver({}, {}))
        res = classify_row(_row(), ris, DeviceIndex())
        self.assertEqual(res.blocking_deny_rule, "R-DENY-SVC-THIEU",
                         "bo sot canh bao deny vi service cua no khong resolve duoc")


class TestHuong1_KhongKhuyenThemPortDuThua(unittest.TestCase):
    def test_TOP1_1_khong_khuyen_them_port_khi_service_khong_do_duoc(self):
        """Source/Dest khop dung, service cua rule KHONG do duoc -> khong the
        ket luan "thieu port", nen khong duoc khuyen "+ ADD PORT"."""
        objs = _objs()
        rule = SecurityRule(index=5, name="R-SVC-THIEU", source=["H-S"],
                            destination=["H-D"], service=["SG-KHONG-CO"],
                            application=["any"], action="allow", disabled=False,
                            from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([rule], GroupResolver(objs, {}), ServiceResolver({}, {}))
        res = classify_row(_row(), ris, DeviceIndex())
        self.assertNotEqual(res.tier, "TOP1.1",
                            "khong do duoc service thi khong duoc ket luan 'chi thieu port'")
        text = "".join(getattr(b, "text", "") or ""
                       for b in exporter.build_name_rule_cell(res)[0])
        self.assertNotIn("ADD PORT", text.upper())
        self.assertTrue(res.untrusted_scope, "phai bao cao tuong minh ly do")
        self.assertIn("SG-KHONG-CO", res.untrusted_scope_detail or "")

    def test_service_sach_thieu_port_van_la_TOP1_1(self):
        """Doi chung non-regression: service doc duoc va that su thieu port."""
        objs = _objs()
        svc = {"SVC-80": ServiceObject("SVC-80", "tcp", "80", ranges=[(80, 80)])}
        rule = SecurityRule(index=5, name="R-80", source=["H-S"], destination=["H-D"],
                            service=["SVC-80"], application=["any"], action="allow",
                            disabled=False, from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([rule], GroupResolver(objs, {}), ServiceResolver(svc, {}))
        res = classify_row(_row(443), ris, DeviceIndex())
        self.assertEqual(res.tier, "TOP1.1")


if __name__ == "__main__":
    unittest.main(verbosity=2)
