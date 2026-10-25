# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_b5_b8_refinements.py).
"""
"""
B5 + B8 (10/2026 - CHECK RULE): 3 diem tinh chinh con lai, deu la "ket luan dung
nhung CON SO / PHAM VI chua chinh xac".

B5 - `_find_blocking_deny_rule()` chua xet ZONE.
  Ham nay dung `_side_all_for_shadow` (chi xet dia chi) + `_ports_covered_for_shadow`
  (chi xet port). Mot rule deny `trust -> untrust` KHONG he chan luong di tu
  `vpn`, nhung tool van canh bao "BI CHAN TRUOC". Huong sai nay **an toan**
  (canh bao thua chu khong bo sot) nhung lam nguoi doc mat long tin vao canh bao -
  va mot canh bao bi coi la nhieu thi lan sau no that cung bi bo qua.
  Ban va: bo qua deny co `_zone_verdict(...) == ZONE_MISMATCH`. CHI bo qua khi
  zone duoc xac dinh CHAC CHAN (`mismatch`); `unknown` thi VAN canh bao (giu
  nguyen huong an toan - khong biet thi phai canh bao).

B8b - blast radius dem theo `total_address_count()` (KHONG khu trung lap).
  Mot field co 2 object chong lan nhau (vd `10.0.0.0/24` va `10.0.0.5`) bi dem
  thanh 256 + 1 = 257 dia chi, trong khi that ra chi 256. Con so cao hon thuc te.
  Uoc luong cao thi "an toan" cho nguoi phe duyet, nhung mot con so SAI thi lam
  mat long tin vao toan bo dong canh bao. `union_address_count()` da ton tai san
  (dung cho exact-scope) va da khu trung lap - chi can dung no.

B8c - chua in blast radius cho tier LIVE_MATCH.
  Tu FIX v3, LIVE_MATCH co the con thieu Source/Dest/Port that su (chi can 1 combo
  allow la dung som), nen dong LIVE_MATCH VAN co the hien "+ ADD SOURCE" - ma lai
  khong co dong hau qua di kem. Dong nao co "+ ADD" thi phai co hau qua.
"""

import ipaddress
import unittest

from check_rule_pan.core import (AddressObject, AddressGroup, ServiceObject,
                             SecurityRule, parse_ip_token, parse_interface_subnets,
                             parse_zones, parse_static_routes)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex, build_zone_lookup
from check_rule_pan.matcher import build_rule_infos, classify_row, _blast_radius_text
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter
import xml.etree.ElementTree as ET


def _ip(s):
    return int(ipaddress.ip_address(s))


XML_ZONE = """<config><devices><entry name="localhost.localdomain">
  <network><interface><ethernet>
    <entry name="ethernet1/1"><layer3><ip><entry name="10.10.10.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/2"><layer3><ip><entry name="192.168.50.1/24"/></ip></layer3></entry>
    <entry name="ethernet1/3"><layer3><ip><entry name="10.20.20.1/24"/></ip></layer3></entry>
  </ethernet></interface></network>
  <vsys><entry name="vsys1"><zone>
    <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
    <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    <entry name="vpn"><network><layer3><member>ethernet1/3</member></layer3></network></entry>
  </zone></entry></vsys>
</entry></devices></config>"""


def _zl():
    root = ET.fromstring(XML_ZONE)
    return build_zone_lookup(parse_interface_subnets(root),
                             parse_zones(root.find("devices/entry/vsys/entry")),
                             routes=parse_static_routes(root))


SRC_VPN, DST = "10.20.20.11", "192.168.50.21"


def _row(src=SRC_VPN, dst=DST, port=443):
    return RequestRow(row_number=2, source_tokens=[parse_ip_token(src)],
                      dest_tokens=[parse_ip_token(dst)],
                      port_tokens=[(port, port, "tcp")], extra_values=[],
                      raw_source=src, raw_dest=dst, raw_port=str(port))


class TestB5_DenyPhaiXetZone(unittest.TestCase):
    def _deny(self, from_zones, to_zones):
        return SecurityRule(index=1, name="R-DENY", source=["any"], destination=["any"],
                            service=["any"], application=["any"], action="deny",
                            disabled=False, from_zones=list(from_zones),
                            to_zones=list(to_zones))

    def _classify(self, deny):
        ris = build_rule_infos([deny], GroupResolver({}, {}), ServiceResolver({}, {}))
        return classify_row(_row(), ris, DeviceIndex(), zone_lookup=_zl())

    def test_deny_lech_zone_thi_KHONG_canh_bao(self):
        """Deny trust->untrust KHONG chan luong di tu vpn."""
        res = self._classify(self._deny(["trust"], ["untrust"]))
        self.assertIsNone(res.blocking_deny_rule,
                          "canh bao thua: deny nay khong he chan luong tu vpn")

    def test_deny_dung_zone_thi_VAN_canh_bao(self):
        res = self._classify(self._deny(["vpn"], ["untrust"]))
        self.assertEqual(res.blocking_deny_rule, "R-DENY")

    def test_deny_zone_any_VAN_canh_bao(self):
        res = self._classify(self._deny(["any"], ["any"]))
        self.assertEqual(res.blocking_deny_rule, "R-DENY")

    def test_zone_KHONG_xac_dinh_duoc_thi_VAN_canh_bao(self):
        """Giu nguyen huong an toan: khong biet zone thi PHAI canh bao."""
        ris = build_rule_infos([self._deny(["trust"], ["untrust"])],
                               GroupResolver({}, {}), ServiceResolver({}, {}))
        res = classify_row(_row(), ris, DeviceIndex(), zone_lookup=[])
        self.assertEqual(res.blocking_deny_rule, "R-DENY",
                         "khong co bang zone -> khong duoc im lang bo qua deny")


class TestB8b_BlastRadiusKhuTrungLap(unittest.TestCase):
    def test_object_chong_lan_khong_bi_dem_hai_lan(self):
        objs = {
            "NET-24": AddressObject("NET-24", "wide", start=_ip("10.0.0.0"),
                                    end=_ip("10.0.0.255"), display="10.0.0.0/24"),
            "H-5": AddressObject("H-5", "host", start=_ip("10.0.0.5"),
                                 end=_ip("10.0.0.5"), display="10.0.0.5"),
            "SRC-OLD": AddressObject("SRV-OLD", "host", start=_ip("172.16.0.1"),
                                     end=_ip("172.16.0.1"), display="172.16.0.1"),
        }
        grps = {"GR": AddressGroup("GR", members=["NET-24", "H-5"])}
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        rule = SecurityRule(index=5, name="R", source=["SRC-OLD"], destination=["GR"],
                            service=["SVC-443"], application=["any"], action="allow",
                            disabled=False, from_zones=["any"], to_zones=["any"])
        ri = build_rule_infos([rule], GroupResolver(objs, grps),
                              ServiceResolver(svc, {}))[0]
        txt = _blast_radius_text(ri, "source")
        self.assertIn("256", txt,
                      f"phai la 256 (da khu trung lap), khong phai 257: {txt}")
        self.assertNotIn("257", txt)


class TestB8c_BlastRadiusChoLiveMatch(unittest.TestCase):
    def test_dong_co_ADD_thi_phai_co_dong_hau_qua(self):
        """Khong tao ca LIVE_MATCH that (can API) - kiem truc tiep hop dong:
        moi dong co '+ ADD' trong o Name Rule thi phai co blast_radius."""
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.0.0.1"),
                                     end=_ip("10.0.0.1"), display="10.0.0.1"),
            "D1": AddressObject("D1", "host", start=_ip(DST), end=_ip(DST), display=DST),
        }
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        rule = SecurityRule(index=5, name="R-TOP2", source=["SRV-OLD"],
                            destination=["D1"], service=["SVC-443"],
                            application=["any"], action="allow", disabled=False,
                            from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([rule], GroupResolver(objs, {}), ServiceResolver(svc, {}))
        res = classify_row(_row(src="10.9.9.9"), ris, DeviceIndex())
        text = "".join(getattr(b, "text", "") or ""
                       for b in exporter.build_name_rule_cell(res)[0])
        if "ADD " in text.upper():
            self.assertTrue(res.blast_radius,
                            "dong co '+ ADD' ma khong co dong hau qua di kem")

    def test_live_match_duoc_tinh_blast_radius(self):
        """Gia lap mot RowResult tier=LIVE_MATCH con thieu Source -> phai co
        blast_radius (tu FIX v3, LIVE_MATCH dung som nen VAN co the thieu that)."""
        from check_rule_pan.matcher import _tag_blast_radius
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.0.0.1"),
                                     end=_ip("10.0.0.1"), display="10.0.0.1"),
            "D1": AddressObject("D1", "host", start=_ip(DST), end=_ip(DST), display=DST),
        }
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        rule = SecurityRule(index=5, name="R-LM", source=["SRV-OLD"], destination=["D1"],
                            service=["SVC-443"], application=["any"], action="allow",
                            disabled=False, from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([rule], GroupResolver(objs, {}), ServiceResolver(svc, {}))
        res = classify_row(_row(src="10.9.9.9"), ris, DeviceIndex())
        res.tier = "LIVE_MATCH"
        res.rule = rule
        res.blast_radius = None
        res = _tag_blast_radius(res, ris)
        self.assertTrue(res.blast_radius,
                        "tier LIVE_MATCH cung phai duoc tinh pham vi anh huong")


class TestB8a_NguongOverlyTrenGUI(unittest.TestCase):
    """2 o nhap moi phai THAT SU duoc dung, khong phai UI chet - va phai duoc doc
    tren MAIN THREAD roi truyen qua tham so (luat Tkinter cua repo nay)."""

    def _src(self):
        """Doc THEO DUONG DAN, khong import module.

        `import check_audit_pan.gui` keo theo `import tkinter`, ma python3.13 trong
        container KHONG co tkinter -> 3 ca nay bao ERROR tren 3.13 (da bi dung 1
        lan). Test nay chi can doc ma nguon nen khong co ly do gi phai import."""
        import os
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        with open(os.path.join(root, "check_audit_pan", "gui.py"), encoding="utf-8") as f:
            return f.read()

    def test_2_o_nhap_duoc_doc_trong_on_check(self):
        import ast
        tree = ast.parse(self._src())
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_on_check"), None)
        self.assertIsNotNone(fn, "khong tim thay _on_check")
        body = ast.dump(fn)
        for ten in ("var_overly_addr", "var_overly_port"):
            self.assertIn(ten, body,
                          f"{ten} khong duoc doc trong _on_check -> o nhap la UI chet")

    def test_KHONG_doc_tk_var_tu_worker(self):
        """Doc tk.StringVar tu worker thread la loi da tung lam mat trang ca luot
        chay cua CHECK RULE (req_file_var). Khong duoc tai pham."""
        import ast
        tree = ast.parse(self._src())
        fn = next((n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "_check_worker"), None)
        self.assertIsNotNone(fn)
        body = ast.dump(fn)
        for ten in ("var_overly_addr", "var_overly_port", "var_unused_threshold"):
            self.assertNotIn(ten, body,
                             f"_check_worker doc {ten} tu worker thread - vi pham "
                             f"luat Tkinter cua repo")

    def test_nguong_di_den_dung_detector(self):
        import ast
        tree = ast.parse(self._src())
        found = False
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") == "find_overly_permissive_by_size":
                kw = {k.arg for k in n.keywords}
                self.assertIn("addr_threshold", kw)
                self.assertIn("port_threshold", kw)
                found = True
        self.assertTrue(found, "khong thay loi goi find_overly_permissive_by_size")


if __name__ == "__main__":
    unittest.main(verbosity=2)
