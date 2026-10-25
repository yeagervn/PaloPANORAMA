# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_top11_service_any.py).

Luat nghiep vu cua 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%,
chi doi ten package. Neu sua 1 ben ma quen ben kia thi 2 ban se troi khoi nhau -
do la dung cai ma quy tac dong bo trong PHAN 0 muon ngan.
"""
"""
LO HONG TOP1.1 (10/2026 - CHECK RULE): TOP1.1 la tier DUY NHAT khong goi
`_service_ok_for_match()`.

Tai lieu cu ghi day la "hanh vi co san tu ban goc dang tin cay, khong phai bug"
(mục II.2.2). Do la **giai thich**, khong phai **ly do chinh dang** - 2 dang hong
rat that:

  1. Rule co `Service=any`: port **KHONG HE thieu** - rule da cho phep port do roi,
     le ra phai khop o TOP1. Loi khuyen "+ ADD PORT" thanh mot change **VO NGHIA**;
     te hon nua la no gan 1 port object vao mot rule service=any, lam rule do
     **trong co chu dich**, lan audit sau kho bat hon.
  2. Rule `service=application-default`: them port object **khong thay doi gi** ve
     pham vi duoc phep.

Tai hien 100% truoc ban va: rule `LEGACY-ANY-SVC` (Source/Dest khop DUNG request,
Service=any) -> `tier=TOP1.1`, o Name Rule in `ADD PORT: tcp/8443`.

Ban va TON TRONG luat da chot II.2.2 ("rule service=any KHONG BAO GIO duoc lam ket
qua hop le"): KHONG bien rule do thanh "da duoc phep" mau xanh, ma de dong di tiep
xuong cac tier duoi y nhu rule do khong ton tai, DONG THOI noi ro bang 1 dong
THONG TIN rang traffic do thuc te da duoc phep boi 1 rule qua rong -> admin di don
rule do o tab CHECK AUDIT, chu khong them port vao no.
"""

import ipaddress
import unittest

from check_rule_pan.core import AddressObject, ServiceObject, SecurityRule, parse_ip_token
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC, DST, PORT = "10.1.1.1", "10.2.2.2", 8443


def _objs():
    return {
        "H-S": AddressObject("H-S", "host", start=_ip(SRC), end=_ip(SRC), display=SRC),
        "H-D": AddressObject("H-D", "host", start=_ip(DST), end=_ip(DST), display=DST),
    }


def _row(port=PORT):
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(SRC)], dest_tokens=[parse_ip_token(DST)],
        port_tokens=[(port, port, "tcp")], extra_values=[],
        raw_source=SRC, raw_dest=DST, raw_port=str(port),
    )


def _classify(service, svc_objs=None):
    rule = SecurityRule(index=5, name="LEGACY-ANY-SVC", source=["H-S"], destination=["H-D"],
                        service=list(service), application=["any"], action="allow",
                        disabled=False, from_zones=["any"], to_zones=["any"])
    ris = build_rule_infos([rule], GroupResolver(_objs(), {}),
                           ServiceResolver(svc_objs or {}, {}))
    return classify_row(_row(), ris, DeviceIndex())


def _cell_text(res):
    cell, _ = exporter.build_name_rule_cell(res)
    return "".join(getattr(b, "text", "") or "" for b in cell)


class TestKhongConKhuyenThemPortVaoRuleServiceAny(unittest.TestCase):
    def test_service_any_khong_duoc_la_TOP1_1(self):
        res = _classify(["any"])
        self.assertNotEqual(res.tier, "TOP1.1",
                            "rule Service=any thi port KHONG thieu - '+ ADD PORT' la "
                            "change vo nghia")

    def test_khong_in_dong_ADD_PORT(self):
        text = _cell_text(_classify(["any"]))
        self.assertNotIn("ADD PORT", text.upper(),
                         "van khuyen them port vao rule service=any")

    def test_van_noi_ro_traffic_da_duoc_phep(self):
        """Chan khong co nghia la im lang: admin phai biet rule qua rong nay dang
        cho phep traffic do, de di don no o CHECK AUDIT."""
        res = _classify(["any"])
        self.assertEqual(res.broad_service_rule, "LEGACY-ANY-SVC")
        text = _cell_text(res)
        self.assertIn("LEGACY-ANY-SVC", text)
        self.assertIn("CHECK AUDIT", text.upper())

    def test_ton_trong_luat_II_2_2_khong_to_xanh_la(self):
        """Luat da chot: rule service=any KHONG BAO GIO duoc lam ket qua hop le ->
        khong duoc tra 'none' (xanh la FULL MATCH) cho dong nay."""
        self.assertNotEqual(exporter._compute_action_level(_classify(["any"])), "none")


class TestKhongPhaBanCuDung(unittest.TestCase):
    def test_service_cu_the_thieu_port_van_la_TOP1_1(self):
        """Doi chung non-regression: rule co service CU THE va thieu dung port
        -> van phai la TOP1.1 '+ ADD PORT' nhu truoc."""
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        res = _classify(["SVC-443"], svc)
        self.assertEqual(res.tier, "TOP1.1")
        self.assertIn("ADD PORT", _cell_text(res).upper())
        self.assertIsNone(res.broad_service_rule)

    def test_service_cu_the_du_port_van_la_TOP1(self):
        svc = {"SVC-8443": ServiceObject("SVC-8443", "tcp", "8443", ranges=[(8443, 8443)])}
        res = _classify(["SVC-8443"], svc)
        self.assertEqual(res.tier, "TOP1")
        self.assertEqual(exporter._compute_action_level(res), "none")

    def test_rule_any_any_any_khong_bi_nhac_lai(self):
        """Rule any/any/any da bi luat II.2.2 loai han tu truoc - khong can (va
        khong nen) in them dong 'LUU Y' cho no, tranh nhieu moi dong."""
        rule = SecurityRule(index=5, name="R-ANY-ANY-ANY", source=["any"],
                            destination=["any"], service=["any"], application=["any"],
                            action="allow", disabled=False,
                            from_zones=["any"], to_zones=["any"])
        ris = build_rule_infos([rule], GroupResolver(_objs(), {}), ServiceResolver({}, {}))
        res = classify_row(_row(), ris, DeviceIndex())
        self.assertIsNone(res.broad_service_rule)


if __name__ == "__main__":
    unittest.main(verbosity=2)
