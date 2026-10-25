# -*- coding: utf-8 -*-
"""
P2 (CHI CO O BAN PANORAMA): deny o `Shared-PRE` = KHONG THE cap phep tu Device
Group nay.

Thu tu lap rap 0.3 la `Shared-PRE -> DG-chain-PRE -> DG-chain-POST -> Shared-POST`,
nen KHONG rule nao trong Device Group co the dung TRUOC `Shared-PRE`. Neu traffic
bi mot deny o do chan thi "them rule moi vao DG" la **vo nghia o moi vi tri** -
cau tra loi dung la "phai sua chinh rule o Shared-PRE".

VI SAO CO FILE NAY (quan trong): khoi `if vi_tri == 'Shared-PRE'` trong
`_tag_blocking_deny()` la **DELTA RIENG** cua ban Panorama - ban standalone khong
co. O dot 2026-10-27c, mot lan port ham do tu standalone sang day da **xoa am
tham** ca khoi P2; chi `testlab` bat duoc (3 ca FAIL). Lab chay cham hon va can
dung ca mock HTTPS, nen them luoi don vi nay de phan hoi ngay va de khong ai port
de len P2 ma khong biet.
"""

import ipaddress
import unittest

from check_rule_pan.core import AddressObject, SecurityRule, parse_ip_token
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC, DST = "10.66.66.88", "192.168.99.99"


def _row():
    return RequestRow(row_number=2, source_tokens=[parse_ip_token(SRC)],
                      dest_tokens=[parse_ip_token(DST)],
                      port_tokens=[(6666, 6666, "tcp")], extra_values=[],
                      raw_source=SRC, raw_dest=DST, raw_port="6666")


def _deny(vi_tri):
    r = SecurityRule(index=0, name="S00-BLOCK", source=["any"], destination=["any"],
                     service=["any"], application=["any"], action="deny",
                     disabled=False, from_zones=["any"], to_zones=["any"])
    r.vi_tri = vi_tri
    return r


def _classify(vi_tri):
    ris = build_rule_infos([_deny(vi_tri)], GroupResolver({}, {}), ServiceResolver({}, {}))
    return classify_row(_row(), ris, DeviceIndex())


def _cell(res):
    c, _ = exporter.build_name_rule_cell(res)
    return "".join(getattr(b, "text", "") or "" for b in c)


class TestP2DenyOShatedPre(unittest.TestCase):
    def test_deny_o_shared_pre_thi_bat_co_rieng(self):
        res = _classify("Shared-PRE")
        self.assertEqual(res.blocking_deny_rule, "S00-BLOCK")
        self.assertTrue(res.blocked_at_shared_pre,
                        "DELTA RIENG cua ban Panorama bi mat - xem docstring dau file")

    def test_ket_luan_noi_dung_ban_chat(self):
        res = _classify("Shared-PRE")
        self.assertIn("KHONG THE cap phep", res.blocking_deny_detail or "")
        self.assertIn("Shared-PRE", res.blocking_deny_detail or "")
        self.assertNotIn("phai dat TREN no", res.blocking_deny_detail or "",
                         "deny o Shared-PRE thi 'dat len tren' la loi khuyen SAI "
                         "ban chat - khong rule nao cua DG dung truoc duoc")

    def test_nhan_o_name_rule_cung_doi_theo(self):
        text = _cell(_classify("Shared-PRE")).upper()
        self.assertIn("KHONG THE CAP PHEP TU DEVICE GROUP NAY", text)

    def test_deny_o_vi_tri_khac_van_la_nhan_cu(self):
        res = _classify("DG-HN-PRE")
        self.assertFalse(res.blocked_at_shared_pre)
        self.assertIn("phai dat TREN no", res.blocking_deny_detail or "")
        self.assertIn("DG-HN-PRE", res.blocking_deny_detail or "",
                      "nhan cu phai co bo sung vi_tri de admin biet sua o dau")


if __name__ == "__main__":
    unittest.main(verbosity=2)
