# -*- coding: utf-8 -*-
"""
Luoi chan cho CONG CHAN APPLICATION cua CHECK RULE.

Cung goc re voi loi nguoi van hanh bao o nhanh audit, nhung o day hau qua
NGUOC LAI.

Cau hinh that hay co rule:

    src=any  dst=any  service=any  zone=any  application=[ping, traceroute]

Truoc day tool khong doc cot Application khi service la port thuong, nen mot
request Oracle tcp/1521 se khop rule nay va duoc bao:

    TOP1 - "traffic DA DUOC PHEP, khong can lam gi"

Thuc te firewall chi cho ping/traceroute di. Nguoi van hanh tin tool, khong tao
rule, traffic van khong thong - va lan sau ho khong tin tool nua.

Bo tool nay lam viec o muc L3-L4: no KHONG biet traffic se bi App-ID nhan dang
thanh ung dung nao, nen KHONG the ket luan mot rule gioi han App-ID co cho
traffic do di hay khong.
"""

import ipaddress
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_rule_pan.core import AddressObject, SecurityRule, ServiceObject, parse_ip_token
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import (_app_restricted, apply_candidate_overlay,
                             build_rule_infos, classify_row)
from check_rule_pan.request import RequestRow
from check_rule_pan.resolver import GroupResolver, ServiceResolver

SRC = "10.10.10.11"
DST = "192.168.50.21"


def _ip(s):
    return int(ipaddress.ip_address(s))


def _request(port=1521):
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(SRC)],
        dest_tokens=[parse_ip_token(DST)],
        port_tokens=[(port, port, "tcp")],
        extra_values=[SRC, DST, str(port)],
        raw_source=SRC, raw_dest=DST, raw_port=str(port),
    )


def _rule(index, name, apps, action="allow", src=("any",), dst=("any",),
          svc=("any",)):
    return SecurityRule(
        index=index, name=name, source=list(src), destination=list(dst),
        service=list(svc), application=list(apps), action=action, disabled=False,
        from_zones=["any"], to_zones=["any"],
    )


def _classify(rules, port=1521):
    objs = {
        "H-SRC": AddressObject("H-SRC", "host", start=_ip(SRC), end=_ip(SRC),
                               display=SRC),
        "H-DST": AddressObject("H-DST", "host", start=_ip(DST), end=_ip(DST),
                               display=DST),
    }
    svc = {"SVC-1521": ServiceObject("SVC-1521", "tcp", "1521",
                                     ranges=[(1521, 1521)])}
    infos = build_rule_infos(rules, GroupResolver(objs, {}),
                             ServiceResolver(svc, {}))
    return classify_row(_request(port), infos, DeviceIndex())


class TestRuleChiBatVaiApplication(unittest.TestCase):
    def test_KHONG_duoc_bao_da_duoc_phep(self):
        """Dung ca nguoi van hanh bao, chieu nguoc cua loi audit."""
        res = _classify([_rule(1, "R-ICMP-ONLY", ["ping", "traceroute"])])
        self.assertNotEqual(res.tier, "TOP1",
                            "rule chi bat ping/traceroute lai bao Oracle DA DUOC PHEP")
        self.assertNotEqual(getattr(res.rule, "name", None), "R-ICMP-ONLY")

    def test_KHONG_duoc_dem_ra_khuyen_them_vao(self):
        """Them Source vao mot rule chi cho ping thi traffic Oracle van khong
        di duoc - mot change VO NGHIA ma lai trong nhu da xong viec."""
        res = _classify([_rule(1, "R-ICMP-ONLY", ["ping"],
                               src=["10.0.0.0/8"], dst=["H-DST"],
                               svc=["SVC-1521"])])
        self.assertNotEqual(getattr(res.rule, "name", None), "R-ICMP-ONLY")

    def test_rule_app_ANY_thi_VAN_lam_ket_qua_nhu_cu(self):
        """Khong duoc sua qua tay: rulebase L3-L4 (application=any) phai chay
        y nhu truoc."""
        res = _classify([_rule(1, "R-ANY", ["any"], src=["H-SRC"], dst=["H-DST"],
                               svc=["SVC-1521"])])
        self.assertEqual(res.tier, "TOP1")
        self.assertEqual(res.rule.name, "R-ANY")

    def test_rule_app_RONG_coi_nhu_any(self):
        res = _classify([_rule(1, "R-TRONG", [], src=["H-SRC"], dst=["H-DST"],
                               svc=["SVC-1521"])])
        self.assertEqual(res.tier, "TOP1")

    def test_deny_chi_bat_PING_khong_duoc_bao_BI_CHAN_TRUOC(self):
        """Mot deny chi chan `ping` KHONG chan Oracle. Canh bao gia o day lam
        canh bao THAT lan sau bi coi la nhieu.

        Di qua nhanh TOP4 (khong co rule allow nao) vi do moi la luc
        `_find_blocking_deny_rule` duoc goi.
        """
        res = _classify([_rule(1, "D-PING", ["ping"], action="deny")])
        self.assertEqual(res.tier, "TOP4")
        self.assertFalse(getattr(res, "blocking_deny_detail", None),
                         "bao BI CHAN TRUOC boi mot deny chi ap cho ping")

    def test_deny_app_ANY_thi_VAN_canh_bao_nhu_cu(self):
        """Khong duoc sua qua tay: deny that su van phai duoc canh bao."""
        res = _classify([_rule(1, "D-ALL", ["any"], action="deny")])
        self.assertEqual(res.tier, "TOP4")
        detail = getattr(res, "blocking_deny_detail", None)
        self.assertTrue(detail, "mat luon kha nang phat hien deny chan truoc")
        self.assertIn("D-ALL", detail)


class TestAppRestrictedTungTruongHop(unittest.TestCase):
    def _r(self, apps):
        return _app_restricted(_rule(1, "r", apps))

    def test_any_va_rong_la_KHONG_gioi_han(self):
        self.assertIsNone(self._r(["any"]))
        self.assertIsNone(self._r([]))
        self.assertIsNone(self._r(["ANY"]))

    def test_co_gioi_han_thi_noi_ro_la_app_nao(self):
        detail = self._r(["ping", "traceroute"])
        self.assertIn("ping", detail)
        self.assertIn("traceroute", detail)

    def test_nhieu_app_thi_cat_bot_nhung_NOI_RO_con_bao_nhieu(self):
        detail = self._r([f"app{i}" for i in range(9)])
        self.assertIn("+5", detail)


class TestCandidateOverlay(unittest.TestCase):
    """Cung mot loi, o nhanh CANDIDATE CONFIG.

    `apply_candidate_overlay()` doi status mot item tu 'new' (TAO MOI) sang
    'candidate' khi thu can them DA co san trong config dang cho commit. Neu
    rule candidate do chi bat vai Application thi no khong bao dam traffic
    L3-L4 nay di duoc: bao "da chuan bi san" la bao DA XONG VIEC cho mot thu
    chua xong - admin bo qua, den ngay commit traffic van khong thong.
    """

    def _overlay(self, apps):
        row = _request()
        res = classify_row(row, [], DeviceIndex())
        self.assertEqual(res.tier, "TOP4")          # khong co rule running nao
        cand = build_rule_infos([_rule(1, "C-CAND", apps)],
                                GroupResolver({}, {}), ServiceResolver({}, {}))
        apply_candidate_overlay(res, row, cand, None)
        return [(m.status, m.existing_name) for m in res.source_report]

    def test_rule_candidate_chi_bat_PING_thi_KHONG_duoc_danh_dau_candidate(self):
        self.assertEqual(self._overlay(["ping"]), [("new", None)])

    def test_rule_candidate_app_ANY_thi_VAN_danh_dau_nhu_cu(self):
        self.assertEqual(self._overlay(["any"]), [("candidate", "C-CAND")])


if __name__ == "__main__":
    unittest.main(verbosity=2)
