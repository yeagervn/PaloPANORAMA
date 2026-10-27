# -*- coding: utf-8 -*-
"""
Luoi chan cho LOI THAT: audit dem rule "any/any/any chi bat vai Application"
ra che (shadow) het ca rulebase.

CA CU THE NGUOI VAN HANH BAO
============================
Cau hinh that rat hay co mot rule dau rulebase kieu:

    src=any  dst=any  service=any  zone=any  application=[ping, traceroute]

Phep "che" cu chi xet zone / source / destination / service, nen rule nay BAO
HET moi rule nam duoi - tool bao ca rulebase la "shadow, khong bao gio chay
toi". Thuc te no CHI cho ping/traceroute di; moi traffic khac van phai nho
dung nhung rule vua bi tool khuyen xoa.

Day la kieu sai NGUY HIEM NHAT cua ca bo tool: khong phai bo sot mot de xuat,
ma la DAY NGUOI DUNG DI XOA RULE DANG CHAY. Xoa xong mat dich vu, va mat theo
kieu kho lan ra nhat vi rule da khong con de doi chieu.
"""

import os
import sys
import unittest
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_audit_pan.core import RuleSnapshot
from check_audit_pan.detectors import _apps_cover, find_shadow_rules
from check_audit_pan.resolver import GroupResolver, ServiceResolver

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)


def rule(index, name, apps, src=("any",), dst=("any",), svc=("any",),
         action="allow", zones=("any",)):
    return RuleSnapshot(
        index=index, name=name, from_zones=list(zones), to_zones=list(zones),
        source=list(src), destination=list(dst), application=list(apps),
        service=list(svc), action=action)


def _shadow(rules):
    resolver = GroupResolver({}, {})
    svc = ServiceResolver({}, {})
    out = find_shadow_rules(rules, resolver, svc, {}, NOW)
    return {f.rule_name: f for f in out}


class TestRuleChiBatVaiApplication(unittest.TestCase):
    def test_rule_PING_TRACEROUTE_khong_duoc_che_rule_khac(self):
        """Dung ca nguoi van hanh bao."""
        rules = [
            rule(1, "R-ICMP-ONLY", ["ping", "traceroute"]),
            rule(2, "R-ORACLE", ["any"], src=["10.1.1.1"], dst=["10.2.2.2"],
                 svc=["tcp-1521"]),
            rule(3, "R-WEB", ["web-browsing"], svc=["tcp-80"]),
        ]
        found = _shadow(rules)
        self.assertNotIn("R-ORACLE", found,
                         "rule chi bat ping/traceroute lai di che rule Oracle")
        self.assertNotIn("R-WEB", found,
                         "rule chi bat ping/traceroute lai di che rule web")

    def test_rule_KHONG_gioi_han_app_thi_VAN_che_nhu_cu(self):
        """Khong duoc sua qua tay: rule any/any/any that su van phai che."""
        rules = [
            rule(1, "R-ANY", ["any"]),
            rule(2, "R-DUOI", ["any"], src=["10.1.1.1"], svc=["tcp-1521"]),
        ]
        self.assertIn("R-DUOI", _shadow(rules), "mat luon kha nang phat hien shadow")

    def test_app_trung_khop_thi_VAN_che(self):
        rules = [
            rule(1, "R-WEB-RONG", ["web-browsing", "ssl"]),
            rule(2, "R-WEB-HEP", ["web-browsing"], src=["10.1.1.1"], svc=["tcp-80"]),
        ]
        self.assertIn("R-WEB-HEP", _shadow(rules))

    def test_app_LECH_thi_KHONG_che(self):
        rules = [
            rule(1, "R-SSH", ["ssh"]),
            rule(2, "R-RDP", ["ms-rdp"], src=["10.1.1.1"]),
        ]
        self.assertNotIn("R-RDP", _shadow(rules))

    def test_R1_gioi_han_app_ma_R2_la_any_thi_KHONG_che(self):
        """R2 cho MOI app; R1 chi vai app - khong the bao chup."""
        rules = [
            rule(1, "R-HEP", ["ping"]),
            rule(2, "R-ANY-DUOI", ["any"], src=["10.1.1.1"]),
        ]
        self.assertNotIn("R-ANY-DUOI", _shadow(rules))


class TestApsCoverTungTruongHop(unittest.TestCase):
    """Khoa rieng vi_t ham so sanh - de doc hon la doi qua ca pipeline."""

    def _c(self, a1, a2):
        return _apps_cover(rule(1, "r1", a1), rule(2, "r2", a2))

    def test_any_bao_moi_thu(self):
        self.assertTrue(self._c(["any"], ["ping"]))
        self.assertTrue(self._c(["any"], ["any"]))

    def test_o_TRONG_coi_nhu_any(self):
        """Config migrate xong co rule trong cot Application."""
        self.assertTrue(self._c([], ["ping"]))
        self.assertFalse(self._c(["ping"], []))

    def test_khong_phan_biet_HOA_THUONG(self):
        self.assertTrue(self._c(["Ping", "TRACEROUTE"], ["ping"]))

    def test_tap_con_thi_bao(self):
        self.assertTrue(self._c(["a", "b", "c"], ["a", "b"]))

    def test_tap_khong_phai_con_thi_KHONG_bao(self):
        self.assertFalse(self._c(["a", "b"], ["a", "b", "c"]))

    def test_app_group_ten_khac_nhau_thi_BAO_THU_khong_ket_luan(self):
        """So theo TEN. Hai ben viet khac ten nhung thuc chat trung nhau thi
        tra False - tuc KHONG ket luan shadow. Sai huong nay chi bo sot mot de
        xuat don dep; sai huong kia lam mat dich vu."""
        self.assertFalse(self._c(["grp-web"], ["web-browsing"]))


if __name__ == "__main__":
    unittest.main(verbosity=2)
