# -*- coding: utf-8 -*-
"""
Luoi chan cho LUAT DA CHOT: RULE HA TANG thi audit BO QUA, khong tinh.

RULE HA TANG LA GI
==================
    src=any  dst=any  service=any  zone src/dst=any
    application=[ping, traceroute, ...]

Nguoi van hanh chot (10/2026): rule dang nay ton tai CO CHU DICH - de
ping/traceroute/... di duoc toan he thong. Audit khong duoc dem no ra:

  * bao "Overly Permissive" la de nghi sai - no rong o L3-L4 dung nhu thiet
    ke, con App-ID moi la cho that su gioi han, ma App-ID thi bo tool L3-L4
    nay khong do duoc;
  * bao UNUSED/UNREACHABLE roi khuyen xoa la dua thang de nghi xoa rule ha
    tang - dung cai hau qua nang nhat ma ca bo tool phai tranh.

DINH NGHIA CO Y HEP: phai DU ca nam o `any` VA co gioi han Application. Chi
can mot o co gia tri that thi khong con la rule ha tang - audit van soi nhu cu.
"""

import os
import sys
import unittest
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_audit_pan.core import RuleHitStat, RuleSnapshot
from check_audit_pan.detectors import (find_disabled_rules,
                                       find_overly_permissive_rules,
                                       find_shadow_rules,
                                       infrastructure_rules,
                                       is_infrastructure_rule)
from check_audit_pan.resolver import GroupResolver, ServiceResolver

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)
CU = NOW - timedelta(days=400)          # tao tu lau, chua tung hit -> UNUSED


def rule(index=1, name="R", app=("ping", "traceroute"), src=("any",),
         dst=("any",), svc=("any",), zones=("any",), action="allow",
         disabled=False, vi_tri=""):
    return RuleSnapshot(index=index, name=name, from_zones=list(zones),
                        to_zones=list(zones), source=list(src),
                        destination=list(dst), application=list(app),
                        service=list(svc), action=action, disabled=disabled,
                        vi_tri=vi_tri)


def _hit0(names):
    """hit-count = 0, rule tao tu 400 ngay truoc -> du dieu kien UNUSED."""
    return {(n, ""): RuleHitStat(hit_count=0, last_hit_timestamp=None,
                                 rule_creation_timestamp=CU,
                                 devices_seen=("S1",), devices_missing=())
            for n in names}


def _shadow(rules, hits=None):
    out = find_shadow_rules(rules, GroupResolver({}, {}), ServiceResolver({}, {}),
                            hits or {}, NOW)
    return {f.rule_name for f in out}


class TestNhanDangRuleHaTang(unittest.TestCase):
    def test_du_nam_o_any_va_co_Application_thi_LA_rule_ha_tang(self):
        self.assertTrue(is_infrastructure_rule(rule()))

    def test_Application_any_thi_KHONG_phai(self):
        """Rule any/any/any that su - audit VAN phai soi no."""
        self.assertFalse(is_infrastructure_rule(rule(app=["any"])))
        self.assertFalse(is_infrastructure_rule(rule(app=[])))

    def test_chi_can_MOT_o_co_gia_tri_that_la_KHONG_con_la_ha_tang(self):
        self.assertFalse(is_infrastructure_rule(rule(svc=["tcp-443"])))
        self.assertFalse(is_infrastructure_rule(rule(src=["10.0.0.0/8"])))
        self.assertFalse(is_infrastructure_rule(rule(dst=["H-DB"])))
        self.assertFalse(is_infrastructure_rule(rule(zones=["trust"])))

    def test_o_de_TRONG_cung_la_any(self):
        self.assertTrue(is_infrastructure_rule(
            rule(src=[], dst=[], svc=[], zones=[])))

    def test_deny_ha_tang_cung_duoc_bo_qua(self):
        """`any/any/any app=[bittorrent] deny` la chan CO CHU DICH, khong phai rac."""
        self.assertTrue(is_infrastructure_rule(rule(app=["bittorrent"], action="deny")))

    def test_liet_ke_duoc_de_GUI_NOI_RA_da_bo_qua_nhung_rule_nao(self):
        rs = [rule(1, "R-HATANG"), rule(2, "R-THUONG", app=["any"], src=["10.1.1.1"])]
        self.assertEqual([r.name for r in infrastructure_rules(rs)], ["R-HATANG"])


class TestAuditBoQuaRuleHaTang(unittest.TestCase):
    def test_KHONG_bao_Overly_Permissive(self):
        self.assertEqual(find_overly_permissive_rules([rule(1, "R-HATANG")]), [])

    def test_doi_chung_rule_any_THAT_thi_VAN_bao_Overly(self):
        """Khong duoc sua qua tay: mat kha nang phat hien rule any/any/any that
        la mat luon ly do ton tai cua nhanh nay."""
        found = find_overly_permissive_rules([rule(1, "R-ANY", app=["any"])])
        self.assertEqual([f.rule_name for f in found], ["R-ANY"])

    def test_KHONG_bao_UNUSED_du_hit_count_bang_0(self):
        self.assertNotIn("R-HATANG",
                         _shadow([rule(1, "R-HATANG")], _hit0(["R-HATANG"])))

    def test_doi_chung_rule_thuong_0_hit_thi_VAN_bao_UNUSED(self):
        rs = [rule(1, "R-THUONG", app=["any"], src=["10.1.1.1"], svc=["tcp-443"])]
        self.assertIn("R-THUONG", _shadow(rs, _hit0(["R-THUONG"])))

    def test_KHONG_bao_UNREACHABLE(self):
        """Rule ha tang nam duoi mot rule any/any/any that."""
        rs = [rule(1, "R-ANY-THAT", app=["any"]), rule(2, "R-HATANG")]
        self.assertNotIn("R-HATANG", _shadow(rs))

    def test_VAN_khong_duoc_che_rule_khac(self):
        """Khoa lai ca A1: rule ha tang dung dau rulebase khong duoc che ai."""
        rs = [rule(1, "R-HATANG"),
              rule(2, "R-ORACLE", app=["any"], src=["10.1.1.1"],
                   dst=["10.2.2.2"], svc=["tcp-1521"], zones=["trust"])]
        self.assertNotIn("R-ORACLE", _shadow(rs))

    def test_VAN_hien_o_Disabled_Rules_neu_bi_tat(self):
        """Quyet dinh CO CHU DICH: 'Disabled' la liet ke SU THAT, khong phai de
        nghi don dep. Mot rule ha tang bi tat nghia la ping toan he thong dang
        hong - do dung la thu can biet."""
        found = find_disabled_rules([rule(1, "R-HATANG", disabled=True)])
        self.assertEqual([f.rule_name for f in found], ["R-HATANG"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
