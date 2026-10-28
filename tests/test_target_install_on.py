# -*- coding: utf-8 -*-
"""
Luoi chan cho TARGET / INSTALL-ON.

CA THAT
=======
He thong co Device Group dung chung cho nhieu site, va trong do co nhung rule
target RIENG tung site:

    <target><devices><entry name="SERIAL-SITE-B"/></devices></target>

Rule do KHONG he ton tai tren firewall cua site A. Truoc day tool khong doc
truong nay, nen:

  * CHECK AUDIT: lay rule cua site B di CHE rule cua site A roi de xuat xoa
    rule site A -> site A mat dich vu, va mat theo kieu kho lan ra nhat vi
    rule da khong con de doi chieu;
  * CHECK RULE: tra loi "traffic DA DUOC PHEP" bang mot rule khong nam tren
    con firewall dang hoi -> nguoi van hanh khong tao rule, traffic van khong
    thong.
"""

import os
import sys
import unittest
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_audit_pan.core import RuleSnapshot
from check_audit_pan.detectors import _targets_cover, find_shadow_rules
from check_audit_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.core import parse_config_root

NOW = datetime(2026, 10, 27, tzinfo=timezone.utc)
SITE_A = "0011AAAA"
SITE_B = "0022BBBB"


def snap(index, name, target=(), negate=False, src=("any",), dst=("any",),
         svc=("any",)):
    return RuleSnapshot(index=index, name=name, from_zones=["any"],
                        to_zones=["any"], source=list(src), destination=list(dst),
                        application=["any"], service=list(svc), action="allow",
                        target_devices=list(target), target_negate=negate)


def _shadow(rules):
    return {f.rule_name for f in find_shadow_rules(
        rules, GroupResolver({}, {}), ServiceResolver({}, {}), {}, NOW)}


class TestPhepBaoTrenChieuTarget(unittest.TestCase):
    def test_khong_co_target_thi_bao_duoc_moi_thu(self):
        self.assertTrue(_targets_cover(snap(1, "a"), snap(2, "b", [SITE_B])))
        self.assertTrue(_targets_cover(snap(1, "a"), snap(2, "b")))

    def test_R1_co_target_ma_R2_ap_cho_TAT_CA_thi_KHONG_bao(self):
        self.assertFalse(_targets_cover(snap(1, "a", [SITE_B]), snap(2, "b")))

    def test_hai_site_KHAC_nhau_thi_KHONG_bao(self):
        self.assertFalse(_targets_cover(snap(1, "a", [SITE_B]),
                                        snap(2, "b", [SITE_A])))

    def test_tap_con_thi_bao(self):
        self.assertTrue(_targets_cover(snap(1, "a", [SITE_A, SITE_B]),
                                       snap(2, "b", [SITE_A])))

    def test_NEGATE_chi_bao_khi_HAI_BEN_GIONG_HET(self):
        """Khong biet truoc toan bo estate thi 'moi firewall TRU X' khong so
        duoc bang phep tap - bao thu, chi bo sot de xuat don dep."""
        self.assertTrue(_targets_cover(snap(1, "a", [SITE_A], negate=True),
                                       snap(2, "b", [SITE_A], negate=True)))
        self.assertFalse(_targets_cover(snap(1, "a", [SITE_A], negate=True),
                                        snap(2, "b", [SITE_A])))
        self.assertFalse(_targets_cover(snap(1, "a", [SITE_A], negate=True),
                                        snap(2, "b", [SITE_B], negate=True)))


class TestAuditKhongChe_RuleKhacSite(unittest.TestCase):
    def test_rule_site_B_KHONG_duoc_che_rule_site_A(self):
        rules = [snap(1, "R-SITE-B", [SITE_B]),
                 snap(2, "R-SITE-A", [SITE_A], src=["10.1.1.1"], svc=["tcp-1521"])]
        self.assertNotIn("R-SITE-A", _shadow(rules),
                         "rule cua site B lai di che rule cua site A")

    def test_rule_KHONG_target_thi_VAN_che_nhu_cu(self):
        """Khong duoc sua qua tay: rule ap cho moi firewall van phai che duoc."""
        rules = [snap(1, "R-MOI-NOI"),
                 snap(2, "R-SITE-A", [SITE_A], src=["10.1.1.1"], svc=["tcp-1521"])]
        self.assertIn("R-SITE-A", _shadow(rules), "mat kha nang phat hien shadow")

    def test_rule_target_KHONG_duoc_bi_che_boi_rule_HEP_hon(self):
        rules = [snap(1, "R-SITE-B", [SITE_B]),
                 snap(2, "R-MOI-NOI", src=["10.1.1.1"], svc=["tcp-1521"])]
        self.assertNotIn("R-MOI-NOI", _shadow(rules))


XML = """<config>
 <shared>
  <address>
   <entry name="H-SRC"><ip-netmask>10.10.10.11/32</ip-netmask></entry>
   <entry name="H-DST"><ip-netmask>192.168.50.21/32</ip-netmask></entry>
  </address>
  <service><entry name="SVC-1521"><protocol><tcp><port>1521</port></tcp></protocol></entry></service>
  <pre-rulebase><security><rules>
   <entry name="R-SITE-B">
    <from><member>any</member></from><to><member>any</member></to>
    <source><member>H-SRC</member></source>
    <destination><member>H-DST</member></destination>
    <service><member>SVC-1521</member></service>
    <application><member>any</member></application>
    <target><devices><entry name="{B}"/></devices></target>
    <action>allow</action>
   </entry>
  </rules></security></pre-rulebase>
 </shared>
 <devices><entry name="localhost.localdomain"><device-group>
   <entry name="DG-ALL"/>
 </device-group></entry></devices>
</config>""".replace("{B}", SITE_B)


class TestCheckRuleLocTheoTargetFirewall(unittest.TestCase):
    def _cfg(self, serial):
        return parse_config_root(ET.fromstring(XML), "DG-ALL", serial)

    def test_doc_duoc_target_tu_XML(self):
        r = self._cfg(None)["rules"][0]
        self.assertEqual(r.target_devices, [SITE_B])
        self.assertFalse(r.target_negate)

    def test_chon_dung_site_thi_GIU_rule(self):
        self.assertEqual([r.name for r in self._cfg(SITE_B)["rules"]], ["R-SITE-B"])

    def test_chon_site_KHAC_thi_LOAI_rule_do_khoi_rulebase(self):
        """Tren firewall site A, rule nay KHONG ton tai - tra loi 'da duoc
        phep' bang no la tra loi bang mot rule khong co that o do."""
        cfg = self._cfg(SITE_A)
        self.assertEqual(cfg["rules"], [])
        self.assertEqual(cfg["target_note"]["bi_loai_vi_target"], 1)

    def test_CHUA_chon_target_thi_GIU_HET_nhung_phai_NOI_RA(self):
        """Khong duoc tu loai khi chua co can cu: loai nham mot rule allow se
        thanh 'chua co rule' va day nguoi dung di tao rule trung."""
        cfg = self._cfg(None)
        self.assertEqual(len(cfg["rules"]), 1)
        self.assertEqual(cfg["target_note"]["rules_co_target"], 1)
        self.assertEqual(cfg["target_note"]["bi_loai_vi_target"], 0)
        self.assertIn("R-SITE-B", cfg["target_note"]["ten_rule_co_target"])

    def test_applies_to_serial_tung_truong_hop(self):
        r = self._cfg(None)["rules"][0]
        self.assertTrue(r.applies_to_serial(SITE_B))
        self.assertFalse(r.applies_to_serial(SITE_A))
        self.assertTrue(r.applies_to_serial(None))      # chua chon -> khong loai
        r.target_negate = True
        self.assertFalse(r.applies_to_serial(SITE_B))
        self.assertTrue(r.applies_to_serial(SITE_A))


class TestBangChungHitCountTheoTarget(unittest.TestCase):
    """Rule chi push xuong site B thi firewall site A khong he co rule do.

    Truoc day no bi tinh la "thieu bang chung" vinh vien -> nhanh UNUSED KHONG
    BAO GIO chay voi ca mang rulebase target rieng tung site: an toan nhung
    audit coi nhu khong lam gi duoc o do.
    """

    def _stat(self, seen, missing, hits=0):
        from check_audit_pan.core import RuleHitStat
        from datetime import timedelta
        return RuleHitStat(hit_count=hits, last_hit_timestamp=None,
                           rule_creation_timestamp=NOW - timedelta(days=400),
                           devices_seen=tuple(seen), devices_missing=tuple(missing))

    def test_firewall_KHONG_duoc_push_rule_thi_khong_tinh_la_thieu(self):
        from check_audit_pan.detectors import trim_evidence_to_target

        r = snap(1, "R-SITE-B", [SITE_B])
        stats = {("R-SITE-B", ""): self._stat([SITE_B], [SITE_A])}
        self.assertFalse(stats[("R-SITE-B", "")].hits_known)
        moi = trim_evidence_to_target(stats, [r])
        self.assertTrue(moi[("R-SITE-B", "")].hits_known,
                        "van doi bang chung tu firewall khong he co rule do")

    def test_rule_KHONG_target_thi_giu_nguyen(self):
        from check_audit_pan.detectors import trim_evidence_to_target

        r = snap(1, "R-MOI-NOI")
        stats = {("R-MOI-NOI", ""): self._stat([SITE_B], [SITE_A])}
        moi = trim_evidence_to_target(stats, [r])
        self.assertFalse(moi[("R-MOI-NOI", "")].hits_known,
                         "mat luon cong chan P1 - de xuat xoa rule dang chay o site khac")

    def test_CHOT_AN_TOAN_chua_firewall_nao_tra_so_lieu_thi_VAN_la_khong_biet(self):
        """Khong co chot nay thi mot rule target vao serial chua he duoc query
        se thanh 'da biet, 0 hit' -> UNUSED -> de xuat XOA mot rule chua ai do
        bao gio."""
        from check_audit_pan.detectors import trim_evidence_to_target

        r = snap(1, "R-SITE-B", [SITE_B])
        stats = {("R-SITE-B", ""): self._stat([], [SITE_A])}
        moi = trim_evidence_to_target(stats, [r])
        self.assertFalse(moi[("R-SITE-B", "")].hits_known)

    def test_dang_NEGATE_cat_dung_chieu(self):
        from check_audit_pan.detectors import trim_evidence_to_target

        r = snap(1, "R-TRU-B", [SITE_B], negate=True)   # ap cho moi con TRU site B
        stats = {("R-TRU-B", ""): self._stat([SITE_A], [SITE_B])}
        moi = trim_evidence_to_target(stats, [r])
        self.assertTrue(moi[("R-TRU-B", "")].hits_known)

        r2 = snap(1, "R-TRU-B", [SITE_B], negate=True)
        stats2 = {("R-TRU-B", ""): self._stat([SITE_A], ["0033CCCC"])}
        moi2 = trim_evidence_to_target(stats2, [r2])
        self.assertFalse(moi2[("R-TRU-B", "")].hits_known,
                         "firewall 0033CCCC CO rule nay ma thieu so lieu - van phai la khong biet")


class TestPredefinedService(unittest.TestCase):
    """`service-http` la HAI port roi rac 80 VA 8080 - KHONG phai dai 80-8080.

    Viet nham thanh dai thi no phu luon tcp/1521, tcp/3389... tuc la bao "da
    duoc phep" cho gan nhu moi thu. Bang nay chi la ban DU PHONG: ten nao co
    trong config thi object that duoc doc truoc (co 1 ca khoa dieu do).
    """

    def _r(self, name, objs=None, groups=None):
        from check_rule_pan.resolver import ServiceResolver
        return ServiceResolver(objs or {}, groups or {}).resolve_name(name)

    def test_service_http_phu_80_VA_8080(self):
        v = self._r("service-http")
        self.assertTrue(v.covers("tcp", 80))
        self.assertTrue(v.covers("tcp", 8080))

    def test_service_http_KHONG_phai_dai_80_8080(self):
        v = self._r("service-http")
        for port in (443, 1521, 3389, 5000):
            self.assertFalse(v.covers("tcp", port), f"phu nham tcp/{port}")

    def test_service_https_chi_443(self):
        v = self._r("service-https")
        self.assertTrue(v.covers("tcp", 443))
        self.assertFalse(v.covers("tcp", 8443))

    def test_object_THAT_trong_config_duoc_doc_TRUOC_bang_du_phong(self):
        from check_rule_pan.core import ServiceObject
        objs = {"service-http": ServiceObject("service-http", "tcp", "9999",
                                              ranges=[(9999, 9999)])}
        v = self._r("service-http", objs)
        self.assertTrue(v.covers("tcp", 9999))
        self.assertFalse(v.covers("tcp", 80), "bang du phong de len object that")


if __name__ == "__main__":
    unittest.main(verbosity=2)
