# -*- coding: utf-8 -*-
"""
RUI RO CAO NHAT CUA CA SUITE (10/2026 - CHECK AUDIT bản Panorama):
hit-count lay tu MOT serial, nhung rule duoc push cho CA DEVICE GROUP.

Kich ban that:
  - Rule `R-SHARED-SQL` nam o `DG-ALL-PRE`, Panorama push xuong 3 firewall.
  - Admin nhap Target Firewall = serial cua firewall HN.
  - Firewall HN khong dung rule do -> `hit_count = 0`, tuoi rule 400 ngay
    -> detector ket luan **UNUSED** -> vao file Import -> Import **DELETE** rule
    khoi candidate-config cua DG -> commit xong la **2 firewall kia mat rule dang
    chay**.

Nguyen tac dung (ban va):
  1. UNUSED chi duoc ket luan khi **0 hit tren MOI firewall** cua Device Group.
  2. Firewall nao **khong doc duoc** hit-count -> `hits_known = False` -> **KHONG
     duoc ket luan UNUSED** (du cac firewall con lai deu 0 hit). "Khong biet"
     khac "bang 0" - dung phan biet da ap cho `_scope_trustworthy()` o CHECK RULE.
  3. Bang chung phai ghi RO da kiem nhung firewall nao: `devices_seen` /
     `devices_missing`.

3 cach `hit_count = 0` ma KHONG co nghia la rule chet (ghi lai de khong ai
"toi uu" bo di): `clear rule hit-count` sau khi debug; member **passive** cua cap
HA khong xu ly traffic nen hit gan 0; rule bi rename/tao lai thi counter ve 0.
Cai (1) va (3) con phu thuoc phien ban PAN-OS - **chua xac nhan tren thiet bi
that**, xem muc CHUA lam.
"""

import datetime
import unittest
from unittest.mock import patch

from check_audit_pan.core import RuleHitStat
from check_audit_pan import pan_api
from check_audit_pan.pan_api import PanApiClient
from check_audit_pan.detectors import _find_unused_rules
from tests.helpers import mk_rule

NOW = datetime.datetime(2026, 10, 26)
CREATED_LONG_AGO = datetime.datetime(2025, 9, 1)      # 420 ngay -> qua nguong 30

SER_A, SER_B, SER_C = "0011AAAA", "0022BBBB", "0033CCCC"


# Moc thoi gian tinh tu NOW de y dinh cua tung ca ro rang, khong mo doan epoch:
#   LAST_HIT_RECENT = NOW - 2 ngay  (trong nguong 30 ngay -> rule DANG duoc dung)
#   CREATED_EPOCH   = 2025-09-01    (420 ngay -> qua nguong, du dieu kien UNUSED)
LAST_HIT_RECENT = 1792800000
CREATED_EPOCH = 1756684800


def _hit_xml(dg, rule_name, hit_count, last_hit=None, created=CREATED_EPOCH):
    """1 response rule-hit-count toi gian, long dung cay nhu thiet bi that."""
    last = f"<last-hit-timestamp>{last_hit}</last-hit-timestamp>" if last_hit else ""
    return f"""<response status="success"><result>
      <rule-hit-count><device-group><entry name="{dg}">
        <pre-rulebase><entry name="security"><rules>
          <entry name="{rule_name}">
            <hit-count>{hit_count}</hit-count>{last}
            <rule-creation-timestamp>{created}</rule-creation-timestamp>
          </entry>
        </rules></entry></pre-rulebase>
      </entry></device-group></rule-hit-count>
    </result></response>"""


EMPTY_XML = '<response status="success"><result/></response>'


class _FakeMulti:
    """Tra response khac nhau theo `target` cua tung request - dung de mo phong
    "rule chi duoc dung tren 1 firewall trong DG"."""

    def __init__(self, per_serial):
        self.per_serial = per_serial      # {serial: xml | Exception}
        self.targets = []

    def __call__(self, params):
        import xml.etree.ElementTree as ET
        tgt = params.get("target")
        self.targets.append(tgt)
        val = self.per_serial.get(tgt, EMPTY_XML)
        if isinstance(val, Exception):
            raise val
        return ET.fromstring(val).find("result")


class TestHitCountGopNhieuFirewall(unittest.TestCase):

    def _multi(self, per_serial, serials):
        fake = _FakeMulti(per_serial)
        with patch.object(PanApiClient, "_request", side_effect=fake):
            stats = pan_api.fetch_rule_hit_count_multi(
                "1.2.3.4", "key", serials, log_func=lambda m: None)
        return stats, fake

    def test_rule_dung_tren_1_firewall_thi_KHONG_phai_unused(self):
        """Dung kich ban nguy hiem: A va C khong dung, B DANG dung."""
        per = {
            SER_A: _hit_xml("DG-ALL", "R-SHARED-SQL", 0),
            SER_B: _hit_xml("DG-ALL", "R-SHARED-SQL", 912, last_hit=LAST_HIT_RECENT),
            SER_C: _hit_xml("DG-ALL", "R-SHARED-SQL", 0),
        }
        stats, _ = self._multi(per, [SER_A, SER_B, SER_C])
        key = ("R-SHARED-SQL", "DG-ALL-PRE")
        self.assertIn(key, stats)
        st = stats[key]
        self.assertEqual(st.hit_count, 912,
                         "phai GOP hit cua ca 3 firewall, khong lay rieng 1 con")
        self.assertTrue(st.hits_known)
        self.assertEqual(set(st.devices_seen), {SER_A, SER_B, SER_C})

        rule = mk_rule(0, "R-SHARED-SQL", src=["any"], dst=["any"], svc=["any"])
        rule.vi_tri = "DG-ALL-PRE"
        unused = _find_unused_rules([rule], stats, NOW)
        self.assertEqual(unused, {},
                         "ket luan UNUSED o day = de xuat XOA mot rule dang chay "
                         "tren firewall khac trong cung Device Group")

    def test_moi_firewall_deu_0_hit_thi_moi_la_unused(self):
        """Doi chung huong con lai: that su khong firewall nao dung -> UNUSED."""
        per = {s: _hit_xml("DG-ALL", "R-DEAD", 0) for s in (SER_A, SER_B, SER_C)}
        stats, _ = self._multi(per, [SER_A, SER_B, SER_C])
        key = ("R-DEAD", "DG-ALL-PRE")
        self.assertEqual(stats[key].hit_count, 0)
        self.assertTrue(stats[key].hits_known)

        rule = mk_rule(0, "R-DEAD", src=["any"], dst=["any"], svc=["any"])
        rule.vi_tri = "DG-ALL-PRE"
        unused = _find_unused_rules([rule], stats, NOW)
        self.assertIn(key, unused, "0 hit tren MOI firewall + qua nguong -> phai la UNUSED")

    def test_mot_firewall_khong_doc_duoc_thi_KHONG_ket_luan_unused(self):
        """"Khong biet" KHAC "bang 0" - cung phan biet da ap o CHECK RULE."""
        per = {
            SER_A: _hit_xml("DG-ALL", "R-DEAD", 0),
            SER_B: _hit_xml("DG-ALL", "R-DEAD", 0),
            SER_C: RuntimeError("firewall khong phan hoi"),
        }
        stats, _ = self._multi(per, [SER_A, SER_B, SER_C])
        key = ("R-DEAD", "DG-ALL-PRE")
        st = stats[key]
        self.assertFalse(st.hits_known,
                         "co firewall khong doc duoc -> bang chung KHONG day du")
        self.assertIn(SER_C, st.devices_missing)

        rule = mk_rule(0, "R-DEAD", src=["any"], dst=["any"], svc=["any"])
        rule.vi_tri = "DG-ALL-PRE"
        self.assertEqual(_find_unused_rules([rule], stats, NOW), {},
                         "thieu bang chung ma van ket luan UNUSED la de xuat xoa bua")

    def test_firewall_khong_tra_dong_nao_cho_rule_do_cung_la_thieu_bang_chung(self):
        """Firewall tra ve OK nhung KHONG co dong nao cho rule nay (vd rule chua
        duoc push tói no) -> cung la 'khong biet', khong duoc coi la 0."""
        per = {
            SER_A: _hit_xml("DG-ALL", "R-DEAD", 0),
            SER_B: EMPTY_XML,
        }
        stats, _ = self._multi(per, [SER_A, SER_B])
        st = stats[("R-DEAD", "DG-ALL-PRE")]
        self.assertFalse(st.hits_known)
        self.assertIn(SER_B, st.devices_missing)

    def test_goi_dung_mot_lan_cho_moi_serial(self):
        """Chi phi phai TUYEN TINH theo so firewall, khong nhan theo so rule."""
        per = {s: _hit_xml("DG-ALL", "R", 0) for s in (SER_A, SER_B)}
        _stats, fake = self._multi(per, [SER_A, SER_B])
        # 4 lenh pham vi (DG pre/post + shared pre/post) x 2 serial
        self.assertEqual(len(fake.targets), 8, fake.targets)
        self.assertEqual(set(fake.targets), {SER_A, SER_B})


class TestTuongThichNguocVoiBanMotFirewall(unittest.TestCase):
    """RuleHitStat dung tay (3 tham so, nhu moi test cu) phai van hoat dong:
    khong co thong tin thiet bi -> coi nhu DA BIET, giu nguyen hanh vi cu."""

    def test_rulehitstat_cu_van_ket_luan_unused(self):
        st = RuleHitStat(hit_count=0, last_hit_timestamp=None,
                         rule_creation_timestamp=CREATED_LONG_AGO)
        self.assertTrue(st.hits_known)
        rule = mk_rule(0, "R-OLD", src=["any"], dst=["any"], svc=["any"])
        rule.vi_tri = "DG1-PRE"
        self.assertIn(("R-OLD", "DG1-PRE"),
                      _find_unused_rules([rule], {("R-OLD", "DG1-PRE"): st}, NOW))


if __name__ == "__main__":
    unittest.main(verbosity=2)
