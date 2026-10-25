# -*- coding: utf-8 -*-
"""
3 diem cuoi, CHI CO O BAN PANORAMA (10/2026).

B2 - rule o `Shared-PRE`/`Shared-POST` ap cho **MOI** firewall Panorama quan ly,
     khong chi cac con trong Device Group dang chon. Nen voi rule Shared, "0 hit
     tren moi con trong DG" **van chua du** bang chung de ket luan UNUSED -> co
     the de xuat xoa mot rule Shared dang chay tren firewall thuoc DG KHAC.
     Cach lam dung ma khong no chi phi API: voi cac con NGOAI DG chi hoi 2 lenh
     pham vi `<shared>` (khong hoi 2 lenh device-group).
       Chi phi = 4 x N_trong_DG + 2 x N_ngoai_DG  (toi thieu de ket luan dung)

B4 - truong hop DOI XUNG cua P2, va ket luan NGUOC DAU. Deny o `Shared-POST` thi
     MOI rule cua Device Group deu duoc danh gia TRUOC no -> them rule allow vao
     DG **LA GIAI PHAP HOP LE** (khac han P2 vo nghia). Phai noi rieng, neu khong
     admin se tuong "bi chan boi Shared thi coi nhu khong lam duoc gi" roi di xin
     quyen Panorama mot cach khong can thiet.

B7 - rule cau hinh CUC BO tren chinh firewall (buoc 3 cua thu tu lap rap 0.3).
     `assemble_security_rules_panorama()` co tham so `local_rules` va vi tri lap
     rap dung tu lau, nhung GUI chua co duong nao nap vao nen no VINH VIEN la
     None -> mot rule allow (hoac DENY) cuc bo nam giua DG-PRE va DG-POST hoan
     toan VO HINH voi tool.
"""

import datetime
import os
import tempfile
import unittest
from unittest.mock import patch

from check_audit_pan import pan_api
from check_audit_pan.pan_api import PanApiClient
from check_audit_pan.detectors import _find_unused_rules
from check_rule_pan.core import parse_local_firewall_rules
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.core import SecurityRule, parse_ip_token
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter
from tests.helpers import mk_rule

NOW = datetime.datetime(2026, 10, 27)
CREATED = int(datetime.datetime(2025, 9, 1).timestamp())
RECENT = int(datetime.datetime(2026, 10, 25).timestamp())

DG_A, DG_B = "0011AAAA", "0022BBBB"          # trong DG dang chon
OTHER = "0099ZZZZ"                            # firewall cua DG KHAC


def _shared_xml(rule, hit, last=None):
    l = f"<last-hit-timestamp>{last}</last-hit-timestamp>" if last else ""
    return f"""<response status="success"><result><rule-hit-count><shared>
      <pre-rulebase><entry name="security"><rules><entry name="{rule}">
        <hit-count>{hit}</hit-count>{l}
        <rule-creation-timestamp>{CREATED}</rule-creation-timestamp>
      </entry></rules></entry></pre-rulebase>
    </shared></rule-hit-count></result></response>"""


EMPTY = '<response status="success"><result/></response>'


class _Fake:
    def __init__(self, per_serial):
        self.per = per_serial
        self.calls = []

    def __call__(self, params):
        import xml.etree.ElementTree as ET
        tgt = params.get("target")
        cmd = params.get("cmd") or ""
        self.calls.append((tgt, "shared" if "<shared>" in cmd else "dg"))
        return ET.fromstring(self.per.get(tgt, EMPTY)).find("result")


class TestB2_PhamViEstateChoRuleShared(unittest.TestCase):
    def _run(self, per, serials, extra):
        fake = _Fake(per)
        with patch.object(PanApiClient, "_request", side_effect=fake):
            stats = pan_api.fetch_rule_hit_count_multi(
                "1.2.3.4", "k", serials, log_func=lambda m: None,
                extra_shared_serials=extra)
        return stats, fake

    def test_rule_shared_dung_o_firewall_cua_DG_KHAC_thi_khong_phai_unused(self):
        per = {DG_A: _shared_xml("S-DEAD", 0), DG_B: _shared_xml("S-DEAD", 0),
               OTHER: _shared_xml("S-DEAD", 777, last=RECENT)}
        stats, _ = self._run(per, [DG_A, DG_B], [OTHER])
        key = ("S-DEAD", "Shared-PRE")
        self.assertEqual(stats[key].hit_count, 777,
                         "phai gop ca firewall ngoai DG cho rule o pham vi Shared")
        r = mk_rule(0, "S-DEAD", src=["any"], dst=["any"], svc=["any"])
        r.vi_tri = "Shared-PRE"
        self.assertEqual(_find_unused_rules([r], stats, NOW), {},
                         "ket luan UNUSED o day = de xuat xoa rule Shared dang chay "
                         "tren firewall thuoc Device Group KHAC")

    def test_khong_doc_duoc_firewall_ngoai_DG_thi_thieu_bang_chung(self):
        per = {DG_A: _shared_xml("S-DEAD", 0), DG_B: _shared_xml("S-DEAD", 0)}
        stats, _ = self._run(per, [DG_A, DG_B], [OTHER])   # OTHER tra EMPTY
        st = stats[("S-DEAD", "Shared-PRE")]
        self.assertFalse(st.hits_known)
        self.assertIn(OTHER, st.devices_missing)

    def test_chi_phi_API_toi_thieu(self):
        """4 lenh cho con trong DG, CHI 2 lenh cho con ngoai DG."""
        per = {DG_A: _shared_xml("S", 0), DG_B: _shared_xml("S", 0),
               OTHER: _shared_xml("S", 0)}
        _stats, fake = self._run(per, [DG_A, DG_B], [OTHER])
        trong = [c for c in fake.calls if c[0] in (DG_A, DG_B)]
        ngoai = [c for c in fake.calls if c[0] == OTHER]
        self.assertEqual(len(trong), 8, "2 con trong DG x 4 lenh")
        self.assertEqual(len(ngoai), 2, f"con ngoai DG chi duoc hoi 2 lenh: {ngoai}")
        self.assertTrue(all(k == "shared" for _s, k in ngoai),
                        "con ngoai DG chi duoc hoi pham vi <shared>")

    def test_rule_trong_DG_khong_doi_pham_vi(self):
        """Rule o DG chi ap cho cac con cua DG - khong duoc doi hoi bang chung tu
        firewall ngoai DG (neu khong thi khong bao gio ket luan duoc gi)."""
        dg_xml = """<response status="success"><result><rule-hit-count><device-group>
          <entry name="DG-X"><pre-rulebase><entry name="security"><rules>
            <entry name="D-DEAD"><hit-count>0</hit-count>
              <rule-creation-timestamp>%d</rule-creation-timestamp></entry>
          </rules></entry></pre-rulebase></entry></device-group></rule-hit-count></result></response>""" % CREATED
        per = {DG_A: dg_xml, DG_B: dg_xml, OTHER: EMPTY}
        stats, _ = self._run(per, [DG_A, DG_B], [OTHER])
        st = stats[("D-DEAD", "DG-X-PRE")]
        self.assertTrue(st.hits_known, "rule trong DG chi can bang chung tu con cua DG")
        r = mk_rule(0, "D-DEAD", src=["any"], dst=["any"], svc=["any"])
        r.vi_tri = "DG-X-PRE"
        self.assertIn(("D-DEAD", "DG-X-PRE"), _find_unused_rules([r], stats, NOW))


def _row(src="10.66.66.88", dst="192.168.99.99", port=6666):
    return RequestRow(row_number=2, source_tokens=[parse_ip_token(src)],
                      dest_tokens=[parse_ip_token(dst)],
                      port_tokens=[(port, port, "tcp")], extra_values=[],
                      raw_source=src, raw_dest=dst, raw_port=str(port))


def _deny(vi_tri):
    r = SecurityRule(index=0, name="S-BLOCK", source=["any"], destination=["any"],
                     service=["any"], application=["any"], action="deny",
                     disabled=False, from_zones=["any"], to_zones=["any"])
    r.vi_tri = vi_tri
    return r


class TestB4_DenyOSharedPost(unittest.TestCase):
    def _classify(self, vi_tri):
        ris = build_rule_infos([_deny(vi_tri)], GroupResolver({}, {}),
                               ServiceResolver({}, {}))
        return classify_row(_row(), ris, DeviceIndex())

    def test_shared_post_ket_luan_NGUOC_DAU_voi_P2(self):
        res = self._classify("Shared-POST")
        self.assertTrue(res.blocked_at_shared_post)
        self.assertFalse(res.blocked_at_shared_pre)
        d = res.blocking_deny_detail or ""
        self.assertIn("KHONG can sua Shared", d,
                      "deny o Shared-POST thi them rule vao DG LA giai phap - phai "
                      "noi ro, neu khong admin di xin quyen Panorama vo ich")
        self.assertNotIn("KHONG THE cap phep", d)

    def test_nhan_o_name_rule_khac_han_P2(self):
        c, _ = exporter.build_name_rule_cell(self._classify("Shared-POST"))
        text = "".join(getattr(b, "text", "") or "" for b in c).upper()
        self.assertIn("SHARED-POST", text)
        self.assertNotIn("KHONG THE CAP PHEP TU DEVICE GROUP NAY", text)

    def test_shared_pre_van_la_P2(self):
        res = self._classify("Shared-PRE")
        self.assertTrue(res.blocked_at_shared_pre)
        self.assertFalse(res.blocked_at_shared_post)


LOCAL_XML = """<config><devices><entry name="localhost.localdomain">
  <vsys><entry name="vsys1"><rulebase><security><rules>
    <entry name="LOCAL-DENY-SQL">
      <from><member>any</member></from><to><member>any</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service><member>any</member></service><application><member>any</member></application>
      <action>deny</action>
    </entry>
    <entry name="LOCAL-ALLOW-WEB">
      <from><member>trust</member></from><to><member>untrust</member></to>
      <source><member>any</member></source><destination><member>any</member></destination>
      <service><member>any</member></service><application><member>any</member></application>
      <action>allow</action>
    </entry>
  </rules></security></rulebase></entry></vsys>
</entry></devices></config>"""


class TestB7_NapRuleCucBo(unittest.TestCase):
    def _file(self, text=LOCAL_XML):
        fd, path = tempfile.mkstemp(suffix=".xml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        self.addCleanup(os.unlink, path)
        return path

    def test_doc_duoc_rule_cuc_bo(self):
        rules = parse_local_firewall_rules(self._file())
        self.assertEqual([r.name for r in rules],
                         ["LOCAL-DENY-SQL", "LOCAL-ALLOW-WEB"])

    def test_gan_nhan_vi_tri_Local(self):
        for r in parse_local_firewall_rules(self._file()):
            self.assertEqual(r.vi_tri, "Local",
                             "0.3 quy dinh nhan 'Local' cho rule cuc bo")

    def test_doc_dung_tung_truong(self):
        r = parse_local_firewall_rules(self._file())[0]
        self.assertEqual(r.action, "deny")
        self.assertEqual(r.from_zones, ["any"])
        r2 = parse_local_firewall_rules(self._file())[1]
        self.assertEqual(r2.from_zones, ["trust"])
        self.assertEqual(r2.to_zones, ["untrust"])

    def test_file_sai_thi_RAISE_chu_khong_nuot(self):
        """Nguoi dung CHU DONG chon file, nen file sai la thong tin ho can biet
        ngay - khac voi cac ham parse khac tra [] im lang."""
        with self.assertRaises(Exception):
            parse_local_firewall_rules(self._file("khong phai xml"))

    def test_deny_cuc_bo_duoc_canh_bao(self):
        """Dung ly do can B7: mot DENY cuc bo truoc day hoan toan vo hinh."""
        local = parse_local_firewall_rules(self._file())
        ris = build_rule_infos(local, GroupResolver({}, {}), ServiceResolver({}, {}))
        res = classify_row(_row(), ris, DeviceIndex())
        self.assertEqual(res.blocking_deny_rule, "LOCAL-DENY-SQL",
                         "deny cuc bo phai duoc xet - truoc B7 no vo hinh voi tool")

    def test_loader_truyen_duoc_local_rules(self):
        from check_rule_pan.core import load_pan_config_from_xml_string
        import inspect
        sig = inspect.signature(load_pan_config_from_xml_string)
        self.assertIn("local_rules", sig.parameters,
                      "loader phai nhan local_rules, neu khong GUI khong co duong nao nap")


if __name__ == "__main__":
    unittest.main(verbosity=2)
