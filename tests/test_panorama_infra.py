# -*- coding: utf-8 -*-
"""
Test HA TANG PANORAMA (require.md PHAN 0) cho ca 3 package *_pan.

Day la phan DUY NHAT khac ban Firewall standalone, nen cung la phan phai duoc
kiem chung ky nhat:
  0.1  Device Group thay VSYS; Target Firewall tuy chon
  0.2  Object layering theo chuoi thua ke Shared -> DG to tien -> ... -> DG hien tai
  0.3  Rulebase lap rap DUNG thu tu PAN-OS danh gia (PRE xuoi, POST nguoc)
  0.4  Candidate config doc theo cau truc DG
  0.5  Live Match BAT BUOC target=<serial>, thieu -> tu bo qua im lang
  0.6  Zone lay tu Template/Template Stack gan voi Target Firewall
  0.8  Map API/xpath Firewall -> Panorama
Khong phu thuoc tkinter, khong goi mang that.
"""

import unittest
import xml.etree.ElementTree as ET
from unittest import mock

from tests.panorama_fixture import PANORAMA_XML

from check_rule_pan import core as rcore
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import build_device_index, build_zone_lookup
from check_rule_pan.matcher import build_rule_infos, classify_row, try_live_match
from check_rule_pan.request import build_manual_request


def _root():
    return ET.fromstring(PANORAMA_XML)


# ---------------------------------------------------------------- 0.1 / 0.2
class TestDeviceGroupChain(unittest.TestCase):
    def test_liet_ke_device_group(self):
        self.assertEqual(rcore.list_devicegroups(_root()), ["DG-ALL", "DG-DC", "DG-HN"])

    def test_chuoi_thua_ke_3_tang(self):
        names, els = rcore.resolve_devicegroup_chain(_root(), "DG-HN")
        self.assertEqual(names, ["shared", "DG-ALL", "DG-DC", "DG-HN"])
        self.assertEqual(len(els), 4)
        self.assertTrue(all(e is not None for e in els))

    def test_chuoi_cua_dg_giua_va_dg_goc(self):
        self.assertEqual(rcore.resolve_devicegroup_chain(_root(), "DG-DC")[0],
                         ["shared", "DG-ALL", "DG-DC"])
        self.assertEqual(rcore.resolve_devicegroup_chain(_root(), "DG-ALL")[0],
                         ["shared", "DG-ALL"])

    def test_dg_khong_ton_tai_chi_con_shared(self):
        self.assertEqual(rcore.resolve_devicegroup_chain(_root(), "KHONG-CO")[0][0], "shared")

    def test_vong_cha_con_hong_khong_treo(self):
        """Cau hinh hong A->B->A: phai CAT vong, khong lap vo han."""
        xml = PANORAMA_XML.replace(
            "<entry name=\"DG-ALL\"/>",
            "<entry name=\"DG-ALL\"><parent-dg>DG-HN</parent-dg></entry>")
        names, _ = rcore.resolve_devicegroup_chain(ET.fromstring(xml), "DG-HN")
        self.assertEqual(names[0], "shared")
        self.assertEqual(len(names), len(set(names)))

    def test_khong_lay_nham_ban_readonly(self):
        """<readonly> chi chua parent-dg, khong co rule/object. Neu lay nham ban do
        thi DG se 'rong khong co rule nao'."""
        entries = rcore._devicegroup_entries(_root())
        self.assertIsNotNone(entries["DG-HN"].find("pre-rulebase"))
        self.assertIsNotNone(entries["DG-HN"].find("address"))


class TestObjectLayering(unittest.TestCase):
    """0.2: object trung ten -> DG CANG GAN DG dang thao tac CANG THANG."""

    def test_dg_gan_nhat_thang(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        self.assertEqual(cfg["address_objects"]["OBJ-COMMON"].display, "10.3.3.3/32")

    def test_dg_giua_thang_dg_to_tien(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-DC")
        self.assertEqual(cfg["address_objects"]["OBJ-COMMON"].display, "10.2.2.2/32")

    def test_dg_goc_thang_shared(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-ALL")
        self.assertEqual(cfg["address_objects"]["OBJ-COMMON"].display, "10.1.1.1/32")

    def test_thua_ke_tu_shared_va_dg_cha(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        self.assertEqual(cfg["address_objects"]["SHARED-ONLY"].display, "10.0.0.9/32")
        self.assertEqual(cfg["address_objects"]["DC-RANGE"].display, "10.5.5.100-10.5.5.110")
        self.assertIn("GR-SHARED", cfg["address_groups"])
        self.assertIn("SVC-443", cfg["service_objects"])

    def test_dg_con_khong_thay_object_cua_dg_anh_em(self):
        """DG-DC KHONG duoc nhin thay object rieng cua DG-HN (khong phai to tien)."""
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-DC")
        self.assertNotIn("HN-HOST", cfg["address_objects"])


# ---------------------------------------------------------------------- 0.3
class TestRulebaseAssembly(unittest.TestCase):
    EXPECTED = [
        ("SHARED-PRE-DENY", "Shared-PRE"),
        ("DGALL-PRE-ALLOW", "DG-ALL-PRE"),
        ("DGDC-PRE", "DG-DC-PRE"),
        ("DGHN-PRE", "DG-HN-PRE"),
        ("DGHN-POST", "DG-HN-POST"),
        ("DGDC-POST", "DG-DC-POST"),
        ("DGALL-POST", "DG-ALL-POST"),
        ("SHARED-POST-CATCHALL", "Shared-POST"),
    ]

    def test_dung_thu_tu_6_buoc(self):
        rules = rcore.assemble_security_rules_panorama(_root(), "DG-HN")
        self.assertEqual([(r.name, r.vi_tri) for r in rules], self.EXPECTED)

    def test_index_tang_dan_theo_thu_tu_lap_rap(self):
        rules = rcore.assemble_security_rules_panorama(_root(), "DG-HN")
        self.assertEqual([r.index for r in rules], list(range(len(rules))))

    def test_post_rulebase_nguoc_chieu_pre(self):
        """PRE: to tien -> hien tai. POST: hien tai -> to tien."""
        rules = rcore.assemble_security_rules_panorama(_root(), "DG-HN")
        pre = [r.dg for r in rules if r.rulebase == "pre" and r.dg != "shared"]
        post = [r.dg for r in rules if r.rulebase == "post" and r.dg != "shared"]
        self.assertEqual(pre, ["DG-ALL", "DG-DC", "DG-HN"])
        self.assertEqual(post, list(reversed(pre)))

    def test_rule_cuc_bo_nam_giua_pre_va_post(self):
        local = rcore.parse_security_rules(ET.fromstring(
            "<vsys><rulebase><security><rules>"
            "<entry name='LOCAL-1'><action>allow</action></entry>"
            "</rules></security></rulebase></vsys>"))
        rules = rcore.assemble_security_rules_panorama(_root(), "DG-HN", local_rules=local)
        names = [r.name for r in rules]
        self.assertEqual(names.index("LOCAL-1"), names.index("DGHN-PRE") + 1)
        self.assertLess(names.index("LOCAL-1"), names.index("DGHN-POST"))

    def test_dg_khac_nhau_cho_rulebase_khac_nhau(self):
        self.assertEqual(len(rcore.assemble_security_rules_panorama(_root(), "DG-ALL")), 4)
        self.assertEqual(len(rcore.assemble_security_rules_panorama(_root(), "DG-HN")), 8)


class TestShadowDungThuTuLapRap(unittest.TestCase):
    """Shadow-check quet nguoc len index nho hon - phai dung thu tu DA LAP RAP,
    nghia la rule deny o Shared-PRE che duoc rule allow o DG-POST."""

    def test_shared_pre_deny_che_rule_dg(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        gr = GroupResolver(cfg["address_objects"], cfg["address_groups"])
        sr = ServiceResolver(cfg["service_objects"], cfg["service_groups"])
        idx = build_device_index(cfg, gr, sr)
        ris = build_rule_infos(cfg["rules"], gr, sr)
        row = build_manual_request([["10.66.66.66", "192.168.100.10", "443"]]).rows[0]
        res = classify_row(row, ris, idx)
        self.assertEqual(res.shadow_warning, "SHARED-PRE-DENY")


# ---------------------------------------------------------------------- 0.6
class TestTemplateZone(unittest.TestCase):
    def test_tim_template_qua_template_stack(self):
        scopes = rcore.resolve_templates_for_serial(_root(), "001122334455")
        self.assertEqual([s.get("name") for s in scopes], ["TPL-OTHER", "TPL-BASE"])

    def test_serial_khong_gan_template_tra_rong(self):
        self.assertEqual(rcore.resolve_templates_for_serial(_root(), "009988776655"), [])
        self.assertEqual(rcore.resolve_templates_for_serial(_root(), None), [])

    def test_parse_interface_va_zone_tu_template(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN", "001122334455")
        self.assertEqual(cfg["zones"], {"trust": ["ethernet1/1"], "untrust": ["ethernet1/2"]})
        self.assertEqual(len(cfg["interface_subnets"]), 3)
        zl = build_zone_lookup(cfg["interface_subnets"], cfg["zones"])
        self.assertEqual(len(zl), 2)

    def test_khong_co_target_thi_zone_tu_vo_hieu(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        self.assertEqual(cfg["zones"], {})
        self.assertEqual(cfg["interface_subnets"], [])
        self.assertEqual(build_zone_lookup(cfg["interface_subnets"], cfg["zones"]), [])

    def test_devicegroup_devices(self):
        self.assertEqual(rcore.devicegroup_devices(_root(), "DG-HN"),
                         ["001122334455", "009988776655"])
        self.assertEqual(rcore.devicegroup_devices(_root(), "DG-ALL"), [])


# ---------------------------------------------------------------------- 0.5
class TestLiveMatchBatBuocTarget(unittest.TestCase):
    def _row(self):
        return build_manual_request([["10.7.7.7", "192.168.100.10", "443"]]).rows[0]

    def test_thieu_target_khong_goi_api(self):
        with mock.patch.object(rcore, "_SESSION") as sess:
            out = rcore.fetch_security_policy_match("1.2.3.4", "KEY", "10.1.1.1",
                                                     "10.2.2.2", 443, "tcp")
            self.assertIsNone(out)
            sess.get.assert_not_called()

    def test_co_target_thi_gui_kem_tham_so_target(self):
        resp = mock.Mock(status_code=200)
        resp.content = (b"<response status='success'><result><rules>"
                        b"<entry name='R-LIVE'><action>allow</action></entry>"
                        b"</rules></result></response>")
        with mock.patch.object(rcore, "_SESSION") as sess:
            sess.get.return_value = resp
            out = rcore.fetch_security_policy_match("1.2.3.4", "KEY", "10.1.1.1",
                                                     "10.2.2.2", 443, "tcp",
                                                     vsys="vsys2",
                                                     target_serial="001122334455")
        self.assertEqual(out, {"rule_name": "R-LIVE", "action": "allow"})
        params = sess.get.call_args.kwargs["params"]
        self.assertEqual(params["target"], "001122334455")
        self.assertEqual(params["vsys"], "vsys2")
        self.assertEqual(params["type"], "op")

    def test_try_live_match_thieu_target_tra_none_ngay(self):
        with mock.patch.object(rcore, "_SESSION") as sess:
            out = try_live_match(self._row(), "1.2.3.4", "KEY", "vsys1", [], None)
            self.assertIsNone(out)
            sess.get.assert_not_called()

    def test_classify_row_thieu_target_van_chay_local(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        gr = GroupResolver(cfg["address_objects"], cfg["address_groups"])
        sr = ServiceResolver(cfg["service_objects"], cfg["service_groups"])
        idx = build_device_index(cfg, gr, sr)
        ris = build_rule_infos(cfg["rules"], gr, sr)
        with mock.patch.object(rcore, "_SESSION") as sess:
            res = classify_row(self._row(), ris, idx, mgmt_ip="1.2.3.4", api_key="KEY")
            sess.get.assert_not_called()
        self.assertEqual(res.tier, "TOP1")
        self.assertEqual(res.rule.name, "DGHN-PRE")
        self.assertIsNone(res.live_match_skip_reason)


# ---------------------------------------------------------------------- 0.8
class TestApiPanorama(unittest.TestCase):
    def _resp(self, body, code=200):
        r = mock.Mock(status_code=code)
        r.content = body
        r.text = body.decode() if isinstance(body, bytes) else body
        return r

    def test_devicegroups_khong_lay_nham_serial(self):
        """Loi cu: selector sai (`devicegroup` so it) + fallback `.//entry` khien
        SERIAL cua thiet bi bi hieu thanh TEN Device Group."""
        body = (b"<response status='success'><result><devicegroups>"
                b"<entry name='DG-A'><devices><entry name='001122334455'/></devices></entry>"
                b"<entry name='DG-B'/></devicegroups></result></response>")
        with mock.patch.object(rcore, "_SESSION") as sess:
            sess.get.return_value = self._resp(body)
            out = rcore.get_panorama_devicegroups("1.2.3.4", "KEY")
        self.assertEqual(out, ["DG-A", "DG-B"])

    def test_devicegroups_loi_thi_tra_rong_khong_raise(self):
        with mock.patch.object(rcore, "_SESSION") as sess:
            sess.get.return_value = self._resp(b"<response status='error'/>")
            self.assertEqual(rcore.get_panorama_devicegroups("1.2.3.4", "KEY"), [])

    def test_danh_sach_thiet_bi_cho_o_target(self):
        body = (b"<response status='success'><result><devices>"
                b"<entry name='001122334455'><serial>001122334455</serial>"
                b"<hostname>FW-HN-01</hostname></entry>"
                b"</devices></result></response>")
        with mock.patch.object(rcore, "_SESSION") as sess:
            sess.get.return_value = self._resp(body)
            self.assertEqual(rcore.get_panorama_devices("1.2.3.4", "KEY"),
                             [("001122334455", "FW-HN-01")])

    def test_thong_bao_loi_doc_duoc_tu_msg_line(self):
        """Bay ElementTree: `root.find('.//msg/line') or root.find('.//msg')` luon
        roi sang ve phai vi <line> khong co con -> mat thong bao loi that."""
        root = ET.fromstring("<response status='error'><msg><line>Invalid credentials</line></msg></response>")
        self.assertEqual(rcore._api_error_message(root), "Invalid credentials")

    def test_running_config_thu_lai_voi_xpath_khi_bi_tu_choi(self):
        ok = self._resp(b"<response status='success'><result><config><shared/></config></result></response>")
        bad = self._resp(b"<response status='error'><msg><line>xpath is required</line></msg></response>")
        with mock.patch.object(rcore, "_SESSION") as sess:
            sess.get.side_effect = [bad, ok]
            xml = rcore.fetch_panorama_config_xml("1.2.3.4", "KEY")
        self.assertIn("<shared", xml)
        self.assertEqual(sess.get.call_count, 2)
        self.assertEqual(sess.get.call_args_list[1].kwargs["params"]["xpath"], "/config")


# ---------------------------------------------------------------------- 0.4
class TestCandidateConfigTheoDG(unittest.TestCase):
    def test_candidate_doc_dung_cau_truc_dg(self):
        cand = rcore.parse_candidate_config(PANORAMA_XML, "DG-HN")
        self.assertEqual(cand["address_objects"]["OBJ-COMMON"].display, "10.3.3.3/32")
        self.assertEqual([r.vi_tri for r in cand["rules"]][:2], ["Shared-PRE", "DG-ALL-PRE"])

    def test_diff_candidate_loai_bo_thu_da_co_tren_running(self):
        cfg = rcore.load_pan_config_from_xml_string(PANORAMA_XML, "DG-HN")
        cand = rcore.parse_candidate_config(PANORAMA_XML, "DG-HN")
        diff = rcore.diff_candidate_config(cfg, cand)
        self.assertEqual(diff["rules"], [])
        self.assertEqual(diff["address_objects"], {})


if __name__ == "__main__":
    unittest.main()
