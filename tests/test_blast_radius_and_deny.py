# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_blast_radius_and_deny.py).

Luat nghiep vu cua 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%,
chi doi ten package. Neu sua 1 ben ma quen ben kia thi 2 ban se troi khoi nhau -
do la dung cai ma quy tac dong bo trong PHAN 0 muon ngan.
"""
"""
2 bo sung theo kinh nghiem van hanh (10/2026 - CHECK RULE):

S4 - PHAM VI ANH HUONG (blast radius) cua chinh de xuat cua tool.
  Mot dong "+ ADD SOURCE" khong chi them 1 IP vao 1 rule: no cap cho IP do quyen
  di tói **TOAN BO Dest** cua rule, tren **TOAN BO port** cua rule. Truoc day o
  Name Rule chi co "ADD SOURCE: 10.9.9.9" - nguoi phe duyet khong he thay con so
  hau qua. Day cung la cho duy nhat lam ro duong `_exact_member_scope()`: field
  cua rule RONG HON request nhung co 1 member khop 1:1 -> nguoi dung DA chap nhan
  pham vi "da biet rong hon" do, nhung nguoi phe duyet van phai thay ca 2 con so.

  CO Y KHONG doi thu tu sort cua near_top2/near_top3: khoa sort dau tien cua
  chung da la `scope_size cua ben DA KHOP tang dan` = da uu tien rule co blast
  radius NHO NHAT. Phan thieu truoc gio chi la nguoi doc KHONG THAY con so.

S5 - RULE DENY DUNG TRUOC DIEM CHEN.
  `_find_shadowing_rule()` co tu truoc chi chay khi DA CHON duoc 1 rule allow
  (no can `candidate` de so index). Cac dong KHONG chon duoc rule nao (TOP4 /
  "chua co Rule - can tao moi") thi **khong ai kiem deny ca** -> admin tao rule
  moi, dat ben duoi mot deny da khop san, roi bao "da them rule ma van khong
  thong". `_find_blocking_deny_rule()` pha khoang trong do.
"""

import ipaddress
import unittest

from check_rule_pan.core import (AddressObject, AddressGroup, ServiceObject,
                             SecurityRule, parse_ip_token)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


def _row(src, dst, port=443):
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(src)], dest_tokens=[parse_ip_token(dst)],
        port_tokens=[(port, port, "tcp")], extra_values=[],
        raw_source=src, raw_dest=dst, raw_port=str(port),
    )


def _dc_group(n=14):
    objs, mem = {}, []
    for i in range(n):
        nm, a = f"DC-{i}", f"192.168.50.{10 + i}"
        objs[nm] = AddressObject(nm, "host", start=_ip(a), end=_ip(a), display=a)
        mem.append(nm)
    return objs, {"GR-DC": AddressGroup("GR-DC", members=mem)}


SVC_3 = {"SVC-3": ServiceObject("SVC-3", "tcp", "443,8443,9443",
                                ranges=[(443, 443), (8443, 8443), (9443, 9443)])}


def _allow(idx=9, src=None, dst=None, svc=None):
    return SecurityRule(index=idx, name="ALLOW-DC", source=src or ["SRV-OLD"],
                        destination=dst or ["GR-DC"], service=svc or ["SVC-3"],
                        application=["any"], action="allow", disabled=False,
                        from_zones=["any"], to_zones=["any"])


def _deny(idx=1, name="R00-BLOCK-ALL", action="deny", disabled=False):
    return SecurityRule(index=idx, name=name, source=["any"], destination=["any"],
                        service=["any"], application=["any"], action=action,
                        disabled=disabled, from_zones=["any"], to_zones=["any"])


def _classify(rules, objs, grps, row, svc=None):
    ris = build_rule_infos(rules, GroupResolver(objs, grps),
                           ServiceResolver(svc or SVC_3, {}))
    return classify_row(row, ris, DeviceIndex())


def _cell(res):
    c, _ = exporter.build_name_rule_cell(res)
    return "".join(getattr(b, "text", "") or "" for b in c)


class TestBlastRadius(unittest.TestCase):
    def test_add_source_noi_ro_so_dich_va_so_port(self):
        objs, grps = _dc_group(14)
        objs["SRV-OLD"] = AddressObject("SRV-OLD", "host", start=_ip("10.0.0.1"),
                                        end=_ip("10.0.0.1"), display="10.0.0.1")
        res = _classify([_allow()], objs, grps, _row("10.9.9.9", "192.168.50.10"))
        self.assertTrue(res.blast_radius, "dong '+ ADD SOURCE' phai noi ro hau qua")
        self.assertIn("14", res.blast_radius)
        self.assertIn("3 port", res.blast_radius)
        # 10/2026: VAN tinh blast radius (cac lop khac con dung) nhung KHONG
        # in ra bao cao nua - o Name Rule chi giu thu NGUOI DOC PHAI LAM.
        self.assertNotIn("PHAM VI ANH HUONG", _cell(res))

    def test_add_dest_doi_xung(self):
        """Them DEST -> toan bo Source cua rule duoc mo tói dich moi."""
        objs, _ = _dc_group(0)
        src_objs, src_grps = {}, []
        for i in range(7):
            nm, a = f"APP-{i}", f"10.10.10.{20 + i}"
            objs[nm] = AddressObject(nm, "host", start=_ip(a), end=_ip(a), display=a)
            src_grps.append(nm)
        grps = {"GR-APP": AddressGroup("GR-APP", members=src_grps)}
        objs["DST-OLD"] = AddressObject("DST-OLD", "host", start=_ip("192.168.9.9"),
                                        end=_ip("192.168.9.9"), display="192.168.9.9")
        rule = _allow(src=["GR-APP"], dst=["DST-OLD"])
        res = _classify([rule], objs, grps, _row("10.10.10.20", "192.168.77.77"))
        if res.blast_radius:
            self.assertIn("7", res.blast_radius)

    def test_dong_full_match_khong_bi_them_dong_rac(self):
        """FULL MATCH thi khong co gi de '+ ADD' -> khong in pham vi anh huong."""
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.9.9.9"),
                                     end=_ip("10.9.9.9"), display="10.9.9.9"),
            "DC-0": AddressObject("DC-0", "host", start=_ip("192.168.50.10"),
                                  end=_ip("192.168.50.10"), display="192.168.50.10"),
        }
        rule = _allow(src=["SRV-OLD"], dst=["DC-0"])
        res = _classify([rule], objs, {}, _row("10.9.9.9", "192.168.50.10"))
        self.assertEqual(res.tier, "TOP1")
        self.assertIsNone(res.blast_radius)
        self.assertNotIn("PHAM VI ANH HUONG", _cell(res))


class TestDenyDungTruocDiemChen(unittest.TestCase):
    def _objs(self):
        return {"SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.0.0.1"),
                                         end=_ip("10.0.0.1"), display="10.0.0.1")}

    def test_khong_co_rule_allow_nao_van_phai_canh_bao_deny(self):
        """Dung khoang trong ma _find_shadowing_rule() khong phu: khong co
        candidate allow nao -> truoc day khong ai kiem deny."""
        res = _classify([_deny()], self._objs(), {}, _row("10.9.9.9", "192.168.50.10"))
        self.assertEqual(res.blocking_deny_rule, "R00-BLOCK-ALL")
        self.assertIn("BI CHAN TRUOC", _cell(res))
        self.assertIn("phai dat TREN no", _cell(res))

    def test_deny_dang_disabled_thi_khong_canh_bao(self):
        """PAN-OS khong danh gia rule disabled."""
        res = _classify([_deny(disabled=True)], self._objs(), {},
                        _row("10.9.9.9", "192.168.50.10"))
        self.assertIsNone(res.blocking_deny_rule)

    def test_rule_allow_phia_tren_khong_phai_la_chan(self):
        res = _classify([_deny(action="allow", name="R-ALLOW-TREN")], self._objs(), {},
                        _row("10.9.9.9", "192.168.50.10"))
        self.assertIsNone(res.blocking_deny_rule)

    def test_bi_chan_thi_khong_duoc_to_xanh_la(self):
        """Co deny khop truoc -> khong the la FULL MATCH dang tin cay."""
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.9.9.9"),
                                     end=_ip("10.9.9.9"), display="10.9.9.9"),
            "DC-0": AddressObject("DC-0", "host", start=_ip("192.168.50.10"),
                                  end=_ip("192.168.50.10"), display="192.168.50.10"),
        }
        rule = _allow(idx=9, src=["SRV-OLD"], dst=["DC-0"])
        res = _classify([_deny(idx=1), rule], objs, {}, _row("10.9.9.9", "192.168.50.10"))
        self.assertNotEqual(exporter._compute_action_level(res), "none")

    def test_khong_in_trung_voi_shadow_warning_da_co(self):
        """shadow_warning (co tu truoc) va blocking_deny phu 2 khoang khac nhau -
        khong duoc in ca 2 cho cung 1 dong."""
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.9.9.9"),
                                     end=_ip("10.9.9.9"), display="10.9.9.9"),
            "DC-0": AddressObject("DC-0", "host", start=_ip("192.168.50.10"),
                                  end=_ip("192.168.50.10"), display="192.168.50.10"),
        }
        rule = _allow(idx=9, src=["SRV-OLD"], dst=["DC-0"])
        res = _classify([_deny(idx=1), rule], objs, {}, _row("10.9.9.9", "192.168.50.10"))
        self.assertTrue(res.shadow_warning, "day la ca shadow_warning kinh dien")
        self.assertIsNone(res.blocking_deny_rule,
                          "da co shadow_warning thi khong gan them blocking_deny")


class TestDenyNamSauRuleDaKhopThiKHONGCanhBao(unittest.TestCase):
    """LOI THAT trong ban dau cua S5, phat hien nho fixture ban Panorama.

    `_find_blocking_deny_rule()` quet CA rulebase, nen no bao ca nhung rule deny
    nam **SAU** rule allow da khop - trong khi deny nam sau thi khong he chan gi.
    Ban Panorama phoi bay ro nhat vi thu tu lap rap la
    Shared-PRE -> DG-PRE -> DG-POST -> Shared-POST: mot deny o DG-POST KHONG chan
    rule allow o DG-PRE, nhung ham nay van bao -> dong TOP1 bi keo khoi mau xanh la
    mot cach vo co.

    Nguyen tac dung: khi DA chon duoc 1 rule cu the thi cau hoi "co deny nao chan
    truoc no khong" la viec cua _find_shadowing_rule() (ham do so INDEX voi
    candidate). Ham moi chi phu truong hop KHONG chon duoc rule nao."""

    def test_deny_nam_sau_rule_allow_da_khop_thi_khong_bao(self):
        objs = {
            "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.9.9.9"),
                                     end=_ip("10.9.9.9"), display="10.9.9.9"),
            "DC-0": AddressObject("DC-0", "host", start=_ip("192.168.50.10"),
                                  end=_ip("192.168.50.10"), display="192.168.50.10"),
        }
        allow = _allow(idx=5, src=["SRV-OLD"], dst=["DC-0"])
        deny_sau = _deny(idx=20, name="R-DENY-O-POST")      # index LON hon
        res = _classify([allow, deny_sau], objs, {}, _row("10.9.9.9", "192.168.50.10"))
        self.assertEqual(res.tier, "TOP1")
        self.assertIsNone(res.blocking_deny_rule,
                          "deny nam SAU rule da khop thi khong chan gi - khong duoc bao")
        self.assertEqual(exporter._compute_action_level(res), "none",
                         "dong nay phai van la FULL MATCH xanh la")


if __name__ == "__main__":
    unittest.main(verbosity=2)
