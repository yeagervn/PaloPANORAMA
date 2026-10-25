# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_zone_gate.py).

Luat nghiep vu cua 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%,
chi doi ten package. Neu sua 1 ben ma quen ben kia thi 2 ban se troi khoi nhau -
do la dung cai ma quy tac dong bo trong PHAN 0 muon ngan.
"""
"""
LO HONG ZONE (10/2026 - CHECK RULE): tool BIET zone lech ma KHONG CHAN.

PAN-OS danh gia `from`/`to` zone la dieu kien match **BAT BUOC**. Mot rule
`trust -> untrust` KHONG cho phep cung luong traffic di vao tu zone `vpn`.

Truoc ban va: `_compute_zone_warning()` da tinh dung zone con thieu va in dong
"THIEU ZONE" trong o Name Rule, NHUNG `_compute_action_level()` **khong he doc
`zone_warning`** -> dong do van tra ve `'none'` = **to xanh la FULL MATCH**.
Mau xanh la cai ma nguoi ta hanh dong theo: requester dong ticket, app team
debug 2 ngay vi firewall van chan. Day la **false "da duoc phep"** - loai sai
dat nhat.

Ban va dung 3 TRANG THAI, khong phai 2 (co y, de khong tao false negative):
  - `match`    : moi dau mut suy duoc zone VA zone cua rule du    -> giu tier
  - `mismatch` : moi dau mut suy duoc zone NHUNG rule thieu zone  -> DEMOTE khoi
                 TOP1/TOP1.1/TOP2/TOP3 (rule van hien lam tham khao o near_*)
  - `unknown`  : khong co zone_lookup, HOAC co dau mut khong suy duoc zone, HOAC
                 rule khong khai bao zone -> GIU tier nhung phai noi ro la chua
                 kiem duoc, tuyet doi khong im lang coi nhu khop

Vi sao phai co trang thai `unknown`: zone duoc suy tu bang Interface/Zone bang
longest-prefix. Cach do khong dang tin khi co default route, route chong lan,
hoac source nam SAU mot router. Neu gate 2 trang thai thi mot suy luan sai se
bao "can tao rule moi" trong khi rule da ton tai -> sinh rule trung. Huong sai
do an toan hon false-allow, nhung van la rac trong rulebase.
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


# Bang Interface/Zone: 10.10.10.0/24 = trust, 10.20.20.0/24 = vpn,
# 192.168.50.0/24 = dmz. Dinh dang zone_lookup: (start, end, prefix_len, zone)
def _zone_lookup():
    def net(cidr, zone):
        n = ipaddress.ip_network(cidr)
        return (int(n.network_address), int(n.broadcast_address), n.prefixlen, zone)
    return [net("10.10.10.0/24", "trust"),
            net("10.20.20.0/24", "vpn"),
            net("192.168.50.0/24", "dmz")]


SRC_TRUST = "10.10.10.11"
SRC_VPN = "10.20.20.11"
DST_DMZ = "192.168.50.21"
PORT = 443


def _request(src, dst=DST_DMZ, port=PORT):
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(src)],
        dest_tokens=[parse_ip_token(dst)],
        port_tokens=[(port, port, "tcp")],
        extra_values=[src, dst, str(port)],
        raw_source=src, raw_dest=dst, raw_port=str(port),
    )


def _objs(src_ip):
    return {
        "H-SRC": AddressObject("H-SRC", "host", start=_ip(src_ip), end=_ip(src_ip),
                               display=src_ip),
        "H-DST": AddressObject("H-DST", "host", start=_ip(DST_DMZ), end=_ip(DST_DMZ),
                               display=DST_DMZ),
    }


def _rule(from_zones, to_zones):
    return SecurityRule(
        index=10, name="ALLOW-WEB-443",
        source=["H-SRC"], destination=["H-DST"],
        service=["SVC-443"], application=["any"],
        action="allow", disabled=False,
        from_zones=list(from_zones), to_zones=list(to_zones),
    )


def _classify(src_ip, from_zones, to_zones, zone_lookup=None):
    objs = _objs(src_ip)
    svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
    infos = build_rule_infos([_rule(from_zones, to_zones)],
                             GroupResolver(objs, {}), ServiceResolver(svc, {}))
    return classify_row(_request(src_ip), infos, DeviceIndex(),
                        zone_lookup=_zone_lookup() if zone_lookup is None else zone_lookup)


class TestZoneLechPhaiChan(unittest.TestCase):
    def test_zone_lech_khong_duoc_to_xanh_la(self):
        """Rule trust->dmz, request di tu VPN. Firewall THAT se chan."""
        res = _classify(SRC_VPN, ["trust"], ["dmz"])
        self.assertEqual(res.zone_verdict, "mismatch")
        self.assertNotEqual(exporter._compute_action_level(res), "none",
                            "zone lech ma van 'none' = to xanh la FULL MATCH -> "
                            "requester dong ticket, firewall van chan")
        self.assertNotIn(res.tier, ("TOP1", "TOP1.1", "TOP2", "TOP3"),
                         f"tier={res.tier}: rule thieu zone khong duoc lam ket qua chinh")

    def test_zone_lech_van_hien_rule_lam_tham_khao(self):
        """Demote KHONG phai la xoa thong tin: admin can biet 'rule nay gan dung,
        chi sai zone' de di sua zone thay vi tao rule trung."""
        res = _classify(SRC_VPN, ["trust"], ["dmz"])
        self.assertIsNotNone(res.nearest_rule or res.rule)
        self.assertIn("vpn", (res.zone_warning or "").lower())

    def test_zone_khop_thi_khong_doi_gi(self):
        """Doi chung non-regression quan trong nhat: zone dung -> van TOP1 xanh la."""
        res = _classify(SRC_TRUST, ["trust"], ["dmz"])
        self.assertEqual(res.zone_verdict, "match")
        self.assertEqual(res.tier, "TOP1")
        self.assertEqual(exporter._compute_action_level(res), "none")

    def test_rule_zone_any_la_du(self):
        """Theo yeu cau nguoi dung: zone 'any' luon coi la du."""
        res = _classify(SRC_VPN, ["any"], ["any"])
        self.assertEqual(res.zone_verdict, "match")
        self.assertEqual(res.tier, "TOP1")


class TestTrangThaiUnknownKhongDuocImLang(unittest.TestCase):
    def test_khong_co_zone_lookup_thi_unknown_chu_khong_phai_match(self):
        """Khong parse duoc Interface/Zone tu XML -> KHONG duoc im lang coi nhu khop."""
        res = _classify(SRC_VPN, ["trust"], ["dmz"], zone_lookup=[])
        self.assertEqual(res.zone_verdict, "unknown")
        self.assertEqual(res.tier, "TOP1", "unknown thi GIU tier - khong tao false negative")
        self.assertTrue(res.zone_unknown_detail,
                        "phai co dong noi ro 'chua kiem duoc zone', khong im lang")

    def test_dau_mut_ngoai_bang_interface_thi_unknown(self):
        """Source 172.x khong thuoc subnet interface nao -> khong suy duoc zone.
        Dung truong hop 'source nam SAU mot router' - tuyet doi khong duoc doan."""
        src = "172.31.9.9"
        objs = _objs(src)
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        infos = build_rule_infos([_rule(["trust"], ["dmz"])],
                                 GroupResolver(objs, {}), ServiceResolver(svc, {}))
        res = classify_row(_request(src), infos, DeviceIndex(), zone_lookup=_zone_lookup())
        self.assertEqual(res.zone_verdict, "unknown")
        self.assertEqual(res.tier, "TOP1")
        self.assertTrue(res.zone_unknown_detail)

    def test_rule_khong_khai_bao_zone_thi_unknown(self):
        res = _classify(SRC_VPN, [], [])
        self.assertEqual(res.zone_verdict, "unknown")


class TestExportPhaiNoiRa(unittest.TestCase):
    def _text(self, res):
        cell, _ = exporter.build_name_rule_cell(res)
        return "".join(getattr(b, "text", "") or "" for b in cell)

    def test_mismatch_in_ro_zone_thieu(self):
        text = self._text(_classify(SRC_VPN, ["trust"], ["dmz"]))
        self.assertIn("ZONE", text.upper())
        self.assertIn("vpn", text.lower())

    def test_unknown_in_ro_la_chua_kiem_duoc(self):
        text = self._text(_classify(SRC_VPN, ["trust"], ["dmz"], zone_lookup=[]))
        self.assertIn("CHUA KIEM DUOC ZONE", text.upper())


if __name__ == "__main__":
    unittest.main(verbosity=2)
