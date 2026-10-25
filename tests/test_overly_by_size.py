# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_overly_by_size.py).

Luat nghiep vu cua 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%,
chi doi ten package. Neu sua 1 ben ma quen ben kia thi 2 ban se troi khoi nhau -
do la dung cai ma quy tac dong bo trong PHAN 0 muon ngan.
"""
"""
S6 (10/2026 - CHECK AUDIT): Overly Permissive theo **VALUE THAT**, khong chi
literal `any`.

Vi sao can: trong mot ruleset da chin, rule nguy hiem **rat it khi** la literal
`any`. No la `GRP-ALL-SERVERS` ma ai do da nuoi len 400 member, hoac
`Net_10.0.0.0/8` lam Source, hoac 1 service group om ca dai 1-65535. Nhanh
literal-any (`find_overly_permissive_rules`, luat D2) **khong bao gio** bat duoc
nhung rule do - va do moi la dang pho bien nhat ma mot auditor can thay.

Nguyen tac cua ban va:
  - KHONG thay the nhanh literal-any (luat D2 giu nguyen 100%, test cu khong doi).
  - Nhanh moi **bo sung**, va tu **bo qua** rule da bi nhanh kia bat -> khong bao
    trung 1 rule 2 lan.
  - Dem theo so dia chi / port **da khu trung lap** (dung chinh ResolvedAddr/
    ResolvedService cua tab nay), khong phai "so member khai bao" - mot group 2
    member van co the om /8.
  - Xep hang theo **pham vi phoi nhiem** = nguon x dich x port giam dan: dung thu
    tu ma mot auditor can doc.
"""

import ipaddress
import unittest

from check_audit_pan.core import RuleSnapshot
from check_audit_pan.detectors import (find_overly_permissive_rules,
                                   find_overly_permissive_by_size,
                                   OVERLY_ADDR_THRESHOLD)
from check_audit_pan.resolver import GroupResolver, ServiceResolver


def _ip(s):
    return int(ipaddress.ip_address(s))


class _Res:
    """Resolver toi gian: tra dung tap range/port theo ten object."""

    def __init__(self, addr_map=None, svc_map=None):
        self.addr_map = addr_map or {}
        self.svc_map = svc_map or {}

    # --- giao dien giong GroupResolver/ServiceResolver cua tab nay ---
    def resolve(self, name):
        from check_audit_pan.resolver import ResolvedAddr
        if name == "any":
            return ResolvedAddr(is_any=True)
        return ResolvedAddr(ranges=list(self.addr_map.get(name, [])))

    def resolve_service(self, name):
        from check_audit_pan.resolver import ResolvedService
        if name == "any":
            return ResolvedService(is_any=True)
        return ResolvedService(ports=list(self.svc_map.get(name, [])))


class _SvcRes(_Res):
    """Giao dien phai khop DUNG ServiceResolver that: _resolve_rules() goi
    `resolve_rule_service(service_names, applications)`, khong phai `resolve()`."""

    def resolve_rule_service(self, service_names, applications):
        from check_audit_pan.resolver import ResolvedService
        if not service_names or "any" in service_names:
            return ResolvedService(is_any=True)
        ports = []
        for nm in service_names:
            ports += list(self.svc_map.get(nm, []))
        return ResolvedService(ports=ports)


def _rule(idx, name, src, dst, svc, action="allow", disabled=False):
    return RuleSnapshot(index=idx, name=name, uuid="", from_zones=["any"],
                        to_zones=["any"], source=list(src), destination=list(dst),
                        application=["any"], service=list(svc), action=action,
                        disabled=disabled)


def _net(cidr):
    n = ipaddress.ip_network(cidr)
    return (int(n.network_address), int(n.broadcast_address))


class TestBatDuocRuleRongMaKhongPhaiLiteralAny(unittest.TestCase):
    """Dung cai ma nhanh literal-any BO SOT."""

    def setUp(self):
        self.addr = {
            "Net_10_8": [_net("10.0.0.0/8")],          # 16.7 trieu dia chi
            "GRP-ALL-SRV": [(_ip("192.168.1.1"), _ip("192.168.1.1"))],   # 1 dia chi
            "HOST-A": [(_ip("10.1.1.1"), _ip("10.1.1.1"))],
        }
        self.svc = {
            "SVC-443": [("tcp", 443, 443)],
            "SG-ALL-TCP": [("tcp", 1, 65535)],
        }
        self.r = _Res(self.addr)
        self.sr = _SvcRes({}, self.svc)

    def test_source_la_subnet_rong_bi_bat(self):
        rules = [_rule(0, "R-SRC-/8", ["Net_10_8"], ["GRP-ALL-SRV"], ["SVC-443"])]
        # nhanh cu KHONG bat duoc
        self.assertEqual(find_overly_permissive_rules(rules), [],
                         "nhanh literal-any dung ra khong bat duoc rule nay")
        out = find_overly_permissive_by_size(rules, self.r, self.sr)
        self.assertEqual(len(out), 1)
        self.assertIn("Source rong", out[0].detail)
        self.assertIn("pham vi phoi nhiem", out[0].detail)

    def test_service_om_ca_dai_port_bi_bat(self):
        rules = [_rule(0, "R-ALL-TCP", ["HOST-A"], ["GRP-ALL-SRV"], ["SG-ALL-TCP"])]
        self.assertEqual(find_overly_permissive_rules(rules), [])
        out = find_overly_permissive_by_size(rules, self.r, self.sr)
        self.assertEqual(len(out), 1)
        self.assertIn("Service rong", out[0].detail)

    def test_rule_hep_that_thi_khong_bi_bao(self):
        rules = [_rule(0, "R-HEP", ["HOST-A"], ["GRP-ALL-SRV"], ["SVC-443"])]
        self.assertEqual(find_overly_permissive_by_size(rules, self.r, self.sr), [])

    def test_khong_bao_trung_voi_nhanh_literal_any(self):
        """Rule co literal any -> nhanh cu da bat, nhanh moi phai BO QUA."""
        rules = [_rule(0, "R-ANY-SRC", ["any"], ["GRP-ALL-SRV"], ["SVC-443"])]
        self.assertEqual(len(find_overly_permissive_rules(rules)), 1)
        self.assertEqual(find_overly_permissive_by_size(rules, self.r, self.sr), [],
                         "bao trung 1 rule o ca 2 nhanh")

    def test_xep_hang_theo_pham_vi_phoi_nhiem_giam_dan(self):
        """Thu tu ma auditor can doc: rule mo ra nhieu nhat nam tren."""
        addr = dict(self.addr)
        addr["Net_172_16"] = [_net("172.16.0.0/16")]      # 65k
        r = _Res(addr)
        rules = [
            _rule(0, "R-NHO", ["Net_172_16"], ["GRP-ALL-SRV"], ["SVC-443"]),
            _rule(1, "R-LON", ["Net_10_8"], ["GRP-ALL-SRV"], ["SVC-443"]),
        ]
        out = find_overly_permissive_by_size(rules, r, self.sr)
        self.assertEqual([f.rule_name for f in out], ["R-LON", "R-NHO"])

    def test_tinh_ca_rule_dang_disabled(self):
        """Giu nguyen tinh than D3 cua nhanh cu."""
        rules = [_rule(0, "R-OFF", ["Net_10_8"], ["GRP-ALL-SRV"], ["SVC-443"],
                       disabled=True)]
        self.assertEqual(len(find_overly_permissive_by_size(rules, self.r, self.sr)), 1)

    def test_nguong_dieu_chinh_duoc(self):
        rules = [_rule(0, "R-/24", ["HOST-A"], ["GRP-ALL-SRV"], ["SVC-443"])]
        addr = dict(self.addr)
        addr["HOST-A"] = [_net("10.1.1.0/24")]            # 256 < nguong mac dinh 1024
        r = _Res(addr)
        self.assertEqual(find_overly_permissive_by_size(rules, r, self.sr), [])
        out = find_overly_permissive_by_size(rules, r, self.sr, addr_threshold=256)
        self.assertEqual(len(out), 1, "nguong phai dieu chinh duoc theo quy mo mang")

    def test_khong_co_resolver_thi_khong_doan_bua(self):
        rules = [_rule(0, "R", ["Net_10_8"], ["GRP-ALL-SRV"], ["SVC-443"])]
        self.assertEqual(find_overly_permissive_by_size(rules, None, None), [])


class TestKhongPhaLuatD2(unittest.TestCase):
    """Nhanh literal-any phai y nguyen - khong duoc doi label/so finding."""

    def test_6_to_hop_literal_any_khong_doi(self):
        rules = [_rule(0, "R1", ["any"], ["any"], ["any"])]
        out = find_overly_permissive_rules(rules)
        self.assertEqual(len(out), 1)
        d = out[0].detail
        for nhan in ("Source=any", "Dest=any", "Dest Port=any", "Source+Dest=any",
                     "Source+Dest Port=any", "Dest+Dest Port=any"):
            self.assertIn(nhan, d)


if __name__ == "__main__":
    unittest.main(verbosity=2)
