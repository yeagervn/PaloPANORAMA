# -*- coding: utf-8 -*-
"""
Test differential cho fix tie-break near_top2/near_top3 dung sai phia
(CHECK RULE - matcher.py::_scan_all_tiers):

- near_top2 = Dest da du, Source dang thieu -> tie-break scope phai do do hep
  cua CHINH BEN SOURCE (ben duoc de xuat "+ ADD"), khong phai ben Dest da khop.
- near_top3 doi xung (do ben Dest).

Dung 2 rule cung roi near_top2:
- Rule A: Source NHO lien quan (3/4 IP, thieu dung 1 IP), Dest RONG (2 IP can
  + 20 IP thua) -> source_total NHO, dest_total LON.
- Rule B: Source HOAN TOAN khong lien quan (subnet 172.16.0.0/24, cover 0/4),
  Dest HEP (2 IP can + 1 IP thua) -> source_total LON, dest_total NHO.

Code cu (sort theo dest_total) chon B; code moi (sort theo source_total) phai
chon A. Test khang dinh ca 2 ve: old-key -> B (chung to test thuc su phan
biet duoc), _select_nearest_from_scan -> A.
"""

import ipaddress
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import (
    build_rule_infos, classify_row, _scan_all_tiers,
    _select_nearest_from_scan,
)
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC_4 = ["10.0.0.%d" % i for i in range(1, 5)]      # 4 IP can
DST_2 = ["192.168.1.%d" % i for i in range(1, 3)]   # 2 IP can


def _make_request():
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(s) for s in SRC_4],
        dest_tokens=[parse_ip_token(s) for s in DST_2],
        port_tokens=[(80, 80, "tcp")],
        extra_values=[",".join(SRC_4), ",".join(DST_2), "80"],
        raw_source=",".join(SRC_4),
        raw_dest=",".join(DST_2),
        raw_port="80",
    )


def _build_infos():
    addr_objs = {}
    # Rule A source: 3 host lien quan (thieu 10.0.0.4).
    src_a_members = []
    for i, ip in enumerate(SRC_4[:3]):
        nm = "A_SRC_H%d" % i
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        src_a_members.append(nm)
    # Rule A dest: 2 IP can + 20 IP thua (RONG).
    dst_a_members = []
    for i, ip in enumerate(DST_2):
        nm = "A_DST_H%d" % i
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        dst_a_members.append(nm)
    for j in range(20):
        ip = "192.168.9.%d" % (10 + j)
        nm = "A_DST_X%d" % j
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        dst_a_members.append(nm)
    # Rule B source: subnet hoan toan khong lien quan.
    addr_objs["B_SRC_WIDE"] = AddressObject(
        "B_SRC_WIDE", "wide", start=_ip("172.16.0.0"), end=_ip("172.16.0.255"),
        display="172.16.0.0/24")
    # Rule B dest: 2 IP can + 1 IP thua (HEP).
    dst_b_members = []
    for i, ip in enumerate(DST_2):
        nm = "B_DST_H%d" % i
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        dst_b_members.append(nm)
    addr_objs["B_DST_X0"] = AddressObject(
        "B_DST_X0", "host", start=_ip("192.168.100.1"),
        end=_ip("192.168.100.1"), display="192.168.100.1")
    dst_b_members.append("B_DST_X0")

    addr_groups = {
        "GR_SRC_A": AddressGroup("GR_SRC_A", members=src_a_members),
        "GR_DST_A": AddressGroup("GR_DST_A", members=dst_a_members),
        "GR_DST_B": AddressGroup("GR_DST_B", members=dst_b_members),
    }
    svc_objs = {"P80": ServiceObject("P80", "tcp", "80", ranges=[(80, 80)])}
    rule_a = SecurityRule(
        index=1, name="Rule-A-near-src", source=["GR_SRC_A"],
        destination=["GR_DST_A"], service=["P80"], application=["any"],
        action="allow", disabled=False)
    rule_b = SecurityRule(
        index=2, name="Rule-B-far-src", source=["B_SRC_WIDE"],
        destination=["GR_DST_B"], service=["P80"], application=["any"],
        action="allow", disabled=False)
    resolver = GroupResolver(addr_objs, addr_groups)
    return build_rule_infos([rule_a, rule_b], resolver,
                            ServiceResolver(svc_objs, {}))


def _ranges(row):
    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens
                  if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens
                  if t['kind'] != 'invalid']
    return src_ranges, dst_ranges, row.port_tokens


class TestNearTop2TieBreakSide(unittest.TestCase):
    def test_select_prefers_nearer_source_not_narrower_dest(self):
        infos = _build_infos()
        row = _make_request()
        src_ranges, dst_ranges, ports = _ranges(row)
        scan = _scan_all_tiers(infos, src_ranges, dst_ranges, ports, None)

        # Ca 2 rule phai cung roi near_top2 (dest du + port du, khong exact).
        self.assertEqual(len(scan["near_top2"]), 2)
        self.assertEqual(scan["near_top3"], [])
        by_name = {t[4].rule.name: t[4] for t in scan["near_top2"]}
        ri_a = by_name["Rule-A-near-src"]
        ri_b = by_name["Rule-B-far-src"]

        # Sanity thiet ke: A dest RONG hon B, nhung A source HEP hon B.
        self.assertGreater(ri_a.dest.total_address_count(),
                           ri_b.dest.total_address_count())
        self.assertLess(ri_a.source.total_address_count(),
                        ri_b.source.total_address_count())

        # Key CU (sort theo dest_total) se chon B -> chung to test phan biet duoc.
        old_winner = min(scan["near_top2"],
                         key=lambda x: (ri_a.dest.total_address_count()
                                        if x[4] is ri_a
                                        else ri_b.dest.total_address_count()))
        self.assertIs(old_winner[4], ri_b)

        # Code MOI phai chon A (source gan hon).
        nearest, kind = _select_nearest_from_scan(scan)
        self.assertEqual(kind, "near_top2")
        self.assertIs(nearest, ri_a)

    def test_classify_end_to_end_new_output_shape(self):
        infos = _build_infos()
        res = classify_row(_make_request(), infos, DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top2")
        self.assertEqual(res.nearest_rule.name, "Rule-A-near-src")
        self.assertEqual(res.nearest_missing_side, "source")
        self.assertEqual(exporter._compute_action_level(res), "near_match")

        cell, _n = exporter.build_name_rule_cell(res)
        txt = "".join(getattr(b, "text", "") for b in list(cell))
        # Khuon moi (B5): "ADD SOURCE: ip1, ip2, ..." (CHI du lieu cua chinh
        # label, khong kem raw_dest/raw_port).
        self.assertIn(
            "ADD SOURCE: 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4", txt)
        self.assertNotIn("+ ADD", txt)
        self.assertNotIn("GAN DUNG", txt)

        # Nhanh near_match co y KHONG noi caveat Live Match nua.
        res.live_match_skip_reason = "scale_limit"
        res.live_match_skip_detail = "999 to hop > gioi han 300"
        cell2, _n2 = exporter.build_name_rule_cell(res)
        txt2 = "".join(getattr(b, "text", "") for b in list(cell2))
        self.assertNotIn("Live Match", txt2)
        self.assertIn("ADD SOURCE:", txt2)


if __name__ == "__main__":
    unittest.main()
