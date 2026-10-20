# -*- coding: utf-8 -*-
"""
Test differential cho fix classify_row TOP2/TOP3 uu tien sai tier khi chi phi
bo sung chenh lech lon so voi near_top2/near_top3 (CHECK RULE - matcher.py):

- Case chinh (tai hien rule 1264 vs 3289 that): rule A (dest = union nhieu
  group RONG -> near_top2, source chi thieu 1 IP) vs rule B (dest = dung 1
  group khop tuyet doi input -> TOP2 exact-scope, source thieu TOAN BO N IP)
  -> ket qua phai CHON A (TOP4/near_top2), KHONG chon B (TOP2).
- Case nguoc (regression guard): rule A doi hoi bo sung NHIEU Source hon rule
  B (TOP2 exact) -> phai GIU NGUYEN B (TOP2) nhu hanh vi cu.
- "Re hon" la strict `<`: bang chi phi -> TOP2/TOP3 exact-scope van thang.
"""

import ipaddress
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC_4 = ["10.1.0.%d" % i for i in range(1, 5)]      # N = 4 IP can
DST_2 = ["192.168.50.%d" % i for i in range(1, 3)]  # 2 IP can


def _make_request():
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(s) for s in SRC_4],
        dest_tokens=[parse_ip_token(s) for s in DST_2],
        port_tokens=[(443, 443, "tcp")],
        extra_values=[",".join(SRC_4), ",".join(DST_2), "443"],
        raw_source=",".join(SRC_4),
        raw_dest=",".join(DST_2),
        raw_port="443",
    )


def _host_objs(addr_objs, prefix, ips):
    members = []
    for i, ip in enumerate(ips):
        nm = "%s_H%d" % (prefix, i)
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        members.append(nm)
    return members


def _svc():
    return {"P443": ServiceObject("P443", "tcp", "443", ranges=[(443, 443)])}


class TestTop2CostPriority(unittest.TestCase):
    def _infos_main(self):
        """Rule A re (thieu 1 Source) vs Rule B exact-scope dat (thieu 4)."""
        addr_objs = {}
        # Rule A: source 3/4 IP lien quan; dest RONG (2 can + 8 thua).
        src_a = _host_objs(addr_objs, "A_SRC", SRC_4[:3])
        dst_a = _host_objs(addr_objs, "A_DST", DST_2)
        dst_a += _host_objs(addr_objs, "A_DST_X",
                            ["192.168.60.%d" % i for i in range(1, 9)])
        # Rule B: source hoan toan khong lien quan (0/4); dest KHOP TUYET DOI.
        src_b = _host_objs(addr_objs, "B_SRC", ["172.20.0.1", "172.20.0.2"])
        dst_b = _host_objs(addr_objs, "B_DST", DST_2)
        addr_groups = {
            "GR_SRC_A": AddressGroup("GR_SRC_A", members=src_a),
            "GR_DST_A": AddressGroup("GR_DST_A", members=dst_a),
            "GR_SRC_B": AddressGroup("GR_SRC_B", members=src_b),
            "GR_DST_B": AddressGroup("GR_DST_B", members=dst_b),
        }
        rule_a = SecurityRule(
            index=1264, name="R1264-wide-cheap", source=["GR_SRC_A"],
            destination=["GR_DST_A"], service=["P443"], application=["any"],
            action="allow", disabled=False)
        rule_b = SecurityRule(
            index=3289, name="R3289-exact-costly", source=["GR_SRC_B"],
            destination=["GR_DST_B"], service=["P443"], application=["any"],
            action="allow", disabled=False)
        resolver = GroupResolver(addr_objs, addr_groups)
        return build_rule_infos([rule_a, rule_b], resolver,
                                ServiceResolver(_svc(), {}))

    def test_cheap_near_top2_beats_costly_top2(self):
        res = classify_row(_make_request(), self._infos_main(), DeviceIndex())
        # TOP2 (B, thieu 4 Source) phai bi ha xuong TOP4/near_top2 (A, thieu 1).
        self.assertEqual(res.tier, "TOP4")
        self.assertIsNone(res.rule)
        self.assertEqual(res.nearest_rule_kind, "near_top2")
        self.assertEqual(res.nearest_rule.name, "R1264-wide-cheap")
        self.assertEqual(res.nearest_missing_side, "source")
        self.assertEqual(exporter._compute_action_level(res), "near_match")
        # Ghi chu minh bach ten rule TOP2 bi bo qua.
        self.assertIn("R3289-exact-costly", res.note or "")
        # Cell Name Rule theo khuon "LABEL | DEST | PORT | IP" (khong sua exporter).
        cell, _n = exporter.build_name_rule_cell(res)
        txt = "".join(getattr(b, "text", "") for b in list(cell))
        self.assertIn("ADD SOURCE:", txt)
        self.assertIn("R1264-wide-cheap", txt)

    def _infos_reverse(self):
        """Rule A dat (thieu 3 Source) vs Rule B exact-scope re (thieu 1)."""
        addr_objs = {}
        # Rule A: source chi 1/4 IP lien quan; dest RONG (2 can + 8 thua).
        src_a = _host_objs(addr_objs, "A_SRC", SRC_4[:1])
        dst_a = _host_objs(addr_objs, "A_DST", DST_2)
        dst_a += _host_objs(addr_objs, "A_DST_X",
                            ["192.168.60.%d" % i for i in range(1, 9)])
        # Rule B: source 3/4 IP lien quan (thieu 1); dest KHOP TUYET DOI.
        src_b = _host_objs(addr_objs, "B_SRC", SRC_4[:3])
        dst_b = _host_objs(addr_objs, "B_DST", DST_2)
        addr_groups = {
            "GR_SRC_A": AddressGroup("GR_SRC_A", members=src_a),
            "GR_DST_A": AddressGroup("GR_DST_A", members=dst_a),
            "GR_SRC_B": AddressGroup("GR_SRC_B", members=src_b),
            "GR_DST_B": AddressGroup("GR_DST_B", members=dst_b),
        }
        rule_a = SecurityRule(
            index=1264, name="R1264-wide-costly", source=["GR_SRC_A"],
            destination=["GR_DST_A"], service=["P443"], application=["any"],
            action="allow", disabled=False)
        rule_b = SecurityRule(
            index=3289, name="R3289-exact-cheap", source=["GR_SRC_B"],
            destination=["GR_DST_B"], service=["P443"], application=["any"],
            action="allow", disabled=False)
        resolver = GroupResolver(addr_objs, addr_groups)
        return build_rule_infos([rule_a, rule_b], resolver,
                                ServiceResolver(_svc(), {}))

    def test_costly_near_top2_does_not_beat_cheap_top2(self):
        res = classify_row(_make_request(), self._infos_reverse(),
                           DeviceIndex())
        # TOP2 (B, thieu 1 Source) van re hon near_top2 (A, thieu 3) -> giu TOP2.
        self.assertEqual(res.tier, "TOP2")
        self.assertEqual(res.rule.name, "R3289-exact-cheap")


class TestTop3CostPriority(unittest.TestCase):
    def _infos(self, cheap_is_near):
        """Doi xung TOP2: Source exact-scope (TOP3) vs Source rong (near_top3).

        cheap_is_near=True: near_top3 (C) thieu 1 Dest, TOP3 (D) thieu 2 Dest
        -> chon C. False: C thieu 2, D thieu 1 -> giu D (TOP3).
        """
        addr_objs = {}
        # Rule C: source RONG (4 can + 3 thua) -> source_full nhung khong exact
        # -> near_top3; dest tuy truong hop.
        src_c = _host_objs(addr_objs, "C_SRC", SRC_4)
        src_c += _host_objs(addr_objs, "C_SRC_X",
                            ["10.9.0.%d" % i for i in range(1, 4)])
        # Rule D: source KHOP TUYET DOI 4/4 IP can -> TOP3; dest tuy truong hop.
        src_d = _host_objs(addr_objs, "D_SRC", SRC_4)
        if cheap_is_near:
            dst_c = _host_objs(addr_objs, "C_DST", DST_2[:1])  # thieu 1
            dst_d = _host_objs(addr_objs, "D_DST", [])          # thieu 2
        else:
            dst_c = _host_objs(addr_objs, "C_DST", [])          # thieu 2
            dst_d = _host_objs(addr_objs, "D_DST", DST_2[:1])   # thieu 1
        addr_groups = {
            "GR_SRC_C": AddressGroup("GR_SRC_C", members=src_c),
            "GR_DST_C": AddressGroup("GR_DST_C", members=dst_c),
            "GR_SRC_D": AddressGroup("GR_SRC_D", members=src_d),
            "GR_DST_D": AddressGroup("GR_DST_D", members=dst_d),
        }
        rule_c = SecurityRule(
            index=100, name="R-near-top3", source=["GR_SRC_C"],
            destination=["GR_DST_C"], service=["P443"],
            application=["any"], action="allow", disabled=False)
        rule_d = SecurityRule(
            index=200, name="R-top3-exact", source=["GR_SRC_D"],
            destination=["GR_DST_D"], service=["P443"],
            application=["any"], action="allow", disabled=False)
        resolver = GroupResolver(addr_objs, addr_groups)
        return build_rule_infos([rule_c, rule_d], resolver,
                                ServiceResolver(_svc(), {}))

    def test_cheap_near_top3_beats_costly_top3(self):
        res = classify_row(_make_request(), self._infos(cheap_is_near=True),
                           DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top3")
        self.assertEqual(res.nearest_rule.name, "R-near-top3")
        self.assertEqual(res.nearest_missing_side, "dest")

    def test_costly_near_top3_does_not_beat_cheap_top3(self):
        res = classify_row(_make_request(), self._infos(cheap_is_near=False),
                           DeviceIndex())
        self.assertEqual(res.tier, "TOP3")
        self.assertEqual(res.rule.name, "R-top3-exact")


if __name__ == "__main__":
    unittest.main()
