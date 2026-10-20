# -*- coding: utf-8 -*-
"""
Test cho full-set exact match trong build_field_report (bao cao thuc te).

Bug: phep so khop tuyet doi 1:1 voi Range bao tron ca dai (vd
Range_10.31.0.120-130, 11 dia chi) chi chay tren tap remaining SAU khi
_greedy_assign da tach cac IP in_rule ra - tap thieu IP nen so khop that bai
oan, residual bi bao "TAO MOI" du object ton tai va bao phu dung khit.

Fix: kiem tra full-set tren TOAN BO host_items goc; neu co object/group khop
1:1 tuyet doi -> bao cao THONG NHAT toan bo IP la exists (ke ca IP da co san
trong rule). Khong match -> fallback luong cu.
"""

import ipaddress
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import build_device_index
from check_rule_pan.matcher import build_rule_infos, build_field_report


def _ip(s):
    return int(ipaddress.ip_address(s))


def _hosts(base, lo, hi):
    return ["%s.%d" % (base, i) for i in range(lo, hi + 1)]


def _ranges_of(ips):
    toks = [parse_ip_token(ip) for ip in ips]
    return [(t['start'], t['end'], t) for t in toks if t['kind'] != 'invalid']


def _make_index(addr_objs, addr_groups):
    cfg = {"address_objects": addr_objs, "address_groups": addr_groups}
    resolver = GroupResolver(addr_objs, addr_groups)
    return build_device_index(cfg, resolver, ServiceResolver({}, {})), resolver


def _statuses(report):
    return {m.display: (m.status, m.existing_name) for m in report}


class TestFullSetStandaloneRange(unittest.TestCase):
    """Case 1 bat buoc: 11 Host IP 10.41.0.120-130, Range doc lap khop khit."""

    def test_all_exists_via_standalone_range(self):
        ips = _hosts("10.41.0", 120, 130)
        addr_objs = {
            "Range_10.41.0.120-130": AddressObject(
                "Range_10.41.0.120-130", "range",
                start=_ip("10.41.0.120"), end=_ip("10.41.0.130"),
                display="10.41.0.120-10.41.0.130"),
            # Object rong hon bao trum thua -> KHONG duoc match (exact-only).
            "Wide_10.41.0.0/24": AddressObject(
                "Wide_10.41.0.0/24", "wide",
                start=_ip("10.41.0.0"), end=_ip("10.41.0.255"),
                display="10.41.0.0/24"),
        }
        idx, _ = _make_index(addr_objs, {})
        report = build_field_report(_ranges_of(ips), [], idx, wide=True)
        st = _statuses(report)
        self.assertEqual(len(st), 11)
        for ip in ips:
            self.assertEqual(st[ip][0], 'exists', ip)
            self.assertEqual(st[ip][1], 'Range_10.41.0.120-130', ip)
        self.assertFalse(any(m.status == 'new' for m in report))


class TestFullSetWithPartialInRule(unittest.TestCase):
    """Case 2 bat buoc: rule da co Host .120/.121, Range + group khop ca dai."""

    def test_all_exists_no_residual_new(self):
        ips = _hosts("10.31.0", 120, 130)
        addr_objs = {
            "Host_10.31.0.120": AddressObject(
                "Host_10.31.0.120", "host",
                start=_ip("10.31.0.120"), end=_ip("10.31.0.120"),
                display="10.31.0.120"),
            "Host_10.31.0.121": AddressObject(
                "Host_10.31.0.121", "host",
                start=_ip("10.31.0.121"), end=_ip("10.31.0.121"),
                display="10.31.0.121"),
            "Range_10.31.0.120-130": AddressObject(
                "Range_10.31.0.120-130", "range",
                start=_ip("10.31.0.120"), end=_ip("10.31.0.130"),
                display="10.31.0.120-10.31.0.130"),
        }
        addr_groups = {
            "Openshift_GR_120-130": AddressGroup(
                "Openshift_GR_120-130", members=["Range_10.31.0.120-130"]),
        }
        idx, resolver = _make_index(addr_objs, addr_groups)
        rule = SecurityRule(
            index=1, name="R-CAND", source=["Host_10.31.0.120",
                                            "Host_10.31.0.121"],
            destination=["any"], service=["any"], application=["any"],
            action="allow", disabled=False)
        infos = build_rule_infos(
            [rule], resolver, ServiceResolver({}, {}))
        report = build_field_report(
            _ranges_of(ips), infos[0].source_members, idx, wide=True)
        st = _statuses(report)
        self.assertEqual(len(st), 11)
        # Khuyen nghi Range doc lap; chap nhan group neu impl chon group.
        names = {nm for _, nm in st.values()}
        self.assertTrue(
            names <= {"Range_10.31.0.120-130", "Openshift_GR_120-130"},
            names)
        self.assertTrue(all(s == 'exists' for s, _ in st.values()))
        self.assertFalse(any(m.status == 'new' for m in report))
        # Khong con residual 122-129 bi TAO MOI.
        for ip in _hosts("10.31.0", 122, 129):
            self.assertEqual(st[ip][0], 'exists', ip)


class TestFullSetNegative(unittest.TestCase):
    """Exact-only: object rong hon / thieu dia chi deu KHONG duoc match."""

    def test_wider_object_never_matches(self):
        ips = _hosts("10.41.0", 120, 130)
        addr_objs = {
            "Wide_10.41.0.0/24": AddressObject(
                "Wide_10.41.0.0/24", "wide",
                start=_ip("10.41.0.0"), end=_ip("10.41.0.255"),
                display="10.41.0.0/24"),
        }
        idx, _ = _make_index(addr_objs, {})
        report = build_field_report(_ranges_of(ips), [], idx, wide=True)
        # Khong co dai dien khop khit -> fallback luong cu: toan bo new.
        self.assertTrue(all(m.status == 'new' for m in report))
        self.assertEqual(len(report), 11)

    def test_exact_rule_keeps_in_rule(self):
        # Rule da co san dai dien chinh xac cho TUNG IP -> giu in_rule,
        # khong danh lai thanh exists (bao ve TOP1 FULL MATCH).
        ips = _hosts("10.41.0", 120, 130)
        addr_objs = {}
        members = []
        for ip in ips:
            nm = "H_%s" % ip.replace('.', '_')
            addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip),
                                          end=_ip(ip), display=ip)
            members.append(nm)
        addr_objs["Range_10.41.0.120-130"] = AddressObject(
            "Range_10.41.0.120-130", "range",
            start=_ip("10.41.0.120"), end=_ip("10.41.0.130"),
            display="10.41.0.120-10.41.0.130")
        idx, resolver = _make_index(addr_objs, {})
        rule = SecurityRule(
            index=1, name="R-EXACT", source=list(members),
            destination=["any"], service=["any"], application=["any"],
            action="allow", disabled=False)
        infos = build_rule_infos(
            [rule], resolver, ServiceResolver({}, {}))
        report = build_field_report(
            _ranges_of(ips), infos[0].source_members, idx, wide=True)
        self.assertTrue(all(m.status == 'in_rule' for m in report))
        self.assertEqual(len(report), 11)


if __name__ == "__main__":
    unittest.main()
