# -*- coding: utf-8 -*-
"""
Test resolver.py (GroupResolver/ServiceResolver) - nhanh UNREACHABLE.
Kiem tra resolve group de quy, chong circular, fqdn bo qua, va y nghia
`covers` = superset (R1 RONG HON HOAC BANG R2).
"""

import unittest
import sys
try:
    import check_audit  # noqa
except ImportError:
    import check_audit_pan as check_audit  # type: ignore
    sys.modules['check_audit'] = check_audit
    for _sub in ['core','resolver','detectors','excel_io','pan_api']:
        try:
            _m = __import__(f'check_audit_pan.{_sub}', fromlist=[_sub])
            sys.modules[f'check_audit.{_sub}'] = _m
        except ImportError:
            pass

from check_audit.core import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from check_audit.resolver import GroupResolver, ServiceResolver
from tests.helpers import ra_host, ra_range, ra_any, svc_ports


class TestGroupResolver(unittest.TestCase):
    def build(self):
        objs = {
            "A": AddressObject("A", "host", start=_ip("10.0.0.5"), end=_ip("10.0.0.5")),
            "B": AddressObject("B", "host", start=_ip("10.0.0.6"), end=_ip("10.0.0.6")),
            "R": AddressObject("R", "range", start=_ip("10.0.0.1"), end=_ip("10.0.0.10")),
            "W": AddressObject("W", "wide", start=_ip("192.168.0.0"), end=_ip("192.168.255.255")),
            "FQ": AddressObject("FQ", "fqdn", raw="db.example.com"),
        }
        grps = {
            "G": AddressGroup("G", members=["A", "B"]),
            "G2": AddressGroup("G2", members=["G", "R"]),
        }
        logs = []
        return GroupResolver(objs, grps, log_func=logs.append), logs

    def test_resolve_host(self):
        r, _ = self.build()
        ra = r.resolve("10.0.0.5")
        self.assertEqual(ra.ranges, [(0x0A000005, 0x0A000005)])  # 167772165

    def test_resolve_group_nested(self):
        r, _ = self.build()
        ra = r.resolve("G2")
        covers = [a for (a, b) in ra.ranges]
        self.assertIn(_ip("10.0.0.5"), covers)
        self.assertIn(_ip("10.0.0.6"), covers)
        # R ('range' 10.0.0.1-10.0.0.10) duoc gop nguyen ca dan
        self.assertIn((_ip("10.0.0.1"), _ip("10.0.0.10")), ra.ranges)

    def test_any(self):
        r, _ = self.build()
        self.assertTrue(r.resolve("any").is_any)

    def test_fqdn_skipped_with_warning(self):
        r, logs = self.build()
        ra = r.resolve("FQ")
        self.assertIn("FQ", ra.unresolved)
        self.assertTrue(any("FQDN" in m for m in logs))

    def test_circular_guard(self):
        # G1 -> G2 -> G1
        objs = {}
        grps = {"G1": AddressGroup("G1", members=["G2"]),
                "G2": AddressGroup("G2", members=["G1"])}
        logs = []
        r = GroupResolver(objs, grps, log_func=logs.append)
        ra = r.resolve("G1")
        self.assertEqual(ra.ranges, [])  # khong crash, khong loop vo han
        self.assertTrue(any("circular" in m.lower() for m in logs))

    def test_unknown_object(self):
        r, logs = self.build()
        ra = r.resolve("NOT_EXIST")
        self.assertIn("NOT_EXIST", ra.unresolved)
        self.assertTrue(any("khong tim thay" in m.lower() for m in logs))

    def test_covers_superset(self):
        r, _ = self.build()
        wide = r.resolve("W")     # 192.168.0.0/16
        host = ra_host("192.168.1.50")
        self.assertTrue(wide.covers(host))
        host_out = ra_host("10.0.0.1")
        self.assertFalse(wide.covers(host_out))
        # R1 la 'any' -> cover moi thu
        self.assertTrue(ra_any().covers(host_out))
        # R2 'any' ma R1 khon rong -> khong cover duoc
        self.assertFalse(wide.covers(ra_any()))


class TestServiceResolver(unittest.TestCase):
    def build(self):
        objs = {
            "TCP_1521": ServiceObject("TCP_1521", "tcp", "1521"),
            "UDP_689": ServiceObject("UDP_689", "udp", "689"),
            "RANGE_1_100": ServiceObject("RANGE_1_100", "tcp", "1-100"),
            "MULTI": ServiceObject("MULTI", "tcp", "1521,8080"),
        }
        grps = {"SG": ServiceGroup("SG", members=["TCP_1521", "UDP_689"])}
        logs = []
        return ServiceResolver(objs, grps, log_func=logs.append), logs

    def test_resolve_single_port(self):
        s, _ = self.build()
        rs = s.resolve_name("TCP_1521")
        self.assertIn(("tcp", 1521, 1521), rs.ports)

    def test_resolve_port_range(self):
        s, _ = self.build()
        rs = s.resolve_name("RANGE_1_100")
        self.assertIn(("tcp", 1, 100), rs.ports)

    def test_resolve_group(self):
        s, _ = self.build()
        rs = s.resolve_name("SG")
        self.assertIn(("tcp", 1521, 1521), rs.ports)
        self.assertIn(("udp", 689, 689), rs.ports)

    def test_rule_service_any_and_appdefault(self):
        s, _ = self.build()
        rs = s.resolve_rule_service(["any"], [])
        self.assertTrue(rs.is_any)
        rs2 = s.resolve_rule_service(["application-default"], ["app-x", "app-y"])
        self.assertTrue(rs2.is_app_default)
        self.assertEqual(rs2.applications, ["app-x", "app-y"])

    def test_covers(self):
        s, _ = self.build()
        any_svc = s.resolve_rule_service(["any"], [])
        tcp1521 = s.resolve_rule_service(["TCP_1521"], [])
        self.assertTrue(any_svc.covers(tcp1521))
        # khac protocol -> khong cover
        udp689 = s.resolve_rule_service(["UDP_689"], [])
        self.assertFalse(tcp1521.covers(udp689))
        self.assertFalse(udp689.covers(tcp1521))
        # 1-100 cover 80
        rng = s.resolve_rule_service(["RANGE_1_100"], [])
        port80 = svc_ports([("tcp", 80, 80)])
        self.assertTrue(rng.covers(port80))
        # app-default khong bi service cu the cover
        appd = s.resolve_rule_service(["application-default"], ["a1"])
        self.assertFalse(rng.covers(appd))


def _ip(ip: str) -> int:
    import ipaddress
    return int(ipaddress.ip_address(ip))


if __name__ == "__main__":
    unittest.main()