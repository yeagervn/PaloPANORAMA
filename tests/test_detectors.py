# -*- coding: utf-8 -*-
"""
Test detectors.py theo toan bo Mục 9 require.md (phần detectors):
  - find_disabled_rules
  - find_overly_permissive_rules (6 to hop any + disabled van duoc liet ke - D3)
  - find_shadow_rules (UNREACHABLE + UNUSED + merge 2 ly do)
  - _find_unused_rules (nguong 30 ngay CO DINH)
"""

import unittest
from datetime import datetime, timedelta
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

from check_audit.core import (
    CHECK_TYPE_SHADOW, CHECK_TYPE_DISABLED, CHECK_TYPE_OVERLY,
    SHADOW_UNREACHABLE, SHADOW_UNUSED,
    Finding,
)
from check_audit.resolver import ResolvedAddr, ResolvedService
from check_audit.detectors import (
    find_disabled_rules, find_overly_permissive_rules,
    find_shadow_rules, _find_unused_rules,
)
from tests.helpers import (
    ra_any, ra_host, ra_range, ra_subnet, svc_any, svc_ports, svc_app_default,
    mk_rule, attach_resolved, hit_stat,
)

NOW = datetime(2026, 8, 28, 12, 0, 0)


class TestDisabledRules(unittest.TestCase):
    def test_2_of_5_disabled(self):
        rules = [mk_rule(i, f"R{i}", disabled=(i in (1, 4))) for i in range(5)]
        out = find_disabled_rules(rules)
        self.assertEqual(len(out), 2)
        names = {f.rule_name for f in out}
        self.assertEqual(names, {"R1", "R4"})
        for f in out:
            self.assertEqual(f.check_type, CHECK_TYPE_DISABLED)
            self.assertTrue(f.disabled)
            self.assertIn("Disabled", f.detail)


class TestOverlyPermissive(unittest.TestCase):
    def test_six_combos_and_detail(self):
        rules = [
            mk_rule(0, "C1", src=["any"], dst=["X"], svc=["S"]),                     # chi src
            mk_rule(1, "C2", src=["Y"], dst=["any"], svc=["S"]),                     # chi dst
            mk_rule(2, "C3", src=["X"], dst=["Y"], svc=["any"]),                     # chi port
            mk_rule(3, "C4", src=["any"], dst=["any"], svc=["S"]),                   # src+dst
            mk_rule(4, "C5", src=["any"], dst=["Y"], svc=["any"]),                   # src+port
            mk_rule(5, "C6", src=["X"], dst=["any"], svc=["any"]),                   # dst+port
            mk_rule(6, "C7", src=["any"], dst=["any"], svc=["any"]),                 # ca 3
            mk_rule(7, "C8", src="X",  dst=["Y"], svc=["S"]),                        # không dính
        ]
        out = find_overly_permissive_rules(rules)
        by_name = {f.rule_name: f.detail for f in out}

        self.assertEqual(by_name["C1"], "Source=any")
        self.assertEqual(by_name["C2"], "Dest=any")
        self.assertEqual(by_name["C3"], "Dest Port=any")
        self.assertEqual(by_name["C4"], "Source=any, Dest=any, Source+Dest=any")
        self.assertEqual(by_name["C5"], "Source=any, Dest Port=any, Source+Dest Port=any")
        self.assertEqual(by_name["C6"], "Dest=any, Dest Port=any, Dest+Dest Port=any")
        self.assertEqual(
            by_name["C7"],
            "Source=any, Dest=any, Dest Port=any, Source+Dest=any, "
            "Source+Dest Port=any, Dest+Dest Port=any")
        self.assertNotIn("C8", by_name)
        # 1 Finding duy nhat cho moi rule
        self.assertEqual(len(out), 7)

    def test_empty_list_treated_as_any(self):
        r = mk_rule(0, "EMPTY_SRC", src=[], dst=["Y"], svc=["S"])
        out = find_overly_permissive_rules([r])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].detail, "Source=any")

    def test_disabled_rule_still_listed(self):
        # D3: overly_permissive xet CA rule disabled
        r = mk_rule(0, "D_DISABLED", disabled=True, src=["any"], dst=["Y"], svc=["S"])
        out = find_overly_permissive_rules([r])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].rule_name, "D_DISABLED")
        self.assertTrue(out[0].disabled)


class TestUnreachable(unittest.TestCase):
    def test_broad_before_specific_same_action(self):
        r1 = mk_rule(0, "R1", src=["any"], dst=["any"], svc=["any"])
        r2 = mk_rule(1, "R2", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f.rule_name, "R2")
        self.assertIn(SHADOW_UNREACHABLE, f.shadow_reasons)
        self.assertTrue(f.same_action)
        self.assertEqual(f.shadowed_by_rule_name, "R1")
        self.assertEqual(f.shadowed_by_rule_index, 0)
        self.assertIn("Bị che bởi rule 'R1'", f.detail)

    def test_different_action_high_risk(self):
        r1 = mk_rule(0, "R1", action="deny", src=["any"], dst=["any"], svc=["any"])
        r2 = mk_rule(1, "R2", action="allow", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertFalse(f.same_action)
        self.assertTrue(f.detail.startswith("⚠ KHÁC ACTION"))
        self.assertNotEqual(f.action, "deny")  # R2 la allow

    def test_narrower_does_not_shadow(self):
        r1 = mk_rule(0, "NARROW", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r1, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        r2 = mk_rule(1, "TARGET", src=["10.0.0.7"], dst=["10.0.0.8"], svc=["TCP_80"])
        attach_resolved(r2, src=ra_host("10.0.0.7"), dst=ra_host("10.0.0.8"),
                        svc=svc_ports([("tcp", 80, 80)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        self.assertEqual(out, [])

    def test_disabled_rule_not_a_shader(self):
        r1 = mk_rule(0, "R1_DISABLED_BROAD", disabled=True, src=["any"], dst=["any"], svc=["any"])
        r3 = mk_rule(1, "R3_BROAD", src=["any"], dst=["any"], svc=["any"])
        r2 = mk_rule(2, "R2_HOST", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        out = find_shadow_rules([r1, r3, r2], None, None, {}, NOW)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f.rule_name, "R2_HOST")
        # R1 disabled khong duoc tinh la rule che - R3 enable moi la nguoi che
        self.assertEqual(f.shadowed_by_rule_name, "R3_BROAD")

    def test_service_protocol_mismatch_no_shadow(self):
        r1 = mk_rule(0, "R1_TCP", src=["any"], dst=["any"], svc=["TCP_1521"])
        attach_resolved(r1, dst=ra_any(), svc=svc_ports([("tcp", 1521, 1521)]))
        r2 = mk_rule(1, "R2_UDP", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["UDP_689"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("udp", 689, 689)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        self.assertEqual(out, [])

    def test_zone_gating(self):
        r1 = mk_rule(0, "R1_OTHER_ZONE", src=["any"], dst=["any"], svc=["any"],
                     from_zones=["z-internal"], to_zones=["z-internal"])
        r2 = mk_rule(1, "R2_HOST", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"],
                     from_zones=["z-external"], to_zones=["z-external"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        # zone khac nhau -> khong che khuat
        self.assertEqual(out, [])


class TestUnused(unittest.TestCase):
    def _mk_rule(self, index, name):
        return mk_rule(index, name, src=["X"], dst=["Y"], svc=["S"])

    def test_no_hit_creation_45d_ago(self):
        rules = [self._mk_rule(0, "r45")]
        hit = {"r45": hit_stat(0, None, NOW - timedelta(days=45))}
        res = _find_unused_rules(rules, hit, NOW)
        self.assertIn("r45", res)
        self.assertEqual(res["r45"]["no_hit_days"], 45)
        self.assertIn("Chưa từng có hit nào kể từ khi tạo rule (45 ngày", res["r45"]["detail_fragment"])

    def test_no_hit_creation_10d_ago_not_listed(self):
        rules = [self._mk_rule(0, "r10")]
        hit = {"r10": hit_stat(0, None, NOW - timedelta(days=10))}
        res = _find_unused_rules(rules, hit, NOW)
        self.assertEqual(res, {})

    def test_hit_40d_ago_listed(self):
        rules = [self._mk_rule(0, "r40")]
        hit = {"r40": hit_stat(5, NOW - timedelta(days=40), NOW - timedelta(days=200))}
        res = _find_unused_rules(rules, hit, NOW)
        self.assertIn("r40", res)
        self.assertEqual(res["r40"]["no_hit_days"], 40)
        self.assertIn("Không có hits trong 40 ngày", res["r40"]["detail_fragment"])

    def test_hit_5d_ago_not_listed(self):
        rules = [self._mk_rule(0, "r5")]
        hit = {"r5": hit_stat(5, NOW - timedelta(days=5), NOW - timedelta(days=200))}
        res = _find_unused_rules(rules, hit, NOW)
        self.assertEqual(res, {})

    def test_empty_hit_stats_no_result(self):
        rules = [self._mk_rule(0, "rA")]
        res = _find_unused_rules(rules, {}, NOW)
        self.assertEqual(res, {})

    def test_stat_missing_rule_skipped(self):
        # hit_stats khong co du lieu cho 1 rule -> bo qua, khong doan
        rules = [self._mk_rule(0, "no_stat")]
        res = _find_unused_rules(rules, {}, NOW)
        self.assertEqual(res, {})


class TestShadowMerge(unittest.TestCase):
    def test_empty_hit_stats_unreachable_still_runs(self):
        # D10: hit_stats rong -> nhanh UNUSED khong crash, UNREACHABLE van chay
        r1 = mk_rule(0, "R1", src=["any"], dst=["any"], svc=["any"])
        r2 = mk_rule(1, "R2", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        out = find_shadow_rules([r1, r2], None, None, {}, NOW)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].shadow_reasons, [SHADOW_UNREACHABLE])

    def test_both_reasons_single_finding(self):
        r1 = mk_rule(0, "R1", src=["any"], dst=["any"], svc=["any"])
        r2 = mk_rule(1, "R2", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r2, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        hit = {"R2": hit_stat(0, None, NOW - timedelta(days=45))}
        out = find_shadow_rules([r1, r2], None, None, hit, NOW)
        self.assertEqual(len(out), 1)  # DUNG 1 Finding, khong tao 2 dong
        f = out[0]
        self.assertEqual(f.shadow_reasons, [SHADOW_UNREACHABLE, SHADOW_UNUSED])
        self.assertIn(" | ", f.detail)
        self.assertEqual(f.shadowed_by_rule_name, "R1")   # co ca field nhanh UNREACHABLE
        self.assertEqual(f.no_hit_days, 45)               # co ca field nhanh UNUSED
        self.assertEqual(f.hit_count, 0)

    def test_unused_only_finding(self):
        r = mk_rule(0, "ONLY_UNUSED", src=["10.0.0.5"], dst=["10.0.0.6"], svc=["TCP_1521"])
        attach_resolved(r, src=ra_host("10.0.0.5"), dst=ra_host("10.0.0.6"),
                        svc=svc_ports([("tcp", 1521, 1521)]))
        hit = {"ONLY_UNUSED": hit_stat(3, NOW - timedelta(days=60), NOW - timedelta(days=300))}
        out = find_shadow_rules([r], None, None, hit, NOW)
        self.assertEqual(len(out), 1)
        f = out[0]
        self.assertEqual(f.shadow_reasons, [SHADOW_UNUSED])
        self.assertIsNone(f.shadowed_by_rule_name)
        self.assertEqual(f.hit_count, 3)
        self.assertEqual(f.last_hit_date, (NOW - timedelta(days=60)).strftime("%Y-%m-%d"))


if __name__ == "__main__":
    unittest.main()