# -*- coding: utf-8 -*-
"""
Test kiem chung file FIX_HOAN_CHINH (6 buoc) bang du lieu that rule 1264/3289.

- B1: TOP2 nhan dien "exact qua 1 member rieng le" -> chon rule 1264 (thieu
  1 Source IP), khong phai 3289 (thieu 16/16).
- B3: build_live_match_field_report tinh group_coverage_pct -> field cover
  100% in "cover full IP(s)".
- B5: _format_add_line dang "LABEL: gia_tri", khong lan raw_dest/raw_port.
- B6: field mixed (in_rule + exists) -> in_rule chi in ten group; field thuan
  in_rule -> giu "(cover full IP(s))".
(B2/B4 da co test trong test_live_match_early_stop.py; case all-fail + cache
o do cung chinh la kiem chung 7 + 8.)
"""

import ipaddress
import unittest
from unittest import mock

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import (
    build_rule_infos, classify_row, build_live_match_field_report,
    MissingItem,
)
from check_rule_pan.index import (
    DeviceIndex, build_device_index, find_existing_ip_representation,
)
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter
from check_rule_pan import matcher


def _ip(s):
    return int(ipaddress.ip_address(s))


# Request that (Book1.xlsx dong 3): 16 Source IP gom .195, 4 Dest, 8282/TCP.
SRC_15 = ["10.6.160.%d" % i for i in range(180, 195)]
SRC_MISSING = "10.6.160.195"
SRC_16 = SRC_15 + [SRC_MISSING]
DST_4 = ["10.0.72.165", "10.0.72.116", "10.4.72.165", "10.4.72.146"]


def _host_objs(addr_objs, prefix, ips):
    members = []
    for i, ip in enumerate(ips):
        nm = "%s_H%d" % (prefix, i)
        addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip),
                                      display=ip)
        members.append(nm)
    return members


def _real_infos():
    addr_objs = {}
    # Prometheus-Prod-GR-SVR: cover 15/16 (thieu .195).
    prom = _host_objs(addr_objs, "PROM", SRC_15)
    # Notify-GR-SRV: khop tuyet doi 4/4 Dest.
    notify = _host_objs(addr_objs, "NOTIFY", DST_4)
    # 2 group Dest khac cua 1264 (10 dia chi khong lien quan).
    coll = _host_objs(addr_objs, "COLL",
                      ["10.9.1.%d" % i for i in range(1, 7)])
    merch = _host_objs(addr_objs, "MERCH",
                       ["10.9.2.%d" % i for i in range(1, 5)])
    addr_groups = {
        "Prometheus-Prod-GR-SVR": AddressGroup("Prometheus-Prod-GR-SVR",
                                               members=prom),
        "Notify-GR-SRV": AddressGroup("Notify-GR-SRV", members=notify),
        "COLLDISB_SRV_GR": AddressGroup("COLLDISB_SRV_GR", members=coll),
        "Merchant-Redis": AddressGroup("Merchant-Redis", members=merch),
    }
    svc_objs = {"TCP_8282": ServiceObject("TCP_8282", "tcp", "8282",
                                          ranges=[(8282, 8282)])}
    rule_1264 = SecurityRule(
        index=1264, name="K8S-Monitor-Prod-002",
        source=["Prometheus-Prod-GR-SVR"],
        destination=["COLLDISB_SRV_GR", "Merchant-Redis", "Notify-GR-SRV"],
        service=["TCP_8282"], application=["any"], action="allow",
        disabled=False)
    rule_3289 = SecurityRule(
        index=3289, name="Optimize-10-0_4-72-num-4684-46",
        source=["Notify-GR-SRV"], destination=["Notify-GR-SRV"],
        service=["TCP_8282"], application=["any"], action="allow",
        disabled=False)
    resolver = GroupResolver(addr_objs, addr_groups)
    return build_rule_infos([rule_1264, rule_3289], resolver,
                            ServiceResolver(svc_objs, {}))


def _real_request():
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(s) for s in SRC_16],
        dest_tokens=[parse_ip_token(s) for s in DST_4],
        port_tokens=[(8282, 8282, "tcp")],
        extra_values=[",".join(SRC_16), ",".join(DST_4), "8282"],
        raw_source=",".join(SRC_16),
        raw_dest=",".join(DST_4),
        raw_port="8282",
    )


class TestStep1Top2ExactMember(unittest.TestCase):
    def test_top2_picks_1264_not_3289(self):
        # Kiem chung 1: TOP2 chon rule 1264 (15/16 Source), src_report thieu
        # dung .195 (khong phai thieu ca 16 IP nhu khi chon nham 3289).
        res = classify_row(_real_request(), _real_infos(), DeviceIndex())
        self.assertEqual(res.tier, "TOP2")
        self.assertEqual(res.rule.name, "K8S-Monitor-Prod-002")
        by_display = {m.display: m.status for m in res.source_report}
        for ip in SRC_15:
            self.assertEqual(by_display.get(ip), "in_rule", ip)
        self.assertEqual(by_display.get(SRC_MISSING), "new")
        # Dest khop tuyet doi qua Notify-GR-SRV.
        self.assertTrue(all(m.status == "in_rule" for m in res.dest_report))


class TestStep3CoveragePct(unittest.TestCase):
    def test_full_covered_field_prints_cover_full(self):
        # Kiem chung 5 (B3): field cover 100% qua LIVE_MATCH -> "cover full
        # IP(s)", khong liet ke IP.
        infos = _real_infos()
        ri_1264 = next(r for r in infos if r.rule.name == "K8S-Monitor-Prod-002")
        req = _real_request()
        dst_ranges = [(t["start"], t["end"], t) for t in req.dest_tokens]
        report = build_live_match_field_report(
            dst_ranges, ri_1264.dest_members, DeviceIndex())
        self.assertTrue(all(m.status == "in_rule" for m in report))
        self.assertTrue(all(m.group_coverage_pct == 100 for m in report))
        cell, _n = exporter.build_field_cell(report)
        txt = "".join(getattr(b, "text", "") for b in list(cell))
        self.assertIn("cover full IP(s)", txt)
        for ip in DST_4:
            self.assertNotIn(ip, txt)


class TestStep5FormatAddLine(unittest.TestCase):
    def test_no_raw_dest_port_leak(self):
        # Kiem chung 4 (B5): "ADD SOURCE: ..." khong chua raw_dest/raw_port.
        req = _real_request()
        assert "10.0.72.165" in req.raw_dest and "8282" in req.raw_port
        res = matcher.RowResult(
            row=req, tier="TOP4", rule=None,
            source_report=[MissingItem(_ip(SRC_MISSING), SRC_MISSING, "new",
                                       None, None)],
            dest_report=[], missing_ports=[])
        line = exporter._format_add_line("ADD SOURCE", res)
        self.assertEqual(line, "ADD SOURCE: %s" % SRC_MISSING)
        self.assertNotIn(req.raw_dest, line)
        self.assertNotIn(req.raw_port, line)


class TestStep6MixedField(unittest.TestCase):
    def test_mixed_hides_cover_detail_pure_keeps_full(self):
        # Kiem chung 6 (B6) - CAP NHAT 09/2026 (gom nhom/sap xep Source-Dest):
        # field co in_rule + exists VAN hien ro chi tiet IP tung group (khong
        # con rut gon chi ten group); field thuan in_rule giu "(cover full IP(s))".
        mixed = [
            MissingItem(_ip(SRC_15[0]), SRC_15[0], "in_rule",
                        "Prometheus-Prod-GR-SVR", "group",
                        group_coverage_pct=94),
            MissingItem(_ip(SRC_MISSING), "Host_10.6.160.195", "exists",
                        "Host_10.6.160.195", "host"),
        ]
        cell, _n = exporter.build_field_cell(mixed)
        txt = "".join(getattr(b, "text", "") for b in list(cell))
        self.assertIn("Prometheus-Prod-GR-SVR", txt)
        self.assertIn("cover:", txt)
        self.assertIn(SRC_15[0], txt)

        pure = [
            MissingItem(_ip(DST_4[0]), DST_4[0], "in_rule",
                        "Notify-GR-SRV", "group", group_coverage_pct=100),
        ]
        cell2, _n2 = exporter.build_field_cell(pure)
        txt2 = "".join(getattr(b, "text", "") for b in list(cell2))
        self.assertIn("cover full IP(s)", txt2)


class TestStep2EarlyStopRealCase(unittest.TestCase):
    def test_live_match_finds_1264_with_one_allow(self):
        # Kiem chung 2 (B2): 1 combo allow -> LIVE_MATCH rule 1264, khong can
        # test het; Name Rule dung khuon moi "ADD SOURCE: .195".
        infos = _real_infos()
        row = _real_request()

        def _fake(*args, **kwargs):
            s_ip = args[2]
            if s_ip == SRC_MISSING:
                return {"action": "drop", "rule_name": "CleanupRule"}
            return {"action": "allow", "rule_name": "K8S-Monitor-Prod-002"}

        with mock.patch.object(matcher, "fetch_security_policy_match",
                               side_effect=_fake):
            # BAN PANORAMA (0.5): Live Match BAT BUOC target=<serial firewall>.
            res = classify_row(row, infos, DeviceIndex(),
                               mgmt_ip="1.2.3.4", api_key="KEY",
                               target_serial="001122334455")
        self.assertEqual(res.tier, "LIVE_MATCH")
        self.assertEqual(res.rule.name, "K8S-Monitor-Prod-002")
        # Kiem chung 3 (B4): report con thieu -> action 'add'.
        self.assertEqual(exporter._compute_action_level(res), "add")
        cell, _n = exporter.build_name_rule_cell(res)
        txt = "".join(getattr(b, "text", "") for b in list(cell))
        # Ket qua mong doi file FINAL: "K8S-Monitor-Prod-002\nADD SOURCE: ...195".
        self.assertIn("K8S-Monitor-Prod-002", txt)
        self.assertIn("ADD SOURCE: %s" % SRC_MISSING, txt)
        self.assertNotIn("10.0.72.165", txt)
        self.assertNotIn("8282", txt)


class TestStep7NoWideShoving(unittest.TestCase):
    def _real_like_index(self):
        # Device that: group NBG-BILL-GR-SRV co 1 member Range rong
        # 10.6.160.100-250 + 1 host object rieng Host_10.6.160.195.
        addr_objs = {
            "NBG_RANGE": AddressObject(
                "NBG_RANGE", "range", start=_ip("10.6.160.100"),
                end=_ip("10.6.160.250"), display="10.6.160.100-10.6.160.250"),
            "Host_10.6.160.195": AddressObject(
                "Host_10.6.160.195", "host", start=_ip("10.6.160.195"),
                end=_ip("10.6.160.195"), display="10.6.160.195"),
        }
        addr_groups = {
            "NBG-BILL-GR-SRV": AddressGroup("NBG-BILL-GR-SRV",
                                            members=["NBG_RANGE"]),
        }
        cfg = {"address_objects": addr_objs, "address_groups": addr_groups}
        resolver = GroupResolver(addr_objs, addr_groups)
        return build_device_index(cfg, resolver, ServiceResolver({}, {}))

    def test_195_resolves_to_host_not_wide_group(self):
        # Kiem chung 12 (B7): .195 co host object rieng -> tra host, KHONG bi
        # nhet vao group co Range rong bao trum.
        idx = self._real_like_index()
        self.assertEqual(
            find_existing_ip_representation(_ip("10.6.160.195"), idx),
            ("Host_10.6.160.195", "host"))

    def test_197_without_exact_object_returns_none(self):
        # .197 khong co object nao khop tuyet doi -> None (tang tren bao
        # 'new'/TAO MOI), KHONG bi nhet vao NBG-BILL-GR-SRV.
        idx = self._real_like_index()
        self.assertIsNone(
            find_existing_ip_representation(_ip("10.6.160.197"), idx))


if __name__ == "__main__":
    unittest.main()
