# -*- coding: utf-8 -*-
"""
Test cho fix wide_full_match (09/2026 - CHECK RULE):
Rule cover du ca 3 chieu qua object RONG (subnet/group) van bi gan nhan
"GAN DUNG - can xac nhan" thay vi FULL MATCH.

Case goc: rule "Push log to Kafka Prod-1" - Source = Net_10.0.0.0/8 (wide),
Dest = group RONG HON 5 IP can, Service group chua range 9092-9096 bao tron
port 9092. Cover du ca 3 chieu nhung truot TOP1/TOP1.1 (wide=False) -> roi
xuong near_top2 (TOP4). Fix: them field RowResult.nearest_fully_covered +
tang hien thi 'wide_full_match' (xanh duong rieng) trong exporter.
"""

import ipaddress
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, ServiceGroup, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow
from check_rule_pan import exporter


def _ip(s):
    return int(ipaddress.ip_address(s))


SRC_23 = ["10.0.88.%d" % i for i in range(161, 184)]  # 161..183 = 23 IP
DST_5 = ["192.168.10.%d" % i for i in range(1, 6)]    # 5 IP


def _make_request(srcs, dsts, port=9092, proto="tcp"):
    src_tokens = [parse_ip_token(s) for s in srcs]
    dst_tokens = [parse_ip_token(s) for s in dsts]
    return RequestRow(
        row_number=2,
        source_tokens=src_tokens,
        dest_tokens=dst_tokens,
        port_tokens=[(port, port, proto)],
        extra_values=[",".join(srcs), ",".join(dsts), str(port)],
        raw_source=",".join(srcs),
        raw_dest=",".join(dsts),
        raw_port=str(port),
    )


def _std_service_objects():
    return {
        "TCP_8080": ServiceObject("TCP_8080", "tcp", "8080", ranges=[(8080, 8080)]),
        "TCP_9090": ServiceObject("TCP_9090", "tcp", "9090", ranges=[(9090, 9090)]),
        "TCP_9092_9096": ServiceObject("TCP_9092_9096", "tcp", "9092-9096", ranges=[(9092, 9096)]),
    }, {"KAFKA_SVC_GR": ServiceGroup("KAFKA_SVC_GR",
                                     members=["TCP_8080", "TCP_9090", "TCP_9092_9096"])}


def _kafka_rule(name="Push log to Kafka Prod-1", src=None, dst=None):
    return SecurityRule(
        index=10, name=name,
        source=src or ["Net_10.0.0.0/8"],
        destination=dst or ["Kafka-prod-GR-SVR"],
        service=["KAFKA_SVC_GR"], application=["any"],
        action="allow", disabled=False,
    )


def _build_infos(rule, addr_objs, addr_groups):
    svc_objs, svc_groups = _std_service_objects()
    resolver = GroupResolver(addr_objs, addr_groups)
    svc_resolver = ServiceResolver(svc_objs, svc_groups)
    return build_rule_infos([rule], resolver, svc_resolver)


def _wide_net_obj():
    return AddressObject("Net_10.0.0.0/8", "wide",
                         start=_ip("10.0.0.0"), end=_ip("10.255.255.255"),
                         display="10.0.0.0/8")


def _dest_group_objs(extra_count=3):
    """Dest group RONG HON input: gom ca 5 IP can + vai IP thua."""
    objs = {}
    members = []
    for i, ip in enumerate(DST_5):
        nm = "KAFKA_H%d" % i
        objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip), display=ip)
        members.append(nm)
    for j in range(extra_count):
        ip = "192.168.99.%d" % (10 + j)
        nm = "KAFKA_EXTRA%d" % j
        objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip), display=ip)
        members.append(nm)
    return objs, members


class TestWideFullMatchNearTop2(unittest.TestCase):
    def test_near_top2_wide_fully_covered(self):
        """Case goc trong anh chup: Source wide + Dest group rong + Port du."""
        addr_objs = {"Net_10.0.0.0/8": _wide_net_obj()}
        d_objs, d_members = _dest_group_objs(extra_count=3)
        addr_objs.update(d_objs)
        addr_groups = {"Kafka-prod-GR-SVR": AddressGroup("Kafka-prod-GR-SVR", members=d_members)}
        rule = _kafka_rule()
        infos = _build_infos(rule, addr_objs, addr_groups)
        row = _make_request(SRC_23, DST_5)
        res = classify_row(row, infos, DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top2")
        self.assertIsNone(res.nearest_missing_side)
        self.assertTrue(res.nearest_fully_covered)
        self.assertEqual(exporter._compute_action_level(res), "wide_full_match")

    def test_near_top2_genuinely_missing_source_stays_near_match(self):
        """Doi chung non-regression: Source THAT SU con thieu -> van mau cam."""
        # Source chi cover 5/23 IP dau (exact host), con lai thieu that.
        addr_objs = {}
        src_members = []
        for i, ip in enumerate(SRC_23[:5]):
            nm = "SRC_H%d" % i
            addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip), display=ip)
            src_members.append(nm)
        d_objs, d_members = _dest_group_objs(extra_count=3)
        addr_objs.update(d_objs)
        addr_groups = {
            "SRC_PARTIAL": AddressGroup("SRC_PARTIAL", members=src_members),
            "Kafka-prod-GR-SVR": AddressGroup("Kafka-prod-GR-SVR", members=d_members),
        }
        rule = _kafka_rule(src=["SRC_PARTIAL"])
        infos = _build_infos(rule, addr_objs, addr_groups)
        row = _make_request(SRC_23, DST_5)
        res = classify_row(row, infos, DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top2")
        self.assertEqual(res.nearest_missing_side, "source")
        self.assertFalse(res.nearest_fully_covered)
        self.assertEqual(exporter._compute_action_level(res), "near_match")


class TestWideFullMatchNearTop3(unittest.TestCase):
    def _near_top3_rule(self, dest_names):
        return SecurityRule(
            index=10, name="Wide Src Rule",
            source=["Net_10.0.0.0/8"],
            destination=list(dest_names),
            service=["KAFKA_SVC_GR"], application=["any"],
            action="allow", disabled=False,
        )

    def test_near_top3_wide_fully_covered(self):
        """Doi xung near_top2: Source wide (khong exact-scope) + Dest da du."""
        # Dest='any' de tranh roi vao near_top2 (uu tien tuyet doi) - van dam bao
        # dest_full de nearest_side=None -> fully_covered=True theo dung spec.
        addr_objs = {"Net_10.0.0.0/8": _wide_net_obj()}
        rule = self._near_top3_rule(["any"])
        infos = _build_infos(rule, addr_objs, {})
        row = _make_request(SRC_23, DST_5)
        res = classify_row(row, infos, DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top3")
        self.assertIsNone(res.nearest_missing_side)
        self.assertTrue(res.nearest_fully_covered)
        self.assertEqual(exporter._compute_action_level(res), "wide_full_match")

    def test_near_top3_genuinely_missing_dest_stays_near_match(self):
        """Doi chung non-regression: Dest THAT SU con thieu -> van mau cam."""
        addr_objs = {"Net_10.0.0.0/8": _wide_net_obj()}
        d_members = []
        for i, ip in enumerate(DST_5[:2]):  # chi cover 2/5
            nm = "DST_H%d" % i
            addr_objs[nm] = AddressObject(nm, "host", start=_ip(ip), end=_ip(ip), display=ip)
            d_members.append(nm)
        addr_groups = {"DST_PARTIAL": AddressGroup("DST_PARTIAL", members=d_members)}
        rule = self._near_top3_rule(["DST_PARTIAL"])
        infos = _build_infos(rule, addr_objs, addr_groups)
        row = _make_request(SRC_23, DST_5)
        res = classify_row(row, infos, DeviceIndex())
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top3")
        self.assertEqual(res.nearest_missing_side, "dest")
        self.assertFalse(res.nearest_fully_covered)
        self.assertEqual(exporter._compute_action_level(res), "near_match")


class TestWideFullMatchDisplay(unittest.TestCase):
    def _wide_res(self):
        addr_objs = {"Net_10.0.0.0/8": _wide_net_obj()}
        d_objs, d_members = _dest_group_objs(extra_count=3)
        addr_objs.update(d_objs)
        addr_groups = {"Kafka-prod-GR-SVR": AddressGroup("Kafka-prod-GR-SVR", members=d_members)}
        infos = _build_infos(_kafka_rule(), addr_objs, addr_groups)
        return classify_row(_make_request(SRC_23, DST_5), infos, DeviceIndex())

    def test_fill_and_cell(self):
        res = self._wide_res()
        fill = exporter._action_fill("wide_full_match")
        self.assertIsNotNone(fill)
        self.assertEqual(str(fill.fgColor.rgb), exporter.WIDE_MATCH_FILL)
        # Mau moi KHONG trung 5 mau action-level dang dung.
        for other in (exporter.GREEN_FILL, exporter.ORANGE_FILL, exporter.RED_FILL,
                      exporter.BLUE_FILL, exporter.CANDIDATE_FILL):
            self.assertNotEqual(exporter.WIDE_MATCH_FILL, other)
        cell, _n = exporter.build_name_rule_cell(res)
        full_text = "".join(b.text for b in cell.rich_paragraphs[0].r) \
            if hasattr(cell, "rich_paragraphs") else str(cell)
        # CellRichText: duyet TextBlock truc tiep neu co the.
        try:
            blocks = list(cell)
            full_text = "".join(getattr(b, "text", "") for b in blocks)
        except Exception:
            pass
        self.assertIn("DA DUOC CHO PHEP", full_text)
        self.assertNotIn("+ ADD", full_text)


if __name__ == "__main__":
    unittest.main()
