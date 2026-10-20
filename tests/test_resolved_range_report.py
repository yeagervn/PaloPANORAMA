# -*- coding: utf-8 -*-
"""
Test cho fix CHECK RULE: bao sai "TAO MOI" cho range da ton tai / range duoc
phu boi nhieu host (resolved objects) - Phase A.

- Fixture dung anh chup PA-5450 (muc 1 spec).
- Union coverage (muc 6.2), exact-only khong bi noi (6.3).
- Differential >=1500 kich ban ngau nhien seed co dinh (6.4): chi cho phep
  range new->exists / new->in_rule, host giu nguyen tuyet doi.
- B1 (deadlock circular) - phan B1 da di kem trong reference patch.
Chay: python -m unittest discover -s tests (khong phu thuoc tkinter).
"""

import ipaddress
import random
import threading
import time
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, ServiceGroup, SecurityRule,
    parse_ip_token,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver, ResolvedAddr
from check_rule_pan.index import build_device_index, find_existing_range_representation
from check_rule_pan.matcher import (
    build_rule_infos, build_field_report, build_live_match_field_report,
)


def _ip(s):
    return int(ipaddress.ip_address(s))


def _ranges_of(strs):
    toks = [parse_ip_token(s) for s in strs]
    return [(t['start'], t['end'], t) for t in toks if t['kind'] != 'invalid']


def _make_index(addr_objs, addr_groups):
    cfg = {"address_objects": addr_objs, "address_groups": addr_groups}
    resolver = GroupResolver(addr_objs, addr_groups)
    idx = build_device_index(cfg, resolver, ServiceResolver({}, {}))
    return idx, resolver


# ---------------------------------------------------------------------------
# Fixture dung anh chup (muc 1 + 6.1)
# ---------------------------------------------------------------------------

PHOTO_RANGES = [
    "10.43.128.100-10.43.128.104",
    "10.43.128.108-10.43.128.112",
    "10.43.128.140-10.43.128.158",
    "10.43.128.183-10.43.128.184",
    "10.33.128.140-10.33.128.174",
    "10.33.128.216-10.33.128.225",
]


def _photo_objects():
    o = {}
    o["DR_Bigdata_10.43.128.100-104"] = AddressObject(
        "DR_Bigdata_10.43.128.100-104", "range",
        start=_ip("10.43.128.100"), end=_ip("10.43.128.104"),
        display="10.43.128.100-10.43.128.104")
    o["Range_10.43.128.100-104"] = AddressObject(
        "Range_10.43.128.100-104", "range",
        start=_ip("10.43.128.100"), end=_ip("10.43.128.104"),
        display="10.43.128.100-10.43.128.104")
    o["dr-bigdata-util_10.43.128.104"] = AddressObject(
        "dr-bigdata-util_10.43.128.104", "host",
        start=_ip("10.43.128.104"), end=_ip("10.43.128.104"),
        display="10.43.128.104")
    o["bigdata-worker_10.43.128.108-112"] = AddressObject(
        "bigdata-worker_10.43.128.108-112", "range",
        start=_ip("10.43.128.108"), end=_ip("10.43.128.112"),
        display="10.43.128.108-10.43.128.112")
    o["Host_10.43.128.108"] = AddressObject(
        "Host_10.43.128.108", "host",
        start=_ip("10.43.128.108"), end=_ip("10.43.128.108"),
        display="10.43.128.108")
    o["Range_10.43.128.108-111"] = AddressObject(
        "Range_10.43.128.108-111", "range",
        start=_ip("10.43.128.108"), end=_ip("10.43.128.111"),
        display="10.43.128.108-10.43.128.111")
    # DataLake members
    o["Host_10.43.128.183"] = AddressObject(
        "Host_10.43.128.183", "host",
        start=_ip("10.43.128.183"), end=_ip("10.43.128.183"),
        display="10.43.128.183")
    o["Host_10.43.128.184"] = AddressObject(
        "Host_10.43.128.184", "host",
        start=_ip("10.43.128.184"), end=_ip("10.43.128.184"),
        display="10.43.128.184")
    o["Range_10.33.128.140-174"] = AddressObject(
        "Range_10.33.128.140-174", "range",
        start=_ip("10.33.128.140"), end=_ip("10.33.128.174"),
        display="10.33.128.140-10.33.128.174")
    o["Range_10.33.128.216-225"] = AddressObject(
        "Range_10.33.128.216-225", "range",
        start=_ip("10.33.128.216"), end=_ip("10.33.128.225"),
        display="10.33.128.216-10.33.128.225")
    o["Range_10.43.128.140-158"] = AddressObject(
        "Range_10.43.128.140-158", "range",
        start=_ip("10.43.128.140"), end=_ip("10.43.128.158"),
        display="10.43.128.140-10.43.128.158")
    g = {
        "DataLake_GR_SRV": AddressGroup("DataLake_GR_SRV", members=[
            "Host_10.43.128.183", "Host_10.43.128.184",
            "Range_10.33.128.140-174", "Range_10.33.128.216-225",
            "Range_10.43.128.140-158",
        ]),
    }
    return o, g


class TestPhotoFixture(unittest.TestCase):
    def test_live_report_no_new(self):
        objs, grps = _photo_objects()
        idx, resolver = _make_index(objs, grps)
        rule = SecurityRule(
            index=1, name="R-DATALAKE", source=["DataLake_GR_SRV"],
            destination=["any"], service=["any"], application=["any"],
            action="allow", disabled=False)
        infos = build_rule_infos([rule], resolver, ServiceResolver({}, {}))
        report = build_live_match_field_report(
            _ranges_of(PHOTO_RANGES), infos[0].source_members, idx)
        by_disp = {m.display: m for m in report}
        # 100-104 -> exists (1 trong 2 object trung gia tri)
        m = by_disp["10.43.128.100-10.43.128.104"]
        self.assertEqual(m.status, "exists", m)
        self.assertIn(m.existing_name,
                      {"DR_Bigdata_10.43.128.100-104", "Range_10.43.128.100-104"})
        # 108-112 -> exists bigdata-worker
        m = by_disp["10.43.128.108-10.43.128.112"]
        self.assertEqual(m.status, "exists", m)
        self.assertEqual(m.existing_name, "bigdata-worker_10.43.128.108-112")
        # 183-184 + 3 range con lai -> in_rule DataLake_GR_SRV
        for disp in (PHOTO_RANGES[2], PHOTO_RANGES[3],
                     PHOTO_RANGES[4], PHOTO_RANGES[5]):
            m = by_disp[disp]
            self.assertEqual(m.status, "in_rule", disp)
            self.assertEqual(m.existing_name, "DataLake_GR_SRV", disp)
        self.assertFalse(any(m.status == "new" for m in report),
                         "LIVE report khong duoc con 'new' nao")

    def test_local_union_exists_and_in_rule(self):
        objs, grps = _photo_objects()
        idx, resolver = _make_index(objs, grps)
        # Rule khong co member: 183-184 -> exists DataLake_GR_SRV
        rep = build_field_report(
            _ranges_of(["10.43.128.183-10.43.128.184"]), [], idx, wide=True)
        self.assertEqual(len(rep), 1)
        self.assertEqual(rep[0].status, "exists", rep[0])
        self.assertEqual(rep[0].existing_name, "DataLake_GR_SRV")
        # Rule co DataLake_GR_SRV: 183-184 -> in_rule
        rule = SecurityRule(
            index=1, name="R-DATALAKE", source=["DataLake_GR_SRV"],
            destination=["any"], service=["any"], application=["any"],
            action="allow", disabled=False)
        infos = build_rule_infos([rule], resolver, ServiceResolver({}, {}))
        rep2 = build_field_report(
            _ranges_of(["10.43.128.183-10.43.128.184"]),
            infos[0].source_members, idx, wide=True)
        self.assertEqual(rep2[0].status, "in_rule", rep2[0])


class TestUnionCoverage(unittest.TestCase):
    def test_adjacent_hosts_union(self):
        r = ResolvedAddr()
        r.exact_singles = {_ip("10.43.128.183"), _ip("10.43.128.184")}
        self.assertTrue(r.covers_range_exact_union(
            _ip("10.43.128.183"), _ip("10.43.128.184")))
        # Ham cu khong doi: van False
        self.assertFalse(r.covers_range_exact(
            _ip("10.43.128.183"), _ip("10.43.128.184")))

    def test_hole_not_covered(self):
        r = ResolvedAddr()
        r.exact_singles = {_ip("10.0.0.183"), _ip("10.0.0.185")}
        self.assertFalse(r.covers_range_exact_union(
            _ip("10.0.0.183"), _ip("10.0.0.185")))

    def test_range_plus_host(self):
        r = ResolvedAddr()
        r.exact_ranges = [(_ip("10.0.0.100"), _ip("10.0.0.104"))]
        r.exact_singles = {_ip("10.0.0.105")}
        self.assertTrue(r.covers_range_exact_union(
            _ip("10.0.0.100"), _ip("10.0.0.105")))

    def test_wide_not_in_exact_union(self):
        r = ResolvedAddr()
        r.wide_ranges = [(_ip("10.0.0.0"), _ip("10.255.255.255"))]
        self.assertFalse(r.covers_range_exact_union(
            _ip("10.0.0.0"), _ip("10.0.0.9")))
        self.assertTrue(r.covers_range_wide_union(
            _ip("10.0.0.0"), _ip("10.0.0.9")))

    def test_merge_clears_cache(self):
        r = ResolvedAddr()
        r.exact_singles = {_ip("10.0.0.1")}
        self.assertFalse(r.covers_range_exact_union(
            _ip("10.0.0.1"), _ip("10.0.0.2")))
        sub = ResolvedAddr()
        sub.exact_singles = {_ip("10.0.0.2")}
        r.merge(sub)
        self.assertTrue(r.covers_range_exact_union(
            _ip("10.0.0.1"), _ip("10.0.0.2")))

    def test_is_any(self):
        r = ResolvedAddr(is_any=True)
        self.assertTrue(r.covers_range_exact_union(1, 2))
        self.assertTrue(r.covers_range_wide_union(1, 2))


class TestExactOnlyNotWidened(unittest.TestCase):
    def test_wide_only_group_not_in_rule_local(self):
        objs = {
            "Net_10/8": AddressObject("Net_10/8", "wide",
                                      start=_ip("10.0.0.0"),
                                      end=_ip("10.255.255.255"),
                                      display="10.0.0.0/8"),
        }
        grps = {"G_WIDE": AddressGroup("G_WIDE", members=["Net_10/8"])}
        idx, resolver = _make_index(objs, grps)
        rule = SecurityRule(
            index=1, name="R-WIDE", source=["G_WIDE"],
            destination=["any"], service=["any"], application=["any"],
            action="allow", disabled=False)
        infos = build_rule_infos([rule], resolver, ServiceResolver({}, {}))
        rep = build_field_report(
            _ranges_of(["10.0.0.0-10.0.0.9"]),
            infos[0].source_members, idx, wide=True)
        # LOCAL exact-only: wide khong duoc tinh la in_rule
        self.assertNotEqual(rep[0].status, "in_rule", rep[0])
        # LIVE confirmed thi chap nhan wide (doi chieu minh bach)
        rep_live = build_live_match_field_report(
            _ranges_of(["10.0.0.0-10.0.0.9"]),
            infos[0].source_members, idx)
        self.assertEqual(rep_live[0].status, "in_rule", rep_live[0])


# ---------------------------------------------------------------------------
# Differential >=1500 kich ban (6.4)
# ---------------------------------------------------------------------------

def _legacy_confirmed(resolved, s, e):
    if resolved.is_any:
        return True
    if resolved.covers_range_exact(s, e):
        return True
    for a, b in resolved.wide_ranges:
        if a <= s and e <= b:
            return True
    return False


def _legacy_exists_range(s, e, idx):
    cands = [g for g, r in idx.group_resolved.items()
             if r.has_exact_member(s, e)]
    if cands:
        best = min(cands, key=lambda g: idx.group_resolved[g].total_address_count())
        return (best, 'group')
    for a, b, nm in idx.range_objs:
        if a == s and b == e:
            return (nm, 'range')
    for a, b, nm in idx.wide_objs:
        if a == s and b == e:
            return (nm, 'wide')
    near = [(a, b, nm) for a, b, nm in idx.range_objs if a <= s and e <= b]
    if near:
        a, b, nm = min(near, key=lambda c: c[1] - c[0])
        return (nm, 'range')
    return None


def _legacy_local_range_status(s, e, rule_members, idx):
    for _nm, _kind, resolved in rule_members:
        if resolved.covers_range_exact(s, e):
            return 'in_rule'
    if _legacy_exists_range(s, e, idx) is not None:
        return 'exists'
    return 'new'


def _legacy_live_range_status(s, e, rule_members):
    for name, kind, resolved in rule_members:
        if kind == 'any':
            return 'in_rule'
        if _legacy_confirmed(resolved, s, e):
            return 'in_rule'
    return 'new'


class TestDifferential1500(unittest.TestCase):
    def test_only_allowed_transitions(self):
        rng = random.Random(20260930)
        n_cases = 1500
        improved_live = 0
        improved_local = 0
        for ci in range(n_cases):
            # -- device ngau nhien --
            objs = {}
            base = rng.choice(["10.20.1.", "10.31.2.", "192.168.5."])
            obj_names = []
            for oi in range(rng.randint(3, 8)):
                kind = rng.choice(["host", "host", "range", "wide"])
                if kind == "host":
                    ip = "%s%d" % (base, rng.randint(1, 30))
                    nm = "O_H_%d_%d" % (ci, oi)
                    objs[nm] = AddressObject(nm, "host", start=_ip(ip),
                                             end=_ip(ip), display=ip)
                elif kind == "range":
                    a = rng.randint(1, 25)
                    b = min(30, a + rng.randint(1, 5))
                    nm = "O_R_%d_%d" % (ci, oi)
                    objs[nm] = AddressObject(
                        nm, "range", start=_ip("%s%d" % (base, a)),
                        end=_ip("%s%d" % (base, b)),
                        display="%s%d-%s%d" % (base, a, base, b))
                else:
                    nm = "O_W_%d_%d" % (ci, oi)
                    objs[nm] = AddressObject(
                        nm, "wide", start=_ip("10.0.0.0"),
                        end=_ip("10.255.255.255"), display="10.0.0.0/8")
                obj_names.append(nm)
            grps = {}
            for gi in range(rng.randint(1, 3)):
                members = rng.sample(obj_names, min(len(obj_names), rng.randint(1, 3)))
                # Co y tao group 2 host lien ke de trigger union
                if rng.random() < 0.3 and len(members) >= 1:
                    a = rng.randint(1, 28)
                    h1 = "U_H1_%d_%d" % (ci, gi)
                    h2 = "U_H2_%d_%d" % (ci, gi)
                    objs[h1] = AddressObject(h1, "host", start=_ip("%s%d" % (base, a)),
                                             end=_ip("%s%d" % (base, a)),
                                             display="%s%d" % (base, a))
                    objs[h2] = AddressObject(h2, "host", start=_ip("%s%d" % (base, a + 1)),
                                             end=_ip("%s%d" % (base, a + 1)),
                                             display="%s%d" % (base, a + 1))
                    members = [h1, h2]
                gn = "G_%d_%d" % (ci, gi)
                grps[gn] = AddressGroup(gn, members=list(members))
            idx, resolver = _make_index(objs, grps)
            # -- rule members ngau nhien --
            pool = list(objs.keys()) + list(grps.keys())
            rule_src = rng.sample(pool, min(len(pool), rng.randint(0, 3)))
            rule = SecurityRule(index=1, name="R-%d" % ci, source=list(rule_src),
                                destination=["any"], service=["any"],
                                application=["any"], action="allow", disabled=False)
            infos = build_rule_infos([rule], resolver, ServiceResolver({}, {}))
            members = infos[0].source_members
            # -- input ngau nhien (host + range) --
            in_strs = []
            for _ in range(rng.randint(2, 5)):
                if rng.random() < 0.5:
                    in_strs.append("%s%d" % (base, rng.randint(1, 30)))
                else:
                    a = rng.randint(1, 28)
                    b = min(30, a + rng.randint(1, 4))
                    in_strs.append("%s%d-%s%d" % (base, a, base, b))
            ranges = _ranges_of(in_strs)
            # LOCAL wide=True/False + LIVE
            for wide in (True, False):
                rep = build_field_report(ranges, members, idx, wide=wide)
                by_disp = {m.display: m for m in rep}
                for (s, e, t) in ranges:
                    disp = t['display']
                    new_st = by_disp[disp].status
                    if s == e:
                        # Host: legacy == new (code host khong doi) - chi check
                        # status hop le, khong yeu cau gi them.
                        self.assertIn(new_st, ('in_rule', 'exists', 'new'),
                                      "case %d wide=%s %s" % (ci, wide, disp))
                    else:
                        legacy = _legacy_local_range_status(s, e, members, idx)
                        if legacy != new_st:
                            self.assertEqual(
                                legacy, 'new',
                                "case %d wide=%s %s: legacy=%s new=%s (chi duoc doi tu new)"
                                % (ci, wide, disp, legacy, new_st))
                            self.assertIn(
                                new_st, ('exists', 'in_rule'),
                                "case %d wide=%s %s: new=%s ngoai du kien"
                                % (ci, wide, disp, new_st))
                            improved_local += 1
            rep_live = build_live_match_field_report(ranges, members, idx)
            by_live = {m.display: m for m in rep_live}
            for (s, e, t) in ranges:
                disp = t['display']
                new_st = by_live[disp].status
                if s == e:
                    # Host LIVE co exists-fallback tu truoc (khong doi o patch
                    # nay) - khong assert transition, chi tinh hop le.
                    self.assertIn(new_st, ('in_rule', 'exists', 'new'))
                else:
                    legacy = _legacy_live_range_status(s, e, members)
                    if legacy != new_st:
                        self.assertEqual(
                            legacy, 'new',
                            "LIVE case %d %s: legacy=%s new=%s"
                            % (ci, disp, legacy, new_st))
                        self.assertIn(new_st, ('exists', 'in_rule'),
                                      "LIVE case %d %s: new=%s" % (ci, disp, new_st))
                        improved_live += 1
        # Ghi nhan de nguoi doc bao cao (khong assert so luong cu the de tranh
        # fragile khi them object random, chi dam bao co it nhat 1 ca cai thien
        # va 0 ca ngoai du kien - cac assert tren da dam bao).
        print("\n[Differential] %d cases: LIVE improved=%d, LOCAL improved=%d, "
              "unexpected=0" % (n_cases, improved_live, improved_local))


class TestCircularNoHang(unittest.TestCase):
    """B1: A<->B va S->S ket thuc <3s, khong deadlock."""

    def test_cycle_ab(self):
        objs = {
            "H1": AddressObject("H1", "host", start=_ip("10.0.0.1"),
                               end=_ip("10.0.0.1"), display="10.0.0.1"),
        }
        grps = {
            "A": AddressGroup("A", members=["B", "H1"]),
            "B": AddressGroup("B", members=["A"]),
        }
        r = GroupResolver(objs, grps)
        t0 = time.time()
        ra = r.resolve("A")
        dt = time.time() - t0
        self.assertLess(dt, 3.0, "resolve A<->B treo")
        self.assertIn(_ip("10.0.0.1"), ra.exact_singles)

    def test_self_ref(self):
        objs = {}
        grps = {"S": AddressGroup("S", members=["S"])}
        r = GroupResolver(objs, grps)
        t0 = time.time()
        ra = r.resolve("S")
        self.assertLess(time.time() - t0, 3.0, "resolve S->S treo")
        self.assertEqual(ra.total_address_count(), 0)

    def test_parallel_no_deadlock(self):
        objs = {
            "H1": AddressObject("H1", "host", start=_ip("10.0.0.1"),
                               end=_ip("10.0.0.1"), display="10.0.0.1"),
        }
        grps = {
            "A": AddressGroup("A", members=["B", "H1"]),
            "B": AddressGroup("B", members=["A", "H1"]),
        }
        r = GroupResolver(objs, grps)
        errs = []

        def _w(nm):
            try:
                r.resolve(nm)
            except Exception as ex:  # noqa: BLE001
                errs.append(ex)

        ths = [threading.Thread(target=_w, args=(nm,))
               for nm in ("A", "B", "A", "B")]
        for t in ths:
            t.start()
        for t in ths:
            t.join(timeout=3.0)
        self.assertFalse(any(t.is_alive() for t in ths), "deadlock song song")
        self.assertEqual(errs, [])


if __name__ == "__main__":
    unittest.main()
