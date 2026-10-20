# -*- coding: utf-8 -*-
"""
resolver.py - GroupResolver / ServiceResolver RIENG cua check_audit (khong
import tu check_rule/check_ip) - chi dung cho thuat toan `shadow` (nhanh
UNREACHABLE, Mục 4.3).

Khac hẳn exact-scope cua check_rule: o day chi can "R1 RONG HON HOAC BANG R2"
(superset, `covers_wide`) - kiem tra "R1 co nuot tron pham vi R2 hay khong".
"""

import threading
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .core import (
    AddressObject, AddressGroup, ServiceObject, ServiceGroup,
    is_literal_ip, parse_cidr_or_ip, parse_service_port,
)


@dataclass
class ResolvedAddr:
    """Tap dia chi da giai (host/range/wide subnet chung 1 list range).
    `covers_wide` mang y nghia superset - R1 rong hon hoac bang R2 la du."""
    ranges: List[Tuple[int, int]] = field(default_factory=list)
    is_any: bool = False
    unresolved: Set[str] = field(default_factory=set)
    _merged_cache: Optional[List[Tuple[int, int]]] = field(default=None, init=False, repr=False, compare=False)

    def _sorted_merged(self) -> List[Tuple[int, int]]:
        if self._merged_cache is not None:
            return self._merged_cache
        if not self.ranges:
            self._merged_cache = []
            return self._merged_cache
        sorted_ranges = sorted(self.ranges, key=lambda x: (x[0], x[1]))
        merged: List[Tuple[int, int]] = [sorted_ranges[0]]
        for a, b in sorted_ranges[1:]:
            pa, pb = merged[-1]
            if a <= pb + 1:
                merged[-1] = (pa, max(pb, b))
            else:
                merged.append((a, b))
        self._merged_cache = merged
        return self._merged_cache

    def covers_range_wide(self, start: int, end: int) -> bool:
        if self.is_any:
            return True
        merged = self._sorted_merged()
        if not merged:
            return False
        import bisect
        starts = [r[0] for r in merged]
        idx = bisect.bisect_right(starts, start) - 1
        if idx < 0:
            return False
        a, b = merged[idx]
        return a <= start and end <= b

    def covers(self, other: 'ResolvedAddr') -> bool:
        """Self (R1) co bao phu toan bo other (R2) hay khong (superset)."""
        if self.is_any:
            return True
        if other.is_any:
            return False
        return all(self.covers_range_wide(a, b) for a, b in other.ranges)

    def merge(self, other: 'ResolvedAddr'):
        self.ranges += other.ranges
        self.is_any = self.is_any or other.is_any
        self.unresolved |= other.unresolved
        self._merged_cache = None


class GroupResolver:
    def __init__(self, address_objects: Dict[str, AddressObject],
                 address_groups: Dict[str, AddressGroup], log_func=None):
        self.address_objects = address_objects
        self.address_groups = address_groups
        self.log = log_func or (lambda msg: None)
        self._cache: Dict[str, ResolvedAddr] = {}
        self._lock = threading.Lock()

    def resolve(self, name: str, visiting: FrozenSet[str] = frozenset()) -> ResolvedAddr:
        if name == "any":
            return ResolvedAddr(is_any=True)
        with self._lock:
            if name in self._cache:
                return self._cache[name]
        if name in visiting:
            self.log(f"CANH BAO: circular reference address tai '{name}' - bo qua, coi nhu rong")
            return ResolvedAddr()
        result = self._compute(name, visiting | {name})
        with self._lock:
            self._cache[name] = result
        return result

    def _compute(self, name: str, visiting: FrozenSet[str]) -> ResolvedAddr:
        r = ResolvedAddr()

        if is_literal_ip(name):
            bounds = parse_cidr_or_ip(name)
            if bounds is not None:
                r.ranges.append(bounds)
                return r
            return r

        obj = self.address_objects.get(name)
        if obj is not None:
            if obj.kind in ("host", "range", "wide"):
                r.ranges.append((obj.start, obj.end))
            elif obj.kind == "fqdn":
                r.unresolved.add(name)
                self.log(f"CANH BAO: object '{name}' la FQDN, khong resolve ra IP (bo qua)")
            else:
                r.unresolved.add(name)
            return r

        grp = self.address_groups.get(name)
        if grp is not None:
            if not grp.members:
                self.log(f"CANH BAO: address-group '{name}' rong members")
            for m in grp.members:
                r.merge(self.resolve(m, visiting))
            return r

        r.unresolved.add(name)
        self.log(f"CANH BAO: khong tim thay Address Object/Group '{name}'")
        return r


@dataclass
class ResolvedService:
    """Service da giai: is_any / is_app_default (application-default) + cac port
    (proto, start, end). `covers` mang y nghia "R1 cho phep toan bo protocol/port R2"."""
    is_any: bool = False
    is_app_default: bool = False
    applications: List[str] = field(default_factory=list)
    ports: List[Tuple[Optional[str], int, int]] = field(default_factory=list)
    _proto_cache: Optional[Dict[Optional[str], List[Tuple[int, int]]]] = field(default=None, init=False, repr=False, compare=False)

    def _sorted_by_proto(self) -> Dict[Optional[str], List[Tuple[int, int]]]:
        if self._proto_cache is not None:
            return self._proto_cache
        grouped: Dict[Optional[str], List[Tuple[int, int]]] = {}
        for p, a, b in self.ports:
            grouped.setdefault(p, []).append((a, b))
        result: Dict[Optional[str], List[Tuple[int, int]]] = {}
        for proto, lst in grouped.items():
            lst.sort(key=lambda x: (x[0], x[1]))
            merged: List[Tuple[int, int]] = [lst[0]] if lst else []
            for a, b in lst[1:]:
                pa, pb = merged[-1]
                if a <= pb + 1:
                    merged[-1] = (pa, max(pb, b))
                else:
                    merged.append((a, b))
            result[proto] = merged
        self._proto_cache = result
        return self._proto_cache

    def _covers_port(self, proto: Optional[str], start: int, end: int) -> bool:
        merged = self._sorted_by_proto().get(proto)
        if not merged:
            return False
        import bisect
        starts = [r[0] for r in merged]
        idx = bisect.bisect_right(starts, start) - 1
        if idx < 0:
            return False
        a, b = merged[idx]
        return a <= start and end <= b

    def covers(self, other: 'ResolvedService') -> bool:
        if self.is_any:
            return True
        if other.is_any:
            return False
        if self.is_app_default:
            if not other.is_app_default:
                return False
            if "any" in self.applications or not self.applications:
                return bool(self.applications) and ("any" in self.applications or not other.applications)
            return set(self.applications) >= set(other.applications)
        if other.is_app_default:
            # R1 dung service cu the (co port) khong the "bao chup" application-default
            return False
        return all(self._covers_port(p, a, b) for (p, a, b) in other.ports)

    def merge(self, other: 'ResolvedService'):
        self.is_any = self.is_any or other.is_any
        self.is_app_default = self.is_app_default or other.is_app_default
        self.applications = list(dict.fromkeys(self.applications + other.applications))
        self.ports += other.ports
        self._proto_cache = None


class ServiceResolver:
    def __init__(self, service_objects: Dict[str, ServiceObject],
                 service_groups: Dict[str, ServiceGroup], log_func=None):
        self.service_objects = service_objects
        self.service_groups = service_groups
        self.log = log_func or (lambda msg: None)
        self._cache: Dict[str, ResolvedService] = {}

    def resolve_name(self, name: str, visiting: FrozenSet[str] = frozenset()) -> ResolvedService:
        if name == "any":
            return ResolvedService(is_any=True)
        if name in self._cache:
            return self._cache[name]
        if name in visiting:
            self.log(f"CANH BAO: circular reference service tai '{name}' - bo qua, coi nhu rong")
            return ResolvedService()

        r = ResolvedService()
        obj = self.service_objects.get(name)
        if obj is not None:
            proto = obj.protocol if obj.protocol in ("tcp", "udp") else None
            for a, b in parse_service_port(obj.port_raw):
                r.ports.append((proto, a, b))
            self._cache[name] = r
            return r

        grp = self.service_groups.get(name)
        if grp is not None:
            for m in grp.members:
                r.merge(self.resolve_name(m, visiting | {name}))
            self._cache[name] = r
            return r

        self.log(f"CANH BAO: khong tim thay Service Object/Group '{name}'")
        self._cache[name] = r
        return r

    def resolve_rule_service(self, service_names: List[str], applications: List[str]) -> ResolvedService:
        r = ResolvedService()
        for nm in service_names:
            if nm == "application-default":
                r.is_app_default = True
                r.applications = list(dict.fromkeys(applications))
                continue
            if nm == "any":
                r.is_any = True
                continue
            r.merge(self.resolve_name(nm))
        return r