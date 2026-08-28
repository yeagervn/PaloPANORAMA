# -*- coding: utf-8 -*-
"""
resolver_engine.py - Engine resolve Address Object/Group (de quy, cache
thread-safe, chong Circular Reference - THANH PHAN LOI QUAN TRONG NHAT) +
resolve Service Group ra Service Object + parser bieu thuc tag Dynamic
Address Group. (Gop tu dag_filter.py + resolver.py + service_resolver.py cu)
"""

import threading
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

from .core import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from .core import is_literal_ip_or_cidr, netmask_to_match_value, parse_ip_range

# ============================================================================
# DYNAMIC ADDRESS GROUP - TAG FILTER PARSER
# ============================================================================
# ============================================================================
# Ngu phap don gian PAN-OS dung cho Dynamic Address Group filter, vi du:
#   'web-server' and 'production'
#   'db' or 'cache' and not 'decommissioned'
#   ('web' or 'app') and 'prod'

class _DagToken:
    __slots__ = ("kind", "value")
    def __init__(self, kind: str, value: Optional[str] = None):
        self.kind = kind
        self.value = value


def _tokenize_dag_filter(expr: str) -> List[_DagToken]:
    tokens: List[_DagToken] = []
    i, n = 0, len(expr)
    while i < n:
        c = expr[i]
        if c.isspace():
            i += 1
            continue
        if c == "'":
            j = expr.find("'", i + 1)
            if j == -1:
                break
            tokens.append(_DagToken("TAG", expr[i + 1:j]))
            i = j + 1
            continue
        if c == "(":
            tokens.append(_DagToken("LPAREN"))
            i += 1
            continue
        if c == ")":
            tokens.append(_DagToken("RPAREN"))
            i += 1
            continue
        j = i
        while j < n and expr[j].isalpha():
            j += 1
        word = expr[i:j].lower()
        if word in ("and", "or", "not"):
            tokens.append(_DagToken(word.upper()))
            i = j
            continue
        i += 1  # ky tu la, bo qua
    return tokens


def _parse_dag_or(tokens, pos):
    node, pos = _parse_dag_and(tokens, pos)
    while pos < len(tokens) and tokens[pos].kind == "OR":
        pos += 1
        rhs, pos = _parse_dag_and(tokens, pos)
        node = ("or", node, rhs)
    return node, pos


def _parse_dag_and(tokens, pos):
    node, pos = _parse_dag_not(tokens, pos)
    while pos < len(tokens) and tokens[pos].kind == "AND":
        pos += 1
        rhs, pos = _parse_dag_not(tokens, pos)
        node = ("and", node, rhs)
    return node, pos


def _parse_dag_not(tokens, pos):
    if pos < len(tokens) and tokens[pos].kind == "NOT":
        pos += 1
        node, pos = _parse_dag_not(tokens, pos)
        return ("not", node), pos
    return _parse_dag_atom(tokens, pos)


def _parse_dag_atom(tokens, pos):
    if pos >= len(tokens):
        return ("tag", ""), pos
    tok = tokens[pos]
    if tok.kind == "TAG":
        return ("tag", tok.value), pos + 1
    if tok.kind == "LPAREN":
        node, pos = _parse_dag_or(tokens, pos + 1)
        if pos < len(tokens) and tokens[pos].kind == "RPAREN":
            pos += 1
        return node, pos
    return ("tag", ""), pos + 1


def parse_dag_filter(expr: str):
    tokens = _tokenize_dag_filter(expr)
    if not tokens:
        return ("tag", "")
    node, _ = _parse_dag_or(tokens, 0)
    return node


def eval_dag_filter(node, tag_set: Set[str]) -> bool:
    kind = node[0]
    if kind == "tag":
        return node[1] in tag_set
    if kind == "and":
        return eval_dag_filter(node[1], tag_set) and eval_dag_filter(node[2], tag_set)
    if kind == "or":
        return eval_dag_filter(node[1], tag_set) or eval_dag_filter(node[2], tag_set)
    if kind == "not":
        return not eval_dag_filter(node[1], tag_set)
    return False

# ============================================================================
# GROUP / OBJECT RESOLVER (Address)
# ============================================================================
# ============================================================================
# GROUP / OBJECT RESOLVER
# ============================================================================
# Yeu cau quan trong nhat cua spec: KHONG match theo ten object, CHI match
# theo VALUE thuc te, sau khi resolve toan bo Address Group (khong gioi han
# so tang long nhau), chong Circular Reference, va CACHE (moi group chi
# resolve DUY NHAT 1 lan).

class ResolvedValues:
    __slots__ = ("exact_ips", "ranges", "unresolved", "member_details")

    def __init__(self):
        self.exact_ips: Set[str] = set()
        self.ranges: Set[Tuple[int, int]] = set()
        self.unresolved: Set[str] = set()
        # (ten_object_hoac_None, value_that_da_format) cho TUNG leaf object da
        # resolve duoc - dung de xuat Excel hien thi VALUE THAT, khong chi ten.
        self.member_details: Set[Tuple[Optional[str], str]] = set()

    def union(self, other: "ResolvedValues") -> "ResolvedValues":
        r = ResolvedValues()
        r.exact_ips = self.exact_ips | other.exact_ips
        r.ranges = self.ranges | other.ranges
        r.unresolved = self.unresolved | other.unresolved
        r.member_details = self.member_details | other.member_details
        return r


def _display_value(obj: "AddressObject") -> str:
    """Value THAT cua 1 Address Object, dung de hien thi (khong dung ten object,
    vi ten co the gay hieu lam - vi du 'Exadata-X62-10.0.6-DC' thuc ra la range
    10.0.6.101-10.0.6.107 chu khong phai 1 host don)."""
    if obj.kind == "ip-netmask":
        v = obj.raw_value
        return v[:-3] if v.endswith("/32") else v
    if obj.kind == "ip-range":
        return obj.raw_value
    if obj.kind == "fqdn":
        return obj.raw_value
    return obj.raw_value


class GroupResolver:
    def __init__(self, address_objects: Dict[str, AddressObject],
                 address_groups: Dict[str, AddressGroup],
                 registered_ip_tags: Optional[Dict[str, Set[str]]] = None,
                 log_func=None):
        self.address_objects = address_objects
        self.address_groups = address_groups
        self.registered_ip_tags = registered_ip_tags or {}
        self._log = log_func or (lambda msg: None)
        self._lock = threading.Lock()
        self._cache: Dict[str, ResolvedValues] = {}
        self._inflight: Dict[str, threading.Event] = {}
        self._dag_ast_cache: Dict[str, tuple] = {}

    def resolve(self, name: str, visiting: FrozenSet[str] = frozenset()) -> ResolvedValues:
        # "any" la tu khoa hop le cua PAN-OS (khong phai object bi thieu).
        # KHONG tinh la match voi 1 IP cu the (tranh ket qua "rong", gay nhieu -
        # dung nhat quan voi quy uoc hien tai: any khong duoc uu tien coi la
        # match cho 1 dia chi cu the). Neu can bao gom rule dung "any", xem
        # cot rieng trong ket qua (any_refs).
        if name == "any":
            return ResolvedValues()

        if name in visiting:
            self._log(f"CANH BAO: phat hien Circular Reference tai Group '{name}' - bo qua nhanh nay, tiep tuc (Continue)")
            rv = ResolvedValues()
            rv.unresolved.add(name)
            return rv

        with self._lock:
            if name in self._cache:
                return self._cache[name]
            ev = self._inflight.get(name)
            if ev is None:
                ev = threading.Event()
                self._inflight[name] = ev
                mine = True
            else:
                mine = False

        if not mine:
            ev.wait()
            with self._lock:
                return self._cache.get(name, ResolvedValues())

        result = self._compute(name, visiting | {name})
        with self._lock:
            self._cache[name] = result
            del self._inflight[name]
            ev.set()
        return result

    def _compute(self, name: str, visiting: FrozenSet[str]) -> ResolvedValues:
        rv = ResolvedValues()

        # 1) IP/CIDR literal go truc tiep trong Source/Destination cua rule
        #    (PAN-OS cho phep nhap IP truc tiep, khong bat buoc phai co Address Object)
        if is_literal_ip_or_cidr(name):
            host = netmask_to_match_value(name)
            if host:
                rv.exact_ips.add(host)
            else:
                rv.unresolved.add(name)  # subnet qua rong -> khong tinh la match (muc 10)
            return rv

        # 2) Address Object
        obj = self.address_objects.get(name)
        if obj is not None:
            if obj.kind == "ip-netmask":
                host = netmask_to_match_value(obj.raw_value)
                if host:
                    rv.exact_ips.add(host)
                    rv.member_details.add((name, _display_value(obj)))
                else:
                    rv.unresolved.add(name)
                    # Subnet rong (vd /24) khong tinh la match, nhung van ghi nhan
                    # value that de hien thi day du trong Excel (thong tin cau hinh
                    # that, khong phai ket qua match).
                    rv.member_details.add((name, _display_value(obj)))
            elif obj.kind == "ip-range":
                rng = parse_ip_range(obj.raw_value)
                if rng:
                    rv.ranges.add(rng)
                    rv.member_details.add((name, _display_value(obj)))
                else:
                    rv.unresolved.add(name)
            else:
                rv.unresolved.add(name)
                if obj.kind == "fqdn":
                    rv.member_details.add((name, _display_value(obj)))
                    self._log(f"Bo qua FQDN Object '{name}' ({obj.raw_value}) - khong the resolve ra IP de so sanh")
            return rv

        # 3) Address Group (static: de quy xuong member; dynamic: qua registered-ip)
        grp = self.address_groups.get(name)
        if grp is not None:
            if grp.kind == "static":
                for member in grp.members:
                    rv = rv.union(self.resolve(member, visiting))
            else:
                ast = self._dag_ast_cache.get(name)
                if ast is None:
                    ast = parse_dag_filter(grp.filter_expr)
                    self._dag_ast_cache[name] = ast
                if self.registered_ip_tags:
                    for ip, tags in self.registered_ip_tags.items():
                        try:
                            if eval_dag_filter(ast, tags):
                                rv.exact_ips.add(ip)
                                rv.member_details.add((None, ip))
                        except Exception:
                            continue
                else:
                    self._log(f"Bo qua Dynamic Address Group '{name}' - khong lay duoc registered-ip tu Firewall")
                    rv.unresolved.add(name)
            return rv

        # 4) Khong tim thay o dau ca -> log canh bao, KHONG crash, tiep tuc (Continue)
        self._log(f"CANH BAO: khong tim thay Object/Group '{name}' - bo qua (Continue)")
        rv.unresolved.add(name)
        return rv

# ============================================================================
# SERVICE GROUP RESOLVER
# ============================================================================
def _resolve_service_leaves(name: str, service_objects: Dict[str, ServiceObject],
                             service_groups: Dict[str, ServiceGroup],
                             cache: Dict[str, List[Tuple[str, str]]],
                             visiting: FrozenSet[str] = frozenset()) -> List[Tuple[str, str]]:
    if name in visiting:
        return []  # circular reference trong service-group - bo qua, khong treo
    if name in cache:
        return cache[name]

    obj = service_objects.get(name)
    if obj is not None:
        val = f"{obj.protocol}/{obj.port}" if obj.port else obj.protocol
        result = [(name, val)]
        cache[name] = result
        return result

    grp = service_groups.get(name)
    if grp is not None:
        result: List[Tuple[str, str]] = []
        seen: Set[Tuple[str, str]] = set()
        for member in grp.members:
            for item in _resolve_service_leaves(member, service_objects, service_groups, cache, visiting | {name}):
                if item not in seen:
                    seen.add(item)
                    result.append(item)
        cache[name] = result
        return result

    return []  # khong tim thay Service Object/Group (giu nguyen ten o noi goi)
