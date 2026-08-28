# -*- coding: utf-8 -*-
"""
matching_engine.py - Doc File Log doi chieu + Index/Search chinh (muc 2 GUI,
EXACT-HOST ONLY) + mo phong 'Test Policy Match' cua PAN-OS cho doi chieu
File Log (CIDR containment day du, chi rule allow, first-match-wins).
(Gop tu log_file_parser.py + search_engine.py + policy_match.py cu)
"""

import os
import csv
import ipaddress
import threading
from dataclasses import dataclass
from typing import Dict, FrozenSet, List, Optional, Set, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import xml.etree.ElementTree as ET

import openpyxl

from .core import (
    DEFAULT_WORKERS,
    AddressObject, AddressGroup, ServiceObject, ServiceGroup, SecurityRule, NatRule, LogEntry,
    is_literal_ip_or_cidr, netmask_to_match_value, parse_ip_range,
)
from .resolver_engine import GroupResolver, _resolve_service_leaves
from .pan_api import (
    merge_layered_objects, assemble_security_rules, assemble_nat_rules,
)

# ============================================================================
# FILE LOG DOI CHIEU
# ============================================================================
# ============================================================================
# Nhan dien header linh hoat (khong phan biet hoa/thuong, bo khoang trang),
# fallback ve dung vi tri cot 1/2/3 neu khong tim thay ten header phu hop.

_LOG_SRC_HEADER_ALIASES = {"source ip", "src ip", "sourceip", "srcip", "source", "src"}
_LOG_DST_HEADER_ALIASES = {"destination ip", "dest ip", "dst ip", "destinationip",
                           "destip", "dstip", "destination", "dest", "dst"}
_LOG_PORT_HEADER_ALIASES = {"port", "dest port", "destination port", "dport"}


def _find_log_header_cols(header_row: List[str]) -> Tuple[Optional[int], Optional[int], Optional[int]]:
    src_col = dst_col = port_col = None
    for idx, h in enumerate(header_row):
        key = (h or "").strip().lower()
        if src_col is None and key in _LOG_SRC_HEADER_ALIASES:
            src_col = idx
        elif dst_col is None and key in _LOG_DST_HEADER_ALIASES:
            dst_col = idx
        elif port_col is None and key in _LOG_PORT_HEADER_ALIASES:
            port_col = idx
    return src_col, dst_col, port_col


def _clean_log_cell(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float) and v == int(v):
        return str(int(v))  # Excel hay luu so port dang float (vd 1521.0)
    return str(v).strip()


def parse_log_file(path: str) -> List[LogEntry]:
    """Doc file Log doi chieu (.xlsx hoac .csv), 3 cot Source IP/Dest IP/Port.
    Nhan dien header linh hoat; neu khong khop ten nao, fallback dung dung
    vi tri cot 1/2/3 theo thu tu."""
    ext = os.path.splitext(path)[1].lower()
    rows: List[List[str]] = []

    if ext == ".csv":
        with open(path, "r", encoding="utf-8-sig", newline="") as f:
            for row in csv.reader(f):
                rows.append([c.strip() for c in row])
    else:
        wb = openpyxl.load_workbook(path, data_only=True)
        ws = wb.worksheets[0]
        for row in ws.iter_rows(values_only=True):
            rows.append([_clean_log_cell(c) for c in row])

    rows = [r for r in rows if any(c.strip() for c in r)]  # bo dong rong hoan toan
    if not rows:
        return []

    src_col, dst_col, port_col = _find_log_header_cols(rows[0])
    start_row = 1
    if src_col is None or dst_col is None or port_col is None:
        # Khong nhan dien duoc header -> fallback dung vi tri cot 1/2/3,
        # va coi dong dau la du lieu (khong phai header).
        src_col, dst_col, port_col = 0, 1, 2
        start_row = 0

    entries: List[LogEntry] = []
    for row in rows[start_row:]:
        if max(src_col, dst_col, port_col) >= len(row):
            continue
        s = row[src_col].strip()
        d = row[dst_col].strip()
        p = row[port_col].strip()
        if not s and not d and not p:
            continue
        entries.append(LogEntry(source_ip=s, dest_ip=d, port=p))
    return entries

# ============================================================================
# INDEX + SEARCH ENGINE CHINH (muc 2 GUI - EXACT-HOST ONLY)
# ============================================================================
# ============================================================================
# INDEX + SEARCH ENGINE
# ============================================================================
# Muc 15 spec: KHONG duoc search tung IP rieng le qua tung rule. Phai build
# Index truoc (IP -> Object -> Group -> Rule), sau do tra cuu O(1) cho moi
# IP can tim. Buoc resolve (nang nhat ve CPU/IO) duoc chay da luong bang
# ThreadPoolExecutor (toi thieu 30 worker theo muc 13).

@dataclass
class IndexData:
    ip_to_refs: Dict[str, List[Tuple[int, str]]]      # exact ip -> [(rule_index, side), ...]
    range_refs: List[Tuple[int, int, int, str]]       # (start_int, end_int, rule_index, side)
    any_refs: List[Tuple[int, str]]                   # rule dung "any" (tach rieng, chi de tham khao)


def build_index(rules: List[SecurityRule], resolver: GroupResolver,
                 progress_cb=None, cancel_event: Optional[threading.Event] = None,
                 max_workers: int = DEFAULT_WORKERS) -> IndexData:
    # Buoc 1: gom tat ca ten tham chieu DUY NHAT (object/group/literal) xuat hien
    # trong Source/Destination cua toan bo rule, roi resolve SONG SONG (da luong).
    # Cache dam bao moi group/object chi thuc su duoc resolve 1 lan (muc 14).
    unique_refs: Set[str] = set()
    for r in rules:
        unique_refs.update(x for x in r.source if x != "any")
        unique_refs.update(x for x in r.destination if x != "any")

    total = len(unique_refs)
    done_count = [0]
    count_lock = threading.Lock()

    def _task(ref: str):
        if cancel_event is not None and cancel_event.is_set():
            return
        resolver.resolve(ref)
        with count_lock:
            done_count[0] += 1
            if progress_cb:
                progress_cb(done_count[0], total)

    if unique_refs:
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            futures = [ex.submit(_task, ref) for ref in unique_refs]
            for f in as_completed(futures):
                f.result()

    # Buoc 2: build index tu ket qua da resolve (da co trong cache -> tra cuu O(1))
    ip_to_refs: Dict[str, List[Tuple[int, str]]] = {}
    range_refs: List[Tuple[int, int, int, str]] = []
    any_refs: List[Tuple[int, str]] = []

    for r in rules:
        for side, entries in (("source", r.source), ("destination", r.destination)):
            for entry in entries:
                if entry == "any":
                    any_refs.append((r.index, side))
                    continue
                resolved = resolver.resolve(entry)  # da cache, khong tinh toan lai
                for ip in resolved.exact_ips:
                    ip_to_refs.setdefault(ip, []).append((r.index, side))
                for rng in resolved.ranges:
                    range_refs.append((rng[0], rng[1], r.index, side))

    return IndexData(ip_to_refs=ip_to_refs, range_refs=range_refs, any_refs=any_refs)


def search_ips(input_ips: List[str], index: IndexData) -> Dict[str, List[Tuple[int, str]]]:
    """Tra ve: input_ip -> [(rule_index, side), ...] (da loai tru cac rule chi dung 'any')."""
    results: Dict[str, List[Tuple[int, str]]] = {}
    for ip_str in input_ips:
        matches: Set[Tuple[int, str]] = set(index.ip_to_refs.get(ip_str, []))
        try:
            ip_int = int(ipaddress.ip_address(ip_str))
        except ValueError:
            results[ip_str] = []
            continue
        for start, end, rule_idx, side in index.range_refs:
            if start <= ip_int <= end:
                matches.add((rule_idx, side))
        results[ip_str] = sorted(matches)
    return results


def parse_dg_objects(config_root: ET.Element, dg_name: str, log_func
                     ) -> Tuple[Dict[str, AddressObject], Dict[str, AddressGroup],
                                Dict[str, ServiceObject], Dict[str, ServiceGroup]]:
    """Doc Address Object/Group + Service Object/Group theo 0.2 (Shared truoc,
    DG xa->gan, DG gan hon DE Shared neu trung ten). Dung CHUNG cho ca pipeline
    Search Rule (muc 2 GUI) va pipeline Export bang NAT (muc 4 GUI), tranh
    doc/parse config 2 lan khi ca 2 tinh nang cung duoc chay 1 luot."""
    merged = merge_layered_objects(config_root, dg_name)
    address_objects = merged["address_objects"]
    address_groups = merged["address_groups"]
    service_objects = merged["service_objects"]
    service_groups = merged["service_groups"]

    log_func(f"Download Objects OK ({len(address_objects)} address object)")
    log_func(f"Download Groups OK ({len(address_groups)} address group)")
    log_func(f"Download Services OK ({len(service_objects)} service object, {len(service_groups)} service group)")

    return address_objects, address_groups, service_objects, service_groups


def run_search_pipeline(config_root: ET.Element, dg_name: str, input_ips: List[str],
                         worker_count: int, log_func, progress_cb, cancel_event: threading.Event,
                         registered_ip_tags: Optional[Dict[str, Set[str]]] = None
                         ) -> Tuple[List[SecurityRule], Dict[str, List[Tuple[int, str]]], "GroupResolver",
                                    Dict[str, ServiceObject], Dict[str, ServiceGroup]]:
    """Pipeline day du: parse object/group theo DG-chain (0.2) -> lắp ráp rulebase
    theo 0.3 -> resolve -> index -> search. Pham vi = Shared + Device Group dang
    chon (ca pre lan post-rulebase), thay vi 1 vsys."""
    address_objects, address_groups, service_objects, service_groups = parse_dg_objects(
        config_root, dg_name, log_func)

    if cancel_event.is_set():
        return [], {}, None, {}, {}

    rules = assemble_security_rules(config_root, dg_name)
    log_func(f"Doc Security Rules OK ({len(rules)} rule) - Device Group '{dg_name}'")

    resolver = GroupResolver(address_objects, address_groups, registered_ip_tags, log_func)

    index = build_index(rules, resolver,
                         progress_cb=lambda d, t: progress_cb("Resolving Groups", d, t),
                         cancel_event=cancel_event, max_workers=worker_count)
    log_func("Resolve OK")

    if cancel_event.is_set():
        return [], {}, None, {}, {}

    match_results = search_ips(input_ips, index)
    log_func("Search OK")

    return rules, match_results, resolver, service_objects, service_groups


def run_nat_export_pipeline(config_root: ET.Element, dg_name: str, log_func,
                             registered_ip_tags: Optional[Dict[str, Set[str]]] = None,
                             resolver: Optional["GroupResolver"] = None
                             ) -> Tuple[List[NatRule], "GroupResolver", Dict[str, ServiceObject], Dict[str, ServiceGroup]]:
    """Pipeline cho tinh nang Export bang NAT (muc 4 GUI): parse object/group theo
    DG-chain (0.2) + lắp ráp NAT rulebase theo 0.3, roi tra ve NGUYEN (khong
    resolve/index - viec 'break' Source/Destination/Translated Address ra value
    that duoc lam luc xuat Excel/CSV, giong het cach lam voi Security Rule). Neu
    da co san 1 GroupResolver (vd tinh nang Search Rule da chay truoc do cung
    phien lam viec nay), truyen vao de tai su dung cache, khong resolve lai."""
    address_objects, address_groups, service_objects, service_groups = parse_dg_objects(
        config_root, dg_name, log_func)

    nat_rules = assemble_nat_rules(config_root, dg_name)
    log_func(f"Doc NAT Rules OK ({len(nat_rules)} rule) - Device Group '{dg_name}'")

    if resolver is None:
        resolver = GroupResolver(address_objects, address_groups, registered_ip_tags, log_func)

    return nat_rules, resolver, service_objects, service_groups

# ============================================================================
# MO PHONG 'TEST POLICY MATCH' CUA PAN-OS CHO DOI CHIEU FILE LOG
# ============================================================================
# ============================================================================
# MO PHONG "TEST POLICY MATCH" CUA PAN-OS CHO DOI CHIEU FILE LOG
# ============================================================================
# Dung rieng cho tinh nang doi chieu File Log (Source IP/Dest IP/Port traffic
# THAT). Nguyen tac dung theo PAN-OS Test Policy Match:
#   - Source IP cua dong Log LUON duoc check theo chieu Source cua rule; Dest
#     IP LUON check theo chieu Destination cua rule (KHONG doi chieu/thu ca
#     2 huong nhu truoc nua).
#   - Dung CIDR containment DAY DU (ke ca subnet rong, vd /24) cho ca 2 ve -
#     vi day chinh xac la cach firewall THAT xu ly goi tin: khong phan biet
#     object la host don hay subnet lon, chi can gia tri nam trong do.
#   - CHI xet cac rule co action=allow (bo qua deny/drop/reset...) - vi day
#     la traffic da duoc xac nhan THAT SU xay ra (report tu log), can tim
#     dung rule ALLOW nao dang cho phep no, khong quan tam cac rule chan.
#   - Rules duoc duyet THEO DUNG THU TU trong rulebase (dung sequence PAN-OS
#     danh gia rule tu tren xuong) va DUNG NGAY o rule DAU TIEN khop du ca 3
#     dieu kien (Source, Destination, Service) - giong het co che "first
#     match wins" that su cua PAN-OS, KHONG liet ke tat ca rule co the khop.
#   - Nhieu dong Log neu cung khop chung 1 rule (rule dau tien giong nhau) se
#     duoc GOM CHUNG lai vao dung 1 hang ket qua cua rule do.
#   - Gioi han: khong co thong tin Zone/Application tu file Log nen KHONG
#     kiem tra 2 tieu chi nay (coi nhu luon phu hop) - can luu y khi doc ket
#     qua, giong nhu Test Policy Match that can du zone/app de chinh xac 100%.

def ip_covered_by_entries_wide(ip: str, entries: List[str], resolver: GroupResolver,
                                range_cache: Dict[str, List[Tuple[int, int]]]) -> bool:
    """CIDR containment day du (ke ca subnet rong) - dung cho ca Source va
    Destination khi mo phong Test Policy Match (khac han quy tac exact-host
    cua tinh nang search chinh o muc 2)."""
    if not ip:
        return False
    try:
        ip_int = int(ipaddress.ip_address(ip))
    except ValueError:
        return False
    for entry in entries:
        if entry == "any":
            return True
        for start, end in _collect_ranges(entry, resolver, range_cache):
            if start <= ip_int <= end:
                return True
    return False


def find_first_allow_rule_match(le: "LogEntry", ordered_allow_rules: List["SecurityRule"],
                                 resolver: GroupResolver,
                                 service_objects: Dict[str, ServiceObject],
                                 service_groups: Dict[str, ServiceGroup],
                                 range_cache: Dict[str, List[Tuple[int, int]]]
                                 ) -> Optional["SecurityRule"]:
    """Mo phong Test Policy Match: tra ve rule ALLOW DAU TIEN (theo dung thu
    tu rulebase, trong ordered_allow_rules da loc san action=allow) ma Source/
    Destination/Service cua dong Log nay khop - dung NGAY khi tim thay, KHONG
    tiep tuc tim them (chi 1 rule duy nhat cho 1 dong log, giong PAN-OS that)."""
    for rule in ordered_allow_rules:
        if not port_covered_by_services(le.port, rule.service, service_objects, service_groups,
                                         rule_applications=rule.application):
            continue
        if not ip_covered_by_entries_wide(le.source_ip, rule.source, resolver, range_cache):
            continue
        if not ip_covered_by_entries_wide(le.dest_ip, rule.destination, resolver, range_cache):
            continue
        return rule
    return None


def _collect_ranges(name: str, resolver: GroupResolver,
                     cache: Dict[str, List[Tuple[int, int]]],
                     visiting: FrozenSet[str] = frozenset()) -> List[Tuple[int, int]]:
    """Thu thap TOAN BO khoang dia chi (start_int, end_int) ma 1 entry
    (object/group/literal) dai dien, KE CA subnet rong (vd /24) - khac voi
    GroupResolver.resolve() (chi giu exact host + ip-range). Dung rieng cho
    che do 'check match all, ke ca subnet' cua doi chieu File Log."""
    if name in cache:
        return cache[name]
    if name in visiting:
        cache[name] = []
        return []

    if is_literal_ip_or_cidr(name):
        try:
            net = ipaddress.ip_network(name.strip(), strict=False)
            result = [(int(net.network_address), int(net.broadcast_address))]
        except ValueError:
            result = []
        cache[name] = result
        return result

    obj = resolver.address_objects.get(name)
    if obj is not None:
        result = []
        if obj.kind == "ip-netmask":
            try:
                net = ipaddress.ip_network(obj.raw_value.strip(), strict=False)
                result = [(int(net.network_address), int(net.broadcast_address))]
            except ValueError:
                pass
        elif obj.kind == "ip-range":
            rng = parse_ip_range(obj.raw_value)
            if rng:
                result = [rng]
        cache[name] = result
        return result

    grp = resolver.address_groups.get(name)
    if grp is not None:
        result = []
        if grp.kind == "static":
            for member in grp.members:
                result.extend(_collect_ranges(member, resolver, cache, visiting | {name}))
        else:
            # Dynamic group: dung lai registered-ip da resolve san (tung IP don le)
            resolved = resolver.resolve(name)
            for ip in resolved.exact_ips:
                try:
                    ip_int = int(ipaddress.ip_address(ip))
                    result.append((ip_int, ip_int))
                except ValueError:
                    pass
        cache[name] = result
        return result

    cache[name] = []
    return []


def _port_str_contains(port_field: str, port_int: int) -> bool:
    """port_field: '1521', '80,8080', '8400-8405' - kiem tra port_int co nam trong khong."""
    for part in port_field.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "-" in part:
                lo, hi = part.split("-", 1)
                if int(lo.strip()) <= port_int <= int(hi.strip()):
                    return True
            elif int(part) == port_int:
                return True
        except ValueError:
            continue
    return False


# Cac ung dung PAN-OS KHONG co khai niem port TCP/UDP (thuoc nhom ICMP) - neu
# 1 rule dung service=application-default VA toan bo application chi gom cac
# ten nay, rule do KHONG THE khop voi 1 dong Log co Port cu the (DNS/LDAP/
# syslog... deu la TCP/UDP, khac han ICMP) - tranh false positive nhu
# "502-ICMP" (source=any, service=application-default) khop nham voi moi port.
_PORTLESS_APPLICATIONS = {"icmp", "ping", "traceroute", "icmpv6"}


def port_covered_by_services(port: str, entries: List[str],
                              service_objects: Dict[str, ServiceObject],
                              service_groups: Dict[str, ServiceGroup],
                              rule_applications: Optional[List[str]] = None) -> bool:
    try:
        port_int = int(str(port).strip())
    except (ValueError, TypeError):
        return False
    cache: Dict[str, List[Tuple[str, str]]] = {}
    for entry in entries:
        if entry == "any":
            return True
        if entry == "application-default":
            if rule_applications and all(a in _PORTLESS_APPLICATIONS for a in rule_applications):
                continue  # rule chi gom app khong co port (ICMP...) - khong the khop 1 dong log co Port
            return True
        obj = service_objects.get(entry)
        if obj is not None:
            if obj.port and _port_str_contains(obj.port, port_int):
                return True
            continue
        grp = service_groups.get(entry)
        if grp is not None:
            for _n, v in _resolve_service_leaves(entry, service_objects, service_groups, cache):
                proto_port = v.split("/", 1)[-1] if "/" in v else v
                if _port_str_contains(proto_port, port_int):
                    return True
    return False
