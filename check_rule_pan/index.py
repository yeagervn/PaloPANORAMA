# -*- coding: utf-8 -*-
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Set
from .resolver import ResolvedAddr, GroupResolver, ServiceResolver


@dataclass
class DeviceIndex:
    host_ip_to_names: Dict[int, List[str]] = field(default_factory=dict)
    range_objs: List[Tuple[int, int, str]] = field(default_factory=list)
    wide_objs: List[Tuple[int, int, str]] = field(default_factory=list)
    group_resolved: Dict[str, ResolvedAddr] = field(default_factory=dict)
    group_member_count: Dict[str, int] = field(default_factory=dict)
    # SUA LOI (08/2026): phia Port/Service truoc gio KHONG co index tra cuu "da co
    # san Service object dai dien chua" (khac han Source/Dest da co day du qua
    # host_ip_to_names/range_objs/wide_objs/group_resolved) - dan toi moi port con
    # thieu deu bi bao "TAO MOI" du thuc te da co san Service object dung port do
    # tren thiet bi (chi la chua duoc gan vao rule dang xet). Them 2 cau truc duoi
    # day, dung dung nguyen tac 'exact-only' da ap dung cho dia chi: mot Service
    # object CHI duoc coi la dai dien dung khi khop TUYET DOI 1 port don (host-
    # analog) hoac khop tuyet doi bounds cua 1 range (range-analog) - KHONG suy dien
    # gan dung tu 1 Service object range/rong hon (vd 8000-9000 khong duoc coi la
    # dai dien cho port don 8080), dung tinh than 'wide khong duoc dung lam dai
    # dien' da ap dung cho AddressObject.
    service_exact_ports: Dict[Tuple[Optional[str], int], List[str]] = field(default_factory=dict)
    service_exact_ranges: List[Tuple[Optional[str], int, int, str]] = field(default_factory=list)


def build_device_index(cfg: dict, resolver: GroupResolver, svc_resolver: ServiceResolver) -> DeviceIndex:
    idx = DeviceIndex()

    for name, obj in cfg['address_objects'].items():
        if obj.kind == 'host':
            idx.host_ip_to_names.setdefault(obj.start, []).append(name)
        elif obj.kind == 'range':
            idx.range_objs.append((obj.start, obj.end, name))
        elif obj.kind == 'wide':
            idx.wide_objs.append((obj.start, obj.end, name))

    for name, grp in cfg['address_groups'].items():
        idx.group_resolved[name] = resolver.resolve(name)
        idx.group_member_count[name] = len(grp.members)

    for name, sobj in cfg.get('service_objects', {}).items():
        proto = sobj.protocol if sobj.protocol in ('tcp', 'udp') else None
        for a, b in sobj.ranges:
            if a == b:
                idx.service_exact_ports.setdefault((proto, a), []).append(name)
            else:
                idx.service_exact_ranges.append((proto, a, b, name))

    return idx


def find_existing_service_representation(proto: Optional[str], start: int, end: int,
                                          idx: DeviceIndex) -> Optional[str]:
    """Tra ve ten Service Object da co san dai dien CHINH XAC cho (proto, start-end)
    dang xet, de bao cao 'chi can them vao rule, khong can tao Service object moi' -
    tuong tu find_existing_ip_representation nhung cho Port. CHI tinh khop TUYET DOI:
    port don khop dung 1 Service object port-don (khong dung service dang range lam
    dai dien gan dung cho port don), hoac range khop dung tuyet doi bounds voi 1
    Service object dang range. Neu proto khong xac dinh duoc tu input (None), thu ca
    tcp va udp - vi 1 Service object co san du 1 trong 2 protocol la du de bao 'da
    co', khong bat buoc phai dung protocol moi tinh la dai dien."""
    if start == end:
        names = idx.service_exact_ports.get((proto, start))
        if names:
            return names[0]
        if proto is None:
            for p in ('tcp', 'udp'):
                names = idx.service_exact_ports.get((p, start))
                if names:
                    return names[0]
        return None

    for p, a, b, name in idx.service_exact_ranges:
        if a == start and b == end and (proto is None or p is None or p == proto):
            return name
    return None


def find_existing_ip_representation(ip_int: int, idx: DeviceIndex,
                                     prefer_groups_covering: Optional[Set[int]] = None
                                     ) -> Optional[Tuple[str, str]]:
    best_group = None
    best_group_score = -1
    for gname, resolved in idx.group_resolved.items():
        if resolved.covers_exact(ip_int):
            score = 1
            if prefer_groups_covering:
                score = sum(1 for x in prefer_groups_covering if resolved.covers_exact(x))
            if score > best_group_score:
                best_group_score = score
                best_group = gname
    if best_group is not None:
        return (best_group, 'group')

    names = idx.host_ip_to_names.get(ip_int)
    if names:
        return (names[0], 'host')

    for a, b, name in idx.range_objs:
        if a <= ip_int <= b:
            return (name, 'range')

    return None


def find_best_covering_group(ip_set: Set[int], idx: DeviceIndex) -> Optional[Tuple[str, Set[int]]]:
    """Chon group 'tot nhat' de gan cho 1 phan (hoac toan bo) ip_set trong 1 vong lap.

    UU TIEN SO 1 (bat buoc): group KHOP TUYET DOI 1:1 - TONG SO DIA CHI THUC SU
    (resolved.total_address_count(), KHONG PHAI so member khai bao) cua group
    nay dung bang so IP no cover duoc trong ip_set, tuc KHONG co dia chi nao
    "thua" ngoai pham vi dang xet. Day la dai dien CHINH XAC nhat co the co (vd
    group 'SOA-PROD_151' co 2 member dang host = dung 2 dia chi = dung 2 IP
    dang xet). LUU Y: so member khai bao KHONG DU dang tin - 1 group co 2
    member dang RANGE (vd 10.0.50.150-151) van co the co THEM dia chi thua
    (.150) khong thuoc ip_set dang xet, nen phai dem theo dia chi thuc su, khong
    phai theo so luong member.

    UU TIEN SO 2 (fallback, giu nguyen hanh vi cu): neu KHONG co group nao
    khop tuyet doi 1:1, moi quay lai tieu chi cu - group cover duoc NHIEU IP
    nhat trong ip_set thang, hoa thi group co tong dia chi nho hon thang. Day
    la co che da dung de gom nhieu IP ve 1 group lon khi khong co lua chon nao
    chinh xac hon (xem lai cac test 'UAG-MDM-GR-SRV').
    """
    full_match_name = None
    full_match_covered: Set[int] = set()

    fallback_name = None
    fallback_covered: Set[int] = set()
    fallback_size = None

    for gname, resolved in idx.group_resolved.items():
        covered = {ip for ip in ip_set if resolved.covers_exact(ip)}
        if not covered:
            continue
        addr_size = resolved.total_address_count()

        if addr_size == len(covered):
            # Tong dia chi THUC SU cua group nay dung bang so IP dang xet -> khop
            # tuyet doi 1:1, khong co dia chi nao thua ngoai pham vi.
            better_full = (full_match_name is None or len(covered) > len(full_match_covered))
            if better_full:
                full_match_name, full_match_covered = gname, covered

        better_fallback = (fallback_name is None or len(covered) > len(fallback_covered) or
                            (len(covered) == len(fallback_covered) and addr_size < fallback_size))
        if better_fallback:
            fallback_name, fallback_covered, fallback_size = gname, covered, addr_size

    if full_match_name is not None:
        return (full_match_name, full_match_covered)
    if fallback_name is None or not fallback_covered:
        return None
    return (fallback_name, fallback_covered)

def build_zone_lookup(interface_subnets: List[Tuple[int, int, int, str]],
                       zones: Dict[str, List[str]]) -> List[Tuple[int, int, int, str]]:
    """Ghep interface_subnets (tu core.parse_interface_subnets) voi zones (tu
    core.parse_zones) thanh 1 bang tra cuu: [(start, end, prefix_len, zone_name), ...],
    sap xep theo prefix_len GIAM DAN (subnet hep nhat/cu the nhat truoc) de tra cuu
    theo kieu "longest prefix match" - giong cach mot ky su mang thuong lam thu cong
    khi map 1 IP ve dung zone (uu tien subnet cang cu the cang chinh xac).

    Neu interface_subnets hoac zones rong (khong parse duoc, hoac cau hinh khong co du
    lieu can thiet), tra ve list rong - tinh nang zone-check se tu dong khong hoat dong,
    khong anh huong gi den cac tinh nang khac.
    """
    iface_to_zone: Dict[str, str] = {}
    for zname, members in zones.items():
        for m in members:
            iface_to_zone[m] = zname

    out = []
    for start, end, prefix, iface in interface_subnets:
        zname = iface_to_zone.get(iface)
        if zname:
            out.append((start, end, prefix, zname))
    out.sort(key=lambda x: -x[2])
    return out


def resolve_zone_for_ip(ip_int: int, zone_lookup: List[Tuple[int, int, int, str]]) -> Optional[str]:
    """Tra ve ten zone chua dia chi IP nay, uu tien subnet hep/cu the nhat (zone_lookup
    da duoc sap xep san theo prefix_len giam dan). Tra ve None neu khong tim thay (vd
    khong parse duoc interface/zone tu XML, hoac IP nam ngoai moi subnet da khai bao) -
    trong truong hop do, tinh nang canh bao zone se tu bo qua IP nay (khong doan bua)."""
    for start, end, _prefix, zname in zone_lookup:
        if start <= ip_int <= end:
            return zname
    return None
