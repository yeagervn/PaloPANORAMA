# -*- coding: utf-8 -*-
import ipaddress
import time  # noqa: F401 - giu lai phong khi can do dac biet cho troubleshoot sau nay
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Set, Any
from concurrent.futures import ThreadPoolExecutor

from .core import SecurityRule, is_literal_ip_or_cidr, fetch_security_policy_match
from .resolver import ResolvedAddr, ResolvedService, GroupResolver, ServiceResolver
from .index import DeviceIndex, find_existing_ip_representation, find_best_covering_group, resolve_zone_for_ip, find_existing_service_representation
from .request import RequestRow


# =========================================================================
# DATA MODELS
# =========================================================================

@dataclass
class RuleInfo:
    rule: SecurityRule
    source: ResolvedAddr
    dest: ResolvedAddr
    service: ResolvedService
    source_members: List[Tuple[str, str, ResolvedAddr]] = field(default_factory=list)
    dest_members: List[Tuple[str, str, ResolvedAddr]] = field(default_factory=list)


@dataclass
class MissingItem:
    ip_int: int
    display: str
    status: str
    existing_name: Optional[str]
    existing_kind: Optional[str]
    is_range_input: bool = False
    range_display: Optional[str] = None
    group_coverage_pct: Optional[int] = None
    group_member_count: Optional[int] = None


@dataclass
class MissingPort:
    start: int
    end: int
    protocol: Optional[str]
    # SUA LOI (08/2026): them status/existing_name, dong bo voi MissingItem ('new' =
    # chua co Service object nao dai dien tren thiet bi, can tao moi that su; 'exists'
    # = da co san 1 Service object dai dien CHINH XAC, chi can ADD vao rule, KHONG
    # can tao object moi) - truoc day moi port thieu deu bi coi la 'new' vo dieu kien.
    status: str = 'new'
    existing_name: Optional[str] = None


@dataclass
class RowResult:
    row: RequestRow
    tier: str
    rule: Optional[SecurityRule]
    source_report: List[MissingItem] = field(default_factory=list)
    dest_report: List[MissingItem] = field(default_factory=list)
    missing_ports: List[MissingPort] = field(default_factory=list)
    note: str = ''
    shadow_warning: Optional[str] = None
    used_candidate_rule: Optional[str] = None
    candidate_ports: List[MissingPort] = field(default_factory=list)
    zone_warning: Optional[str] = None
    # Chi duoc dien khi tier == 'TOP4' va tim duoc 1 rule "gan dung nhat" de goi y
    # (xem _find_nearest_candidate_rule) - KHONG phai rule duoc chon/ap dung chinh
    # thuc nhu res.rule cua TOP1-3, chi la thong tin THAM KHAO hien truc tiep o cot
    # Name Rule khi khong co FULL/TOP1-3 match nao.
    nearest_rule: Optional[SecurityRule] = None
    nearest_rule_kind: Optional[str] = None      # 'near_top2' | 'near_top3' | 'generic'
    nearest_missing_side: Optional[str] = None   # 'source' (near_top2) | 'dest' (near_top3)
    nearest_detail: Optional[str] = None         # "Dest x/y khop | Source x/y khop | Port du/thieu"


# =========================================================================
# RULE PRE-PROCESSING
# =========================================================================

def _resolve_members_with_kind(names: List[str], resolver: GroupResolver) -> List[Tuple[str, str, ResolvedAddr]]:
    out = []
    for nm in names:
        resolved = resolver.resolve(nm)
        if nm == 'any':
            kind = 'any'
        elif nm in resolver.address_groups:
            kind = 'group'
        elif nm in resolver.address_objects:
            obj_kind = resolver.address_objects[nm].kind
            kind = {'host': 'host', 'range': 'range', 'wide': 'wide', 'fqdn': 'fqdn'}.get(obj_kind, 'host')
        elif is_literal_ip_or_cidr(nm) is not None:
            kind = 'literal'
        else:
            kind = 'unknown'
        out.append((nm, kind, resolved))
    return out


def build_rule_infos(rules: List[SecurityRule], resolver: GroupResolver,
                      svc_resolver: ServiceResolver, log_func=None,
                      progress_cb=None) -> List[RuleInfo]:
    """Xay RuleInfo cho TAT CA rule (khong chi rule allow) - giu nguyen thu tu rulebase
    (rules da duoc gan .index tang dan tu luc parse XML). Can co ca rule deny/drop trong
    danh sach de _find_shadowing_rule() phat hien truong hop 1 rule allow o duoi bi 1
    rule deny/drop o TREN che khuat (PAN-OS luon ap dung rule dau tien khop, bat ke
    thuat toan LOCAL co tim thay 1 rule allow "co ve phu hop" o phia duoi hay khong)."""
    out = []
    total = len(rules)
    for n, r in enumerate(rules, 1):
        source_members = _resolve_members_with_kind(r.source, resolver)
        dest_members = _resolve_members_with_kind(r.destination, resolver)
        src = ResolvedAddr()
        for _nm, _k, resolved in source_members:
            src.merge(resolved)
        dst = ResolvedAddr()
        for _nm, _k, resolved in dest_members:
            dst.merge(resolved)
        svc = svc_resolver.resolve_rule_service(r.service, r.application)
        out.append(RuleInfo(r, src, dst, svc, source_members, dest_members))
        if progress_cb and n % 100 == 0:
            progress_cb(n, total)
    if progress_cb:
        progress_cb(total, total)
    return out


def _side_all_for_shadow(resolved: ResolvedAddr, ranges) -> bool:
    """CHI dung cho kiem tra shadowing (_find_shadowing_rule) - KHONG dung cho logic chon
    rule allow (TOP1-TOP4) de khong lam thay doi hanh vi dang dung cua thuat toan do.

    Khac voi _side_all() dung chung: ham nay co kiem tra them resolved.is_any. Ly do: cac
    rule deny/drop dac thu (vd chan 1 subnet nguy hiem, dat phia tren toan bo policy) rat
    hay dung source=any hoac destination=any de ap dung cho MOI traffic di qua, nhung
    _side_all()/covers_range_exact()/covers_range_wide() dung chung KHONG he kiem tra
    is_any - se lam sot hoan toan cac rule loai nay khoi shadow-check, gay canh bao gia
    an toan (bao "FULL MATCH" trong khi thuc te co the bi 1 rule deny=any chan truoc)."""
    if resolved.is_any:
        return True
    return all(resolved.covers_range_wide(s, e) for (s, e, _t) in ranges)


def _ports_covered_for_shadow(service: ResolvedService, ports) -> bool:
    """CHI dung cho kiem tra shadowing - tuong tu _side_all_for_shadow nhung cho phia
    service/port: co kiem tra service.is_any (rule dung service=any) ma _ports_covered()/
    ResolvedService.covers() dung chung KHONG kiem tra."""
    if service.is_any:
        return True
    return _ports_covered(service, ports)


def _find_shadowing_rule(rule_infos: List[RuleInfo], candidate: RuleInfo,
                          src_ranges, dst_ranges, ports) -> Optional[RuleInfo]:
    """Tim rule co thu tu (index) NHO HON candidate (tuc PAN-OS danh gia TRUOC candidate)
    ma cung khop dung traffic nay va action KHAC 'allow' (deny/drop/reset...). Neu tim
    thay, candidate dang bi "che khuat" - PAN-OS se ap dung rule do truoc, khong phai
    candidate, du candidate co ve "phu hop" theo thuat toan LOCAL. Bo qua rule dang
    disabled (PAN-OS khong danh gia rule disabled) va rule allow phia truoc (khong gay
    rui ro an toan, van cho phep traffic). rule_infos da duoc dam bao thu tu tang dan
    theo index tu build_rule_infos(), nen ket qua tim thay dau tien la rule co index
    nho nhat (gan voi thu tu PAN-OS ap dung thuc te nhat).

    Dung _side_all_for_shadow/_ports_covered_for_shadow (co xet is_any) thay vi
    _side_all/_ports_covered thong thuong, de khong bo sot cac rule deny/drop dac thu
    dung source=any/destination=any/service=any dat phia tren policy chinh.
    """
    for ri in rule_infos:
        if ri.rule.index >= candidate.rule.index:
            continue
        if ri.rule.disabled or ri.rule.action == 'allow':
            continue
        if _ports_covered_for_shadow(ri.service, ports) and \
           _side_all_for_shadow(ri.source, src_ranges) and \
           _side_all_for_shadow(ri.dest, dst_ranges):
            return ri
    return None


def _ranges_total_count(ranges) -> int:
    """Tong so dia chi ma 1 list (start,end,token) dang xet chiem (khong khu trung lap
    - du dung de so sanh voi ResolvedAddr.total_address_count() nham kiem tra 'group/
    field nay co CHI CHUA dung cac dia chi trong input, khong thua gi khac' hay khong."""
    return sum(e - s + 1 for (s, e, _t) in ranges)


def _is_exactly_scoped(resolved: ResolvedAddr, ranges) -> bool:
    """Kiem tra 1 ResolvedAddr (source hoac dest cua 1 rule) co CHI CHUA DUNG cac dia
    chi trong 'ranges' hay khong - khong thua bat ky dia chi nao khac. Dung de chan cac
    goi y 'ADD PORT'/'ADD SOURCE'/'ADD DEST' KHONG AN TOAN: neu 1 rule cover du dieu
    kien nhung source/dest cua no la 1 group RONG (chua nhieu object khac ngoai pham vi
    dang xet), thi viec 'chi can bo sung phan con thieu' se VO TINH cap them quyen cho
    TAT CA cac object khac trong group do - khong chi rieng IP dang duoc yeu cau. CHI
    khi group/field do khop CHINH XAC 1:1 voi dung tap dang xet, goi y bo sung moi thuc
    su an toan."""
    return resolved.total_address_count() == _ranges_total_count(ranges)


def _shadow_warning_text(shadow: Optional[RuleInfo]) -> Optional[str]:
    """Tra ve TEN cua rule dang che khuat (khong phai ca cau dai) - exporter.py se tu
    dung ten nay de dung dong '-BLOCK BOI RULE: <ten>' theo dinh dang output moi."""
    if shadow is None:
        return None
    return shadow.rule.name


def _missing_zones(ranges, rule_zones: List[str],
                    zone_lookup: Optional[List[Tuple[int, int, int, str]]]) -> Set[str]:
    """Tra ve tap ten Zone (tren zone_lookup - du lieu Interface/Zone THAT parse tu
    XML thiet bi) MA cac dia chi trong `ranges` thuoc ve nhung CHUA nam trong
    `rule_zones` cua 1 rule dang xet. 'any' trong rule_zones luon duoc coi la du.
    Neu zone_lookup rong hoac khong xac dinh duoc zone cua 1 IP nao do, IP/zone do
    duoc BO QUA (khong doan bua, tranh bao sai) - ham nay dung CHUNG cho ca
    _compute_zone_warning (hien thi canh bao TOP1-3) va _find_nearest_candidate_rule
    (xep hang TOP4, xem SUA LOI 2026-08 phia duoi)."""
    if not zone_lookup or 'any' in rule_zones:
        return set()
    needed: Set[str] = set()
    for (s, e, _t) in ranges:
        z_start = resolve_zone_for_ip(s, zone_lookup)
        z_end = resolve_zone_for_ip(e, zone_lookup) if e != s else z_start
        for z in (z_start, z_end):
            if z:
                needed.add(z)
    return needed - set(rule_zones)


def _compute_zone_warning(rule: SecurityRule, src_ranges, dst_ranges,
                           zone_lookup: Optional[List[Tuple[int, int, int, str]]]) -> Optional[str]:
    """Sau khi 1 rule da duoc CHON lam candidate (TOP1/TOP1.1/TOP2/TOP3, giu nguyen
    logic chon rule cu, KHONG doi gi ca) - kiem tra THEM lieu rule do co du Source
    Zone / Dest Zone cho request nay hay chua. Zone 'any' luon duoc coi la du (theo
    yeu cau nguoi dung). Neu zone_lookup rong (khong parse duoc Interface/Zone tu
    XML that) hoac khong xac dinh duoc zone cua 1 IP nao do, BO QUA IP/canh bao do -
    khong doan bua, tranh bao sai.

    Tra ve None neu du zone roi (hoac khong the xac dinh - im lang, khong lam phien),
    hoac chuoi mo ta zone con thieu neu phat hien thieu that su.
    """
    if not zone_lookup:
        return None

    missing_src = _missing_zones(src_ranges, rule.from_zones, zone_lookup)
    missing_dst = _missing_zones(dst_ranges, rule.to_zones, zone_lookup)
    if not missing_src and not missing_dst:
        return None

    parts = []
    if missing_src:
        parts.append(f"Source Zone can bo sung: {', '.join(sorted(missing_src))}")
    if missing_dst:
        parts.append(f"Dest Zone can bo sung: {', '.join(sorted(missing_dst))}")
    return " | ".join(parts)


# =========================================================================
# REPORT BUILDING & LOCAL HELPERS
# =========================================================================

def _ports_covered(service: ResolvedService, ports) -> bool:
    return all(service.covers(proto, s) and service.covers(proto, e) for (s, e, proto) in ports)


def _service_ok_for_match(service: ResolvedService, ports) -> bool:
    """Dung thay cho _ports_covered() thuan tuy o TAT CA cac tier chon rule chinh
    (TOP1/TOP2/TOP3) VA o _find_nearest_candidate_rule (TOP4 hint) - THEO YEU CAU
    RIENG cua nguoi dung: 1 rule co service='any' LUON la truong hop BO QUA, KHONG
    duoc tinh la ket qua hop le, du ve mat ky thuat 'any' co the duoc coi la da cover
    moi port dang xet.

    Truoc ban vien nay, dieu nay VO TINH da dung (covers() cua ResolvedService khong
    tung kiem tra is_any nen 1 service='any' luon tra ve 'khong cover port nao' -
    hanh vi dung mong muon nhung khong tuong minh/khong tu tai lieu hoa, de vo tinh
    vo hieu neu sau nay ai do them xu ly is_any vao covers()). Ham nay lam dieu do
    THANH TUONG MINH, tach biet han voi _ports_covered_for_shadow (ham RIENG cho
    shadow-check, NGUOC LAI can coi service=any la 'cover moi port' de khong bo sot
    rui ro bi 1 rule deny/drop service=any dat phia tren che khuat)."""
    if service.is_any:
        return False
    return _ports_covered(service, ports)


def _both_sides_any(ri: 'RuleInfo') -> bool:
    """THEO YEU CAU RIENG cua nguoi dung: KHONG chap nhan 1 rule lam ket qua hop le neu
    CA source VA destination CUNG LUC deu la 'any' (rule dang cho phep MOI traffic ca 2
    chieu) - du ve mat ky thuat covers_range_exact()/covers_range_wide() co the coi ca
    2 ben la 'da cover du' input mot cach doc lap (is_any tra ve True cho TUNG ben rieng
    biet). 1 rule chi 'any' o DUY NHAT 1 ben (source HOAC dest, khong phai ca hai) VAN
    duoc chap nhan binh thuong - chi loai truong hop ca hai cung 'any'.

    SUA LOI (xem doc muc lien quan): TOP1 (full match) truoc day KHONG co buoc kiem
    tra nay - 1 rule Source=any + Dest=any + Service=<port cu the khop> se bi TOP1
    chon nham la 'FULL MATCH - khong can tao rule moi', SAI voi yeu cau nguoi dung.
    TOP1.1/TOP2/TOP3 KHONG dinh loi nay vi da co san dieu kien _is_exactly_scoped()
    (is_any co total_address_count()=inf, khong bao gio khop 1:1 voi input huu han)
    tu dong loai tru 'any' o dung phia bat buoc chinh xac cua cac tier do."""
    return ri.source.is_any and ri.dest.is_any


def _side_all(resolved: ResolvedAddr, ranges, wide: bool) -> bool:
    if wide:
        return all(resolved.covers_range_wide(s, e) for (s, e, _t) in ranges)
    return all(resolved.covers_range_exact(s, e) for (s, e, _t) in ranges)


def build_field_report(ranges, rule_members: List[Tuple[str, str, ResolvedAddr]],
                        idx: DeviceIndex, wide: bool) -> List[MissingItem]:
    host_items = [(s, e, t) for (s, e, t) in ranges if s == e]
    range_items = [(s, e, t) for (s, e, t) in ranges if s != e]
    total = len(host_items)

    results: List[MissingItem] = []
    remaining: Set[int] = {s for (s, e, t) in host_items}
    ip_display = {s: t['display'] for (s, e, t) in host_items}

    def _greedy_assign(candidates, status, check_wide):
        nonlocal remaining
        while remaining:
            best_name, best_kind, best_covered, best_size = None, None, set(), None
            for name, kind, resolved in candidates:
                covered = {ip for ip in remaining
                           if (resolved.covers_range_wide(ip, ip) if check_wide
                               else resolved.covers_range_exact(ip, ip))}
                if not covered:
                    continue
                size = idx.group_member_count.get(name, 10 ** 9) if kind == 'group' else 1
                better = (best_name is None or len(covered) > len(best_covered) or
                          (len(covered) == len(best_covered) and size < best_size))
                if better:
                    best_name, best_kind, best_covered, best_size = name, kind, covered, size
            if best_name is None or not best_covered:
                return
            pct = round(len(best_covered) / total * 100) if total else 0
            mcount = idx.group_member_count.get(best_name) if best_kind == 'group' else None
            for ip in best_covered:
                results.append(MissingItem(ip, ip_display[ip], status, best_name, best_kind,
                                            group_coverage_pct=pct, group_member_count=mcount))
            remaining -= best_covered

    _greedy_assign(rule_members, 'in_rule', check_wide=False)

    while remaining:
        found = find_best_covering_group(remaining, idx)
        if not found:
            break
        gname, covered = found
        pct = round(len(covered) / total * 100) if total else 0
        for ip in covered:
            results.append(MissingItem(ip, ip_display[ip], 'exists', gname, 'group',
                                        group_coverage_pct=pct, group_member_count=idx.group_member_count.get(gname)))
        remaining -= covered

    still_remaining = set()
    for ip in remaining:
        found = find_existing_ip_representation(ip, idx)
        if found:
            nm, kind = found
            mcount = idx.group_member_count.get(nm) if kind == 'group' else None
            results.append(MissingItem(ip, ip_display[ip], 'exists', nm, kind, group_member_count=mcount))
        else:
            still_remaining.add(ip)
    remaining = still_remaining

    for ip in remaining:
        results.append(MissingItem(ip, ip_display[ip], 'new', None, None))

    for (s, e, t) in range_items:
        disp = t['display']
        found_exact_in_rule = None
        for name, kind, resolved in rule_members:
            if resolved.covers_range_exact(s, e):
                found_exact_in_rule = (name, kind)
                break
        if found_exact_in_rule:
            results.append(MissingItem(s, disp, 'in_rule', found_exact_in_rule[0], found_exact_in_rule[1],
                                        is_range_input=True, range_display=disp))
            continue
        exists_as = None
        group_candidates = [gname for gname, resolved in idx.group_resolved.items()
                             if resolved.has_exact_member(s, e)]
        if group_candidates:
            # Nhieu group co the cung co 1 member khop tuyet doi voi input nay (vd 1
            # group nho, purpose-built CHI co dung member nay, VA 1 group catch-all
            # lon hon cung tinh co chua member do). Luon chon group co TONG DIA CHI
            # THUC SU nho nhat (khong phai so member khai bao - 1 group it member
            # nhung member la range/wide rong van co the "to" hon group nhieu member
            # nho) - dai dien sat/chinh xac nhat, khong de group lon "an theo thu tu quet".
            best_gname = min(group_candidates, key=lambda g: idx.group_resolved[g].total_address_count())
            exists_as = (best_gname, 'group')
        if not exists_as:
            exact_candidates = []
            for a, b, nm in idx.range_objs:
                if a == s and b == e:
                    exact_candidates.append((nm, 'range'))
            for a, b, nm in idx.wide_objs:
                if a == s and b == e:
                    exact_candidates.append((nm, 'wide'))
            if exact_candidates:
                exists_as = exact_candidates[0]
            else:
                # Khong co khop tuyet doi nao. Chi cho phep fallback ve object 'range' gan
                # nhat (khoang IP cu the do admin tao, thuong sat nghia thuc te) - TUYET DOI
                # KHONG fallback sang object 'wide' (netmask/subnet) khi khong khop tuyet doi,
                # vi loai nay co the rat rong (vd /8, /0) va se bi coi la "gia tri qua lon"
                # khong dai dien chinh xac cho input.
                near_candidates = [(a, b, nm) for a, b, nm in idx.range_objs if a <= s and e <= b]
                if near_candidates:
                    a, b, nm = min(near_candidates, key=lambda c: c[1] - c[0])
                    exists_as = (nm, 'range')
        if exists_as:
            results.append(MissingItem(s, disp, 'exists', exists_as[0], exists_as[1],
                                        is_range_input=True, range_display=disp))
            continue
        results.append(MissingItem(s, disp, 'new', None, None,
                                    is_range_input=True, range_display=disp))

    results.sort(key=lambda m: m.ip_int)
    return results


def build_live_match_field_report(ranges, rule_members: List[Tuple[str, str, ResolvedAddr]],
                                   idx: DeviceIndex) -> List[MissingItem]:
    """Xay Source/Dest report rieng cho tier LIVE_MATCH (da duoc PAN-OS Test Policy Match
    xac nhan ALLOW tren chinh thiet bi).

    Khac voi build_field_report (thuat toan LOCAL, exact-only theo quyet dinh thiet ke):
    o day dung covers_range_wide_confirmed() nen CHAP NHAN ca truong hop IP chi duoc cover
    qua 1 member la subnet rong / 'any' cua rule - vi luc nay chi la hien thi/doi chieu
    minh bach ("nho object/subnet nao ma da duoc allow"), khong con anh huong dung/sai nua.
    """
    host_items = [(s, e, t) for (s, e, t) in ranges if s == e]
    range_items = [(s, e, t) for (s, e, t) in ranges if s != e]
    ip_display = {s: t['display'] for (s, e, t) in host_items}

    def _find_in_rule(s, e):
        for name, kind, resolved in rule_members:
            if kind == 'any':
                return (name, 'any')
            if resolved.covers_range_wide_confirmed(s, e):
                return (name, kind)
        return None

    results: List[MissingItem] = []

    for (s, e, t) in host_items:
        found = _find_in_rule(s, s)
        if found:
            nm, kind = found
            results.append(MissingItem(s, ip_display[s], 'in_rule', nm, kind))
            continue
        # Hiem khi xay ra vi API da confirm ALLOW, nhung van du phong: tim dai dien
        # tren toan thiet bi, neu khong co gi thi moi coi la 'new'.
        ex = find_existing_ip_representation(s, idx)
        if ex:
            nm, kind = ex
            results.append(MissingItem(s, ip_display[s], 'exists', nm, kind))
        else:
            results.append(MissingItem(s, ip_display[s], 'new', None, None))

    for (s, e, t) in range_items:
        disp = t['display']
        found = _find_in_rule(s, e)
        if found:
            nm, kind = found
            results.append(MissingItem(s, disp, 'in_rule', nm, kind,
                                        is_range_input=True, range_display=disp))
            continue
        results.append(MissingItem(s, disp, 'new', None, None,
                                    is_range_input=True, range_display=disp))

    results.sort(key=lambda m: m.ip_int)
    return results


def find_missing_ports(ports, service: ResolvedService,
                        idx: Optional[DeviceIndex] = None) -> List[MissingPort]:
    """Voi moi port CHUA duoc rule/candidate dang xet cover, tra cuu THEM (neu co idx)
    xem tren thiet bi da co san 1 Service object dai dien CHINH XAC cho port do chua
    (xem find_existing_service_representation trong index.py) - dung dung nguyen tac
    'exact-only' nhu AddressObject. Neu co -> status='exists' (chi can ADD vao rule),
    neu khong -> giu nguyen 'new' (that su can tao Service object moi) nhu truoc day.
    idx=None (khong truyen) giu nguyen hanh vi cu 100% (an toan nguoc, dung cho moi
    loi goi cu chua kip truyen idx)."""
    out = []
    for (s, e, proto) in ports:
        if service.covers(proto, s) and service.covers(proto, e):
            continue
        existing_name = find_existing_service_representation(proto, s, e, idx) if idx is not None else None
        if existing_name:
            out.append(MissingPort(s, e, proto, status='exists', existing_name=existing_name))
        else:
            out.append(MissingPort(s, e, proto, status='new'))
    return out


def _check_same_subnet(src_ranges, dst_ranges, prefix_len: int) -> bool:
    all_items = src_ranges + dst_ranges
    if not all_items:
        return False
    if any(s != e for s, e, _t in all_items):
        return False
    if not (0 < prefix_len <= 32):
        return False
    mask = (0xFFFFFFFF << (32 - prefix_len)) & 0xFFFFFFFF
    networks = {s & mask for s, e, _t in all_items}
    return len(networks) == 1


# =========================================================================
# LIVE POLICY MATCH API CHECKING
# =========================================================================

def _live_match_test_ips(tok: dict) -> List[int]:
    """Xac dinh (cac) dia chi IP can goi Test Policy Match de dai dien cho 1 token input,
    tuy theo loai (`host`/`range`/`cidr`) - KHONG bao gio chi dung '.start' mac dinh cho
    moi loai nhu truoc day (gay rui ro FULL MATCH gia cho range/subnet chi vi 1 diem dau
    dai duoc firewall allow).

    - `host`: 1 IP duy nhat (start == end) - test dung 100%, khong can gi them.
    - `range` (vd '10.1.1.5-10.1.1.20', admin go thang 1 khoang IP cu the): test CA 2
      dau mut (start VA end) - ca 2 phai cung khop 1 rule allow thi ca dai moi duoc coi
      la FULL MATCH (xem dieu kien 'len(matched_rules) > 1' o try_live_match, tu dong
      loai bo neu 2 dau mut khop 2 rule khac nhau). Day la yeu cau rieng theo quyet dinh
      thiet ke: range luon phai test ca 2 dau, khong chi 1 diem dai dien.
    - `cidr` (subnet/netmask, vd '10.1.2.0/24'): CHI can test 1 diem duy nhat (network
      address, '.start') la du - theo dung quyet dinh thiet ke rieng cho subnet (khac voi
      range o tren), Live Match o day chi dong vai tro 'kiem tra nhanh', khong bat buoc
      phai bao phu tung host trong subnet.
    """
    if tok['kind'] == 'range' and tok['start'] != tok['end']:
        return [tok['start'], tok['end']]
    return [tok['start']]


def try_live_match(
    row: RequestRow,
    mgmt_ip: str,
    api_key: str,
    vsys: str,
    rule_infos: List[RuleInfo],
    idx: DeviceIndex,
    max_combos: int = 50,
    max_workers: int = 30,
    log_func=None,
    target_serial: Optional[str] = None,
) -> Optional[RowResult]:
    """Gọi trực tiếp API Test Policy Match QUA PANORAMA (proxy) - BAT BUOC target"""
    if not mgmt_ip or not api_key:
        return None
    # BAN PANORAMA (0.5): thieu Target Firewall (serial) -> Live Match tu bo qua ngay,
    # im lang (roi thang xuong thuat toan local). Khong bao loi / khong goi API.
    if not target_serial:
        return None

    combinations = []
    unknown_proto_count = 0
    for src_tok in row.source_tokens:
        if src_tok['kind'] == 'invalid':
            continue
        src_ips = _live_match_test_ips(src_tok)
        for dst_tok in row.dest_tokens:
            if dst_tok['kind'] == 'invalid':
                continue
            dst_ips = _live_match_test_ips(dst_tok)
            for (p_start, p_end, proto) in row.port_tokens:
                if p_end - p_start > 50:
                    if log_func:
                        log_func(f"[Live Match] Bỏ qua: dải port {p_start}-{p_end} quá rộng (>50).")
                    return None
                for port in range(p_start, p_end + 1):
                    protocol_str = proto or 'tcp'
                    if proto is None:
                        unknown_proto_count += 1
                    for src_ip_int in src_ips:
                        s_ip_str = str(ipaddress.IPv4Address(src_ip_int))
                        for dst_ip_int in dst_ips:
                            d_ip_str = str(ipaddress.IPv4Address(dst_ip_int))
                            combinations.append((s_ip_str, d_ip_str, port, protocol_str))

    if unknown_proto_count and log_func:
        log_func(f"[Live Match] {unknown_proto_count} combo khong xac dinh duoc protocol tu file "
                 f"input (thieu hau to /tcp hoac /udp, hoac cot Protocol trong) - mac dinh dung TCP, "
                 f"ket qua co the sai neu traffic thuc te la UDP.")

    if not combinations:
        return None
    if len(combinations) > max_combos:
        if log_func:
            log_func(f"[Live Match] Bỏ qua: {len(combinations)} tổ hợp Source/Dest/Port > giới hạn {max_combos}.")
        return None

    matched_rules = set()
    error_messages: List[str] = []

    def _collect_error(msg):
        error_messages.append(msg)

    def _check_one(combo):
        s_ip, d_ip, port, proto = combo
        return fetch_security_policy_match(mgmt_ip, api_key, s_ip, d_ip, port, proto, vsys=vsys,
                                           target_serial=target_serial, log_func=_collect_error)

    with ThreadPoolExecutor(max_workers=min(max_workers, len(combinations))) as executor:
        results = list(executor.map(_check_one, combinations))
    if log_func:
        log_func(f"[Live Match] Da kiem tra {len(combinations)} to hop Source/Dest/Port qua Test Policy Match.")
    if log_func and error_messages:
        n_timeout = sum(1 for m in error_messages if 'timed out' in m or 'exception' in m)
        n_denied = sum(1 for m in error_messages if 'tu choi yeu cau' in m)
        n_other = len(error_messages) - n_timeout - n_denied
        log_func(f"[Live Match] {len(error_messages)}/{len(combinations)} call loi "
                 f"(timeout/exception: {n_timeout}, firewall tu choi: {n_denied}, khac: {n_other}) "
                 f"- vi du: {error_messages[0]}")

    for combo, res in zip(combinations, results):
        s_ip, d_ip, port, proto = combo
        if not res:
            if log_func:
                log_func(f"[Live Match] {s_ip}->{d_ip}:{port}/{proto} không xác nhận được "
                          f"(xem tóm tắt lỗi phía trên) -> chuyển sang thuật toán local.")
            return None
        if res.get("action") != "allow":
            if log_func:
                log_func(f"[Live Match] {s_ip}->{d_ip}:{port}/{proto} khớp rule "
                          f"'{res.get('rule_name')}' nhưng action='{res.get('action')}' "
                          f"(không phải allow) -> chuyển sang thuật toán local.")
            return None
        matched_rules.add(res.get("rule_name"))

    if not matched_rules:
        return None

    if len(matched_rules) > 1:
        # Cac to hop Source/Dest/Port trong CUNG 1 dong nhung khop NHIEU rule KHAC NHAU
        # tren firewall that (vd 1 dest IP di qua rule A, dest IP con lai trong cung dong
        # lai di qua rule B). Truoc day code lay list(matched_rules)[0] - thu tu 1 Python
        # set la KHONG xac dinh (dua tren hash, khong phai thu tu tim thay) - co the bao
        # nham "FULL MATCH qua rule X" trong khi thuc te ket qua la SU KET HOP cua nhieu
        # rule khac nhau. An toan hon: KHONG tu chon 1 rule dai dien, chuyen sang thuat
        # toan local (bao cao chi tiet tung phan thay vi gop nham thanh 1 ket luan).
        if log_func:
            log_func(f"[Live Match] Cac to hop Source/Dest/Port trong dong nay khop VOI "
                      f"NHIEU RULE KHAC NHAU tren firewall ({', '.join(sorted(matched_rules))}) "
                      f"- khong the gop thanh 1 FULL MATCH duy nhat. Chuyen sang thuat toan "
                      f"local de bao cao chi tiet tung phan.")
        return None

    rule_name = next(iter(matched_rules))
    matched_rule_info = next((r for r in rule_infos if r.rule.name == rule_name), None)

    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens if t['kind'] != 'invalid']

    if matched_rule_info:
        src_report = build_live_match_field_report(src_ranges, matched_rule_info.source_members, idx)
        dst_report = build_live_match_field_report(dst_ranges, matched_rule_info.dest_members, idx)
        matched_rule = matched_rule_info.rule
    else:
        # Nếu rule không tìm thấy trong file cấu hình local nhưng API báo match
        src_report = build_live_match_field_report(src_ranges, [], idx)
        dst_report = build_live_match_field_report(dst_ranges, [], idx)
        matched_rule = SecurityRule(index=-1, name=rule_name, source=['?'], destination=['?'],
                                     service=['?'], application=['?'], action='allow', disabled=False)

    return RowResult(
        row=row,
        tier="LIVE_MATCH",
        rule=matched_rule,
        source_report=src_report,
        dest_report=dst_report,
        missing_ports=[],
        note=f"FULL MATCH trực tiếp trên Firewall qua Test Policy Match (Rule: {rule_name})"
    )


def apply_candidate_overlay(res: RowResult, row: RequestRow,
                             candidate_rule_infos: List[RuleInfo],
                             candidate_idx: Optional[DeviceIndex]) -> None:
    """Sau khi da co ket qua chinh (dua tren RUNNING config, tuyet doi KHONG doi) - quet
    them CANDIDATE config (rule/object dang cho commit, co the do admin khac tao o session
    khac - khi commit se ap dung CHUNG cho tat ca) de:
    1. Tranh goi y "TAO MOI" TRUNG voi thu da chuan bi san trong candidate (item nao dang
       'new' ma da co trong candidate thi doi status thanh 'candidate', hien mau xanh
       duong "-> CANDICATE" thay vi do "-> TAO MOI").
    2. Khong bo sot: item nao van THUC SU chua co o ca running lan candidate thi VAN giu
       nguyen 'new'/'TAO MOI' nhu cu - dam bao khong "an" mat viec con thieu that.

    Sua TRUC TIEP tren cac field cua res (source_report/dest_report/missing_ports/
    candidate_ports/used_candidate_rule). KHONG bao gio suy ra "FULL MATCH" tu ket qua
    o day - item 'candidate' khong tinh vao dieu kien "da xong hoan toan", vi chi la
    du kien, chua co hieu luc that cho toi khi duoc Commit."""
    if res.tier in ('LIVE_MATCH', 'SAME_SUBNET', 'INVALID'):
        return
    if not candidate_rule_infos and candidate_idx is None:
        return

    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens if t['kind'] != 'invalid']
    ports = row.port_tokens

    def _addr_covers(resolved, ip_int) -> bool:
        # CHI dung trong ham nay - co xet is_any (rule candidate dung source/destination=
        # any) ma ResolvedAddr.covers_range_wide() dung chung KHONG kiem tra.
        if resolved.is_any:
            return True
        return resolved.covers_range_wide(ip_int, ip_int)

    def _svc_covers(service, proto, port) -> bool:
        # Tuong tu _addr_covers nhung cho service=any.
        if service.is_any:
            return True
        return service.covers(proto, port)

    def _ports_covered_any_aware(service, port_tokens) -> bool:
        if service.is_any:
            return True
        return _ports_covered(service, port_tokens)

    best_rule = None
    if candidate_rule_infos:
        best_score = -1
        for ri in candidate_rule_infos:
            if ri.rule.action != 'allow' or ri.rule.disabled:
                continue
            score = sum(1 for (s, e, _t) in src_ranges if _addr_covers(ri.source, s))
            score += sum(1 for (s, e, _t) in dst_ranges if _addr_covers(ri.dest, s))
            if _ports_covered_any_aware(ri.service, ports):
                score += 1
            if score > best_score:
                best_score, best_rule = score, ri

    used = False

    def _overlay_side(items, side_getter):
        nonlocal used
        for m in items:
            if m.status != 'new':
                continue
            if best_rule is not None and _addr_covers(side_getter(best_rule), m.ip_int):
                m.status = 'candidate'
                m.existing_name = best_rule.rule.name
                m.existing_kind = 'candidate_rule'
                used = True
                continue
            if candidate_idx is not None:
                found = find_existing_ip_representation(m.ip_int, candidate_idx)
                if found:
                    m.status = 'candidate'
                    m.existing_name, m.existing_kind = found
                    used = True

    _overlay_side(res.source_report, lambda ri: ri.source)
    _overlay_side(res.dest_report, lambda ri: ri.dest)

    if best_rule is not None and res.missing_ports:
        remaining_ports = []
        for mp in res.missing_ports:
            proto = mp.protocol or 'tcp'
            if _svc_covers(best_rule.service, proto, mp.start) and _svc_covers(best_rule.service, proto, mp.end):
                res.candidate_ports.append(mp)
                used = True
            else:
                remaining_ports.append(mp)
        res.missing_ports = remaining_ports

    if used:
        res.used_candidate_rule = best_rule.rule.name if best_rule is not None else "candidate object"


def _addr_scope_size(resolved: ResolvedAddr) -> float:
    """Wrapper mong quanh ResolvedAddr.total_address_count() (dung chung logic voi
    index.find_best_covering_group) - dung lam tieu chi xep hang do 'chat' cua 1
    dai dien khi so sanh cac candidate rule trong TOP2/TOP3."""
    return resolved.total_address_count()


def _scan_all_tiers(rule_infos: List[RuleInfo], src_ranges, dst_ranges, ports,
                     zone_lookup: Optional[List[Tuple[int, int, int, str]]] = None) -> dict:
    """TOI UU HIEU NANG (khong doi 1 chut ket qua/luat nao so voi ban truoc) - gop 5
    vong lap rieng biet tung co trong classify_row/​_find_nearest_candidate_rule
    (TOP1, TOP1.1, TOP2, TOP3, va near_top2/near_top3/generic cua TOP4) thanh 1 LAN
    DUY NHAT quet qua toan bo rule_infos cho 1 dong request. Voi rulebase/file
    request lon, day la phan tram thoi gian CPU dang ke nhat cua toan bo pipeline -
    gop lai giup giam ~5 lan so lan duyet full list cho 1 dong (tot nhat la giam
    xuong dung 1 lan quet, hoac dung 0 - break ngay lap tuc - neu TOP1 khop som).

    NGUYEN TAC BAT BUOC khi doc/sua ham nay: TUYET DOI khong doi DIEU KIEN nhan biet
    tung tier (copy y het tung dieu kien tu ban goc, KHONG "toi uu" hay rut gon dieu
    kien logic - chi toi uu SO LAN DUYET LIST va SO LAN TINH LAI cung 1 gia tri cover
    cho cung 1 rule). Da co bo test differential (chay ca ham nay LAN ham
    _find_nearest_candidate_rule/​classify_row PHIEN BAN CU tren hang tram kich ban
    ngau nhien, so sanh tung field cua RowResult) xac nhan ket qua GIONG HET truoc
    khi thay the - xem ghi chu kiem chung trong PaloRuleSearchSuite_TaiLieu.md muc XIV.

    Tra ve dict thay vi RowResult - classify_row la noi DUY NHAT chiu trach nhiem
    dung du lieu nay de dung RowResult (giu nguyen cau truc code goc, de doi chieu).
    """
    top1_match: Optional[RuleInfo] = None      # rule DAU TIEN (theo thu tu list) thoa TOP1
    top1_1_match: Optional[RuleInfo] = None    # rule DAU TIEN thoa TOP1.1 (chi dung neu top1_match=None)
    top2: List[Tuple[int, RuleInfo]] = []
    top3: List[Tuple[int, RuleInfo]] = []
    near_top2: List[Tuple[float, int, float, RuleInfo]] = []
    near_top3: List[Tuple[float, int, float, RuleInfo]] = []
    generic: List[Tuple[float, RuleInfo]] = []

    n_src = len(src_ranges)
    n_dst = len(dst_ranges)

    # Sau khi tim duoc top1_1_match, TOP2/TOP3/near_top2/near_top3/generic cua CAC
    # RULE PHIA SAU khong con y nghia nua (TOP1.1 luon thang chung neu TOP1 khong
    # xuat hien them - ma dieu do CHI duoc xac dinh SAU KHI quet het list) - nen chi
    # con can tiep tuc kiem tra dieu kien TOP1 (phong khi no xuat hien MUON hon trong
    # list), bo qua toan bo phan tinh toan con lai de tiet kiem cong suc.
    skip_lower_tiers = False

    for ri in rule_infos:
        if ri.rule.action != 'allow' or ri.rule.disabled:
            continue

        both_any = _both_sides_any(ri)

        # ---- TOP1: uu tien tuyet doi, "rule DAU TIEN theo thu tu list" thoa dieu
        # kien - giong het vong lap TOP1 rieng biet ban goc (dieu kien copy nguyen
        # van, khong doi 1 ky tu). Tim duoc la BREAK NGAY, khong can xet gi them cho
        # dong request nay nua (dung y het hanh vi "return" cua ban goc). ----
        if not both_any and _service_ok_for_match(ri.service, ports) and \
           _side_all(ri.source, src_ranges, wide=False) and \
           _side_all(ri.dest, dst_ranges, wide=False):
            top1_match = ri
            break

        if skip_lower_tiers:
            continue

        # ---- TOP1.1: chi ghi nhan CANDIDATE DAU TIEN (dieu kien copy nguyen van tu
        # vong lap TOP1.1 ban goc) - KHONG break, vi 1 rule TOP1 co the xuat hien o
        # vi tri SAU trong list va phai duoc uu tien tuyet doi hon. ----
        if top1_1_match is None and not both_any and \
           _side_all(ri.source, src_ranges, wide=False) and _side_all(ri.dest, dst_ranges, wide=False):
            if _is_exactly_scoped(ri.source, src_ranges) and _is_exactly_scoped(ri.dest, dst_ranges):
                top1_1_match = ri
                skip_lower_tiers = True
                continue

        # ---- Tinh CHUNG 1 lan duy nhat cho rule nay: truoc day 3 noi khac nhau
        # (vong lap TOP2, vong lap TOP3, va _find_nearest_candidate_rule) deu tu
        # tinh lai CHINH XAC cung 4 gia tri nay cho CUNG 1 rule - gop lai o day la
        # phan tiet kiem CPU dang ke nhat. ----
        port_ok = _service_ok_for_match(ri.service, ports)
        dst_covered_cnt = sum(1 for (s, e, _t) in dst_ranges if ri.dest.covers_range_wide(s, e))
        src_covered_cnt = sum(1 for (s, e, _t) in src_ranges if ri.source.covers_range_wide(s, e))
        dest_full = bool(n_dst) and dst_covered_cnt == n_dst
        source_full = bool(n_src) and src_covered_cnt == n_src

        # ---- TOP2 candidacy (dieu kien copy nguyen van vong lap TOP2 ban goc) ----
        if port_ok and dest_full and _is_exactly_scoped(ri.dest, dst_ranges):
            top2.append((src_covered_cnt, ri))
        # ---- TOP3 candidacy (dieu kien copy nguyen van vong lap TOP3 ban goc) ----
        if port_ok and source_full and _is_exactly_scoped(ri.source, src_ranges):
            top3.append((dst_covered_cnt, ri))

        # ---- near_top2/near_top3/generic (dieu kien copy nguyen van tu
        # _find_nearest_candidate_rule ban goc, ke ca thu tu if/continue) ----
        if both_any:
            continue
        if port_ok and dest_full and not ri.dest.is_any and not _is_exactly_scoped(ri.dest, dst_ranges):
            frac = src_covered_cnt / n_src if src_ranges else 0
            missing_zone_cnt = len(_missing_zones(src_ranges, ri.rule.from_zones, zone_lookup))
            near_top2.append((ri.dest.total_address_count(), missing_zone_cnt, -frac, ri))
            continue
        if port_ok and source_full and not ri.source.is_any and not _is_exactly_scoped(ri.source, src_ranges):
            frac = dst_covered_cnt / n_dst if dst_ranges else 0
            missing_zone_cnt = len(_missing_zones(dst_ranges, ri.rule.to_zones, zone_lookup))
            near_top3.append((ri.source.total_address_count(), missing_zone_cnt, -frac, ri))
            continue
        if dst_covered_cnt == 0 and src_covered_cnt == 0:
            continue
        score = (dst_covered_cnt / n_dst if dst_ranges else 0) + \
                (src_covered_cnt / n_src if src_ranges else 0) + \
                (1 if port_ok else 0)
        generic.append((score, ri))

    return {
        "top1_match": top1_match,
        "top1_1_match": top1_1_match,
        "top2": top2,
        "top3": top3,
        "near_top2": near_top2,
        "near_top3": near_top3,
        "generic": generic,
    }


def _select_nearest_from_scan(scan: dict) -> Optional[Tuple[RuleInfo, str]]:
    """Ap dung DUNG NGUYEN VAN thu bac uu tien near_top2 > near_top3 > generic (xem
    docstring goc trong _find_nearest_candidate_rule) len 3 list da thu thap san boi
    _scan_all_tiers - tach rieng ham nay de CA _find_nearest_candidate_rule (goi doc
    lap, neu co) LAN classify_row (dung truc tiep ket qua _scan_all_tiers, khong quet
    lai) deu dung chung 1 noi DUY NHAT chua logic chon-tier-nao, tranh 2 noi code dieu
    kien nay bi lech nhau qua thoi gian bao tri."""
    near_top2 = scan["near_top2"]
    near_top3 = scan["near_top3"]
    generic = scan["generic"]
    if near_top2:
        near_top2.sort(key=lambda x: (x[0], x[1], x[2]))
        _sz, _zc, _nf, ri = near_top2[0]
        return (ri, 'near_top2')
    if near_top3:
        near_top3.sort(key=lambda x: (x[0], x[1], x[2]))
        _sz, _zc, _nf, ri = near_top3[0]
        return (ri, 'near_top3')
    if generic:
        generic.sort(key=lambda x: -x[0])
        _score, ri = generic[0]
        return (ri, 'generic')
    return None


def _find_nearest_candidate_rule(rule_infos: List[RuleInfo], src_ranges, dst_ranges,
                                  ports, zone_lookup: Optional[List[Tuple[int, int, int, str]]] = None
                                  ) -> Optional[Tuple[RuleInfo, str]]:
    """CHI dung khi da roi toi TOP4 (khong co rule nao du dieu kien an toan cho
    TOP1/TOP1.1/TOP2/TOP3) - tim 1 rule 'GAN DUNG NHAT' de GOI Y cho admin xem xet
    (KHONG phai de tu dong chon/ap dung nhu TOP1-3).

    QUAN TRONG - PHAN TANG UU TIEN (khac ban dau, da sua theo phan hoi thuc te): Port
    KHONG duoc coi ngang hang voi Dest/Source trong 1 cong thuc diem so gop chung nhu
    truoc day. 1 rule Dest+Source khop nhung Port SAI HOAN TOAN (vd rule ICMP trong
    khi input la TCP) ban chat la 1 loai traffic/service KHAC HAN, khong phai "gan
    dung" theo nghia thuc te - trong khi 1 rule co Port DA KHOP DU + 1 ben (Source
    hoac Dest) da khop DU, chi thieu dung 1 ben con lai, moi thuc su la candidate
    "gan dung" dang gia (tuong duong TOP2/TOP3 that, chi thieu dieu kien an toan
    '_is_exactly_scoped'). Vi vay chia lam 3 tang uu tien GIAM DAN:

    1. near_top2: giong het dieu kien cua TOP2 THAT (Dest cover DU input + Port DU) -
       CHI thieu dung 1 dieu kien an toan '_is_exactly_scoped(Dest)' (Dest cua rule
       nay RONG HON input, co the chua them dia chi khac ngoai pham vi dang xet) ->
       goi y "+ ADD SOURCE" (kem canh bao ro rang chua qua kiem tra an toan tuyet doi).
    2. near_top3: doi xung voi (1) - Source cover DU + Port DU, chi thieu exact-scope
       Source -> goi y "+ ADD DEST".
    3. generic: cac truong hop con lai (thieu Port, hoac chi cover 1 phan ca Dest lan
       Source) - MO TA THAM KHAO don thuan, KHONG goi y "+ ADD" cu the vi khong the
       xac dinh ro can bo sung chinh xac gi.

    near_top2/near_top3 LUON duoc uu tien tra ve TRUOC generic, bat ke diem so tuyet
    doi the nao - dung theo dinh huong: candidate co Port dung + 1 ben khop du LUON
    dang tin cay hon candidate Dest+Source khop nhung sai Port.

    THU BAC GIUA near_top2 VA near_top3 (sua loi 08/2026): near_top2 LUON duoc uu
    tien tuyet doi truoc near_top3 - dung y het tinh than TOP2 THAT luon duoc thu
    TRUOC TOP3 THAT trong classify_row (TOP2 co candidate la return luon, khong bao
    gio con xet TOP3). KHONG duoc so sanh diem/scope CHEO giua 2 nhom nay voi nhau
    (vd 1 candidate near_top3 co Dest scope rat nho khong duoc phep "thang" 1
    candidate near_top2 chi vi con so do tinh co nho hon - 2 con so khac ban chat,
    1 ben do scope Source, 1 ben do scope Dest). Neu near_top2 co it nhat 1 candidate,
    near_top3 bi bo qua hoan toan du co the "dep" hon ve diem so.

    Rule co Dest/Source = 'any' o phia da "khop du" KHONG duoc tinh vao near_top2/
    near_top3 (qua chung chung, goi y "+ ADD" vao 1 rule Dest/Source=any khong co
    nhieu gia tri thuc te, de roi xuong nhanh generic hoac bi loai neu ca 2 ben deu
    khong lien quan).

    Tra ve None neu KHONG co rule nao lien quan chut nao."""
    scan = _scan_all_tiers(rule_infos, src_ranges, dst_ranges, ports, zone_lookup)
    return _select_nearest_from_scan(scan)


def _describe_nearest_rule(ri: RuleInfo, src_ranges, dst_ranges, ports) -> str:
    """Mo ta ngan gon phan da khop / con thieu cua 1 rule duoc goi y boi
    _find_nearest_candidate_rule - dung hien thi truc tiep trong cot 'Rule Lien Quan
    (TOP4)' cua file Excel xuat ra, KHONG dung de tu dong ap dung/bo sung gi ca (chi
    la thong tin tham khao cho admin quyet dinh)."""
    dst_missing = [t['display'] for (s, e, t) in dst_ranges if not ri.dest.covers_range_wide(s, e)]
    src_missing = [t['display'] for (s, e, t) in src_ranges if not ri.source.covers_range_wide(s, e)]
    port_ok = _service_ok_for_match(ri.service, ports)

    dst_covered = len(dst_ranges) - len(dst_missing)
    src_covered = len(src_ranges) - len(src_missing)

    parts = [f"Dest {dst_covered}/{len(dst_ranges)} khop" +
             (f" (thieu: {', '.join(dst_missing)})" if dst_missing else "")]
    parts.append(f"Source {src_covered}/{len(src_ranges)} khop" +
                 (f" (thieu: {', '.join(src_missing)})" if src_missing else ""))
    parts.append("Port du" if port_ok else "Port thieu")
    return " | ".join(parts)


# =========================================================================
# MAIN ROW CLASSIFICATION ENGINE
# =========================================================================

def classify_row(
    row: RequestRow,
    rule_infos: List[RuleInfo],
    idx: DeviceIndex,
    same_subnet_prefix: int = 24,
    mgmt_ip: Optional[str] = None,
    api_key: Optional[str] = None,
    vsys: str = "vsys1",
    max_workers: int = 30,
    log_func=None,
    zone_lookup: Optional[List[Tuple[int, int, int, str]]] = None,
    target_serial: Optional[str] = None,
) -> RowResult:
    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens if t['kind'] != 'invalid']
    ports = row.port_tokens

    if not src_ranges or not dst_ranges or not ports:
        return RowResult(row, 'INVALID', None, note='Dữ liệu IP/Port không hợp lệ.')

    # ƯU TIÊN BƯỚC 1: Test Policy Match - BAN PANORAMA chi chay khi co Target Firewall
    # (0.5); thieu target -> LIVE_MATCH tu bo qua im lang, roi thang xuong local.
    if mgmt_ip and api_key and target_serial:
        live_res = try_live_match(row, mgmt_ip, api_key, vsys, rule_infos, idx,
                                   max_workers=max_workers, log_func=log_func,
                                   target_serial=target_serial)
        if live_res:
            return live_res

    # BƯỚC 2: Kiểm tra Same Subnet
    if _check_same_subnet(src_ranges, dst_ranges, same_subnet_prefix):
        return RowResult(row, 'SAME_SUBNET', None,
                          note=f'Source và Dest cùng nằm trong 1 subnet /{same_subnet_prefix}.')

    # BƯỚC 3: Nếu kết nối CHƯA tồn tại đầy đủ trên thiết bị -> Nhảy sang các logic phân tích offline
    #
    # TOI UU HIEU NANG (khong doi 1 chut luat/ket qua nao): TRUOC DAY o day co 4 vong
    # lap rieng biet `for ri in rule_infos` (TOP1, TOP1.1, TOP2, TOP3) cong them 1
    # vong lap thu 5 ben trong _find_nearest_candidate_rule (TOP4) - nghia la 1 dong
    # request roi vao TOP4 (khong khop TOP1-3) phai quet TOAN BO rulebase toi 5 LAN.
    # Da gop ca 5 vong lap do thanh 1 LAN DUY NHAT quet qua rule_infos (ham
    # _scan_all_tiers) - dieu kien nhan biet tung tier giu NGUYEN VAN tung chu (xem
    # docstring _scan_all_tiers), CHI toi uu so lan duyet list + so lan tinh lai
    # cover cho cung 1 rule. Da kiem chung bang test differential (so sanh RowResult
    # tung field giua ban truoc/sau toi uu tren hang tram kich ban ngau nhien) - xem
    # PaloRuleSearchSuite_TaiLieu.md muc XIV.
    scan = _scan_all_tiers(rule_infos, src_ranges, dst_ranges, ports, zone_lookup)

    if scan["top1_match"] is not None:
        ri = scan["top1_match"]
        src_report = build_field_report(src_ranges, ri.source_members, idx, wide=False)
        dst_report = build_field_report(dst_ranges, ri.dest_members, idx, wide=False)
        shadow = _find_shadowing_rule(rule_infos, ri, src_ranges, dst_ranges, ports)
        return RowResult(row, 'TOP1', ri.rule, src_report, dst_report,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(ri.rule, src_ranges, dst_ranges, zone_lookup))

    if scan["top1_1_match"] is not None:
        ri = scan["top1_1_match"]
        src_report = build_field_report(src_ranges, ri.source_members, idx, wide=False)
        dst_report = build_field_report(dst_ranges, ri.dest_members, idx, wide=False)
        missing_ports = find_missing_ports(ports, ri.service, idx)
        shadow = _find_shadowing_rule(rule_infos, ri, src_ranges, dst_ranges, ports)
        return RowResult(row, 'TOP1.1', ri.rule, src_report, dst_report, missing_ports=missing_ports,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(ri.rule, src_ranges, dst_ranges, zone_lookup))

    top2 = scan["top2"]
    if top2:
        # Uu tien Dest HEP HON (cu the hon) TRUOC TIEN, TUYET DOI - mot rule co dest la
        # group nho, purpose-built (vd 'SOA-EMS-Core-150-151') phai luon thang mot rule
        # dest la group rong/catch-all (vd 'SOA-EMS') dung lam candidate, BAT KE rule
        # catch-all do co the cover duoc nhieu Source hon. Chi khi 2 rule co Dest scope
        # bang nhau (hoa diem) moi xet tiep den so Source duoc cover nhieu hon.
        top2.sort(key=lambda x: (_addr_scope_size(x[1].dest), -x[0]))
        _cnt, best = top2[0]
        src_report = build_field_report(src_ranges, best.source_members, idx, wide=True)
        dst_report = build_field_report(dst_ranges, best.dest_members, idx, wide=True)
        shadow = _find_shadowing_rule(rule_infos, best, src_ranges, dst_ranges, ports)
        return RowResult(row, 'TOP2', best.rule, src_report, dst_report,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(best.rule, src_ranges, dst_ranges, zone_lookup))

    top3 = scan["top3"]
    if top3:
        # Doi xung voi TOP2: uu tien Source HEP HON TRUOC TIEN, TUYET DOI (vi o day Dest
        # da duoc bat buoc cover du roi, Source moi la phan con thieu can chon dai dien
        # chinh xac nhat) - khong con de "cover duoc nhieu Dest hon" ghi de len do cu the.
        top3.sort(key=lambda x: (_addr_scope_size(x[1].source), -x[0]))
        _cnt, best = top3[0]
        src_report = build_field_report(src_ranges, best.source_members, idx, wide=True)
        dst_report = build_field_report(dst_ranges, best.dest_members, idx, wide=True)
        shadow = _find_shadowing_rule(rule_infos, best, src_ranges, dst_ranges, ports)
        return RowResult(row, 'TOP3', best.rule, src_report, dst_report,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(best.rule, src_ranges, dst_ranges, zone_lookup))

    src_report = build_field_report(src_ranges, [], idx, wide=True)
    dst_report = build_field_report(dst_ranges, [], idx, wide=True)
    missing_ports = find_missing_ports(ports, ResolvedService(), idx)

    # Goi y rule GAN DUNG NHAT (chi tham khao, khong tu dong chon/ap dung) - CHI 1 ket
    # qua duy nhat (khong con liet ke tran lan nhieu rule/group nhu truoc), hien truc
    # tiep trong o Name Rule (xem build_name_rule_cell trong exporter.py). "Chua co Rule
    # - can tao moi" gio CHI con la truong hop cuoi cung, khi khong tim duoc gi ca.
    # Dung LAI ket qua da co san tu `scan` (near_top2/near_top3/generic) qua
    # _select_nearest_from_scan - KHONG goi _find_nearest_candidate_rule() nua (se
    # trigger quet lai LAN THU 2 toan bo rule_infos, mat het loi ich toi uu vua lam).
    nearest_rule = nearest_kind = nearest_side = nearest_detail = None
    nearest = _select_nearest_from_scan(scan)
    if nearest is not None:
        near_ri, near_kind = nearest
        nearest_rule = near_ri.rule
        nearest_kind = near_kind
        nearest_detail = _describe_nearest_rule(near_ri, src_ranges, dst_ranges, ports)
        if near_kind == 'near_top2':
            nearest_side = 'source'
        elif near_kind == 'near_top3':
            nearest_side = 'dest'

    return RowResult(row, 'TOP4', None, src_report, dst_report, missing_ports=missing_ports,
                      nearest_rule=nearest_rule, nearest_rule_kind=nearest_kind,
                      nearest_missing_side=nearest_side, nearest_detail=nearest_detail)