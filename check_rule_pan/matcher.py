# -*- coding: utf-8 -*-
import ipaddress
import time  # noqa: F401 - giu lai phong khi can do dac biet cho troubleshoot sau nay
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Set, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

from .core import SecurityRule, is_literal_ip_or_cidr, fetch_security_policy_match
from .resolver import ResolvedAddr, ResolvedService, GroupResolver, ServiceResolver
from .index import DeviceIndex, find_existing_ip_representation, find_best_covering_group, resolve_zone_for_ip, find_existing_service_representation, find_existing_range_representation, global_find_rank_objects
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
    nearest_missing_side: Optional[str] = None   # 'source' (near_top2) | 'dest' (near_top3) | None (ben do THUC RA da khop du - xem SUA LOI trong classify_row)
    nearest_detail: Optional[str] = None         # "Dest x/y khop | Source x/y khop | Port du/thieu"
    nearest_fully_covered: bool = False   # True khi near_top2/near_top3 nhung CA HAI ben (Source
                                          # VA Dest) + Port deu da cover du qua wide-match, chi thieu
                                          # dung dieu kien an toan exact-scope (khong co gi de "+ ADD")
    # SUA LOI (10/2026): doi xung voi nearest_fully_covered nhung cho tier TOP2/TOP3.
    # TOP2 chi bat buoc Dest cover du + exact-scope + Port du - KHONG he xet Source;
    # TOP3 doi xung. Neu ben "gia dinh con thieu" do THUC RA da duoc chinh rule nay
    # cover DU 100% (thuong qua 1 subnet rong nhu Net_10.1.1.0/24, ma tang bao cao
    # LOCAL co y KHONG tinh la in_rule theo nguyen tac exact-only) thi KHONG con gi
    # de "+ ADD" - exporter dung co nay de hien 'DA DUOC CHO PHEP' (xanh duong, kem
    # khuyen nghi xac nhan Live Match) thay vi mau cam "+ ADD SOURCE/DEST" + "TAO MOI"
    # SAI. Day la dung co che da ap dung cho near_top2/near_top3 tu ban 09/2026,
    # truoc gio con thieu o TOP2/TOP3.
    wide_fully_covered: bool = False
    # Ly do Live Match khong hoan tat cho dong nay (chi dien khi Live Match DA DUOC
    # BAT - co mgmt_ip/api_key - nhung try_live_match() tra ve None). Exporter dung
    # 2 field nay de noi them 1 dong caveat rieng trong o Name Rule cho MOI action
    # level (khong chi TOP4), vi day la thong tin ve QUA TRINH kiem tra, doc lap voi
    # ket luan LOCAL cuoi cung.
    live_match_skip_reason: Optional[str] = None   # LIVE_MATCH_SKIP_SCALE | LIVE_MATCH_SKIP_INCONCLUSIVE
    live_match_skip_detail: Optional[str] = None   # mo ta cu the (so combo, combo loi...)
    # SUA LOI (10/2026 - "tool khong doc duoc" ma khong he bao gi): token Source/Dest
    # nao parse_ip_token() khong hieu truoc gio bi classify_row() LOC BO AM THAM khoi
    # src_ranges/dst_ranges - neu dong con token khac hop le thi dong do van chay binh
    # thuong va co the ra "FULL MATCH" xanh la, trong khi 1 dai IP cua request da BIEN
    # MAT khoi ket qua ma khong co bat ky canh bao nao. 2 field duoi day luu lai dung
    # cac token do de exporter in 1 dong DO ngay trong o Source/Dest va chan khong cho
    # dong do duoc to xanh "FULL MATCH".
    unparsed_source: List[str] = field(default_factory=list)
    unparsed_dest: List[str] = field(default_factory=list)


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
    return all(resolved.covers_input_wide(s, e) for (s, e, _t) in ranges)


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
    ivs = sorted((s, e) for (s, e, _t) in ranges)
    total, cur_s, cur_e = 0, None, None
    for a, b in ivs:
        if cur_e is not None and a <= cur_e + 1:
            cur_e = max(cur_e, b)
        else:
            if cur_e is not None:
                total += cur_e - cur_s + 1
            cur_s, cur_e = a, b
    if cur_e is not None:
        total += cur_e - cur_s + 1
    return total


def _is_exactly_scoped(resolved: ResolvedAddr, ranges) -> bool:
    """Kiem tra 1 ResolvedAddr (source hoac dest cua 1 rule) co CHI CHUA DUNG cac dia
    chi trong 'ranges' hay khong - khong thua bat ky dia chi nao khac. Dung de chan cac
    goi y 'ADD PORT'/'ADD SOURCE'/'ADD DEST' KHONG AN TOAN: neu 1 rule cover du dieu
    kien nhung source/dest cua no la 1 group RONG (chua nhieu object khac ngoai pham vi
    dang xet), thi viec 'chi can bo sung phan con thieu' se VO TINH cap them quyen cho
    TAT CA cac object khac trong group do - khong chi rieng IP dang duoc yeu cau. CHI
    khi group/field do khop CHINH XAC 1:1 voi dung tap dang xet, goi y bo sung moi thuc
    su an toan."""
    return resolved.union_address_count() == _ranges_total_count(ranges)


def _exact_member_scope(members: List[Tuple[str, str, "ResolvedAddr"]], ranges) -> Optional[int]:
    """Kiem tra field (Source hoac Dest cua 1 rule, co the gom NHIEU object khac
    nhau) co chua DUNG 1 member RIENG LE dai dien CHINH XAC 1:1 cho toan bo
    'ranges' cua request hay khong - khac voi _is_exactly_scoped() (xet TONG GOP
    ca field, se bi false-negative khi field co them object KHONG lien quan cho
    muc dich khac cua rule). Neu co, tra ve total_address_count() cua RIENG
    member do (dung lam 'scope an toan that su' cho tier TOP2/TOP3 va tie-break,
    thay vi bi tinh nham theo tong ca field). Tra ve None neu khong co member nao
    khop tuyet doi rieng le - giu nguyen hanh vi cu (chi con dua vao
    _is_exactly_scoped)."""
    req_total = _ranges_total_count(ranges)
    if req_total == 0:
        return None
    for _nm, _kind, resolved in members:
        if resolved.union_address_count() == req_total and \
           all(resolved.covers_input_wide(s, e) for (s, e, _t) in ranges):
            return resolved.total_address_count()
    return None


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
    """SUA LOI (10/2026): dung covers_input_wide/covers_input_exact thay cho
    covers_range_wide/covers_range_exact - xem docstring covers_input_exact() trong
    resolver.py. Ly do: 1 TOKEN INPUT dang RANGE duoc rule cover DU nho HOP nhieu
    member lien ke (11 host object, hay 2 range object 100-104 + 105-110) truoc day
    bi coi la CHUA cover nen tier roi xuong TOP2/TOP3/TOP4 va tool goi y '+ ADD
    SOURCE/DEST' oan - trong khi tang BAO CAO (build_field_report) da dung dung hop
    interval tu ban fix 09/2026 -> 2 tang lech nhau. Voi input la IP DON, 2 ham moi
    cho ket qua Y HET 2 ham cu (da chung minh trong docstring resolver), nen thay
    doi nay CHI tac dong den token input dang range/CIDR va CHI theo huong 'nhan ra
    them coverage THAT SU co' - khong bao gio ngung nhan 1 coverage da nhan truoc day.
    Nguyen tac exact-only cua thiet ke goc GIU NGUYEN: nhanh wide=False van KHONG
    chap nhan subnet rong (ngoai tru member co bounds trung khit 1:1 voi input)."""
    if wide:
        return all(resolved.covers_input_wide(s, e) for (s, e, _t) in ranges)
    return all(resolved.covers_input_exact(s, e) for (s, e, _t) in ranges)


def _find_full_set_exact_match(host_set: Set[int], idx: DeviceIndex
                               ) -> Optional[Tuple[str, str]]:
    """Tim 1 Address Object (Range/Wide dung doc lap) hoac 1 Address Group khop
    tuyet doi 1:1 voi TOAN BO tap host IP goc cua field (dung du so dia chi,
    khong thua khong thieu) - tra ve (ten, kind) hoac None.

    Nguyen tac exact-only TUYET DOI khong noi long:
    - Object doc lap: khoang [a, b] phai co dung bang len(host_set) dia chi VA
      tap dia chi do phai trung khit host_set (object rong hon bao trum thua
      dia chi ngoai tap -> loai).
    - Group: tong dia chi thuc su (total_address_count) phai dung bang
      len(host_set) VA tung IP phai duoc cover exact (covers_range_exact -
      khong dung wide) - group co member thua/subnet rong -> loai nho dieu
      kien dem bang nhau."""
    n = len(host_set)
    if not n:
        return None
    rng_hit = [nm for a, b, nm in idx.range_objs
               if b - a + 1 == n and set(range(a, b + 1)) == host_set]
    if rng_hit:
        return (global_find_rank_objects(rng_hit, idx)[0], 'range')
    wide_hit = [nm for a, b, nm in idx.wide_objs
                if b - a + 1 == n and set(range(a, b + 1)) == host_set]
    if wide_hit:
        return (global_find_rank_objects(wide_hit, idx)[0], 'wide')
    grp_hit = [gname for gname, resolved in idx.group_resolved.items()
               if resolved.total_address_count() == n and
               all(resolved.covers_range_exact(ip, ip) for ip in host_set)]
    if grp_hit:
        return (min(grp_hit, key=lambda g: (idx.group_member_count.get(g, 10 ** 9), g)), 'group')
    return None


def _field_union_cover(rule_members: List[Tuple[str, str, ResolvedAddr]],
                        start: int, end: int, use_wide: bool
                        ) -> Optional[Tuple[str, str]]:
    """SUA LOI (10/2026 - "range da nam DU trong rule nhung van bao TAO MOI"): cac
    nhanh bao cao range truoc day CHI xet TUNG MEMBER RIENG LE
    (`resolved.covers_range_exact_union(s, e)` cho tung member) - nen 1 dai input duoc
    rule cover DU nho HOP NHIEU MEMBER KHAC NHAU cua cung 1 field (vd Source cua rule
    gom 2 object Range_100-104 + Range_105-110, input la 10.1.1.100-110) van roi xuong
    'exists'/'new' -> bao "can ADD/TAO MOI" oan. Ham nay bu dung khoang trong do: hop
    interval cua TOAN BO member trong field roi kiem tra lai.

    Tra ve (ten_dai_dien, kind) cua CAC member THUC SU gop phan cover dai nay (de admin
    doi chieu duoc 'nho object nao'), hoac None neu hop cac member VAN khong du.

    - `use_wide=False`: exact-only (host + ip-range), KHONG tinh subnet rong - dung cho
      bao cao LOCAL, giu nguyen nguyen tac thiet ke goc.
    - `use_wide=True`: chap nhan ca subnet rong - CHI dung cho bao cao LIVE_MATCH (da
      duoc chinh firewall xac nhan allow).
    Neu field co member 'any' thi da duoc xu ly truoc do o noi goi, khong vao day.
    """
    if not rule_members:
        return None
    merged = ResolvedAddr()
    for _nm, _kind, resolved in rule_members:
        if resolved.is_any:
            return (_nm, _kind)
        merged.exact_singles |= resolved.exact_singles
        merged.exact_ranges += resolved.exact_ranges
        if use_wide:
            merged.wide_ranges += resolved.wide_ranges
    merged._iv_cache.clear()
    covered = (merged.covers_range_wide_union(start, end) if use_wide
               else merged.covers_range_exact_union(start, end))
    if not covered:
        return None

    # Xac dinh dung nhung member co dong gop dia chi NAM TRONG [start, end] - khong
    # liet ke bua cac member khong lien quan.
    contributors: List[Tuple[str, str]] = []
    for nm, kind, resolved in rule_members:
        ivs = [(x, x) for x in resolved.exact_singles] + list(resolved.exact_ranges)
        if use_wide:
            ivs += list(resolved.wide_ranges)
        if any(a <= end and start <= b for a, b in ivs):
            contributors.append((nm, kind))
    if not contributors:
        return None
    if len(contributors) == 1:
        return contributors[0]
    names = [nm for nm, _k in contributors]
    label = " + ".join(names[:3])
    if len(names) > 3:
        label += f" + {len(names) - 3} object khac"
    kind = 'group' if any(k == 'group' for _n, k in contributors) else 'multi'
    return (label, kind)


def _mark_side_fully_covered(report: List[MissingItem], ranges,
                              rule_members: List[Tuple[str, str, ResolvedAddr]]) -> None:
    """SUA LOI (10/2026): chi duoc goi khi da XAC NHAN rule dang xet cover DU 100% ben
    nay (RowResult.wide_fully_covered) - doi cac item con dang 'new'/'exists' thanh
    'in_rule' kem ten member chiu trach nhiem, de o Source/Dest KHONG con dong do
    "TAO MOI"/cam "can ADD" trai nguoc voi ket luan "DA DUOC CHO PHEP" o cot Name Rule.

    KHONG noi long nguyen tac exact-only cua build_field_report(): ham do van giu y
    nguyen hanh vi (va test test_wide_only_group_not_in_rule_local van dung) - day chi
    la buoc HAU XU LY o classify_row, chay DUY NHAT khi ca ben da duoc chung minh cover
    du, nen khong the sinh ra goi y "nhet IP vao object rong" nao.
    """
    if not report or not rule_members:
        return
    disp_to_se = {}
    for (s, e, t) in ranges:
        disp_to_se[t['display']] = (s, e)
    for m in report:
        if m.status not in ('new', 'exists'):
            continue
        s, e = disp_to_se.get(m.range_display or m.display, (m.ip_int, m.ip_int))
        found = None
        for name, kind, resolved in rule_members:
            if kind == 'any':
                found = (name, 'any')
                break
            if resolved.covers_input_wide(s, e):
                found = (name, kind)
                break
        if found is None:
            found = _field_union_cover(rule_members, s, e, use_wide=True)
        if found is None:
            continue
        m.status = 'in_rule'
        m.existing_name, m.existing_kind = found
        m.group_coverage_pct = None
        m.group_member_count = None


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

    # FULL-SET EXACT MATCH (chay SAU greedy de bao ve rule da khop khit): neu
    # _greedy_assign da gan HET tap goc thanh in_rule (rule da co san dai dien
    # chinh xac cho tung IP) thi giu nguyen - khong danh lai thanh exists.
    # Nguoc lai (con residual), kiem tra 1 object/group khop tuyet doi 1:1 voi
    # TOAN BO tap goc: neu co, bao cao THONG NHAT toan bo IP la exists theo
    # object/group do (ke ca IP da co san trong rule qua Host rieng le - tranh
    # che vun bao cao), residual khong bao gio roi vao new/TAO MOI oan.
    # Ly do phai dung tap GOC (host_items) chu khong phai remaining: remaining
    # da thieu cac IP in_rule nen phep so khop 1:1 voi Range bao tron ca dai
    # (vd Range_10.31.0.120-130, 11 dia chi) se that bai oan.
    if remaining:
        full_match = _find_full_set_exact_match(
            {s for (s, e, t) in host_items}, idx)
        if full_match is not None:
            full_name, full_kind = full_match
            full_mcount = idx.group_member_count.get(full_name) \
                if full_kind == 'group' else None
            results = [MissingItem(s, ip_display[s], 'exists', full_name,
                                   full_kind, group_coverage_pct=100,
                                   group_member_count=full_mcount)
                       for (s, e, t) in host_items]
            remaining = set()

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
            if resolved.covers_input_exact(s, e):
                found_exact_in_rule = (name, kind)
                break
        if found_exact_in_rule is None:
            # Khong member nao RIENG LE cover du -> thu HOP toan bo member cua field
            # (vd Source = Range_100-104 + Range_105-110, input 100-110).
            found_exact_in_rule = _field_union_cover(rule_members, s, e, use_wide=False)
        if found_exact_in_rule:
            results.append(MissingItem(s, disp, 'in_rule', found_exact_in_rule[0], found_exact_in_rule[1],
                                        is_range_input=True, range_display=disp))
            continue
        exists_as = find_existing_range_representation(s, e, idx)
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
        # Khong member nao RIENG LE cover du -> thu HOP toan bo member cua field
        # (LIVE chap nhan ca subnet rong vi firewall da xac nhan allow).
        return _field_union_cover(rule_members, s, e, use_wide=True)

    results: List[MissingItem] = []

    for (s, e, t) in host_items:
        found = _find_in_rule(s, s)
        if found:
            nm, kind = found
            results.append(MissingItem(s, ip_display[s], 'in_rule', nm, kind))
            continue
        # Tu v3: day la nhanh THUONG GAP (Live Match chi con dung SO IP dai dien de
        # xac dinh rule, khong con test het moi combo) - tim dai dien tren toan thiet
        # bi cho IP KHONG khop truc tiep member cua rule, neu khong co gi thi moi coi
        # la 'new' (that su can bo sung).
        ex = find_existing_ip_representation(s, idx)
        if ex:
            nm, kind = ex
            results.append(MissingItem(s, ip_display[s], 'exists', nm, kind))
        else:
            results.append(MissingItem(s, ip_display[s], 'new', None, None))

    # SUA LOI: build_live_match_field_report truoc gio BO QUA group_coverage_pct,
    # khien hien thi cot Source/Dest luon liet ke het danh sach IP thay vi rut gon
    # "cover full IP(s)" du group da cover 100% dau vao. Tinh lai dung cong thuc
    # voi build_field_report (LOCAL): % theo TONG so host item cua field nay.
    total = len(host_items)
    if total:
        in_rule_counts: Dict[str, int] = {}
        for m in results:
            if m.status == 'in_rule' and m.existing_kind != 'any':
                in_rule_counts[m.existing_name] = in_rule_counts.get(m.existing_name, 0) + 1
        for m in results:
            if m.status == 'in_rule' and m.existing_kind != 'any':
                m.group_coverage_pct = round(in_rule_counts[m.existing_name] / total * 100)
                m.group_member_count = (idx.group_member_count.get(m.existing_name)
                                         if m.existing_kind == 'group' else None)

    for (s, e, t) in range_items:
        disp = t['display']
        found = _find_in_rule(s, e)
        if found:
            nm, kind = found
            results.append(MissingItem(s, disp, 'in_rule', nm, kind,
                                        is_range_input=True, range_display=disp))
            continue
        ex = find_existing_range_representation(s, e, idx)
        if ex:
            results.append(MissingItem(s, disp, 'exists', ex[0], ex[1],
                                        is_range_input=True, range_display=disp,
                                        group_member_count=(idx.group_member_count.get(ex[0]) if ex[1] == 'group' else None)))
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


# Ly do try_live_match() khong hoan tat, dung de build caveat minh bach o tang
# LOCAL fallback (xem RowResult.live_match_skip_reason). 2 nhom PHAN BIET:
# - SCALE: chua goi API firewall lan nao (vuot gioi han quy mo / khong co combo
#   hop le) - y nghia "CHUA kiem tra gi ca".
# - INCONCLUSIVE: da goi API nhung khong ket luan duoc (loi/timeout, action !=
#   allow, khop nhieu rule khac nhau) - y nghia "da kiem tra va co van de that".
LIVE_MATCH_SKIP_SCALE = "scale_limit"          # nhom 1: chua goi API lan nao
LIVE_MATCH_SKIP_INCONCLUSIVE = "inconclusive"  # nhom 2: da goi API nhung khong ket luan duoc


def try_live_match(
    row: RequestRow,
    mgmt_ip: str,
    api_key: str,
    vsys: str,
    rule_infos: List[RuleInfo],
    idx: DeviceIndex,
    max_combos: int = 300,
    max_workers: int = 30,
    log_func=None,
    max_port_span: int = 50,
    skip_info: Optional[dict] = None,
    live_match_concurrency: Optional[int] = None,
    live_match_semaphore: Optional[Any] = None,
    combo_cache: Optional[dict] = None,
    target_serial: Optional[str] = None,
) -> Optional[RowResult]:
    """Gọi API Test Policy Match QUA PANORAMA (proxy xuong dataplane firewall)

    BAN PANORAMA (require.md 0.5): `test security-policy-match` chay tren DATAPLANE
    cua 1 firewall cu the, Panorama chi forward - nen BAT BUOC co `target_serial`
    (serial firewall). Thieu target -> tra None NGAY, IM LANG (roi thang xuong thuat
    toan LOCAL), khong goi API, khong bao loi - dung tinh than "delegate hoan toan
    cho firewall, khong doan bua" cua ban goc, chi them 1 dieu kien tien quyet
    "phai biet doan ho AI". Moi luat con lai cua II.2.4 GIU NGUYEN TUYET DOI.

    NGUYEN TAC (v3, thay the all-or-nothing cu): chi can 1 combo Source x Dest
    x Port trong 1 dong tra `action=allow` la NHAN DIEN NGAY rule do (rule_name
    dau tien khop allow), DUNG SOM cac combo con lai (huy future chua chay) de
    tiet kiem API call - sau do dung LOCAL/static object matching
    (build_live_match_field_report, khong can them API call nao) doi chieu
    chinh xac TOAN BO Source/Dest request voi dung member cua rule vua xac
    dinh: IP nao khop thi 'in_rule', IP nao khong khop tu roi vao 'exists'/'new'
    nhu binh thuong. KHONG con abort vi 1 combo bi chan/loi/cho rule khac -
    combo fail rieng le chi la 1 IP "con thieu" trong report. Chi khi KHONG co
    combo nao allow moi tra None (INCONCLUSIVE) de classify_row() roi ve LOCAL.

    `max_combos` (mac dinh 300) la tran an toan so combo/API call cho 1 dong -
    cau hinh duoc tu GUI (o "Gioi han to hop Live Match"). `max_port_span`
    (mac dinh 50) la gioi han rieng cho do dai 1 port-range don le, doc lap voi
    `max_combos`. Khi khong hoan tat, ghi ly do vao `skip_info` (dict ngoai,
    2 key 'reason'/'detail') truoc moi `return None` de `classify_row()` gan
    tiep vao RowResult LOCAL fallback - admin nhin Excel biet ngay Live Match
    co duoc thu hay khong va vi sao (khong chi nam trong log.txt).

    HIEU NANG (09/2026, bat buoc di kem khi nang max_combos 50 -> 300):
    - Ket qua duoc xu ly theo thu tu HOAN THANH thuc te (`as_completed`), KHONG
      doi het nhu `executor.map()` truoc day. Ngay khi 1 combo tra
      `action=allow` -> lay `rule_name` cua no, huy cac future CHUA chay
      (`future.cancel()`) va DUNG SOM ngay lap tuc (1 combo allow DA DU de xac
      dinh rule, khong can test tiep - tiet kiem API call + tai firewall).
    - `live_match_semaphore` (threading.Semaphore DUNG CHUNG toan luot chay, do
      `gui.py` khoi tao 1 lan, mac dinh 30): moi lan goi API that deu `with`
      semaphore nay truoc - gioi han TONG so API call dong thoi tren toan tool,
      doc lap voi so DONG chay song song (`max_workers`/`thread_count`). Neu
      khong truyen, moi dong tu chay doc lap nhu truoc (tuong thich nguoc).
    - `live_match_concurrency` (tuy chon): so worker cua executor NOI BO cho
      vong goi API cua RIENG dong nay; mac dinh fallback ve
      `min(max_workers, len(combinations))` nhu hanh vi cu.
    - `combo_cache` (tuy chon, dict DUNG CHUNG toan luot chay): dedup combo
      TRUNG nhau giua cac dong - key `(src_ip, dst_ip, port, proto)`, tra cache
      truoc khi goi API, ghi vao cache sau khi goi (ket qua 1 combo la bat bien
      trong 1 luot chay nen tai su dung khong anh huong do chinh xac)."""
    def _mark_skip(reason: str, detail: str):
        if skip_info is not None:
            skip_info['reason'] = reason
            skip_info['detail'] = detail

    if not mgmt_ip or not api_key:
        return None
    # BAN PANORAMA (0.5): thieu Target Firewall (serial) -> bo qua tier LIVE_MATCH
    # ngay, im lang. KHONG ghi skip_info vi day khong phai "da thu nhung that bai"
    # (scale/inconclusive) ma la "tinh nang chua du dieu kien tien quyet" - giong
    # het cach zone-lookup tu vo hieu khi khong co du lieu Template.
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
                if p_end - p_start > max_port_span:
                    if log_func:
                        log_func(f"[Live Match] Bỏ qua: dải port {p_start}-{p_end} quá rộng (>{max_port_span}).")
                    _mark_skip(LIVE_MATCH_SKIP_SCALE,
                               f"dai port {p_start}-{p_end} vuot qua gioi han {max_port_span}")
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
        _mark_skip(LIVE_MATCH_SKIP_SCALE,
                   "khong co to hop Source/Dest/Port hop le de test")
        return None
    if len(combinations) > max_combos:
        if log_func:
            log_func(f"[Live Match] Bỏ qua: {len(combinations)} tổ hợp Source/Dest/Port > giới hạn {max_combos}.")
        _mark_skip(LIVE_MATCH_SKIP_SCALE,
                   f"{len(combinations)} to hop > gioi han {max_combos}")
        return None

    matched_rule_name: Optional[str] = None
    error_messages: List[str] = []

    def _collect_error(msg):
        error_messages.append(msg)

    def _fetch_one(combo):
        """1 lan goi API that cho 1 combo: tra cache truoc (neu co), gioi han
        dong thoi qua semaphore dung chung (neu co), ghi cache sau khi goi."""
        if combo_cache is not None and combo in combo_cache:
            return combo_cache[combo]
        s_ip, d_ip, port, proto = combo
        if live_match_semaphore is not None:
            with live_match_semaphore:
                res = fetch_security_policy_match(mgmt_ip, api_key, s_ip, d_ip, port, proto, vsys=vsys,
                                                   target_serial=target_serial, log_func=_collect_error)
        else:
            res = fetch_security_policy_match(mgmt_ip, api_key, s_ip, d_ip, port, proto, vsys=vsys,
                                               target_serial=target_serial, log_func=_collect_error)
        if combo_cache is not None:
            combo_cache[combo] = res
        return res

    def _check_one_result(combo, res) -> bool:
        """SUA (v3): khong con abort khi gap combo fail/bi chan/loi rieng le - chi
        ghi log roi bo qua, tiep tuc xet combo khac. Tra ve True NGAY KHI gap 1
        combo action=allow dau tien (dung lam tin hieu DUNG SOM - da du de xac
        dinh rule, khong can cho het cac combo con lai). Rule bi CHAN boi 1 rule
        khac (vd action=drop cua 1 rule cleanup dung truoc) khong con lam mat
        ket qua cua CA DONG nua - no chi la 1 IP/combo con thieu, se duoc LOCAL
        doi chieu tinh chinh xac o buoc sau (build_live_match_field_report),
        khong can goi them API nao nua cho no."""
        nonlocal matched_rule_name
        s_ip, d_ip, port, proto = combo
        if not res:
            if log_func:
                log_func(f"[Live Match] {s_ip}->{d_ip}:{port}/{proto} không xác nhận được (lỗi/timeout).")
            return False
        if res.get("action") != "allow":
            if log_func:
                log_func(f"[Live Match] {s_ip}->{d_ip}:{port}/{proto} khớp rule "
                          f"'{res.get('rule_name')}' nhưng action='{res.get('action')}' (không phải allow).")
            return False
        matched_rule_name = res.get("rule_name")
        if log_func:
            log_func(f"[Live Match] {s_ip}->{d_ip}:{port}/{proto} khớp rule "
                      f"'{matched_rule_name}' action=allow - đã xác định được rule, dừng Live Match "
                      f"sớm, chuyển sang đối chiếu tĩnh (LOCAL) với đúng rule này để tính phần còn thiếu.")
        return True

    # 1. Cac combo da co san trong cache - dung ngay khi gap 1 combo allow.
    to_fetch = []
    for combo in combinations:
        if combo_cache is not None and combo in combo_cache:
            if _check_one_result(combo, combo_cache[combo]):
                break
        else:
            to_fetch.append(combo)

    # 2. Goi API cho cac combo con lai - dung ngay khi gap 1 combo allow, huy
    # cac future CHUA chay (khong con can test tiep, da du de xac dinh rule).
    if matched_rule_name is None and to_fetch:
        pool_size = live_match_concurrency or min(max_workers, len(to_fetch))
        pool_size = max(1, pool_size)
        with ThreadPoolExecutor(max_workers=pool_size) as executor:
            future_to_combo = {executor.submit(_fetch_one, c): c for c in to_fetch}
            for fut in as_completed(future_to_combo):
                combo = future_to_combo[fut]
                try:
                    res = fut.result()
                except Exception:
                    res = None
                if _check_one_result(combo, res):
                    for f in future_to_combo:
                        f.cancel()
                    break

    if log_func:
        log_func(f"[Live Match] Da kiem tra {len(combinations)} to hop Source/Dest/Port qua Test Policy Match.")
    if log_func and error_messages:
        n_timeout = sum(1 for m in error_messages if 'timed out' in m or 'exception' in m)
        n_denied = sum(1 for m in error_messages if 'tu choi yeu cau' in m)
        n_other = len(error_messages) - n_timeout - n_denied
        log_func(f"[Live Match] {len(error_messages)}/{len(combinations)} call loi "
                 f"(timeout/exception: {n_timeout}, firewall tu choi: {n_denied}, khac: {n_other}) "
                 f"- vi du: {error_messages[0]}")

    if matched_rule_name is None:
        _mark_skip(LIVE_MATCH_SKIP_INCONCLUSIVE,
                   "khong co to hop nao khop action=allow tren firewall (da thu het hoac tat ca deu fail/loi)")
        return None

    matched_rule_info = next((r for r in rule_infos if r.rule.name == matched_rule_name), None)

    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens if t['kind'] != 'invalid']

    if matched_rule_info:
        # build_live_match_field_report tu doi chieu TOAN BO src_ranges/dst_ranges (ca
        # nhung IP CHUA duoc test qua API) voi dung member cua rule vua xac dinh - IP nao
        # khop thi 'in_rule', IP nao khong khop se tu dong roi vao 'exists'/'new' NHU
        # BINH THUONG (xem build_live_match_field_report, khong can sua gi them o do).
        src_report = build_live_match_field_report(src_ranges, matched_rule_info.source_members, idx)
        dst_report = build_live_match_field_report(dst_ranges, matched_rule_info.dest_members, idx)
        matched_rule = matched_rule_info.rule
    else:
        src_report = build_live_match_field_report(src_ranges, [], idx)
        dst_report = build_live_match_field_report(dst_ranges, [], idx)
        matched_rule = SecurityRule(index=-1, name=matched_rule_name, source=['?'], destination=['?'],
                                     service=['?'], application=['?'], action='allow', disabled=False)

    return RowResult(
        row=row,
        tier="LIVE_MATCH",
        rule=matched_rule,
        source_report=src_report,
        dest_report=dst_report,
        missing_ports=[],
        note=f"XÁC NHẬN QUA FIREWALL (Rule: {matched_rule_name}) - đã tìm thấy tổ hợp khớp "
             f"allow qua Test Policy Match, dùng LOCAL đối chiếu tĩnh để xác định chính xác "
             f"phần Source/Dest còn thiếu (xem cột Source/Dest)."
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
        dst_covered_cnt = sum(1 for (s, e, _t) in dst_ranges if ri.dest.covers_input_wide(s, e))
        src_covered_cnt = sum(1 for (s, e, _t) in src_ranges if ri.source.covers_input_wide(s, e))
        dest_full = bool(n_dst) and dst_covered_cnt == n_dst
        source_full = bool(n_src) and src_covered_cnt == n_src

        # B1 (exact qua 1 member rieng le): field co NHIEU object nhung 1 member
        # trong do khop tuyet doi 1:1 voi request (vd Notify-GR-SRV dung 4/4 IP
        # trong field Dest 14 dia chi cua rule 1264) van duoc coi la exact-scope
        # that su - tranh false-negative cua _is_exactly_scoped() (xet tong gop
        # ca field). Khi _exact_member_scope tra None, hanh vi y het truoc day.
        dest_member_scope = _exact_member_scope(ri.dest_members, dst_ranges)
        source_member_scope = _exact_member_scope(ri.source_members, src_ranges)
        dest_exact_ok = _is_exactly_scoped(ri.dest, dst_ranges) or dest_member_scope is not None
        source_exact_ok = _is_exactly_scoped(ri.source, src_ranges) or source_member_scope is not None

        # ---- TOP2 candidacy (dieu kien copy nguyen van vong lap TOP2 ban goc) ----
        if port_ok and dest_full and dest_exact_ok:
            top2.append((src_covered_cnt, ri, dest_member_scope))
        # ---- TOP3 candidacy (dieu kien copy nguyen van vong lap TOP3 ban goc) ----
        if port_ok and source_full and source_exact_ok:
            top3.append((dst_covered_cnt, ri, source_member_scope))

        # ---- near_top2/near_top3/generic (dieu kien copy nguyen van tu
        # _find_nearest_candidate_rule ban goc, ke ca thu tu if/continue) ----
        if both_any:
            continue
        if port_ok and dest_full and not ri.dest.is_any and not dest_exact_ok:
            frac = src_covered_cnt / n_src if src_ranges else 0
            missing_zone_cnt = len(_missing_zones(src_ranges, ri.rule.from_zones, zone_lookup))
            src_fully_covered_wide = bool(src_ranges) and src_covered_cnt == n_src
            near_top2.append((0 if src_fully_covered_wide else 1,
                               ri.source.total_address_count(), missing_zone_cnt, -frac, ri))
            continue
        if port_ok and source_full and not ri.source.is_any and not source_exact_ok:
            frac = dst_covered_cnt / n_dst if dst_ranges else 0
            missing_zone_cnt = len(_missing_zones(dst_ranges, ri.rule.to_zones, zone_lookup))
            dst_fully_covered_wide = bool(dst_ranges) and dst_covered_cnt == n_dst
            near_top3.append((0 if dst_fully_covered_wide else 1,
                               ri.dest.total_address_count(), missing_zone_cnt, -frac, ri))
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
        near_top2.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
        _fc, _sz, _zc, _nf, ri = near_top2[0]
        return (ri, 'near_top2')
    if near_top3:
        near_top3.sort(key=lambda x: (x[0], x[1], x[2], x[3]))
        _fc, _sz, _zc, _nf, ri = near_top3[0]
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
    dst_missing = [t['display'] for (s, e, t) in dst_ranges if not ri.dest.covers_input_wide(s, e)]
    src_missing = [t['display'] for (s, e, t) in src_ranges if not ri.source.covers_input_wide(s, e)]
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
    max_combos: int = 300,
    max_port_span: int = 50,
    live_match_concurrency: Optional[int] = None,
    live_match_semaphore: Optional[Any] = None,
    combo_cache: Optional[dict] = None,
    target_serial: Optional[str] = None,
) -> RowResult:
    src_ranges = [(t['start'], t['end'], t) for t in row.source_tokens if t['kind'] != 'invalid']
    dst_ranges = [(t['start'], t['end'], t) for t in row.dest_tokens if t['kind'] != 'invalid']
    ports = row.port_tokens

    # SUA LOI (10/2026): giu lai cac token KHONG parse duoc de bao cao tuong minh,
    # thay vi loai bo am tham nhu truoc (xem RowResult.unparsed_source/_dest).
    bad_src = [t['display'] or t['raw'] for t in row.source_tokens if t['kind'] == 'invalid']
    bad_dst = [t['display'] or t['raw'] for t in row.dest_tokens if t['kind'] == 'invalid']

    if not src_ranges or not dst_ranges or not ports:
        note = 'Dữ liệu IP/Port không hợp lệ.'
        bad_all = bad_src + bad_dst
        if bad_all:
            note += ' Không đọc được: ' + ', '.join(bad_all[:6])
            if len(bad_all) > 6:
                note += f" (+{len(bad_all) - 6} giá trị khác)"
        return RowResult(row, 'INVALID', None, note=note,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

    # ƯU TIÊN BƯỚC 1: Dùng tính năng Test Policy Match để check trực tiếp trên thiết bị trước
    # SUA LOI (09/2026 - minh bach Live Match): neu try_live_match() khong hoan tat
    # (vuot gioi han quy mo / goi API nhung khong ket luan duoc), LUU LAI ly do de
    # gan vao RowResult LOCAL cuoi cung - admin nhin Excel biet ngay Live Match co
    # duoc thu hay khong. CHI set khi Live Match DA DUOC BAT (co mgmt_ip + api_key)
    # - khong hien caveat gay nhieu cho case chua bat tu dau.
    live_skip_reason: Optional[str] = None
    live_skip_detail: Optional[str] = None
    # BAN PANORAMA (0.5): them dieu kien tien quyet `target_serial` - thieu Target
    # Firewall thi tier LIVE_MATCH tu bo qua IM LANG (khong set live_skip_reason vi
    # day khong phai "da thu Live Match nhung khong ket luan duoc").
    if mgmt_ip and api_key and target_serial:
        skip_info: dict = {}
        live_res = try_live_match(row, mgmt_ip, api_key, vsys, rule_infos, idx,
                                   max_combos=max_combos, max_workers=max_workers,
                                   log_func=log_func, max_port_span=max_port_span,
                                   skip_info=skip_info,
                                   live_match_concurrency=live_match_concurrency,
                                   live_match_semaphore=live_match_semaphore,
                                   combo_cache=combo_cache,
                                   target_serial=target_serial)
        if live_res:
            live_res.unparsed_source = bad_src
            live_res.unparsed_dest = bad_dst
            return live_res
        if skip_info.get('reason'):
            live_skip_reason = skip_info['reason']
            live_skip_detail = skip_info.get('detail')

    # BƯỚC 2: Kiểm tra Same Subnet
    if _check_same_subnet(src_ranges, dst_ranges, same_subnet_prefix):
        return RowResult(row, 'SAME_SUBNET', None,
                          note=f'Source và Dest cùng nằm trong 1 subnet /{same_subnet_prefix}.',
                          live_match_skip_reason=live_skip_reason,
                          live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

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
                          zone_warning=_compute_zone_warning(ri.rule, src_ranges, dst_ranges, zone_lookup),
                          live_match_skip_reason=live_skip_reason,
                          live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

    if scan["top1_1_match"] is not None:
        ri = scan["top1_1_match"]
        src_report = build_field_report(src_ranges, ri.source_members, idx, wide=False)
        dst_report = build_field_report(dst_ranges, ri.dest_members, idx, wide=False)
        missing_ports = find_missing_ports(ports, ri.service, idx)
        shadow = _find_shadowing_rule(rule_infos, ri, src_ranges, dst_ranges, ports)
        return RowResult(row, 'TOP1.1', ri.rule, src_report, dst_report, missing_ports=missing_ports,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(ri.rule, src_ranges, dst_ranges, zone_lookup),
                          live_match_skip_reason=live_skip_reason,
                          live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

    top2 = scan["top2"]
    if top2:
        # Uu tien Dest HEP HON (cu the hon) TRUOC TIEN, TUYET DOI - mot rule co dest la
        # group nho, purpose-built (vd 'SOA-EMS-Core-150-151') phai luon thang mot rule
        # dest la group rong/catch-all (vd 'SOA-EMS') dung lam candidate, BAT KE rule
        # catch-all do co the cover duoc nhieu Source hon. Chi khi 2 rule co Dest scope
        # bang nhau (hoa diem) moi xet tiep den so Source duoc cover nhieu hon.
        # B1: rule vao TOP2 nho 1 member khop tuyet doi rieng le (x[2] is not None)
        # dung scope RIENG member do (nho, cong bang) thay vi tong ca field.
        top2.sort(key=lambda x: (
            x[2] if x[2] is not None else _addr_scope_size(x[1].dest), -x[0]))
        _cnt, best, _scope = top2[0]
        # UU TIEN CHI PHI BO SUNG (so sanh voi near_top2 tot nhat da co san trong
        # scan, KHONG quet lai): TOP2 "exact-scope nhung ton kem" (can ADD nhieu
        # Source IP) thua near_top2 "chi can ADD it Source IP hon han" - dung
        # strict `<` de khi bang chi phi, TOP2 exact-scope van thang (uu tien an
        # toan khi hoa). Dieu kien nhan biet tier trong _scan_all_tiers va logic
        # sort trong _select_nearest_from_scan giu nguyen tuyet doi.
        top2_missing_src = len(src_ranges) - _cnt
        near_top2 = scan["near_top2"]
        alt_ri = None
        alt_missing_src = None
        if near_top2:
            near_sorted = sorted(near_top2, key=lambda x: (x[0], x[1], x[2], x[3]))
            _fc, _sz, _zc, _nf, cand_ri = near_sorted[0]
            cand_covered = sum(1 for (s, e, _t) in src_ranges if cand_ri.source.covers_input_wide(s, e))
            alt_ri = cand_ri
            alt_missing_src = len(src_ranges) - cand_covered
        if alt_ri is not None and alt_missing_src < top2_missing_src:
            # Ung vien near_top2 yeu cau bo sung IT Source hon han TOP2 "exact
            # scope" -> dung luon near_top2 lam ket qua chinh (tier 'TOP4',
            # near_kind='near_top2'), y het nhanh near_match thuong sinh ra o
            # cuoi classify_row - build lai report cho DUNG alt_ri, KHONG dung
            # report cua `best` (rule TOP2 cu) nua. Vẫn giữ 1 dòng ghi chú tên
            # rule TOP2 "exact scope" bị bỏ qua để minh bạch (không phải log,
            # chỉ 1 dòng ngắn).
            src_report = build_field_report(src_ranges, [], idx, wide=True)
            dst_report = build_field_report(dst_ranges, [], idx, wide=True)
            nearest_detail = _describe_nearest_rule(alt_ri, src_ranges, dst_ranges, ports)
            return RowResult(row, 'TOP4', None, src_report, dst_report,
                              missing_ports=find_missing_ports(ports, ResolvedService(), idx),
                              nearest_rule=alt_ri.rule, nearest_rule_kind='near_top2',
                              nearest_missing_side='source', nearest_detail=nearest_detail,
                              note=f"Bo qua TOP2 exact-scope '{best.rule.name}' vi can bo sung "
                                   f"{top2_missing_src} Source IP, trong khi '{alt_ri.rule.name}' "
                                   f"chi can bo sung {alt_missing_src} Source IP.",
                              live_match_skip_reason=live_skip_reason,
                              live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)
        src_report = build_field_report(src_ranges, best.source_members, idx, wide=True)
        dst_report = build_field_report(dst_ranges, best.dest_members, idx, wide=True)
        shadow = _find_shadowing_rule(rule_infos, best, src_ranges, dst_ranges, ports)
        # TOP2 chi dam bao Dest du + Port du. Neu Source (ben "gia dinh con thieu")
        # THUC RA cung da duoc rule nay cover du 100% -> khong con gi de "+ ADD"
        # (xem RowResult.wide_fully_covered).
        src_all_covered = bool(src_ranges) and all(
            best.source.covers_input_wide(s, e) for (s, e, _t) in src_ranges)
        if src_all_covered:
            _mark_side_fully_covered(src_report, src_ranges, best.source_members)
        return RowResult(row, 'TOP2', best.rule, src_report, dst_report,
                          wide_fully_covered=src_all_covered,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(best.rule, src_ranges, dst_ranges, zone_lookup),
                          live_match_skip_reason=live_skip_reason,
                          live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

    top3 = scan["top3"]
    if top3:
        # Doi xung voi TOP2: uu tien Source HEP HON TRUOC TIEN, TUYET DOI (vi o day Dest
        # da duoc bat buoc cover du roi, Source moi la phan con thieu can chon dai dien
        # chinh xac nhat) - khong con de "cover duoc nhieu Dest hon" ghi de len do cu the.
        # B1 (doi xung TOP2): dung scope RIENG member khop tuyet doi neu co.
        top3.sort(key=lambda x: (
            x[2] if x[2] is not None else _addr_scope_size(x[1].source), -x[0]))
        _cnt, best, _scope = top3[0]
        # Doi xung voi TOP2 o tren: TOP3 "exact-scope nhung ton kem" (can ADD
        # nhieu Dest IP) thua near_top3 "chi can ADD it Dest IP hon han" - dung
        # strict `<` de khi bang chi phi, TOP3 exact-scope van thang.
        top3_missing_dst = len(dst_ranges) - _cnt
        near_top3 = scan["near_top3"]
        alt_ri = None
        alt_missing_dst = None
        if near_top3:
            near_sorted = sorted(near_top3, key=lambda x: (x[0], x[1], x[2], x[3]))
            _fc, _sz, _zc, _nf, cand_ri = near_sorted[0]
            cand_covered = sum(1 for (s, e, _t) in dst_ranges if cand_ri.dest.covers_input_wide(s, e))
            alt_ri = cand_ri
            alt_missing_dst = len(dst_ranges) - cand_covered
        if alt_ri is not None and alt_missing_dst < top3_missing_dst:
            # Ung vien near_top3 yeu cau bo sung IT Dest hon han TOP3 "exact
            # scope" -> dung luon near_top3 lam ket qua chinh (tier 'TOP4',
            # near_kind='near_top3'), build lai report cho DUNG alt_ri. Vẫn giữ
            # 1 dòng ghi chú tên rule TOP3 "exact scope" bị bỏ qua để minh
            # bạch (không phải log, chỉ 1 dòng ngắn).
            src_report = build_field_report(src_ranges, [], idx, wide=True)
            dst_report = build_field_report(dst_ranges, [], idx, wide=True)
            nearest_detail = _describe_nearest_rule(alt_ri, src_ranges, dst_ranges, ports)
            return RowResult(row, 'TOP4', None, src_report, dst_report,
                              missing_ports=find_missing_ports(ports, ResolvedService(), idx),
                              nearest_rule=alt_ri.rule, nearest_rule_kind='near_top3',
                              nearest_missing_side='dest', nearest_detail=nearest_detail,
                              note=f"Bo qua TOP3 exact-scope '{best.rule.name}' vi can bo sung "
                                   f"{top3_missing_dst} Dest IP, trong khi '{alt_ri.rule.name}' "
                                   f"chi can bo sung {alt_missing_dst} Dest IP.",
                              live_match_skip_reason=live_skip_reason,
                              live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)
        src_report = build_field_report(src_ranges, best.source_members, idx, wide=True)
        dst_report = build_field_report(dst_ranges, best.dest_members, idx, wide=True)
        shadow = _find_shadowing_rule(rule_infos, best, src_ranges, dst_ranges, ports)
        # Doi xung TOP2: TOP3 chi dam bao Source du + Port du - kiem tra lai Dest.
        dst_all_covered = bool(dst_ranges) and all(
            best.dest.covers_input_wide(s, e) for (s, e, _t) in dst_ranges)
        if dst_all_covered:
            _mark_side_fully_covered(dst_report, dst_ranges, best.dest_members)
        return RowResult(row, 'TOP3', best.rule, src_report, dst_report,
                          wide_fully_covered=dst_all_covered,
                          shadow_warning=_shadow_warning_text(shadow),
                          zone_warning=_compute_zone_warning(best.rule, src_ranges, dst_ranges, zone_lookup),
                          live_match_skip_reason=live_skip_reason,
                          live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)

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
    nearest_fully_covered = False
    nearest = _select_nearest_from_scan(scan)
    if nearest is not None:
        near_ri, near_kind = nearest
        nearest_rule = near_ri.rule
        nearest_kind = near_kind
        nearest_detail = _describe_nearest_rule(near_ri, src_ranges, dst_ranges, ports)
        # SUA LOI (bao cao thuc te: 1 dong hien "+ ADD SOURCE" du nearest_detail da
        # ghi ro "Source 23/23 khop" - TUC LA Source THUC TE da duoc rule nay cover
        # DU roi, khong con gi de "them" nua). Nguyen nhan: near_top2/near_top3 chi
        # dam bao 1 BEN (Dest cho near_top2, Source cho near_top3) da "du" (dest_full/
        # source_full) + Port du - dieu kien nhan biet tier (o _scan_all_tiers) KHONG
        # xet toi ben CON LAI (vd near_top2 duoc chon chi vi Dest chua qua duoc
        # _is_exactly_scoped, HOAN TOAN khong lien quan Source) - nen ben con lai
        # (Source cho near_top2 / Dest cho near_top3) co the THUC RA da duoc chinh
        # rule nay cover DU roi (thuong qua 1 subnet/wide rong nhu Net_10.0.0.0/8),
        # nhung code cu GAN CUNG nearest_side='source'/'dest' bat ke thuc te, khien
        # nhan '+ ADD SOURCE/DEST' hien SAI cho ca truong hop ben do da khop 100%.
        # KHONG doi dieu kien nhan biet near_top2/near_top3 trong _scan_all_tiers (theo
        # dung nguyen tac bat buoc o docstring ham do) - CHI sua o day: tinh THEM xem
        # ben "gia dinh thieu" co THUC SU con thieu IP nao khong truoc khi gan nhan.
        if near_kind == 'near_top2':
            src_all_covered = bool(src_ranges) and all(
                near_ri.source.covers_input_wide(s, e) for (s, e, _t) in src_ranges)
            nearest_side = None if src_all_covered else 'source'
            # SUA LOI (09/2026 - wide_full_match): near_top2 theo dinh nghia luon co
            # port_ok=True VA dest_full=True (dieu kien nhan biet trong _scan_all_tiers
            # - TUYET DOI khong doi). Neu them Source (ben "gia dinh thieu") THUC RA
            # cung da cover du het qua wide-match (nearest_side is None) thi CA HAI
            # ben + Port deu da du, chi thieu dung dieu kien an toan exact-scope -
            # danh dau de tang hien thi doi sang 'wide_full_match' thay vi "GAN DUNG".
            nearest_fully_covered = (nearest_side is None)
        elif near_kind == 'near_top3':
            dst_all_covered = bool(dst_ranges) and all(
                near_ri.dest.covers_input_wide(s, e) for (s, e, _t) in dst_ranges)
            nearest_side = None if dst_all_covered else 'dest'
            # Doi xung voi near_top2 o tren: near_top3 luon co port_ok + source_full.
            nearest_fully_covered = (nearest_side is None)
        # 'generic' theo dinh nghia khong dam bao port hoac chi cover 1 phan -
        # khong bao gio du dieu kien nay -> giu nearest_fully_covered=False.

    return RowResult(row, 'TOP4', None, src_report, dst_report, missing_ports=missing_ports,
                      nearest_rule=nearest_rule, nearest_rule_kind=nearest_kind,
                      nearest_missing_side=nearest_side, nearest_detail=nearest_detail,
                      nearest_fully_covered=nearest_fully_covered,
                      live_match_skip_reason=live_skip_reason,
                      live_match_skip_detail=live_skip_detail,
                          unparsed_source=bad_src, unparsed_dest=bad_dst)