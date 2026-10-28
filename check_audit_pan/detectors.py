# -*- coding: utf-8 -*-
"""
detectors.py - 3 ham phat hien cua CHECK AUDIT (Mục 4 require.md):

  - find_disabled_rules()                 -> Disabled Rules (4.1)
  - find_overly_permissive_rules()        -> Overly Permissive Rules (4.2)
  - find_shadow_rules()                   -> Shadow Rules (4.5) hop nhat 2 nhanh:
        _find_unreachable_rules()   UNREACHABLE - rule bi che khuat boi rule truoc (4.3)
        _find_unused_rules()        UNUSED - rule khong co hits >= 30 ngay (4.4, D10)
"""

import bisect
from dataclasses import replace
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Set

from .core import (
    Finding, RuleSnapshot, RuleHitStat,
    UNUSED_RULE_THRESHOLD_DAYS,
    CHECK_TYPE_SHADOW, CHECK_TYPE_DISABLED, CHECK_TYPE_OVERLY,
    CHECK_TYPE_TARGET_SAI,
    SHADOW_UNREACHABLE, SHADOW_UNUSED,
)
from .resolver import ResolvedAddr

NOW_TYPE = datetime


# ============================================================================
# RULE CHET - <target> tro toi serial KHONG thuoc Device Group nay
# ============================================================================
def _dead_finding(r: RuleSnapshot, ngoai: List[str], serials, pham_vi: str) -> Finding:
    f = Finding(
        check_type=CHECK_TYPE_TARGET_SAI,
        rule_name=r.name,
        rule_uuid=r.uuid,
        rule_index=r.index,
        source=r.source,
        destination=r.destination,
        service=r.service,
        action=r.action,
        disabled=r.disabled,
        detail=(f"Target tro toi serial {', '.join(ngoai)} - KHONG serial nao "
                f"thuoc {pham_vi} ({', '.join(sorted(serials))}). Rule nay "
                f"KHONG duoc push xuong firewall nao ca."),
    )
    # Gan vi_tri NGAY TAI DAY. Quet toan bo Panorama thi finding den tu nhieu
    # Device Group khac nhau, ma `rule_index` lai la chi so trong rulebase cua
    # RIENG noi do - de gui.py suy vi_tri tu rule_index (nhu cac nhanh khac)
    # se gan nham vi tri cua mot rule hoan toan khac.
    f.vi_tri = r.vi_tri
    return f


def _dead_target(r: RuleSnapshot, serials) -> Optional[List[str]]:
    """Danh sach serial la cua rule, hoac None neu rule nay khong phai rule chet.

    Dung chung cho ca hai duong (1 Device Group va quet toan bo), de hai duong
    khong the troi khoi nhau ve dinh nghia.
    """
    tgt = [d for d in (r.target_devices or []) if d]
    if not tgt or r.target_negate:
        return None
    ngoai = [d for d in tgt if d not in serials]
    return ngoai if len(ngoai) == len(tgt) else None


def find_dead_target_rules_all(scopes) -> List[Finding]:
    """Quet rule CHET tren TOAN BO Panorama (Shared + moi Device Group).

    `scopes` = ket qua `pan_api.collect_target_scopes()`: list
    (nhan_pham_vi, rules_cua_rieng_noi_do, tap_serial_hop_le).

    Khac ban mot-Device-Group o cho KHONG phai bo qua rule Shared / DG cha
    nua: quet toan bo thi biet duoc tap serial hop le THAT cua tung noi (rule
    cua DG cha duoc phep target toi firewall cua DG con; rule Shared duoc phep
    target toi firewall cua bat ky DG nao), nen khong con ly do phai im lang
    voi chung.

    Van giu chot: pham vi nao khong doc duoc firewall nao thi BO QUA pham vi
    do - khong co can cu thi khong ket luan.
    """
    out: List[Finding] = []
    for pham_vi, rules, serials in (scopes or []):
        serials = {x for x in (serials or []) if x}
        if not serials:
            continue
        nhan = ("moi Device Group" if pham_vi == "Shared"
                else f"Device Group '{pham_vi}' va cac DG con")
        for r in rules or []:
            ngoai = _dead_target(r, serials)
            if ngoai:
                out.append(_dead_finding(r, ngoai, serials, nhan))
    return out


# ============================================================================
# 4.1 DISABLED RULES
# ============================================================================
def find_disabled_rules(rules: List[RuleSnapshot]) -> List[Finding]:
    """Mo hinh don gian nhat - dung lam baseline test nhanh."""
    out: List[Finding] = []
    for r in rules:
        if r.disabled:
            out.append(Finding(
                check_type=CHECK_TYPE_DISABLED,
                rule_name=r.name,
                rule_uuid=r.uuid,
                rule_index=r.index,
                source=r.source,
                destination=r.destination,
                service=r.service,
                action=r.action,
                disabled=True,
                detail="Rule đang ở trạng thái Disabled",
            ))
    return out


# ============================================================================
# 4.2 OVERLY PERMISSIVE RULES (literal "any" - D2, bao gom ca rule disabled - D3)
# ============================================================================
def find_overly_permissive_rules(rules: List[RuleSnapshot]) -> List[Finding]:
    """VOI MỖI rule tinh 3 co literal any (source/destination/service). Neu bat
    ky dieu kien nao trong 6 to hop dung -> 1 Finding duy nhat (gop het ly do
    vao detail), KHONG resolve object/group (D2)."""
    out: List[Finding] = []
    for r in rules:
        # Rule HA TANG: rong o L3-L4 dung nhu thiet ke - xem is_infrastructure_rule().
        if is_infrastructure_rule(r):
            continue
        src_any = r.source == ["any"] or r.source == []
        dst_any = r.destination == ["any"] or r.destination == []
        port_any = r.service == ["any"] or r.service == []

        conds: List[str] = []
        if src_any:
            conds.append("Source=any")
        if dst_any:
            conds.append("Dest=any")
        if port_any:
            conds.append("Dest Port=any")
        if src_any and dst_any:
            conds.append("Source+Dest=any")
        if src_any and port_any:
            conds.append("Source+Dest Port=any")
        if dst_any and port_any:
            conds.append("Dest+Dest Port=any")
        if not conds:
            continue

        out.append(Finding(
            check_type=CHECK_TYPE_OVERLY,
            rule_name=r.name,
            rule_uuid=r.uuid,
            rule_index=r.index,
            source=r.source,
            destination=r.destination,
            service=r.service,
            action=r.action,
            disabled=r.disabled,
            detail=", ".join(conds),
        ))
    return out


# Nguong mac dinh cho nhanh "rong theo VALUE THAT" (S6, 10/2026). Co the ghi de
# qua tham so de nguoi dung tu dieu chinh theo quy mo mang cua minh.
OVERLY_ADDR_THRESHOLD = 1024      # ~ /22 tro len
OVERLY_PORT_THRESHOLD = 1024


def _resolved_addr_count(ra) -> float:
    """So dia chi THUC SU mot ResolvedAddr bao phu (da khu trung lap/chong lan).
    'any' -> inf."""
    if ra is None:
        return 0
    if getattr(ra, 'is_any', False):
        return float('inf')
    total = 0
    for a, b in ra._sorted_merged():
        total += (b - a + 1)
    return total


def _resolved_port_count(rs) -> float:
    """So port mot ResolvedService cho phep. 'any' -> inf.
    application-default khong dem duoc theo port -> 0 (khong ket luan)."""
    if rs is None:
        return 0
    if getattr(rs, 'is_any', False):
        return float('inf')
    if getattr(rs, 'is_app_default', False):
        return 0
    total = 0
    for _p, a, b in getattr(rs, 'ports', []) or []:
        total += (b - a + 1)
    return total


def _fmt_big(v) -> str:
    return "any" if v == float('inf') else f"{int(v)}"


def find_overly_permissive_by_size(rules: List[RuleSnapshot], resolver, svc_resolver,
                                   addr_threshold: int = OVERLY_ADDR_THRESHOLD,
                                   port_threshold: int = OVERLY_PORT_THRESHOLD
                                   ) -> List[Finding]:
    """S6 (10/2026): rule rong theo **VALUE THAT** sau khi resolve, khong chi
    literal `any`.

    Vi sao can: trong mot ruleset da chin, rule nguy hiem **rat it khi** la literal
    `any`. No la `GRP-ALL-SERVERS` ma ai do da nuoi len 400 member, hoac
    `Net_10.0.0.0/8` lam Source. Nhanh literal-any (find_overly_permissive_rules,
    D2) khong bao gio bat duoc nhung rule do - va do moi la dang pho bien nhat.

    Ham nay KHONG thay the nhanh literal-any: no **bo sung**, va co y **bo qua** cac
    rule da bi nhanh kia bat (tranh bao trung 1 rule 2 lan). Xep hang theo tich
    `so_dia_chi x so_port` giam dan - dung thu tu ma mot auditor can doc.

    Dung lai dung ResolvedAddr/ResolvedService cua chinh tab nay (_resolve_rules),
    nen con so la so da KHU TRUNG LAP, khong phai "so member khai bao"."""
    out: List[Finding] = []
    if resolver is None or svc_resolver is None:
        return out
    _resolve_rules(rules, resolver, svc_resolver)
    scored = []
    for r in rules:
        src_any = r.source == ["any"] or r.source == []
        dst_any = r.destination == ["any"] or r.destination == []
        port_any = r.service == ["any"] or r.service == []
        if src_any or dst_any or port_any:
            continue          # nhanh literal-any da bat - khong bao trung
        n_src = _resolved_addr_count(getattr(r, 'resolved_source', None))
        n_dst = _resolved_addr_count(getattr(r, 'resolved_destination', None))
        n_port = _resolved_port_count(getattr(r, 'resolved_service', None))
        conds = []
        if n_src >= addr_threshold:
            conds.append(f"Source rong: {_fmt_big(n_src)} dia chi")
        if n_dst >= addr_threshold:
            conds.append(f"Dest rong: {_fmt_big(n_dst)} dia chi")
        if n_port >= port_threshold:
            conds.append(f"Service rong: {_fmt_big(n_port)} port")
        if not conds:
            continue
        # Pham vi phoi nhiem = so cap (dia chi x port) ma rule nay mo ra
        exposure = max(n_src, 1) * max(n_dst, 1) * max(n_port, 1)
        detail = (", ".join(conds) +
                  f" | pham vi phoi nhiem ~ {_fmt_big(n_src)} nguon x "
                  f"{_fmt_big(n_dst)} dich x {_fmt_big(n_port)} port")
        scored.append((exposure, Finding(
            check_type=CHECK_TYPE_OVERLY,
            rule_name=r.name,
            rule_uuid=r.uuid,
            rule_index=r.index,
            source=r.source,
            destination=r.destination,
            service=r.service,
            action=r.action,
            disabled=r.disabled,
            detail=detail,
        )))
    scored.sort(key=lambda t: t[0], reverse=True)
    out = [f for _sc, f in scored]
    return out


# ============================================================================
# RESOLVE PHU TRO cho ca 2 nhanh UNREACHABLE
# ============================================================================
def _resolve_rules(rules: List[RuleSnapshot], resolver, svc_resolver):
    for r in rules:
        if r.resolved_source is None:
            r.resolved_source = _resolve_entries(r.source, resolver)
        if r.resolved_destination is None:
            r.resolved_destination = _resolve_entries(r.destination, resolver)
        if r.resolved_service is None:
            r.resolved_service = svc_resolver.resolve_rule_service(r.service, r.application)


def _resolve_entries(entries: List[str], resolver) -> ResolvedAddr:
    acc = ResolvedAddr()
    for e in entries:
        acc.merge(resolver.resolve(e))
    return acc


# ============================================================================
# 4.3 NHANH UNREACHABLE
# ============================================================================
def _zones_cover(z1: List[str], z2: List[str]) -> bool:
    """R1.from_zones cover R2.from_zones: R1 cover R2 nếu R1=any (bất kể R2), ngược lại
    nếu R2=any mà R1 không phải any thì R1 không cover (sửa audit 2026-09-02: trước đây
    `if \"any\" in z1 or \"any\" in z2: return True` gây false-positive khi R2=any còn R1 cụ thể)."""
    if "any" in z1:
        return True
    if "any" in z2:
        return False
    return set(z1) >= set(z2)


def _zones_cover_fast(i1: int, i2: int, from_any, to_any, from_zone_sets, to_zone_sets,
                       is_from: bool) -> bool:
    """Ban FAST cua _zones_cover(): dung frozenset precompute thay vi dung set moi
    lan goi (vong lap O(n^2) tren rulebase hang nghin rule).

    QUAN TRONG: phai copy DUNG luat da SUA cua _zones_cover() - "R1 any -> cover;
    R2 any ma R1 cu the -> KHONG cover". Ban toi uu cu cua Firewall standalone con
    giu `from_any[i1] or from_any[i2] -> True` (false-positive khi R2=any) nen
    KHONG duoc bung nguyen xi sang day."""
    if is_from:
        if from_any[i1]:
            return True
        if from_any[i2]:
            return False
        return from_zone_sets[i1] >= from_zone_sets[i2]
    if to_any[i1]:
        return True
    if to_any[i2]:
        return False
    return to_zone_sets[i1] >= to_zone_sets[i2]


def _app_set(rule: RuleSnapshot) -> Optional[Set[str]]:
    """Tap Application cua 1 rule. None = KHONG gioi han (any).

    PAN-OS de trong cot Application la khong hop le, nhung config that van co
    rule bi trong sau khi migrate - coi nhu 'any' (khong gioi han) la phia AN
    TOAN cho rule BI che, va phia khong an toan cho rule DI che; ca hai huong
    deu duoc xu ly o `_apps_cover`.
    """
    apps = {a.strip().lower() for a in (rule.application or []) if a and a.strip()}
    if not apps or "any" in apps:
        return None
    return apps


def _apps_cover(r1: RuleSnapshot, r2: RuleSnapshot) -> bool:
    """R1 co BAO duoc R2 tren chieu APPLICATION khong?

    DAY LA LOI TUNG LAM TOOL KHUYEN XOA NHAM RULE DANG DUNG.
    ================================================================
    Cau hinh that rat hay co mot rule dau rulebase kieu:

        src=any  dst=any  service=any  zone=any  application=[ping, traceroute]

    Truoc day phep "che" chi xet zone/source/destination/service, nen rule nay
    BAO HET moi rule nam duoi no - tool bao ca rulebase la "shadow, khong bao
    gio chay toi" va nguoi van hanh di xoa. Thuc te no CHI cho ping/traceroute
    di; moi traffic khac van phai nho dung nhung rule vua bi xoa. Hau qua la
    mat dich vu, va mat theo kieu kho lan ra nhat: rule bi xoa, log khong con
    gi de doi chieu.

    LUAT:
      * R1 khong gioi han app (any)      -> bao duoc moi thu.
      * R1 CO gioi han, R2 khong gioi han -> KHONG bao (R2 cho ca app khac).
      * Ca hai cung gioi han              -> bao khi tap cua R2 nam trong R1.

    CO Y BAO THU: ten app-group / application-filter so theo TEN. Hai ben viet
    khac ten nhung thuc chat trung nhau thi ham nay tra False - tuc la KHONG
    ket luan shadow. Sai theo huong nay chi lam bo sot mot de xuat don dep;
    sai theo huong kia lam mat dich vu.
    """
    a1 = _app_set(r1)
    if a1 is None:
        return True
    a2 = _app_set(r2)
    if a2 is None:
        return False
    return a2 <= a1


def trim_evidence_to_target(hit_stats, rules: List[RuleSnapshot]):
    """Rule chi push xuong vai firewall thi chi DOI bang chung tu dung may con do.

    VI SAO CAN
    ==========
    `hits_known` False khi co firewall trong pham vi query ma khong tra ve dong
    nao cho rule. Mot rule target rieng site B thi firewall site A KHONG HE co
    rule do, nen no vinh vien "thieu bang chung" -> nhanh UNUSED khong bao gio
    chay voi nhung rule target rieng site. Im lang khong ket luan la an toan,
    nhung dong nghia audit KHONG lam gi duoc voi ca mang rulebase do.

    Nay: voi rule co <target>, chi nhung firewall THAT SU duoc push rule moi
    tinh vao `devices_missing`.

    CHOT AN TOAN: neu sau khi cat ma KHONG con firewall nao tung tra ve so lieu
    cho rule (devices_seen rong), ham GIU NGUYEN trang thai "thieu bang chung".
    Khong co cai chot nay thi mot rule target vao serial chua he duoc query se
    thanh "da biet, 0 hit" -> UNUSED -> de xuat XOA mot rule chua ai do bao gio.
    """
    by_name: Dict[str, RuleSnapshot] = {}
    for r in rules or []:
        by_name[(r.name, r.vi_tri)] = r          # type: ignore[index]
        by_name.setdefault(r.name, r)            # type: ignore[index]

    out = dict(hit_stats or {})
    for key, stat in list(out.items()):
        rule = by_name.get(key)
        if rule is None and isinstance(key, tuple):
            rule = by_name.get(key[0])
        if rule is None or not rule.target_devices:
            continue
        tap = set(rule.target_devices)
        if rule.target_negate:
            # "Moi firewall TRU may con nay" -> may con bi tru khong he co rule,
            # thieu so lieu o do la binh thuong.
            con_thieu = tuple(d for d in (stat.devices_missing or ()) if d not in tap)
        else:
            con_thieu = tuple(d for d in (stat.devices_missing or ()) if d in tap)
        if con_thieu == tuple(stat.devices_missing or ()):
            continue
        if not stat.devices_seen:
            continue                              # chot an toan - xem docstring
        moi = replace(stat, devices_missing=con_thieu)
        out[key] = moi
    return out


def _targets_cover(r1: RuleSnapshot, r2: RuleSnapshot) -> bool:
    """R1 co ap len DU moi firewall ma R2 ap len khong? (chieu TARGET/INSTALL-ON)

    DAY LA MOT HUONG XOA NHAM RULE DANG CHAY KHAC.
    ====================================================================
    He thong that co Device Group dung chung cho nhieu site, va trong do co
    nhung rule target RIENG tung site. Mot rule cua site B khong he ton tai
    tren firewall cua site A - no KHONG the che rule cua site A. Truoc day
    phep "che" khong doc <target> nen van ket luan shadow, roi de xuat xoa
    rule cua site A: site A mat dich vu, con log thi khong con rule de doi
    chieu.

    LUAT (giong het cach xet zone/application - phep bao tren mot chieu nua):
      * R1 khong co <target>            -> ap cho moi firewall -> bao duoc.
      * R1 co target, R2 khong co       -> R2 ap rong hon -> KHONG bao.
      * Ca hai deu la danh sach thuong  -> bao khi tap cua R2 nam trong R1.
      * Co dinh NEGATE o bat ky ben nao -> chi bao khi HAI BEN GIONG HET
        nhau. "Moi firewall TRU X" va mot danh sach thuong khong so duoc
        bang phep tap neu khong biet truoc toan bo estate; BAO THU o day chi
        lam bo sot mot de xuat don dep, con sai huong kia la mat dich vu.
    """
    d1 = [x for x in (r1.target_devices or []) if x]
    d2 = [x for x in (r2.target_devices or []) if x]
    if not d1 and not r1.target_negate:
        return True
    if r1.target_negate or r2.target_negate:
        return (r1.target_negate == r2.target_negate) and set(d1) == set(d2)
    if not d2:
        return False
    return set(d2) <= set(d1)


def _field_is_any(values: Optional[List[str]]) -> bool:
    """O de TRONG hoac dung chu `any` - ca hai deu la "khong gioi han"."""
    vals = {v.strip().lower() for v in (values or []) if v and v.strip()}
    return (not vals) or vals == {"any"}


def is_infrastructure_rule(rule: RuleSnapshot) -> bool:
    """Rule HA TANG: MOI o L3-L4 deu `any`, va CHI khai bao Application.

        src=any  dst=any  service=any  zone src/dst=any
        application=[ping, traceroute, ...]

    LUAT NGUOI VAN HANH DA CHOT (10/2026): rule dang nay la rule HA TANG - no
    ton tai co chu dich de ping/traceroute/ldap... di duoc toan he thong.
    Audit KHONG duoc dem no ra lam finding:

      * bao no "Overly Permissive" la de nghi sai - no rong o L3-L4 dung nhu
        thiet ke, con App-ID moi la cho that su gioi han;
      * bao no UNUSED/UNREACHABLE roi khuyen xoa la dung thang vao rule ha tang;
      * va no cung KHONG duoc che rule khac (viec do do `_apps_cover` chan).

    Dinh nghia co y HEP: phai DU ca nam o `any` VA co gioi han Application.
    Chi can mot o co gia tri that (vd service=tcp-443) thi khong con la rule
    ha tang nua - luc do no la rule binh thuong va audit van soi nhu cu.
    Khong phan biet action: mot rule `any/any/any app=[bittorrent] deny` cung
    la rule ha tang (chan co chu dich), khong phai rac.
    """
    if _app_set(rule) is None:           # Application = any/rong -> rule L3-L4 thuong
        return False
    return (_field_is_any(rule.source) and _field_is_any(rule.destination)
            and _field_is_any(rule.service) and _field_is_any(rule.from_zones)
            and _field_is_any(rule.to_zones))


def infrastructure_rules(rules: List[RuleSnapshot]) -> List[RuleSnapshot]:
    """Danh sach rule ha tang - de GUI NOI RA da bo qua nhung rule nao.

    Bo qua trong im lang la cach chac chan nhat de lan sau khong ai biet tool
    da khong soi nhung rule do.
    """
    return [r for r in rules if is_infrastructure_rule(r)]


def _covers_rule_fast(r1: RuleSnapshot, r2: RuleSnapshot, i1: int, i2: int,
                      from_any, to_any, from_zone_sets, to_zone_sets) -> bool:
    """Ban FAST cua _covers_rule() cho vong lap O(n^2): zone precomputed, thu tu
    kiem tra re->dat giu nguyen. `r1.disabled` da duoc loc truoc qua
    `enabled_indices` nen khong check lai o day."""
    # Application dung DAU: phep so hai tap ten la re nhat trong nam chieu, ma
    # no lai loai duoc dung cai rule any/any/any-chi-bat-vai-app von dung dau
    # rulebase nen bi dem ra so voi MOI rule ben duoi.
    if not _apps_cover(r1, r2):
        return False
    # Target/Install-On dung ngay sau Application: cung la phep so hai tap ten,
    # re hon moi phep tinh dia chi ben duoi, ma lai loai duoc dung truong hop
    # "rule cua site B di che rule cua site A".
    if not _targets_cover(r1, r2):
        return False
    if not _zones_cover_fast(i1, i2, from_any, to_any, from_zone_sets, to_zone_sets, True):
        return False
    if not _zones_cover_fast(i1, i2, from_any, to_any, from_zone_sets, to_zone_sets, False):
        return False
    if r1.resolved_source is None or r2.resolved_source is None:
        return False
    if not r1.resolved_source.covers(r2.resolved_source):
        return False
    if r1.resolved_destination is None or r2.resolved_destination is None:
        return False
    if not r1.resolved_destination.covers(r2.resolved_destination):
        return False
    if r1.resolved_service is None or r2.resolved_service is None:
        return False
    if not r1.resolved_service.covers(r2.resolved_service):
        return False
    return True


def _unreachable_detail_fragment(r1: RuleSnapshot, r2: RuleSnapshot) -> str:
    frag = f"Bị che bởi rule '{r1.name}' (index {r1.index}, action={r1.action})"
    if r2.disabled:
        frag += " (R2 đang Disabled)"
    if r1.action != r2.action:
        frag = "⚠ KHÁC ACTION - " + frag
    return frag


def _covers_rule(r1: RuleSnapshot, r2: RuleSnapshot) -> bool:
    """Toan bo 5 dieu kien Mục 4.3. R1 khong disabled moi duoc tinh la "rule che".
    R2 co the disabled hay khong (van bao cao, chi ghi chu trong detail)."""
    if r1.disabled:
        return False
    if not _zones_cover(r1.from_zones, r2.from_zones):
        return False
    if not _zones_cover(r1.to_zones, r2.to_zones):
        return False
    if r1.resolved_source is None or r2.resolved_source is None:
        return False
    if not r1.resolved_source.covers(r2.resolved_source):
        return False
    if r1.resolved_destination is None or r2.resolved_destination is None:
        return False
    if not r1.resolved_destination.covers(r2.resolved_destination):
        return False
    if r1.resolved_service is None or r2.resolved_service is None:
        return False
    if not r1.resolved_service.covers(r2.resolved_service):
        return False
    return True


def _find_unreachable_rules(rules: List[RuleSnapshot], resolver, svc_resolver) -> Dict[Tuple[str, str], dict]:
    """
    Rule R2 (index i2) bi che khuat boi R1 (index i1 < i2) khi VA CHI KHI toan
    bo 5 dieu kien o Mục 4.3. Rule dau tien (index nho nhat) thoa -> duoc chon,
    dung tim ngay (break) - dung thu tu PAN-OS danh gia rule.
    SỬA 2026-09-02 (lỗ hổng D9): khoá theo (rule_name, vi_tri) thay vì tên thuần,
    để phân biệt 2 rule trùng tên ở 2 DG khác nhau. Giữ thêm khoá tên thuần khi
    vi_tri rỗng để tương thích test cũ standalone.
    Tra ve Dict[(rule_name, vi_tri) -> {shadowed_by_rule_name, shadowed_by_rule_index,
    same_action, detail_fragment}].
    """
    _resolve_rules(rules, resolver, svc_resolver)

    # TOI UU (giu nguyen 100% dieu kien 5-dieu-kien Muc 4.3, chi giam so lan tinh
    # lai cung 1 gia tri): precompute zone set + chi duyet R1 ENABLED co index < i2.
    n = len(rules)
    from_zone_sets = [frozenset(r.from_zones) for r in rules]
    to_zone_sets = [frozenset(r.to_zones) for r in rules]
    from_any = ["any" in r.from_zones for r in rules]
    to_any = ["any" in r.to_zones for r in rules]
    enabled_indices = [i for i, r in enumerate(rules) if not r.disabled]

    shadow: Dict[Tuple[str, str], dict] = {}
    for i2 in range(n):
        r2 = rules[i2]
        upto = bisect.bisect_left(enabled_indices, i2)
        for i1 in enabled_indices[:upto]:
            r1 = rules[i1]
            if not _covers_rule_fast(r1, r2, i1, i2, from_any, to_any,
                                      from_zone_sets, to_zone_sets):
                continue
            entry = {
                "shadowed_by_rule_name": r1.name,
                "shadowed_by_rule_index": r1.index,
                "same_action": (r1.action == r2.action),
                "detail_fragment": _unreachable_detail_fragment(r1, r2),
            }
            shadow[(r2.name, r2.vi_tri)] = entry
            # backward compat cho test cũ khi vi_tri rỗng
            if r2.vi_tri == "":
                shadow[r2.name] = entry  # type: ignore
            break  # tim thay R1 dau tien la du - khong can quet tiep
    return shadow  # type: ignore


# ============================================================================
# 4.4 NHANH UNUSED (No Hits) - du lieu chi lay tu Policy Optimizer rule-hit-count
# ============================================================================
def _find_unused_rules(rules: List[RuleSnapshot], hit_stats: Dict[Tuple[str, str], RuleHitStat],
                       now: NOW_TYPE,
                       threshold_days: int = UNUSED_RULE_THRESHOLD_DAYS
                       ) -> Dict[Tuple[str, str], dict]:
    """
    Nguong so ngay khong hit - mac dinh UNUSED_RULE_THRESHOLD_DAYS (30), co the
    ghi de qua GUI (`threshold_days`). Rule khong co du lieu
    hit (stat None) -> bo qua, khong doan. hit_stats rong (API khong ho tro) ->
    ham nay khong sinh ket qua gi, nhanh UNREACHABLE van chay doc lap (D10).
    SỬA 2026-09-02: hit_stats khoá theo (rule_name, vi_tri) để xử lý trùng tên khác DG (D9).
    """
    result: Dict[Tuple[str, str], dict] = {}
    # Hỗ trợ cả hit_stats cũ khoá tên thuần (standalone tests) và mới khoá (name, vi_tri)
    has_string_keys = any(isinstance(k, str) for k in hit_stats.keys()) if hit_stats else False
    for r in rules:
        stat = hit_stats.get((r.name, r.vi_tri))
        if stat is None and has_string_keys:
            # fallback cho test cũ / standalone: khoá tên thuần
            stat = hit_stats.get(r.name)  # type: ignore
        if stat is None:
            # thêm fallback cho vi_tri rỗng
            if r.vi_tri == "":
                stat = hit_stats.get((r.name, ""))  # type: ignore
            if stat is None:
                continue

        # P1 (10/2026) - CONG CHAN QUAN TRONG NHAT CUA TAB NAY.
        # "Khong biet" KHAC "bang 0". Neu co firewall trong pham vi query ma khong
        # doc duoc hit-count cho rule nay (loi API, hoac tra ve OK nhung khong co
        # dong nao cho rule do) thi bang chung KHONG day du -> khong duoc ket luan
        # UNUSED, vi UNUSED la cai dua rule vao file Import va Import se DELETE no
        # khoi candidate-config cua ca Device Group.
        if not getattr(stat, 'hits_known', True):
            continue

        no_hit_days: Optional[int]
        if stat.hit_count and stat.hit_count > 0 and stat.last_hit_timestamp:
            no_hit_days = (now - stat.last_hit_timestamp).days
            if no_hit_days < threshold_days:
                continue
            reason_detail = (
                f"Không có hits trong {no_hit_days} ngày "
                f"(lần hit gần nhất: {stat.last_hit_date})"
            )
        else:
            # hit_count == 0 hoac None -> CHUA TUNG co hit
            if stat.rule_creation_timestamp is None:
                continue  # khong du du lieu -> khong doan bung
            no_hit_days = (now - stat.rule_creation_timestamp).days
            if no_hit_days < threshold_days:
                continue  # rule moi tao, chua du nguong
            reason_detail = (
                f"Chưa từng có hit nào kể từ khi tạo rule ({no_hit_days} ngày, "
                f"tạo lúc: {stat.rule_creation_date})"
            )

        entry = {
            "hit_count": stat.hit_count or 0,
            "last_hit_date": stat.last_hit_date,
            "rule_creation_date": stat.rule_creation_date,
            "no_hit_days": no_hit_days,
            "detail_fragment": reason_detail,
        }
        result[(r.name, r.vi_tri)] = entry
        # backward compat cho test cũ standalone (khoá tên thuần) — chỉ khi vi_tri rỗng hoặc hit_stats cũ
        if has_string_keys or r.vi_tri == "":
            result[r.name] = entry  # type: ignore
    return result  # type: ignore


# ============================================================================
# 4.5 SHADOW RULES - hop nhat 2 nhanh UNREACHABLE + UNUSED
# ============================================================================
def find_shadow_rules(rules: List[RuleSnapshot], resolver, svc_resolver,
                      hit_stats: Dict[Tuple[str, str], RuleHitStat], now: NOW_TYPE,
                      threshold_days: int = UNUSED_RULE_THRESHOLD_DAYS) -> List[Finding]:
    """
    Ham public duy nhat gui.py goi cho tinh nang "Shadow Rules". 1 rule dinh ca
    2 ly do chi tao DUNG 1 Finding, detail noi ca 2 mo ta bang dau " | ".
    SỬA 2026-09-02: hit_stats và unused_map khoá theo (rule_name, vi_tri) (D9).
    """
    unreachable_map = _find_unreachable_rules(rules, resolver, svc_resolver)
    unused_map = _find_unused_rules(rules, hit_stats, now, threshold_days)

    out: List[Finding] = []
    for r in rules:
        # Rule HA TANG khong bao gio la rac: no rong o L3-L4 dung nhu thiet ke,
        # va phan that su gioi han nam o App-ID - thu tool nay khong do duoc.
        # Bao no UNUSED/UNREACHABLE la dua thang de nghi xoa rule ha tang.
        # Xem is_infrastructure_rule().
        if is_infrastructure_rule(r):
            continue
        reasons: List[str] = []
        detail_parts: List[str] = []
        _unreach_key = (r.name, r.vi_tri)
        _unreach_entry = unreachable_map.get(_unreach_key)
        if _unreach_entry is None:
            _unreach_entry = unreachable_map.get(r.name)  # type: ignore  # fallback
        if _unreach_entry is not None:
            reasons.append(SHADOW_UNREACHABLE)
            detail_parts.append(_unreach_entry["detail_fragment"])
        # hỗ trợ cả khoá tuple mới và khoá string cũ
        _unused_key = (r.name, r.vi_tri)
        _unused_entry = unused_map.get(_unused_key)
        if _unused_entry is None:
            _unused_entry = unused_map.get(r.name)  # type: ignore  # fallback standalone
        if _unused_entry is not None:
            reasons.append(SHADOW_UNUSED)
            detail_parts.append(_unused_entry["detail_fragment"])
        if not reasons:
            continue

        f = Finding(
            check_type=CHECK_TYPE_SHADOW,
            rule_name=r.name,
            rule_uuid=r.uuid,
            rule_index=r.index,
            source=r.source,
            destination=r.destination,
            service=r.service,
            action=r.action,
            disabled=r.disabled,
            detail=" | ".join(detail_parts),
            shadow_reasons=reasons,
        )
        if SHADOW_UNREACHABLE in reasons:
            _ue2 = unreachable_map.get((r.name, r.vi_tri))
            if _ue2 is None:
                _ue2 = unreachable_map.get(r.name)  # type: ignore
            f.shadowed_by_rule_name = _ue2["shadowed_by_rule_name"]  # type: ignore
            f.shadowed_by_rule_index = _ue2["shadowed_by_rule_index"]  # type: ignore
            f.same_action = _ue2["same_action"]  # type: ignore
        if SHADOW_UNUSED in reasons:
            _ue = unused_map.get((r.name, r.vi_tri))
            if _ue is None:
                _ue = unused_map.get(r.name)  # type: ignore
            f.hit_count = _ue["hit_count"]  # type: ignore
            f.last_hit_date = _ue["last_hit_date"]  # type: ignore
            f.rule_creation_date = _ue["rule_creation_date"]  # type: ignore
            f.no_hit_days = _ue["no_hit_days"]  # type: ignore
        # Gan vi_tri cho Finding để gui dùng cho xác minh batch
        f.vi_tri = r.vi_tri
        out.append(f)
    return out