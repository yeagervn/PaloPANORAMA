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
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .core import (
    Finding, RuleSnapshot, RuleHitStat,
    UNUSED_RULE_THRESHOLD_DAYS,
    CHECK_TYPE_SHADOW, CHECK_TYPE_DISABLED, CHECK_TYPE_OVERLY,
    SHADOW_UNREACHABLE, SHADOW_UNUSED,
)
from .resolver import ResolvedAddr

NOW_TYPE = datetime


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


def _covers_rule_fast(r1: RuleSnapshot, r2: RuleSnapshot, i1: int, i2: int,
                      from_any, to_any, from_zone_sets, to_zone_sets) -> bool:
    """Ban FAST cua _covers_rule() cho vong lap O(n^2): zone precomputed, thu tu
    kiem tra re->dat giu nguyen. `r1.disabled` da duoc loc truoc qua
    `enabled_indices` nen khong check lai o day."""
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