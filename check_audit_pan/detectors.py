# -*- coding: utf-8 -*-
"""
detectors.py - 3 ham phat hien cua CHECK AUDIT (Mục 4 require.md):

  - find_disabled_rules()                 -> Disabled Rules (4.1)
  - find_overly_permissive_rules()        -> Overly Permissive Rules (4.2)
  - find_shadow_rules()                   -> Shadow Rules (4.5) hop nhat 2 nhanh:
        _find_unreachable_rules()   UNREACHABLE - rule bi che khuat boi rule truoc (4.3)
        _find_unused_rules()        UNUSED - rule khong co hits >= 30 ngay (4.4, D10)
"""

from datetime import datetime
from typing import Dict, List, Optional

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
    """R1.from_zones cover R2.from_zones (any o 1 trong 2 ben, hoac R1 chua 'any',
    hoac tap zone R1 supertable tap zone R2)."""
    if "any" in z1 or "any" in z2:
        return True
    return set(z1) >= set(z2)


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


def _find_unreachable_rules(rules: List[RuleSnapshot], resolver, svc_resolver) -> Dict[str, dict]:
    """
    Rule R2 (index i2) bi che khuat boi R1 (index i1 < i2) khi VA CHI KHI toan
    bo 5 dieu kien o Mục 4.3. Rule dau tien (index nho nhat) thoa -> duoc chon,
    dung tim ngay (break) - dung thu tu PAN-OS danh gia rule.
    Tra ve Dict[rule_name -> {shadowed_by_rule_name, shadowed_by_rule_index,
    same_action, detail_fragment}].
    """
    _resolve_rules(rules, resolver, svc_resolver)

    shadow: Dict[str, dict] = {}
    for i2 in range(len(rules)):
        r2 = rules[i2]
        for i1 in range(i2):
            r1 = rules[i1]
            if not _covers_rule(r1, r2):
                continue
            shadow[r2.name] = {
                "shadowed_by_rule_name": r1.name,
                "shadowed_by_rule_index": r1.index,
                "same_action": (r1.action == r2.action),
                "detail_fragment": _unreachable_detail_fragment(r1, r2),
            }
            break  # tim thay R1 dau tien la du - khong can quet tiep
    return shadow


# ============================================================================
# 4.4 NHANH UNUSED (No Hits) - du lieu chi lay tu Policy Optimizer rule-hit-count
# ============================================================================
def _find_unused_rules(rules: List[RuleSnapshot], hit_stats: Dict[str, RuleHitStat],
                       now: NOW_TYPE) -> Dict[str, dict]:
    """
    Nguong CO DINH 30 ngay (UNUSED_RULE_THRESHOLD_DAYS). Rule khong co du lieu
    hit (stat None) -> bo qua, khong doan. hit_stats rong (API khong ho tro) ->
    ham nay khong sinh ket qua gi, nhanh UNREACHABLE van chay doc lap (D10).
    """
    result: Dict[str, dict] = {}
    for r in rules:
        stat = hit_stats.get(r.name)
        if stat is None:
            continue

        no_hit_days: Optional[int]
        if stat.hit_count and stat.hit_count > 0 and stat.last_hit_timestamp:
            no_hit_days = (now - stat.last_hit_timestamp).days
            if no_hit_days < UNUSED_RULE_THRESHOLD_DAYS:
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
            if no_hit_days < UNUSED_RULE_THRESHOLD_DAYS:
                continue  # rule moi tao, chua du 30 ngay
            reason_detail = (
                f"Chưa từng có hit nào kể từ khi tạo rule ({no_hit_days} ngày, "
                f"tạo lúc: {stat.rule_creation_date})"
            )

        result[r.name] = {
            "hit_count": stat.hit_count or 0,
            "last_hit_date": stat.last_hit_date,
            "rule_creation_date": stat.rule_creation_date,
            "no_hit_days": no_hit_days,
            "detail_fragment": reason_detail,
        }
    return result


# ============================================================================
# 4.5 SHADOW RULES - hop nhat 2 nhanh UNREACHABLE + UNUSED
# ============================================================================
def find_shadow_rules(rules: List[RuleSnapshot], resolver, svc_resolver,
                      hit_stats: Dict[str, RuleHitStat], now: NOW_TYPE) -> List[Finding]:
    """
    Ham public duy nhat gui.py goi cho tinh nang "Shadow Rules". 1 rule dinh ca
    2 ly do chi tao DUNG 1 Finding, detail noi ca 2 mo ta bang dau " | ".
    """
    unreachable_map = _find_unreachable_rules(rules, resolver, svc_resolver)
    unused_map = _find_unused_rules(rules, hit_stats, now)

    out: List[Finding] = []
    for r in rules:
        reasons: List[str] = []
        detail_parts: List[str] = []

        if r.name in unreachable_map:
            reasons.append(SHADOW_UNREACHABLE)
            detail_parts.append(unreachable_map[r.name]["detail_fragment"])
        if r.name in unused_map:
            reasons.append(SHADOW_UNUSED)
            detail_parts.append(unused_map[r.name]["detail_fragment"])
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
            f.shadowed_by_rule_name = unreachable_map[r.name]["shadowed_by_rule_name"]
            f.shadowed_by_rule_index = unreachable_map[r.name]["shadowed_by_rule_index"]
            f.same_action = unreachable_map[r.name]["same_action"]
        if SHADOW_UNUSED in reasons:
            f.hit_count = unused_map[r.name]["hit_count"]
            f.last_hit_date = unused_map[r.name]["last_hit_date"]
            f.rule_creation_date = unused_map[r.name]["rule_creation_date"]
            f.no_hit_days = unused_map[r.name]["no_hit_days"]
        out.append(f)
    return out