# -*- coding: utf-8 -*-
"""
rows.py - dung dong ket qua cho BANG tren giao dien tab CHECK IP.

Tach rieng khoi gui.py vi toan bo cho nay la ham THUAN: khong `import tkinter`,
khong cham widget. Nho vay test duoc tren moi trinh thong dich, ke ca ban khong
co Tk - ma day lai dung la phan de sai nhat (lech cot, mat dong, hien nham IP).

VI SAO CO BANG NAY
==================
Truoc day tab CHECK IP chay xong chi ghi 1 dong log "Export OK -> ..." roi bat
nguoi dung di mo file Excel. Nay ket qua hien THANG tren tool; file chi xuat
khi bam nut Export.

MOT BANG, NHIEU LOAI KET QUA
============================
Bang co 10 cot theo bo cot cua Security Rule - ban Panorama thay cot UUID bang
cot VI TRI (Shared-PRE / <DG>-PRE / <DG>-POST / Shared-POST), vi thu tu 4 vi tri
do quyet dinh rule nao an rule nao, con UUID thi khong ai doc bang mat. Cac muc khac (NAT, Check Object,
doi chieu Log) co y nghia cot khac han, nen moi muc TU IN dong ten muc + dong
ten cot cua no ngay truoc du lieu - thay vi nhoi tat ca vao mot bo tieu de
chung ma bo nao cung sai mot nua.

CHI HIEN THONG TIN CUA IP INPUT
===============================
O Source/Dest cua 1 rule co the chua hang chuc object. Bang chi hien object/
group BAO IP dang tra; nhanh khong lien quan chi con lai cai TEN. Xem
`excel_export._expand_entry_runs`.

Bang KHONG boc `*...*` quanh gia tri khop nhu ban CSV: CSV phai danh dau vi no
in day du moi member nen can chi ra cai nao la IP dang tra; o bang thi da loc
san roi, danh dau them chi lam ban mat.
"""

from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

RULE_HEADERS = ("Name Rule", "Vi tri", "Source IP", "Dest IP", "Service",
                "Matched Side", "Source Zone", "Destination Zone",
                "Application", "Action")
NAT_HEADERS = ("Rule Name", "Vi tri", "Source Address", "Destination Address",
               "Service", "NAT Type", "Source Zone", "Destination Zone",
               "Source Translated", "Destination Translated")
WHERE_HEADERS = ("Nhom ket qua", "Ten", "Loai", "Gia tri / Duong dan",
                 "Vi tri Panorama", "Thu tu", "Action", "O khop",
                 "Qua (vi sao dinh)", "Ghi chu")
LOG_HEADERS = ("Dong Log", "Source IP", "Dest IP", "Port", "Ket qua",
               "Rule quyet dinh", "", "", "", "")

NCOL = len(RULE_HEADERS)

SECTION_TITLE = {
    "rule": "SECURITY RULE KHOP IP",
    "nat": "NAT RULE",
    "where": "CHECK OBJECT (Where Used)",
    "log": "DOI CHIEU FILE LOG",
}
SECTION_HEADERS = {
    "rule": RULE_HEADERS, "nat": NAT_HEADERS,
    "where": WHERE_HEADERS, "log": LOG_HEADERS,
}


def _pad(cells: Sequence[Any]) -> Tuple[str, ...]:
    """Moi dong PHAI du 10 o - thieu mot o la Tk day cac o sau lech sang trai."""
    out = [("" if c is None else str(c)) for c in cells][:NCOL]
    return tuple(out + [""] * (NCOL - len(out)))


def section(kind: str) -> List[Dict[str, Any]]:
    return [
        {"kind": "section", "cells": _pad([f"== {SECTION_TITLE[kind]} =="])},
        {"kind": "hdr", "cells": _pad(SECTION_HEADERS[kind])},
    ]


def note_row(text: str) -> Dict[str, Any]:
    return {"kind": "note", "cells": _pad(["(ghi chu)", text])}


def _one_line(text: str) -> str:
    """Bang Treeview khong hien duoc xuong dong - gop lai, giu dau phay."""
    return " ".join(str(text or "").split())


# ---------------------------------------------------------------------------
# SECURITY RULE
# ---------------------------------------------------------------------------
def rule_rows(rules, match_results, resolver, service_objects, service_groups,
              target_ips: Optional[Set[str]] = None) -> List[Dict[str, Any]]:
    """Mot rule MOT dong, gom het cac IP da khop vao rule do.

    Gom theo RULE chu khong theo IP: tra 50 IP ma 40 con cung khop mot rule thi
    in 40 dong giong het nhau la bat nguoi doc tu loc bang mat.
    """
    from .excel_export import (_build_address_runs, _build_service_plain,
                               _runs_plain_text)

    target_ips = set(target_ips or [])
    by_rule: Dict[int, Dict[str, set]] = {}
    for ip_str, matches in (match_results or {}).items():
        for rule_idx, side in matches:
            d = by_rule.setdefault(rule_idx, {"ips": set(), "sides": set()})
            d["ips"].add(ip_str)
            d["sides"].add(side)

    out: List[Dict[str, Any]] = []
    for rule in rules or []:
        hit = by_rule.get(rule.index)
        if not hit:
            continue
        ips = target_ips or hit["ips"]
        out.append({"kind": "rule", "disabled": bool(rule.disabled), "cells": _pad([
            rule.name,
            getattr(rule, "vi_tri", ""),
            _one_line(_runs_plain_text(_build_address_runs(
                rule.source, resolver, ips, filter_to_matched=True))),
            _one_line(_runs_plain_text(_build_address_runs(
                rule.destination, resolver, ips, filter_to_matched=True))),
            _one_line(_build_service_plain(rule.service, service_objects, service_groups)),
            " + ".join(sorted(hit["sides"])),
            ", ".join(rule.from_zones),
            ", ".join(rule.to_zones),
            ", ".join(rule.application),
            ("[DISABLED] " if rule.disabled else "") + rule.action,
        ])})
    if not out:
        out.append(note_row("Khong co Security Rule nao neu dich danh cac IP nay."))
    return out


# ---------------------------------------------------------------------------
# NAT
# ---------------------------------------------------------------------------
def nat_rows(nat_rules, resolver, service_objects, service_groups,
             target_ips: Optional[Set[str]] = None,
             search_mode: bool = False) -> List[Dict[str, Any]]:
    from .excel_export import (_build_address_runs, _build_service_plain,
                               _nat_dst_xlate_runs, _nat_src_xlate_runs,
                               _runs_plain_text, _SRC_XLATE_TYPE_LABEL)

    ips = set(target_ips or [])
    out: List[Dict[str, Any]] = []
    for rule in nat_rules or []:
        out.append({"kind": "nat", "disabled": bool(rule.disabled), "cells": _pad([
            rule.name,
            getattr(rule, "vi_tri", ""),
            _one_line(_runs_plain_text(_build_address_runs(
                rule.source, resolver, ips, filter_to_matched=search_mode))),
            _one_line(_runs_plain_text(_build_address_runs(
                rule.destination, resolver, ips, filter_to_matched=search_mode))),
            _one_line(_build_service_plain([rule.service], service_objects, service_groups)),
            rule.nat_type,
            ", ".join(rule.from_zones),
            ", ".join(rule.to_zones),
            _one_line(_SRC_XLATE_TYPE_LABEL.get(rule.src_xlate_type, rule.src_xlate_type)
                      + " " + _runs_plain_text(_nat_src_xlate_runs(
                          rule, resolver, ips, filter_to_matched=search_mode))),
            _one_line(_runs_plain_text(_nat_dst_xlate_runs(
                rule, resolver, ips, filter_to_matched=search_mode))),
        ])})
    if not out:
        out.append(note_row("Khong co NAT rule nao khop."))
    return out


# ---------------------------------------------------------------------------
# CHECK OBJECT (Where Used)
# ---------------------------------------------------------------------------
def where_rows(reports) -> List[Dict[str, Any]]:
    """Giu NGUYEN ba nhom (tham chieu / theo gia tri / chi vi 'any') - do la
    thong tin chinh cua tinh nang nay, lam phang la mat."""
    out: List[Dict[str, Any]] = []
    for report in reports or []:
        out.append({"kind": "section", "cells": _pad([f"  >> {report.query}"])})
        for hit in report.objects:
            out.append({"kind": "where", "cells": _pad([
                "OBJECT", hit.name, hit.kind, hit.value, "", "", "", "",
                hit.kind_text, hit.note])})
        for hit in report.groups:
            out.append({"kind": "where", "cells": _pad([
                "GROUP", hit.name, f"address-group ({hit.group_kind})",
                hit.path_text, "", f"cap {hit.depth}", "", "", "", hit.note])})
        for label, bucket in (("RULE (tham chieu)", report.rules_by_reference),
                              ("RULE (theo gia tri)", report.rules_by_value),
                              ("RULE (chi vi 'any')", report.rules_by_any)):
            for hit in bucket:
                out.append({"kind": "where", "disabled": bool(hit.disabled), "cells": _pad([
                    label, hit.rule_name, "security-rule", "", hit.vi_tri,
                    f"#{hit.rule_index}", hit.action, hit.side_text, hit.via,
                    "DISABLED" if hit.disabled else ""])})
        for hit in report.nat_hits:
            out.append({"kind": "where", "disabled": bool(hit.disabled), "cells": _pad([
                "NAT RULE", hit.rule_name, "nat-rule", "", hit.vi_tri,
                f"#{hit.rule_index}", "", hit.side_text, hit.via,
                "DISABLED" if hit.disabled else ""])})
        for note in report.notes:
            out.extend([note_row(part) for part in _wrap_note(note)])
    return out


def _wrap_note(text: str, width: int = 150) -> List[str]:
    """Ghi chu dai hon mot o thi xuong dong tiep, KHONG cat cut.

    Ghi chu la cho tool noi VI SAO - cat im lang la bo mat ly do.
    """
    words = str(text or "").split()
    if not words:
        return [""]
    lines, cur = [], ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}" if cur else w
    lines.append(cur)
    return lines


# ---------------------------------------------------------------------------
# DOI CHIEU FILE LOG
# ---------------------------------------------------------------------------
def log_rows(log_entries, rules, resolver, service_objects, service_groups
             ) -> List[Dict[str, Any]]:
    from .matching_engine import find_first_allow_rule_match

    allow_rules = [r for r in (rules or [])
                   if not r.disabled and r.action.lower() == "allow"]
    cache: Dict[str, List[Tuple[int, int]]] = {}
    out: List[Dict[str, Any]] = []
    for idx, le in enumerate(log_entries or [], start=1):
        hit = find_first_allow_rule_match(le, allow_rules, resolver,
                                          service_objects, service_groups, cache)
        out.append({"kind": "log", "ok": hit is not None, "cells": _pad([
            idx, le.source_ip, le.dest_ip, le.port,
            "DUOC DI" if hit else "KHONG CO RULE ALLOW NAO KHOP",
            hit.name if hit else ""])})
    if not out:
        out.append(note_row("File Log khong co dong traffic hop le nao."))
    return out
