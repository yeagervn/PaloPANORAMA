# -*- coding: utf-8 -*-
"""
excel_export.py - Hien thi rich-text (dam/do/XANH LA DAM cho input IP) va
xuat ket qua ra file Excel dua tren template nhung san, giu nguyen style
goc, chen cot Log neu co doi chieu File Log.
(Gop tu rich_display.py + excel_export.py cu)
"""

import os
import csv
import ipaddress
from copy import copy as copy_style
from datetime import datetime
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

import openpyxl
from openpyxl.styles import Font, Alignment
from openpyxl.cell.text import InlineFont
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.utils import get_column_letter

from .core import (
    EXTRA_HEADERS, LOG_EXTRA_HEADERS, NAT_HEADERS, _get_template_bytes,
    SecurityRule, NatRule, ServiceObject, ServiceGroup, LogEntry,
    is_literal_ip_or_cidr, parse_ip_range,
)
from .resolver_engine import GroupResolver, _display_value, _resolve_service_leaves
from .matching_engine import find_first_allow_rule_match

# ============================================================================
# HIEN THI RICH-TEXT: dam (ten) / do (value thong tin) / XANH LA DAM (value
# TRUNG voi input IP dang tim) - cho Source IP / Dest IP / Service
# ============================================================================
# ============================================================================
# HIEN THI VALUE THAT (khong chi ten) CHO SOURCE IP / DEST IP KHI XUAT EXCEL
# ============================================================================
# Theo yeu cau: neu Source/Destination cua rule la 1 Address Group, phai in ra
# toan bo member da resolve KEM VALUE THAT cua no (khong chi ten object), vi
# ten object co the gay hieu lam (vd 1 object ten "Exadata-X62-10.0.6-DC"
# nhung value that la range 10.0.6.101-10.0.6.107, khong phai host don).
#
# Trinh bay truc quan (rich text trong 1 cell Excel):
#   - Ten object/group: IN DAM
#   - Value la 1 trong cac IP dang tim (INPUT IP): TO MAU XANH LA (de phan
#     biet ngay dau la IP minh dang can tim trong ca chuoi gia tri)
#   - Value khac (chi mang tinh thong tin, khong phai IP dang tim): TO MAU DO
#   - Moi member trong 1 group: xuong dong rieng (giong vi du TWAPI-GR-APP)
#
# Ham _expand_entry_runs/_build_address_runs tra ve danh sach "runs" dang
# (loai, text) - loai la 'name' (in dam), 'value' (do, thong tin), 'value_matched'
# (xanh la, TRUNG voi input IP), hoac 'text' (ky tu cau truc: dau phay, ngoac,
# xuong dong) - sau do _runs_to_rich_text() moi chuyen thanh openpyxl
# CellRichText that su ghi vao cell.

# Ten 2 sheet khi xuat GOP 1 file (xem export_combined_to_excel o cuoi file).
RULE_SHEET_TITLE = "Security Rules"
NAT_SHEET_TITLE = "NAT Rules"


def _member_matches_target(value_str: str, target_ips: Set[str]) -> bool:
    """value_str la value hien thi cua 1 leaf member (vd '10.3.16.11' hoac
    '10.4.96.121-10.4.96.122'). Tra ve True neu no la 1 trong cac input IP
    dang tim (host), hoac chua 1 trong cac input IP do (range)."""
    if value_str in target_ips:
        return True
    if "-" in value_str:
        rng = parse_ip_range(value_str)
        if rng:
            start, end = rng
            for ip in target_ips:
                try:
                    ip_int = int(ipaddress.ip_address(ip))
                except ValueError:
                    continue
                if start <= ip_int <= end:
                    return True
    return False


def _value_run_kind(val: str, target_ips: Set[str]) -> str:
    """'value_matched' (xanh la) neu val trung/chua 1 input IP dang tim,
    nguoc lai 'value' (do, chi mang tinh thong tin)."""
    return "value_matched" if (target_ips and _member_matches_target(val, target_ips)) else "value"


def _expand_entry_runs(entry: str, resolver: GroupResolver, target_ips: Set[str],
                        filter_to_matched: bool = True) -> List[Tuple[str, str]]:
    if entry == "any":
        return [("text", "any")]
    if is_literal_ip_or_cidr(entry):
        return [(_value_run_kind(entry, target_ips), entry)]  # literal go thang trong rule, ban than no da la value

    obj = resolver.address_objects.get(entry)
    if obj is not None:
        val = _display_value(obj)
        if val:
            return [("name", entry), ("text", " ("), (_value_run_kind(val, target_ips), val), ("text", ")")]
        return [("name", entry)]

    grp = resolver.address_groups.get(entry)
    if grp is not None:
        resolved = resolver.resolve(entry)  # da cache tu buoc build_index, O(1)
        all_members = sorted(resolved.member_details, key=lambda t: (t[0] or "", t[1]))
        if filter_to_matched:
            # GROUP CO BAO IP DANG TRA -> chi hien dung member bao no (xanh la).
            # Mot group co hang chuc member, nhan len hai phia cua hang chuc
            # rule, thi in het la nguoi doc phai tu do mat tim xem IP minh nhap
            # nam o dau.
            #
            # GROUP KHONG LIEN QUAN (phia ben kia rule) -> VAN break ra DU
            # member, mau do.
            #   Ban 10/2026 dau tien thu gon ca cum nay con DUNG MOT CAI TEN
            #   group. Nguoi van hanh bao sai: doc mot dong rule ma chi thay
            #   "GRP-DC-SERVERS" thi khong tra loi duoc cau hoi ke tiep - "the
            #   dau ben kia la nhung IP nao?" - va lai phai mo thiet bi ra xem,
            #   dung viec ma tool phai lam thay. Mau da phan biet san: xanh la
            #   = IP dang tra, do = phan con lai (chi de doc).
            members = [(n, v) for (n, v) in all_members
                       if _member_matches_target(v, target_ips)]
            if not members:
                members = all_members
        else:
            # Dung cho Export bang NAT (muc 4 GUI): LUON hien THAT DAY DU moi
            # member (khong loc bo) - chi khac mau (xanh la neu trung IP nhap
            # tay de highlight, do neu khong) - vi day la "xuat toan bo" chu
            # khong phai "tim kiem", khong duoc phep an bot thong tin.
            members = all_members
        if not members:
            return [("name", entry)]
        runs: List[Tuple[str, str]] = [("name", entry), ("text", " (\n")]
        for idx, (n, v) in enumerate(members):
            if idx > 0:
                runs.append(("text", ",\n"))
            if n:
                runs.append(("name", n))
                runs.append(("text", " ("))
                runs.append((_value_run_kind(v, target_ips), v))
                runs.append(("text", ")"))
            else:
                runs.append((_value_run_kind(v, target_ips), v))
        runs.append(("text", ")"))
        return runs

    return [("name", entry)]  # khong tim thay object/group (da canh bao rieng trong log)


def _build_address_runs(entries: List[str], resolver: GroupResolver, target_ips: Set[str],
                         filter_to_matched: bool = True) -> List[Tuple[str, str]]:
    runs: List[Tuple[str, str]] = []
    for i, entry in enumerate(entries):
        if i > 0:
            runs.append(("text", ", "))
        runs.extend(_expand_entry_runs(entry, resolver, target_ips, filter_to_matched))
    return runs


def _runs_plain_text(runs: List[Tuple[str, str]]) -> str:
    return "".join(text for _, text in runs)


def _runs_plain_text_marked(runs: List[Tuple[str, str]]) -> str:
    """Nhu _runs_plain_text, nhung boc value TRUNG voi IP nhap tay highlight
    (kind='value_matched') trong dau `*...*` - CSV khong co mau/dinh dang nen
    dung ky hieu nay de VAN phan biet duoc IP nhap tay voi phan con lai."""
    parts = []
    for kind, text in runs:
        parts.append(f"*{text}*" if kind == "value_matched" else text)
    return "".join(parts)


def _build_address_plain(entries: List[str], resolver: GroupResolver,
                          highlight_ips: Set[str] = frozenset(),
                          filter_to_matched: bool = False) -> str:
    """Ban plain-text (khong rich text/mau) cua _build_address_runs, dung cho
    xuat CSV (CSV khong ho tro dinh dang mau/dam) - giu nguyen ten Group va
    break chi tiet tung Object/IP that ben trong; mac dinh LUON full (che do
    Full - filter_to_matched=False), nhung neu duoc goi tu che do Search
    (No o muc 4 GUI) thi filter_to_matched=True se CHI hien member khop voi
    IP dang tim - chi khac la khong to mau - neu co highlight_ips (IP nguoi
    dung nhap tay o muc 4 GUI), gia tri trung se duoc boc `*...*` de van
    phan biet duoc trong CSV."""
    if not entries:
        return ""
    runs = _build_address_runs(entries, resolver, highlight_ips, filter_to_matched=filter_to_matched)
    return _runs_plain_text_marked(runs) if highlight_ips else _runs_plain_text(runs)


def _build_service_plain(entries: List[str], service_objects: Dict[str, ServiceObject],
                          service_groups: Dict[str, ServiceGroup]) -> str:
    """Ban plain-text cua Service (protocol/port that), dung cho CSV."""
    if not entries:
        return ""
    cache: Dict[str, List[Tuple[str, str]]] = {}
    return _runs_plain_text(_build_service_runs(entries, service_objects, service_groups, cache))


def _runs_to_rich_text(runs: List[Tuple[str, str]], name_font: InlineFont, value_font: InlineFont,
                        matched_value_font: Optional[InlineFont] = None):
    blocks = []
    for kind, text in runs:
        if not text:
            continue
        if kind == "name":
            blocks.append(TextBlock(name_font, text))
        elif kind == "value_matched":
            blocks.append(TextBlock(matched_value_font or value_font, text))
        elif kind == "value":
            blocks.append(TextBlock(value_font, text))
        else:
            blocks.append(text)
    if not blocks:
        blocks = [""]
    return CellRichText(*blocks)



# ============================================================================
# HIEN THI VALUE THAT CHO SERVICE (vd sqlnet2-1521 -> tcp/1521, http -> tcp/80)
# ============================================================================
# Cung nguyen tac nhu Source/Dest IP: KHONG chi hien ten Service Object/Group,
# ma "break" ra protocol/port that. "any" va "application-default" la tu khoa
# dac biet cua PAN-OS (khong phai object) nen giu nguyen, khong resolve.


def _expand_service_entry_runs(entry: str, service_objects: Dict[str, ServiceObject],
                                service_groups: Dict[str, ServiceGroup],
                                cache: Dict[str, List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    if entry in ("any", "application-default"):
        return [("text", entry)]

    obj = service_objects.get(entry)
    if obj is not None:
        val = f"{obj.protocol}/{obj.port}" if obj.port else obj.protocol
        return [("name", entry), ("text", " ("), ("value", val), ("text", ")")]

    grp = service_groups.get(entry)
    if grp is not None:
        leaves = _resolve_service_leaves(entry, service_objects, service_groups, cache)
        if not leaves:
            return [("name", entry)]
        runs: List[Tuple[str, str]] = [("name", entry), ("text", " (\n")]
        for idx, (n, v) in enumerate(leaves):
            if idx > 0:
                runs.append(("text", ",\n"))
            runs.append(("name", n))
            runs.append(("text", " ("))
            runs.append(("value", v))
            runs.append(("text", ")"))
        runs.append(("text", ")"))
        return runs

    return [("name", entry)]  # khong tim thay (giu nguyen ten, khong crash)


def _build_service_runs(entries: List[str], service_objects: Dict[str, ServiceObject],
                         service_groups: Dict[str, ServiceGroup],
                         cache: Dict[str, List[Tuple[str, str]]]) -> List[Tuple[str, str]]:
    runs: List[Tuple[str, str]] = []
    for i, entry in enumerate(entries):
        if i > 0:
            runs.append(("text", ", "))
        runs.extend(_expand_service_entry_runs(entry, service_objects, service_groups, cache))
    return runs

# ============================================================================
# XUAT KET QUA RA EXCEL
# ============================================================================
# ============================================================================
# EXCEL EXPORT
# ============================================================================
# Muc 16/17 spec: dung DUNG template co san (khong tao workbook moi), giu
# nguyen 100% Font/Fill/Border/Merge/Width/Height/Freeze/Filter/Conditional
# Format cua 4 cot goc (Name Rule/Source IP/Dest IP/Service). Vi spec cung
# yeu cau ghi FULL thong tin Rule (UUID, Zone, Action, Profile, Log Setting,
# Schedule, Tag, Disabled, Target, HIP, Source User...) ma template mau chi
# co 4 cot, script se BO SUNG THEM cac cot do ben phai (giu nguyen style
# header/data cua template, ke dai ra), khong dung/xoa 4 cot goc.

def _insert_columns_after(ws, headers: List[str], insert_after_col: int) -> None:
    """Chen 1 nhom cot moi (headers) ngay sau cot insert_after_col, day cac cot
    con lai sang phai. Tu tay dich chuyen value + style + do rong cot (KHONG
    dung ws.insert_cols() cua openpyxl de tranh cac rui ro/loi dinh dang khong
    on dinh giua cac phien ban). Workbook luc nay chi co 4 dong (template goc)
    nen chi phi vong lap khong dang ke."""
    n = len(headers)
    max_col = ws.max_column
    max_row = ws.max_row

    for row in range(1, max_row + 1):
        for col in range(max_col, insert_after_col, -1):
            src_cell = ws.cell(row=row, column=col)
            dst_cell = ws.cell(row=row, column=col + n)
            dst_cell.value = src_cell.value
            dst_cell.font = copy_style(src_cell.font)
            dst_cell.fill = copy_style(src_cell.fill)
            dst_cell.border = copy_style(src_cell.border)
            dst_cell.alignment = copy_style(src_cell.alignment)
            src_cell.value = None

    for col in range(max_col, insert_after_col, -1):
        old_letter = get_column_letter(col)
        new_letter = get_column_letter(col + n)
        if old_letter in ws.column_dimensions:
            ws.column_dimensions[new_letter].width = ws.column_dimensions[old_letter].width

    header_style_ref = ws.cell(row=1, column=insert_after_col)
    for i, htext in enumerate(headers):
        c = ws.cell(row=1, column=insert_after_col + 1 + i, value=htext)
        c.font = copy_style(header_style_ref.font)
        c.fill = copy_style(header_style_ref.fill)
        c.border = copy_style(header_style_ref.border)
        c.alignment = copy_style(header_style_ref.alignment)
        ws.column_dimensions[get_column_letter(insert_after_col + 1 + i)].width = max(18, len(htext) + 4)


def export_to_excel(output_dir: str, rules: List[SecurityRule],
                     match_results: Dict[str, List[Tuple[int, str]]],
                     resolver: GroupResolver,
                     service_objects: Dict[str, ServiceObject],
                     service_groups: Dict[str, ServiceGroup],
                     log_entries: Optional[List[LogEntry]] = None,
                     log_func=None, _wb_only: bool = False):
    """Luon dung template CO DINH nhung san trong script (khong con nhan
    template_path tu nguoi dung nua - da bo yeu cau chon file moi lan chay).
    Bản Panorama: chen cot "Vi tri Rule" ngay sau cot Name Rule. Neu
    log_entries duoc cung cap (tu file Log doi chieu), chen them 3 cot
    Log Source IP/Log Dest IP/Log Port ngay sau cot Vi tri Rule."""
    log_func = log_func or (lambda msg: None)
    os.makedirs(output_dir, exist_ok=True)

    wb = openpyxl.load_workbook(_get_template_bytes())
    ws = wb.worksheets[0]

    # Xac dinh cot "Name Rule" tu template (truoc khi chen) de biet chen "Vi tri
    # Rule" vao dau; sau do chen toan bo cot moi ROI moi nhan dien lai vi tri cac
    # cot (vi them cot lam dich chuyen vi tri ban dau).
    col_name_rule_base = 1
    for col in range(1, ws.max_column + 1):
        v = ws.cell(row=1, column=col).value
        if v and str(v).strip().lower() == "name rule":
            col_name_rule_base = col
            break

    _insert_columns_after(ws, ["Vi tri Rule"], col_name_rule_base)
    if log_entries:
        _insert_columns_after(ws, LOG_EXTRA_HEADERS, col_name_rule_base + 1)

    # Nhan dien cot theo TEXT header (khong phu thuoc thu tu A/B/C/D cung),
    # fallback ve vi tri mac dinh neu template thay doi header.
    header_map: Dict[str, int] = {}
    max_existing_col = 0
    for col in range(1, ws.max_column + 1):
        v = ws.cell(row=1, column=col).value
        if v:
            header_map[str(v).strip().lower()] = col
            max_existing_col = max(max_existing_col, col)
    if max_existing_col == 0:
        max_existing_col = 4

    col_name_rule = header_map.get("name rule", 1)
    col_source_ip = header_map.get("source ip", col_name_rule + 1)
    col_dest_ip = header_map.get("dest ip", col_name_rule + 2)
    col_service = header_map.get("service", col_name_rule + 3)
    col_vi_tri = header_map.get("vi tri rule")
    col_log_src = header_map.get("log source ip")
    col_log_dst = header_map.get("log dest ip")
    col_log_port = header_map.get("log port")

    header_style_ref = ws.cell(row=1, column=col_name_rule)
    extra_col_start = max_existing_col + 1
    disabled_extra_idx = EXTRA_HEADERS.index("Disabled")
    disabled_col = extra_col_start + disabled_extra_idx

    for i, htext in enumerate(EXTRA_HEADERS):
        c = ws.cell(row=1, column=extra_col_start + i, value=htext)
        c.font = copy_style(header_style_ref.font)
        c.fill = copy_style(header_style_ref.fill)
        c.border = copy_style(header_style_ref.border)
        c.alignment = copy_style(header_style_ref.alignment)
        ws.column_dimensions[get_column_letter(extra_col_start + i)].width = max(16, len(htext) + 4)

    # Style cua dong du lieu, lay tu dong 2 (dong du lieu dau tien da duoc
    # dinh dang san trong template) de ap dung nhat quan cho dong/cot moi.
    # Dung copy_style() vi cell.font/.fill/... doc tu workbook da load la
    # StyleProxy (khong hashable/khong gan lai truc tiep duoc cho cell khac).
    data_style_ref = ws.cell(row=2, column=col_name_rule)
    base_font = copy_style(data_style_ref.font)
    base_fill = copy_style(data_style_ref.fill)
    base_border = copy_style(data_style_ref.border)
    base_align = copy_style(data_style_ref.alignment)
    template_row_height = ws.row_dimensions[2].height or 15.75
    disabled_font = Font(name=base_font.name, size=base_font.size, bold=True, color="FFFF0000")

    # Font dung cho rich text trong Source IP / Dest IP / Service: ten object/group
    # IN DAM, value (IP/range/port that) TO MAU DO - cung font/size voi template.
    name_inline_font = InlineFont(rFont=base_font.name, sz=base_font.size, b=True)
    value_inline_font = InlineFont(rFont=base_font.name, sz=base_font.size, color="FFFF0000")
    # Value TRUNG voi input IP dang tim -> to XANH LA de phan biet voi cac
    # value khac (chi mang tinh thong tin) dang to DO.
    matched_value_inline_font = InlineFont(rFont=base_font.name, sz=base_font.size, b=True, color="FF008000")
    # Theo yeu cau: TOAN BO gia tri cac cot mac dinh can le TRAI (khong phu
    # thuoc alignment goc cua template) - rieng Source IP/Dest IP/Service can
    # them bat wrap_text de cac dong xuong dong (\n) hien thi dung.
    data_align = Alignment(horizontal="left", vertical=base_align.vertical)
    wrap_align = Alignment(horizontal="left", vertical=base_align.vertical, wrap_text=True)
    service_cache: Dict[str, List[Tuple[str, str]]] = {}

    # Gom ket qua theo TUNG RULE (1 rule chi xuat 1 dong du lieu, liet ke day
    # du cac IP da tim thay match vao rule do - tranh lap lai rule nhieu lan
    # khi nguoi dung tim nhieu IP cung luc, giu ket qua gon gang, de doc).
    rule_matches: Dict[int, Dict[str, set]] = {}
    for ip_str, matches in match_results.items():
        for rule_idx, side in matches:
            d = rule_matches.setdefault(rule_idx, {"ips": set(), "sides": set()})
            d["ips"].add(ip_str)
            d["sides"].add(side)

    # Doi chieu File Log: MO PHONG "Test Policy Match" that cua PAN-OS.
    # - Chi xet rule action=allow, di DUNG THU TU rulebase, dung o rule DAU
    #   TIEN khop (khong liet ke tat ca rule co the khop).
    # - Nhieu dong Log cung khop chung 1 rule se duoc GOM CHUNG vao dung 1
    #   hang cua rule do (setdefault + append).
    # - Quet TOAN BO rulebase (khong gioi han trong cac rule da tim qua Input
    #   IP muc 2), vi cau hoi o day la "rule ALLOW nao THUC SU dang xu ly
    #   dung luong traffic that nay" - co the la 1 rule khac hoan toan.
    rule_log_matches: Dict[int, List[LogEntry]] = {}
    if log_entries:
        range_cache: Dict[str, List[Tuple[int, int]]] = {}
        ordered_allow_rules = [r for r in rules if r.action == "allow"]
        unmatched = 0
        for le in log_entries:
            matched_rule = find_first_allow_rule_match(
                le, ordered_allow_rules, resolver, service_objects, service_groups, range_cache)
            if matched_rule is not None:
                rule_log_matches.setdefault(matched_rule.index, []).append(le)
                rule_matches.setdefault(matched_rule.index, {"ips": set(), "sides": set()})
            else:
                unmatched += 1
        log_func(f"Doi chieu File Log OK ({len(rule_log_matches)} rule ALLOW thuc su dang xu ly traffic, "
                 f"{len(log_entries) - unmatched}/{len(log_entries)} dong log tim thay rule tuong ung)")
        if unmatched:
            log_func(f"CANH BAO: {unmatched} dong Log khong tim thay rule ALLOW nao khop "
                     f"(luu y: khong co du lieu Zone/Application tu file Log nen chua the kiem tra 2 tieu chi nay)")

    matched_rule_indexes = sorted(rule_matches.keys(), key=lambda i: rules[i].name.lower())
    total_cols = extra_col_start + len(EXTRA_HEADERS) - 1

    row_num = 2
    for rule_idx in matched_rule_indexes:
        rule = rules[rule_idx]
        info = rule_matches[rule_idx]
        if info["sides"]:
            side_label = ", ".join(sorted("Source" if s == "source" else "Destination" for s in info["sides"]))
        elif rule_idx in rule_log_matches:
            side_label = "(qua File Log)"  # rule nay chi duoc tim thay qua doi chieu Log, khong qua Input IP muc 2
        else:
            side_label = ""

        source_runs = _build_address_runs(rule.source, resolver, info["ips"])
        dest_runs = _build_address_runs(rule.destination, resolver, info["ips"])
        service_runs = _build_service_runs(rule.service, service_objects, service_groups, service_cache)
        source_rich = _runs_to_rich_text(source_runs, name_inline_font, value_inline_font, matched_value_inline_font)
        dest_rich = _runs_to_rich_text(dest_runs, name_inline_font, value_inline_font, matched_value_inline_font)
        service_rich = _runs_to_rich_text(service_runs, name_inline_font, value_inline_font)

        # Traffic that (tu File Log) da xac dinh o rule_log_matches phia tren.
        matching_logs = rule_log_matches.get(rule_idx, [])
        log_src_lines = [le.source_ip for le in matching_logs]
        log_dst_lines = [le.dest_ip for le in matching_logs]
        log_port_lines = [le.port for le in matching_logs]

        row_values: Dict[int, str] = {
            col_name_rule: rule.name,
        }
        if col_vi_tri:
            row_values[col_vi_tri] = rule.vi_tri
        if col_log_src and log_src_lines:
            row_values[col_log_src] = "\n".join(log_src_lines)
        if col_log_dst and log_dst_lines:
            row_values[col_log_dst] = "\n".join(log_dst_lines)
        if col_log_port and log_port_lines:
            row_values[col_log_port] = "\n".join(log_port_lines)
        extras = [
            side_label, rule.uuid,
            ", ".join(rule.from_zones), ", ".join(rule.to_zones),
            ", ".join(rule.application), rule.action, rule.security_profile,
            rule.log_setting, rule.schedule, rule.description,
            ", ".join(rule.tags), "Yes" if rule.disabled else "No",
            rule.target, rule.hip, ", ".join(rule.source_user),
        ]
        for i, val in enumerate(extras):
            row_values[extra_col_start + i] = val

        is_new_row = row_num > 4  # template chi dinh dang san 3 dong du lieu (2,3,4)
        for col in range(1, total_cols + 1):
            cell = ws.cell(row=row_num, column=col)
            if col == col_source_ip:
                cell.value = source_rich
            elif col == col_dest_ip:
                cell.value = dest_rich
            elif col == col_service:
                cell.value = service_rich
            else:
                cell.value = row_values.get(col, "")
            if is_new_row or col > max_existing_col or col in (col_log_src, col_log_dst, col_log_port):
                cell.font = base_font
                cell.fill = base_fill
                cell.border = base_border
            cell.alignment = wrap_align if col in (col_source_ip, col_dest_ip, col_service,
                                                     col_log_src, col_log_dst, col_log_port) else data_align

        # Chieu cao dong = so dong thuc te nhieu nhat giua Source IP/Dest IP/
        # Service/Log (tinh theo so ky tu xuong dong "\n"), de group nhieu
        # member hoac nhieu dong log van hien thi day du, khong bi cat.
        max_lines = max(
            1,
            _runs_plain_text(source_runs).count("\n") + 1,
            _runs_plain_text(dest_runs).count("\n") + 1,
            _runs_plain_text(service_runs).count("\n") + 1,
            len(log_src_lines),
        )
        ws.row_dimensions[row_num].height = template_row_height * max_lines

        if rule.disabled:
            ws.cell(row=row_num, column=disabled_col).font = disabled_font

        row_num += 1

    # `_wb_only=True` (noi bo, dung boi export_combined_to_excel): tra ve chinh
    # Workbook da dien xong thay vi save ra dia - de con them sheet NAT vao CUNG
    # 1 file. Noi dung/template/dinh dang sheet GIU NGUYEN 100%.
    if _wb_only:
        log_func(f"Sheet Rule da san sang ({len(matched_rule_indexes)} rule)")
        return wb

    filename = f"rule_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    output_path = os.path.join(output_dir, filename)
    wb.save(output_path)
    log_func(f"Export OK -> {filename} ({len(matched_rule_indexes)} rule)")
    return output_path


# ============================================================================
# XUAT BANG NAT (tinh nang thu 4 GUI): file rieng (khong dung template Rule
# Search vi cau truc cot khac hoan toan). Ho tro CA 2 dinh dang theo lua chon
# cua nguoi dung (xlsx/csv) VA 2 CHE DO theo lua chon Yes/No cua nguoi dung:
#   - FULL (Yes): liet ke TOAN BO NAT Rule cua VSYS da chon, khong loc gi ca;
#     co the tuy chon nhap IP de highlight (khong bat buoc).
#   - SEARCH (No): BAT BUOC nhap IP can tim - CHI xuat nhung NAT rule co
#     Source/Destination/Source Translated/Destination Translated Address
#     thuc su khop voi IP nhap, CHI hien member khop (khong xuat full member
#     cua Group), gia tri khop duoc TO XANH LA DAM (giong nguyen tac Search
#     Rule muc 2).
#   - xlsx: rich text (ten Group/Object IN DAM, value that TO MAU DO), dung
#     nguyen tac hien thi giong het Security Rule (Source/Dest Address +
#     Source/Destination Translated Address deu la Group/Object thi GIU TEN
#     Group va BREAK chi tiet cac member/value that ben trong).
#   - csv: plain text (CSV khong ho tro rich text), nhung VAN giu nguyen cau
#     truc "TenGroup (member1 (value1), member2 (value2))" nhu tren, chi
#     khac la khong co mau/dinh dang.
# ============================================================================

_SRC_XLATE_TYPE_LABEL = {
    "dynamic-ip-and-port": "Dynamic IP And Port",
    "dynamic-ip": "Dynamic IP",
    "static-ip": "Static IP",
    "": "(No Source NAT)",
}
_DST_XLATE_TYPE_LABEL = {
    "static": "Static",
    "dynamic": "Dynamic (Distribution)",
    "": "(No Destination NAT)",
}


def _nat_src_xlate_runs(rule: NatRule, resolver: GroupResolver,
                         highlight_ips: Set[str] = frozenset(),
                         filter_to_matched: bool = False) -> List[Tuple[str, str]]:
    """Runs (rich-text tokens) the hien dia chi da Source Translation - break
    Group/Object ra value that, giong het cach lam voi Source/Dest Address.
    Mac dinh hien FULL member (filter_to_matched=False, che do Full - "xuat
    toan bo") - o che do Search (No o muc 4 GUI), filter_to_matched=True se
    CHI hien member khop voi IP dang tim; neu co truyen highlight_ips (IP
    nguoi dung nhap tay o muc 4 GUI) thi value trung se to XANH LA."""
    if rule.src_xlate_type == "dynamic-ip-and-port" and rule.src_xlate_interface:
        # Kieu "interface-address": lay IP dong truc tiep tu interface (khong
        # phai 1 Address Object/Group co dinh) - hien ten interface, kem IP
        # gan (neu co cau hinh, co the la 1 Address Object nen van thu resolve).
        runs: List[Tuple[str, str]] = [("name", f"Interface: {rule.src_xlate_interface}")]
        if rule.src_xlate_interface_ip:
            runs.append(("text", " ("))
            runs.extend(_expand_entry_runs(rule.src_xlate_interface_ip, resolver, highlight_ips,
                                            filter_to_matched=filter_to_matched))
            runs.append(("text", ")"))
        return runs
    if rule.src_xlate_addresses:
        return _build_address_runs(rule.src_xlate_addresses, resolver, highlight_ips,
                                    filter_to_matched=filter_to_matched)
    return [("text", "")]


def _nat_dst_xlate_runs(rule: NatRule, resolver: GroupResolver,
                         highlight_ips: Set[str] = frozenset(),
                         filter_to_matched: bool = False) -> List[Tuple[str, str]]:
    """Runs the hien dia chi da Destination Translation (translated-address
    thuong la 1 Address Object hoac 1 IP literal - van thu resolve/break ra
    value that neu la Object/Group). Xem docstring o tren (Full vs Search)."""
    if not rule.dst_xlate_address:
        return [("text", "")]
    return _build_address_runs([rule.dst_xlate_address], resolver, highlight_ips,
                                filter_to_matched=filter_to_matched)


# ============================================================================
# CHE DO SEARCH (muc 4 GUI, chon "No"): loc NAT Rule nao co Source/Destination
# Address hoac Source/Destination Translated Address chua it nhat 1 trong cac
# IP nguoi dung nhap tay (exact host, hoac nam trong 1 range/CIDR resolve
# duoc) - KHAC voi che do Full (Yes), o day chi xuat NHUNG rule THUC SU khop,
# khong xuat toan bo bang NAT.
# ============================================================================

def _entry_matched_ips(entry: str, resolver: GroupResolver, target_ips: Set[str]) -> Set[str]:
    """Tra ve tap con cua target_ips thuc su khop voi 1 entry (Address Object/
    Group/IP literal), sau khi resolve ra value that (exact IP hoac range)."""
    if not entry or entry == "any":
        return set()
    rv = resolver.resolve(entry)
    matched: Set[str] = set(rv.exact_ips) & target_ips
    if rv.ranges:
        for ip in target_ips:
            try:
                ip_int = int(ipaddress.ip_address(ip))
            except ValueError:
                continue
            for start, end in rv.ranges:
                if start <= ip_int <= end:
                    matched.add(ip)
                    break
    return matched


def _nat_rule_matched_ips(rule: NatRule, resolver: GroupResolver, target_ips: Set[str]) -> Set[str]:
    """Tra ve tap hop cac IP (trong target_ips) thuc su khop voi 1 NAT rule -
    kiem tra CA 4 truong: Source Address, Destination Address, Source
    Translated Address, Destination Translated Address (dung cho che do
    Search khi chon 'No' o muc 4 GUI)."""
    matched: Set[str] = set()
    for entry in rule.source:
        matched |= _entry_matched_ips(entry, resolver, target_ips)
    for entry in rule.destination:
        matched |= _entry_matched_ips(entry, resolver, target_ips)
    src_entries = list(rule.src_xlate_addresses)
    if rule.src_xlate_interface_ip:
        src_entries.append(rule.src_xlate_interface_ip)
    for entry in src_entries:
        matched |= _entry_matched_ips(entry, resolver, target_ips)
    if rule.dst_xlate_address:
        matched |= _entry_matched_ips(rule.dst_xlate_address, resolver, target_ips)
    return matched


_NAT_WRAP_HEADERS = {"Source Address", "Destination Address", "Service",
                     "Source Translated Address", "Destination Translated Address"}


def export_nat_to_excel(output_dir: str, nat_rules: List[NatRule], resolver: GroupResolver,
                         service_objects: Dict[str, ServiceObject],
                         service_groups: Dict[str, ServiceGroup],
                         highlight_ips: Optional[Set[str]] = None,
                         filter_ips: Optional[Set[str]] = None,
                         log_func=None, _into_wb=None, _wb_only: bool = False):
    """Xuat NAT Rule ra 1 file .xlsx rieng (workbook moi, khong dung
    template Security Rule). 2 CHE DO (muc 4 GUI):
      - FULL (chon 'Yes'): filter_ips rong/None -> xuat TOAN BO NAT Rule; neu
        co `highlight_ips` (tuy chon), gia tri Source/Destination/Translated
        Address nao trung se duoc TO XANH LA DAM de phan biet, nhung KHONG
        loc bot rule/member nao ca.
      - SEARCH (chon 'No'): `filter_ips` co gia tri -> CHI xuat NHUNG NAT
        rule co Source/Destination/Source Translated/Destination Translated
        Address thuc su khop voi 1 trong cac IP nay (giong nguyen tac Search
        Rule muc 2), CHI hien member khop trong tung Group (khong xuat full
        member), va value khop duoc TO XANH LA DAM."""
    log_func = log_func or (lambda msg: None)
    highlight_ips = highlight_ips or set()
    filter_ips = filter_ips or set()
    search_mode = bool(filter_ips)
    effective_highlight = filter_ips if search_mode else highlight_ips
    os.makedirs(output_dir, exist_ok=True)

    rules_to_export = nat_rules
    if search_mode:
        rules_to_export = [r for r in nat_rules if _nat_rule_matched_ips(r, resolver, filter_ips)]
        log_func(f"[NAT Search] Loc theo {len(filter_ips)} IP nhap tay: "
                 f"{len(rules_to_export)}/{len(nat_rules)} rule khop")
        if not rules_to_export:
            log_func("[NAT Search] Khong tim thay NAT rule nao khop voi cac IP da nhap")

    # `_into_wb` (noi bo): thay vi tao workbook moi, ghi NAT vao 1 SHEET moi cua
    # workbook da cho (sheet Rule nam cung file). Toan bo header/dinh dang/mau/
    # rich-text/logic loc GIU NGUYEN 100%.
    if _into_wb is not None:
        wb = _into_wb
        ws = wb.create_sheet(NAT_SHEET_TITLE)
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = NAT_SHEET_TITLE

    header_font = Font(bold=True, color="FFFFFFFF")
    header_fill_hex = "FF305496"
    from openpyxl.styles import PatternFill
    header_fill = PatternFill(fill_type="solid", fgColor=header_fill_hex)
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    data_align = Alignment(horizontal="left", vertical="top")
    wrap_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
    disabled_font = Font(bold=True, color="FFFF0000")

    name_inline_font = InlineFont(rFont="Calibri", sz=11, b=True)
    value_inline_font = InlineFont(rFont="Calibri", sz=11, color="FFFF0000")
    matched_value_inline_font = InlineFont(rFont="Calibri", sz=11, b=True, color="FF008000")

    for col, htext in enumerate(NAT_HEADERS, start=1):
        c = ws.cell(row=1, column=col, value=htext)
        c.font = header_font
        c.fill = header_fill
        c.alignment = header_align
        ws.column_dimensions[get_column_letter(col)].width = 22 if htext in _NAT_WRAP_HEADERS else 16
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = f"A1:{get_column_letter(len(NAT_HEADERS))}1"

    service_cache: Dict[str, List[Tuple[str, str]]] = {}

    row_num = 2
    for rule in rules_to_export:
        source_runs = _build_address_runs(rule.source, resolver, effective_highlight, filter_to_matched=search_mode)
        dest_runs = _build_address_runs(rule.destination, resolver, effective_highlight, filter_to_matched=search_mode)
        service_runs = _build_service_runs([rule.service], service_objects, service_groups, service_cache)
        src_xlate_runs = _nat_src_xlate_runs(rule, resolver, effective_highlight, filter_to_matched=search_mode)
        dst_xlate_runs = _nat_dst_xlate_runs(rule, resolver, effective_highlight, filter_to_matched=search_mode)

        source_rich = _runs_to_rich_text(source_runs, name_inline_font, value_inline_font, matched_value_inline_font)
        dest_rich = _runs_to_rich_text(dest_runs, name_inline_font, value_inline_font, matched_value_inline_font)
        service_rich = _runs_to_rich_text(service_runs, name_inline_font, value_inline_font)
        src_xlate_rich = _runs_to_rich_text(src_xlate_runs, name_inline_font, value_inline_font, matched_value_inline_font)
        dst_xlate_rich = _runs_to_rich_text(dst_xlate_runs, name_inline_font, value_inline_font, matched_value_inline_font)

        values = [
            rule.name, rule.vi_tri, rule.uuid, "Yes" if rule.disabled else "No",
            ", ".join(rule.tags), rule.description,
            ", ".join(rule.from_zones), ", ".join(rule.to_zones), rule.to_interface,
            source_rich, dest_rich, service_rich, rule.nat_type,
            _SRC_XLATE_TYPE_LABEL.get(rule.src_xlate_type, rule.src_xlate_type),
            src_xlate_rich,
            "Yes" if rule.src_xlate_bidirectional else "No",
            _DST_XLATE_TYPE_LABEL.get(rule.dst_xlate_type, rule.dst_xlate_type),
            dst_xlate_rich, rule.dst_xlate_port,
        ]
        for col, val in enumerate(values, start=1):
            cell = ws.cell(row=row_num, column=col, value=val)
            htext = NAT_HEADERS[col - 1]
            cell.alignment = wrap_align if htext in _NAT_WRAP_HEADERS else data_align
            if htext == "Disabled" and rule.disabled:
                cell.font = disabled_font

        max_lines = max(
            1,
            _runs_plain_text(source_runs).count("\n") + 1,
            _runs_plain_text(dest_runs).count("\n") + 1,
            _runs_plain_text(service_runs).count("\n") + 1,
            _runs_plain_text(src_xlate_runs).count("\n") + 1,
            _runs_plain_text(dst_xlate_runs).count("\n") + 1,
        )
        ws.row_dimensions[row_num].height = 15.75 * max_lines
        row_num += 1

    if _wb_only:
        if search_mode:
            log_func(f"Sheet NAT (Search) da san sang ({len(rules_to_export)}/{len(nat_rules)} rule khop "
                     f"voi {len(filter_ips)} IP nhap tay)")
        else:
            log_func(f"Sheet NAT (Full) da san sang ({len(rules_to_export)} rule)"
                     + (f" - highlight {len(highlight_ips)} IP nhap tay" if highlight_ips else ""))
        return wb

    prefix = "nat_search" if search_mode else "nat"
    filename = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    output_path = os.path.join(output_dir, filename)
    wb.save(output_path)
    if search_mode:
        log_func(f"Export NAT (Search) OK -> {filename} ({len(rules_to_export)}/{len(nat_rules)} rule khop "
                 f"voi {len(filter_ips)} IP nhap tay)")
    else:
        log_func(f"Export NAT (Full) OK -> {filename} ({len(rules_to_export)} rule)"
                 + (f" - highlight {len(highlight_ips)} IP nhap tay" if highlight_ips else ""))
    return output_path


# ============================================================================
# XUAT GOP 1 FILE 2 SHEET - 1 luot chay lam ca Rule lan NAT thi chi sinh 1 file
# ============================================================================

def export_combined_to_excel(output_dir: str,
                              rules: List[SecurityRule],
                              match_results: Dict[str, List[Tuple[int, str]]],
                              resolver: GroupResolver,
                              service_objects: Dict[str, ServiceObject],
                              service_groups: Dict[str, ServiceGroup],
                              nat_rules: Optional[List[NatRule]] = None,
                              nat_resolver: Optional[GroupResolver] = None,
                              nat_service_objects: Optional[Dict[str, ServiceObject]] = None,
                              nat_service_groups: Optional[Dict[str, ServiceGroup]] = None,
                              log_entries: Optional[List[LogEntry]] = None,
                              highlight_ips: Optional[Set[str]] = None,
                              filter_ips: Optional[Set[str]] = None,
                              where_reports=None,
                              log_func=None) -> str:
    """Khi 1 luot chay lam CA Check Rule LAN Export NAT -> gop vao DUNG 1 file
    .xlsx co 2 sheet thay vi sinh 2 file roi rac:
      - Sheet "Security Rules": y het file rule_*.xlsx (template nhung san, cot
        "Vi tri Rule" cua ban Panorama, 3 cot Log doi chieu neu co).
      - Sheet "NAT Rules": y het file nat_*.xlsx (header/mau/rich-text/che do
        Full-Search/highlight giu nguyen 100%).

    Khong viet lai logic export nao: tai su dung chinh export_to_excel() va
    export_nat_to_excel() o che do `_wb_only`/`_into_wb`. Dung 2 `resolver` RIENG
    cho 2 phan, dung nhu khi xuat 2 file roi."""
    log_func = log_func or (lambda msg: None)
    os.makedirs(output_dir, exist_ok=True)

    wb = export_to_excel(output_dir, rules, match_results, resolver,
                          service_objects, service_groups,
                          log_entries=log_entries, log_func=log_func, _wb_only=True)
    wb.worksheets[0].title = RULE_SHEET_TITLE
    sheet_names = [RULE_SHEET_TITLE]

    if nat_rules is not None:
        export_nat_to_excel(output_dir, nat_rules, nat_resolver,
                             nat_service_objects or {}, nat_service_groups or {},
                             highlight_ips=highlight_ips, filter_ips=filter_ips,
                             log_func=log_func, _into_wb=wb, _wb_only=True)
        sheet_names.append(NAT_SHEET_TITLE)

    if where_reports:
        export_where_used_to_excel(output_dir, where_reports,
                                    log_func=log_func, _into_wb=wb, _wb_only=True)
        sheet_names.append(WHERE_SHEET_TITLE)

    # Ten file noi dung no chua gi - nguoi dung mo thu muc output sau 1 ngay
    # khong con nho luot nao chay cai gi.
    parts = ["rule"]
    if nat_rules is not None:
        parts.append("nat")
    if where_reports:
        parts.append("object")
    prefix = "_".join(parts) + ("_search" if filter_ips else "")
    filename = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    output_path = os.path.join(output_dir, filename)
    wb.save(output_path)
    log_func(f"Export OK -> {filename} ({len(sheet_names)} sheet: "
             + " + ".join(sheet_names) + ")")
    return output_path


def export_nat_to_csv(output_dir: str, nat_rules: List[NatRule], resolver: GroupResolver,
                       service_objects: Dict[str, ServiceObject],
                       service_groups: Dict[str, ServiceGroup],
                       highlight_ips: Optional[Set[str]] = None,
                       filter_ips: Optional[Set[str]] = None,
                       log_func=None) -> str:
    """Xuat NAT Rule cua VSYS ra 1 file .csv (plain text, UTF-8 BOM de Excel
    mo tieng Viet khong bi loi font). 2 CHE DO giong het export_nat_to_excel
    (xem docstring o do): FULL (`filter_ips` rong/None, xuat toan bo, giu
    nguyen cau truc breakdown Group/Object) hoac SEARCH (`filter_ips` co gia
    tri, CHI xuat rule khop + CHI hien member khop) - gia tri khop duoc boc
    `*...*` (xem `_runs_plain_text_marked`) vi CSV khong co mau/dinh dang."""
    log_func = log_func or (lambda msg: None)
    highlight_ips = highlight_ips or set()
    filter_ips = filter_ips or set()
    search_mode = bool(filter_ips)
    effective_highlight = filter_ips if search_mode else highlight_ips
    os.makedirs(output_dir, exist_ok=True)

    rules_to_export = nat_rules
    if search_mode:
        rules_to_export = [r for r in nat_rules if _nat_rule_matched_ips(r, resolver, filter_ips)]
        log_func(f"[NAT Search] Loc theo {len(filter_ips)} IP nhap tay: "
                 f"{len(rules_to_export)}/{len(nat_rules)} rule khop")
        if not rules_to_export:
            log_func("[NAT Search] Khong tim thay NAT rule nao khop voi cac IP da nhap")

    prefix = "nat_search" if search_mode else "nat"
    filename = f"{prefix}_{datetime.now():%Y%m%d_%H%M%S}.csv"
    output_path = os.path.join(output_dir, filename)

    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(NAT_HEADERS)
        for rule in rules_to_export:
            source_plain = _build_address_plain(rule.source, resolver, effective_highlight, filter_to_matched=search_mode)
            dest_plain = _build_address_plain(rule.destination, resolver, effective_highlight, filter_to_matched=search_mode)
            service_plain = _build_service_plain([rule.service], service_objects, service_groups)
            src_xlate_runs = _nat_src_xlate_runs(rule, resolver, effective_highlight, filter_to_matched=search_mode)
            dst_xlate_runs = _nat_dst_xlate_runs(rule, resolver, effective_highlight, filter_to_matched=search_mode)
            src_xlate_plain = _runs_plain_text_marked(src_xlate_runs) if effective_highlight else _runs_plain_text(src_xlate_runs)
            dst_xlate_plain = _runs_plain_text_marked(dst_xlate_runs) if effective_highlight else _runs_plain_text(dst_xlate_runs)

            writer.writerow([
                rule.name, rule.vi_tri, rule.uuid, "Yes" if rule.disabled else "No",
                ", ".join(rule.tags), rule.description,
                ", ".join(rule.from_zones), ", ".join(rule.to_zones), rule.to_interface,
                source_plain, dest_plain, service_plain, rule.nat_type,
                _SRC_XLATE_TYPE_LABEL.get(rule.src_xlate_type, rule.src_xlate_type),
                src_xlate_plain,
                "Yes" if rule.src_xlate_bidirectional else "No",
                _DST_XLATE_TYPE_LABEL.get(rule.dst_xlate_type, rule.dst_xlate_type),
                dst_xlate_plain, rule.dst_xlate_port,
            ])

    if search_mode:
        log_func(f"Export NAT (Search) OK -> {filename} ({len(rules_to_export)}/{len(nat_rules)} rule khop "
                 f"voi {len(filter_ips)} IP nhap tay, boc *...*)")
    else:
        log_func(f"Export NAT (Full) OK -> {filename} ({len(rules_to_export)} rule)"
                 + (f" - highlight {len(highlight_ips)} IP nhap tay (boc *...*)" if highlight_ips else ""))
    return output_path


# ============================================================================
# CHECK OBJECT (muc 5) - sheet "Object Where Used"
# ============================================================================
WHERE_SHEET_TITLE = "Object Where Used"
# RIENG BAN PANORAMA: co them cot "Vi tri Panorama" (Shared-PRE / <DG>-PRE /
# <DG>-POST / Shared-POST). Thu tu 4 vi tri nay quyet dinh rule nao an rule
# nao, nen thieu no la thieu dung thu nguoi doc can de biet phai sua o dau.
WHERE_HEADERS = [
    "Da tra", "Nhom ket qua", "Ten", "Loai", "Gia tri / Duong dan",
    "Vi tri Panorama", "Thu tu / Cap", "Action", "O khop",
    "Qua (vi sao dinh)", "Ghi chu",
]
# Mau nen tach 3 NHOM ket qua. 3 nhom nay co do tin cay khac han nhau, de
# chung mot mau thi nguoi doc phai doc tung dong moi biet dong nao la dong
# nao - dung thu de sai nhat khi copy sang ticket.
_WHERE_GROUP_FILL = {
    "OBJECT": "FFDCE6F1",
    "GROUP": "FFE2EFDA",
    "RULE (tham chieu)": "FFFFF2CC",
    "RULE (theo gia tri)": "FFFCE4D6",
    "RULE (chi vi 'any')": "FFF2F2F2",
    "NAT RULE": "FFE4DFEC",
    "GHI CHU": "FFFFFFFF",
}


def _where_rows(report) -> List[List[str]]:
    """Doi 1 UsageReport thanh cac dong phang de ghi ra Excel/CSV.

    Giu NGUYEN 3 nhom rule rieng bang cot "Nhom ket qua" - do la thong tin
    chinh cua tinh nang nay, khong duoc lam phang mat.
    """
    q = report.query
    rows: List[List[str]] = []
    for hit in report.objects:
        rows.append([q, "OBJECT", hit.name, hit.kind, hit.value, "", "", "", "",
                     hit.kind_text, hit.note])
    for hit in report.groups:
        rows.append([q, "GROUP", hit.name, f"address-group ({hit.group_kind})",
                     hit.path_text, "", f"cap {hit.depth}", "", "", "", hit.note])
    for label, bucket in (("RULE (tham chieu)", report.rules_by_reference),
                          ("RULE (theo gia tri)", report.rules_by_value),
                          ("RULE (chi vi 'any')", report.rules_by_any)):
        for hit in bucket:
            rows.append([q, label, hit.rule_name, "security-rule", "",
                         hit.vi_tri, f"#{hit.rule_index}", hit.action,
                         hit.side_text, hit.via,
                         "DISABLED" if hit.disabled else ""])
    for hit in report.nat_hits:
        rows.append([q, "NAT RULE", hit.rule_name, "nat-rule", "",
                     hit.vi_tri, f"#{hit.rule_index}", "", hit.side_text,
                     hit.via, "DISABLED" if hit.disabled else ""])
    for note in report.notes:
        rows.append([q, "GHI CHU", "", "", "", "", "", "", "", "", note])
    if not rows:
        rows.append([q, "GHI CHU", "", "", "", "", "", "", "", "",
                     "Khong tim thay gi lien quan."])
    return rows


def export_where_used_to_excel(output_dir: str, reports, log_func=None,
                                _into_wb=None, _wb_only: bool = False):
    """Xuat ket qua Check Object ra 1 file .xlsx (hoac 1 sheet cua file gop).

    `_into_wb` / `_wb_only`: giong het export_nat_to_excel - de luot chay lam
    nhieu phan cung luc van ra DUNG 1 file nhieu sheet."""
    log_func = log_func or (lambda msg: None)
    os.makedirs(output_dir, exist_ok=True)

    if _into_wb is not None:
        wb = _into_wb
        ws = wb.create_sheet(WHERE_SHEET_TITLE)
    else:
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = WHERE_SHEET_TITLE

    from openpyxl.styles import PatternFill

    header_font = Font(bold=True, color="FFFFFFFF")
    header_fill = PatternFill(fill_type="solid", fgColor="FF305496")
    header_align = Alignment(horizontal="center", vertical="center", wrap_text=True)
    data_align = Alignment(horizontal="left", vertical="top")
    wrap_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
    note_font = Font(italic=True, color="FF9C5700")
    disabled_font = Font(bold=True, color="FFFF0000")

    widths = [20, 20, 34, 22, 46, 16, 12, 12, 24, 40, 60]
    for col, htext in enumerate(WHERE_HEADERS, start=1):
        c = ws.cell(row=1, column=col, value=htext)
        c.font = header_font
        c.fill = header_fill
        c.alignment = header_align
        ws.column_dimensions[get_column_letter(col)].width = widths[col - 1]
    ws.freeze_panes = "A2"

    row_idx = 1
    total = 0
    for report in reports or []:
        for values in _where_rows(report):
            row_idx += 1
            total += 1
            fill_hex = _WHERE_GROUP_FILL.get(values[1])
            for col, val in enumerate(values, start=1):
                c = ws.cell(row=row_idx, column=col, value=val)
                c.alignment = wrap_align if col in (5, 10, 11) else data_align
                if fill_hex and fill_hex != "FFFFFFFF":
                    c.fill = PatternFill(fill_type="solid", fgColor=fill_hex)
                if values[1] == "GHI CHU":
                    c.font = note_font
                elif col == 11 and val == "DISABLED":
                    c.font = disabled_font

    if _wb_only:
        log_func(f"Sheet {WHERE_SHEET_TITLE} da san sang ({total} dong, "
                 f"{len(reports or [])} muc da tra)")
        return wb

    filename = f"object_where_used_{datetime.now():%Y%m%d_%H%M%S}.xlsx"
    output_path = os.path.join(output_dir, filename)
    wb.save(output_path)
    log_func(f"Export Check Object OK -> {filename} ({total} dong, "
             f"{len(reports or [])} muc da tra)")
    return output_path


def export_where_used_to_csv(output_dir: str, reports, log_func=None) -> str:
    """Ban CSV cua sheet tren - dung khi luot chay chon dinh dang csv o muc 4."""
    log_func = log_func or (lambda msg: None)
    os.makedirs(output_dir, exist_ok=True)
    filename = f"object_where_used_{datetime.now():%Y%m%d_%H%M%S}.csv"
    output_path = os.path.join(output_dir, filename)
    total = 0
    with open(output_path, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(WHERE_HEADERS)
        for report in reports or []:
            for values in _where_rows(report):
                writer.writerow(values)
                total += 1
    log_func(f"Export Check Object OK -> {filename} ({total} dong)")
    return output_path
