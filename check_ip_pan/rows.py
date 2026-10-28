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

import re as _re
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
        cells_runs = [
            _cell_runs(rule.name),
            _cell_runs(getattr(rule, "vi_tri", "")),
            _runs_one_line(_build_address_runs(
                rule.source, resolver, ips, filter_to_matched=True)),
            _runs_one_line(_build_address_runs(
                rule.destination, resolver, ips, filter_to_matched=True)),
            _cell_runs(_one_line(_build_service_plain(
                rule.service, service_objects, service_groups))),
            _cell_runs(" + ".join(sorted(hit["sides"]))),
            _cell_runs(", ".join(rule.from_zones)),
            _cell_runs(", ".join(rule.to_zones)),
            _cell_runs(", ".join(rule.application)),
            _cell_runs(("[DISABLED] " if rule.disabled else "") + rule.action),
        ]
        out.append({"kind": "rule", "disabled": bool(rule.disabled),
                    "runs": _pad_runs(cells_runs),
                    "cells": _pad(["".join(t for _, t in c).strip()
                                   for c in cells_runs])})
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
        cells_runs = [
            _cell_runs(rule.name),
            _cell_runs(getattr(rule, "vi_tri", "")),
            _runs_one_line(_build_address_runs(
                rule.source, resolver, ips, filter_to_matched=search_mode)),
            _runs_one_line(_build_address_runs(
                rule.destination, resolver, ips, filter_to_matched=search_mode)),
            _cell_runs(_one_line(_build_service_plain(
                [rule.service], service_objects, service_groups))),
            _cell_runs(rule.nat_type),
            _cell_runs(", ".join(rule.from_zones)),
            _cell_runs(", ".join(rule.to_zones)),
            [("text", _SRC_XLATE_TYPE_LABEL.get(rule.src_xlate_type,
                                                rule.src_xlate_type) + " ")]
            + _runs_one_line(_nat_src_xlate_runs(
                rule, resolver, ips, filter_to_matched=search_mode)),
            _runs_one_line(_nat_dst_xlate_runs(
                rule, resolver, ips, filter_to_matched=search_mode)),
        ]
        out.append({"kind": "nat", "disabled": bool(rule.disabled),
                    "runs": _pad_runs(cells_runs),
                    "cells": _pad(["".join(t for _, t in c).strip()
                                   for c in cells_runs])})
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

# ===========================================================================
# DUNG BANG CHU CO TO MAU CHO GIAO DIEN
# ===========================================================================
# VI SAO KHONG CON DUNG ttk.Treeview
# ----------------------------------
# Treeview chi to mau duoc CA MOT DONG (theo tag), khong to duoc mot DOAN CHU
# ben trong mot o. Nhung chinh cai doan chu do moi la thong tin: trong o
# Source/Dest cua mot rule, "10.3.16.11" la IP dang tra (xanh la) con nhung
# member khac cua group la phan chi de doc (do). Mat mau la nguoi doc lai phai
# tu do mat so tung dong - dung cai viec ma file Excel xuat ra da lam duoc tu
# lau (xem `_runs_to_rich_text`).
#
# Nen bang tren giao dien duoc dung bang mot widget Text: moi o duoc ngat dong
# trong DUNG be ngang cua cot no, va tung doan chu duoc dan tag rieng.
#
# Toan bo phan tinh toan nam o day - ham THUAN, khong `import tkinter` - de
# test duoc tren trinh thong dich khong co Tk. gui.py chi con viec doc
# `segments` roi `insert`.

#: Be ngang (so ky tu) cua 10 cot - ban Panorama co them cot 'Vi tri'. Font trong bang la font DEU, nen so ky tu
#: la do do that su.
COL_WIDTHS = (26, 16, 46, 46, 22, 13, 14, 14, 18, 12)
#: Ngan cach giua 2 cot: mot duong ke doc THAT, khong phai hai dau cach.
#:
#: Hai dau cach thi mat phai tu doan ranh gioi cot - voi o co noi dung dai,
#: xuong dong trong cot cua no, thi gan nhu khong doan duoc. Ky tu nay cung la
#: cai de bat chuot khi keo co gian cot (xem `column_edges`).
COL_GAP = " │ "


def column_edges(widths: Sequence[int] = None, gap: str = None) -> List[int]:
    """Vi tri (tinh theo SO KY TU) cua tung duong ke doc.

    GUI dung no de biet nguoi dung dang bam vao duong ke nao: doi toa do chuot
    ra chi so ky tu roi so voi danh sach nay. De o day vi no la HE QUA TRUC
    TIEP cua cach dung bang - tinh lai ben `gui.py` la hai noi cung tu suy ra
    mot thu roi som muon lech nhau.
    """
    widths = list(COL_WIDTHS if widths is None else widths)
    gap = COL_GAP if gap is None else gap
    giua = len(gap) // 2
    edges: List[int] = []
    pos = 0
    for w in widths[:-1]:
        pos += w
        edges.append(pos + giua)
        pos += len(gap)
    return edges

_WS = _re.compile(r"\s+")


def _runs_one_line(runs: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Gop moi khoang trang/xuong dong trong tung run thanh MOT dau cach.

    Khong dung `_one_line()` cho ca chuoi: lam vay se an mat dau cach o dau/
    cuoi tung run, tuc la hai run dinh lien nhau ("GRP-A" + ", " -> "GRP-A,"
    mat luon dau cach sau dau phay).
    """
    out: List[Tuple[str, str]] = []
    for kind, text in runs:
        t = _WS.sub(" ", str(text or ""))
        if t:
            out.append((kind, t))
    return out


def _cell_runs(value: Any) -> List[Tuple[str, str]]:
    return [("text", "" if value is None else str(value))]


def _pad_runs(cells_runs: Sequence[Sequence[Tuple[str, str]]]
              ) -> Tuple[List[Tuple[str, str]], ...]:
    out = [list(c) for c in cells_runs][:NCOL]
    while len(out) < NCOL:
        out.append([("text", "")])
    return tuple(out)


def _chunks(runs: Sequence[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """Cat runs thanh cac 'tu' duoc phep ngat dong GIUA chung.

    Cat SAU dau cach / dau phay / dau mo ngoac - tuc la dau phan cach di theo
    tu dung truoc no, nen dong moi khong bao gio bat dau bang dau phay.
    """
    out: List[Tuple[str, str]] = []
    for kind, text in runs:
        for part in _re.split(r"(?<=[ ,(])", str(text or "")):
            if part:
                out.append((kind, part))
    return out


def wrap_runs(runs: Sequence[Tuple[str, str]], width: int
              ) -> List[List[Tuple[str, str]]]:
    """Ngat `runs` thanh cac dong rong toi da `width` ky tu.

    Mot 'tu' dai hon ca be ngang cot (ten object dai, chuoi IP-IP) thi bi cat
    CUNG thay vi day cot phinh ra - cot phinh ra la ca bang lech.
    """
    lines: List[List[Tuple[str, str]]] = []
    cur: List[Tuple[str, str]] = []
    cur_len = 0
    for kind, text in _chunks(runs):
        while text:
            if cur_len == 0:
                text = text.lstrip(" ")     # khong mo dau dong bang dau cach
                if not text:
                    break
            room = width - cur_len
            if len(text) <= room:
                piece, text = text, ""
            elif cur_len == 0:
                piece, text = text[:room], text[room:]
            else:
                lines.append(cur)
                cur, cur_len = [], 0
                continue
            cur.append((kind, piece))
            cur_len += len(piece)
            if cur_len >= width and text:
                lines.append(cur)
                cur, cur_len = [], 0
    if cur or not lines:
        lines.append(cur)
    return lines


def row_tag(row: Dict[str, Any]) -> str:
    """Tag cho CA DONG (mau nen/mau chu nen). '' = dong thuong.

    De o day chu khong o gui.py vi day la luat trinh bay, va luat thi phai
    test duoc ma khong can mo cua so.
    """
    kind = row.get("kind")
    if kind in ("section", "hdr", "note"):
        return kind
    if kind == "log":
        return "ok" if row.get("ok") else "no"
    return "off" if row.get("disabled") else ""


def is_data_row(row: Dict[str, Any]) -> bool:
    return row.get("kind") not in ("section", "hdr", "note")


#: Mui ten o dau dong tieu de muc. Bam vao dong do la thu gon / mo lai.
MUI_TEN_MO = "▼"
MUI_TEN_DONG = "▶"


def khoa_muc(row: Dict[str, Any]) -> str:
    """Khoa nhan dang mot muc - dung de NHO muc nao dang thu gon.

    Nho theo CHI SO DONG thi chay lai mot luot khac la lech het, vi so dong
    cua moi muc doi theo ket qua. Nho theo chu cua dong tieu de thi muc
    "SECURITY RULE" van la muc do o moi luot chay.
    """
    return " ".join("".join(str(c) for c in row.get("cells") or []).split())


def ap_dung_thu_gon(display: Sequence[Dict[str, Any]],
                    dang_dong: Sequence[str] = ()) -> List[Dict[str, Any]]:
    """Chen mui ten vao dau moi dong tieu de muc, va BO cac dong cua muc dang
    thu gon.

    Mot luot chay co the ra bon muc (Security Rule, NAT, Check Object, doi
    chieu log); muc nao dang khong quan tam thi no van chiem cho va day muc
    can xem xuong duoi. Thu gon duoc la nguoi doc tu quyet cho nao can nhin -
    thay vi tool quyet thay.
    """
    dong = set(dang_dong or ())
    out: List[Dict[str, Any]] = []
    an = False
    for row in display:
        if row.get("kind") == "section":
            khoa = khoa_muc(row)
            an = khoa in dong
            moi = dict(row)
            cells = list(row.get("cells") or ())
            mui = MUI_TEN_DONG if an else MUI_TEN_MO
            dau = str(cells[0]) if cells else ""
            cells[0] = f"{mui} {dau.lstrip()}" if dau.strip() else mui
            moi["cells"] = tuple(cells)
            moi["khoa_muc"] = khoa
            moi.pop("runs", None)       # da doi chu o cell[0] -> runs cu khong con dung
            out.append(moi)
            continue
        if not an:
            out.append(row)
    return out


def layout(display: Sequence[Dict[str, Any]],
           widths: Sequence[int] = COL_WIDTHS,
           gap: str = COL_GAP) -> List[Dict[str, Any]]:
    """Doi danh sach dong ket qua thanh danh sach DONG MAN HINH.

    Moi dong man hinh: {"tag": <tag ca dong>, "segments": [(tag_doan, chu)...]}.
    Mot dong ket qua co the trai ra nhieu dong man hinh (o nao dai thi xuong
    dong TRONG cot cua no) - khong cat bot chu nao.
    """
    full = sum(widths) + len(gap) * (len(widths) - 1)
    out: List[Dict[str, Any]] = []
    for _chi_so, row in enumerate(display):
        tag = row_tag(row)
        cells = row.get("runs") or [_cell_runs(c) for c in row["cells"]]

        # Dong tieu de muc / ghi chu KHONG chia cot: nhet mot cau dai vao o dau
        # tien rong 26 ky tu thi no xuong dong lam ba bon khuc, trong nhu bang
        # bi vo. Cho no trai het be ngang bang.
        if tag in ("section", "note"):
            runs: List[Tuple[str, str]] = []
            for cell in cells:
                if not "".join(t for _, t in cell).strip():
                    continue
                if runs:
                    runs.append(("text", "  "))
                runs.extend(cell)
            for line in wrap_runs(_runs_one_line(runs), full):
                used = sum(len(t) for _, t in line)
                out.append({"tag": tag, "row": _chi_so,
                            "segments": list(line) +
                            ([("text", " " * (full - used))] if used < full else [])})
            continue
        wrapped = [wrap_runs(_runs_one_line(c), w)
                   for c, w in zip(cells, widths)]
        for i in range(max(len(w) for w in wrapped)):
            segs: List[Tuple[str, str]] = []
            for ci, (w, width) in enumerate(zip(wrapped, widths)):
                if ci:
                    segs.append(("text", gap))
                line = w[i] if i < len(w) else []
                segs.extend(line)
                used = sum(len(t) for _, t in line)
                if used < width:
                    segs.append(("text", " " * (width - used)))
            out.append({"tag": tag, "row": _chi_so, "segments": segs})
    return out


def layout_plain(display: Sequence[Dict[str, Any]], **kw) -> str:
    """Ban chu tron cua `layout()` - dung cho test va cho log."""
    return "\n".join("".join(t for _, t in ln["segments"]).rstrip()
                     for ln in layout(display, **kw))
