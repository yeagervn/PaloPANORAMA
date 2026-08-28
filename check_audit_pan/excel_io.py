# -*- coding: utf-8 -*-
"""
excel_io.py - Xuat/Import file cua CHECK AUDIT (Mục 6 require.md):

  - export_findings(...)     Viet 1 file .xlsx / .csv theo dung danh sach cot
                              nen chung (D7) + cot phu theo tinh nang (D8, D10).
  - parse_import_file(...)   Doc lai file .xlsx da export (hoac ban admin da
                              chinh sua), validate cau truc cot, tra ve
                              List[(rule_name, finding_type)] cho GUI hoi xoa.
"""

import csv
import datetime as _dt
import os
from typing import Dict, List, Optional, Tuple

from .core import (
    Finding,
    CHECK_TYPE_LABELS,
    SHADOW_UNUSED,
    format_service_entries,
    build_service_info,
    ServiceObject, ServiceGroup,
)

# Dung dung thu tu cot bat buoc Mục 6 (D7 - 1 dinh dang nen chung cho ca 3 tinh nang).
# Ban Panorama them cot thu 15 "Vi tri Rule" NGAY SAU "Name Rule" (IV.5) - bat buoc
# de Import dựng đúng xpath DELETE.
HEADERS = [
    "Loại (Finding Type)", "Name Rule", "Vi tri Rule", "Source IP", "Dest IP", "Port",
    "Action", "Disabled", "Detail", "Rule UUID", "Shadow Reason",
    "Hit Count", "Last Hit Date", "Rule Creation Date", "No Hits Duration",
]


# ============================================================================
# XUAT FILE
# ============================================================================
def _no_hit_duration_text(f: Finding) -> str:
    """Tai cau "1 cot mo ta chinh xac no hits duoc bao lau" (D10/Mục 4.4) lai
    tu cac field cua Finding khi nhanh UNUSED xuat hien - dung cho ca xlsx/csv.
    Khac 2 truong hop de trong: khong thuoc UNUSED (phan biet qua Shadow Reason)."""
    if SHADOW_UNUSED not in f.shadow_reasons or f.no_hit_days is None:
        return ""
    if f.hit_count and f.hit_count > 0 and f.last_hit_date:
        return (f"Không có hits trong {f.no_hit_days} ngày "
                f"(lần hit gần nhất: {f.last_hit_date})")
    if f.rule_creation_date:
        return (f"Chưa từng có hit nào kể từ khi tạo rule ({f.no_hit_days} ngày, "
                f"tạo lúc: {f.rule_creation_date})")
    return ""


def _row_values(f: Finding, service_info) -> List[str]:
    """1 dong du lieu (toan bo cot) cua 1 Finding - dung chung cho xlsx/csv."""
    is_shadow = f.check_type == "shadow"
    is_shadow_unused = is_shadow and SHADOW_UNUSED in f.shadow_reasons
    row = [
        CHECK_TYPE_LABELS.get(f.check_type, f.check_type),
        f.rule_name,
        f.vi_tri,
        ", ".join(f.source),
        ", ".join(f.destination),
        format_service_entries(f.service, service_info),
        f.action,
        "Yes" if f.disabled else "No",
        f.detail,
        f.rule_uuid,
        ", ".join(f.shadow_reasons) if is_shadow else "",
        str(f.hit_count) if (is_shadow_unused and f.hit_count is not None) else "",
        f.last_hit_date if is_shadow_unused else "",
        f.rule_creation_date if is_shadow else "",
        _no_hit_duration_text(f),
    ]
    return row


RESULT_FONT_NAME = "Times New Roman"
RESULT_FONT_SIZE = 11
HEADER_FILL_HEX = "FF0D7377"      # teal-blue đậm cho header
HEADER_FONT_HEX = "FF1F1F1F"      # chữ header gần đen, in đậm
BORDER_GRAY_HEX = "FFC9C9C9"      # path kẻ mảnh giữa các ô/dòng


def _cell_border():
    from openpyxl.styles import Border, Side
    side = Side(style="thin", color=BORDER_GRAY_HEX)
    return Border(left=side, right=side, top=side, bottom=side)


def _data_font():
    from openpyxl.styles import Font
    return Font(name=RESULT_FONT_NAME, size=RESULT_FONT_SIZE)


def _header_font():
    from openpyxl.styles import Font
    return Font(name=RESULT_FONT_NAME, size=RESULT_FONT_SIZE,
                bold=True, color=HEADER_FONT_HEX)


def _header_fill():
    from openpyxl.styles import PatternFill
    return PatternFill(start_color=HEADER_FILL_HEX, end_color=HEADER_FILL_HEX,
                       fill_type="solid")


def export_findings(
    findings: List[Finding],
    out_path: str,
    fmt: str = "xlsx",
    service_info: Optional[Dict[str, List[Tuple[Optional[str], str]]]] = None,
    types: Optional[List[str]] = None,
    log_func=None,
) -> str:
    """
    Xuat toan bo Finding ra file .xlsx (mac dinh) hoac .csv.

    `service_info`: map ten service/group -> [(protocol, port)] de format cot
    Port theo D8 (bang build_service_info cua core - dung khi co data thuc).
    `types`: danh sach loai check da chay trong luot nay - dung de dat ten file
    (1 loai -> audit_<loai>_<ts>, nhieu loai -> audit_combo_<ts>).
    """
    log = log_func or (lambda msg: None)
    if not findings:
        raise ValueError("Khong co Finding nao de export (Export bi vo hieu khi chua co ket qua Check).")

    fmt = (fmt or "xlsx").lower()
    suffix = "combo"
    if types and len(types) == 1:
        suffix = types[0]

    full_path = os.path.join(out_path, f"audit_{suffix}_{_dt.datetime.now().strftime('%Y%m%d_%H%M%S')}.{fmt}")
    os.makedirs(out_path, exist_ok=True)
    d7 = f"{'xlsx' if fmt == 'xlsx' else 'csv'}"

    if fmt == "xlsx":
        _export_xlsx(findings, full_path, service_info)
    elif fmt == "csv":
        _export_csv(findings, full_path, service_info)
    else:
        raise ValueError(f"Dinh dang khong ho tro: {fmt} (chi xlsx/csv).")

    log(f"Export {d7} OK: {full_path} (co bao gom tinh nang co Import duoc: "
        f"{'shadow' in (types or []) or 'disabled' in (types or [])})")
    return full_path


def _export_xlsx(findings, out_path, service_info):
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font
    from openpyxl.utils import get_column_letter

    wb = Workbook()
    ws = wb.active
    ws.title = "Audit"
    # Tat gridline cua sheet, chi giu path ke manh tu Border -> nhin giong bang.
    ws.sheet_view.showGridLines = False

    # 1 hang header duy nhat: nen teal-blue dam, chu gan den in dam, TNR 11.
    ws.append(HEADERS)
    for c_idx in range(1, len(HEADERS) + 1):
        cell = ws.cell(row=1, column=c_idx)
        cell.font = _header_font()
        cell.fill = _header_fill()
        cell.border = _cell_border()
        cell.alignment = Alignment(horizontal="center", vertical="center",
                                   wrap_text=True)
    ws.row_dimensions[1].height = 20

    # Kiem du lieu: mot le trai, rieng Action/Disabled can giua, Detail wrap.
    data_align = Alignment(horizontal="left", vertical="top")
    center_align = Alignment(horizontal="center", vertical="top")
    wrap_align = Alignment(horizontal="left", vertical="top", wrap_text=True)
    center_cols = {HEADERS.index(c) + 1 for c in ("Action", "Disabled")}
    detail_col = HEADERS.index("Detail") + 1

    for f in findings:
        ws.append(_row_values(f, service_info))
        r = ws.max_row
        for c_idx in range(1, len(HEADERS) + 1):
            cell = ws.cell(row=r, column=c_idx)
            cell.font = _data_font()
            cell.border = _cell_border()
            cell.number_format = "@"
            if c_idx in center_cols:
                cell.alignment = center_align
            elif c_idx == detail_col:
                cell.alignment = wrap_align
            else:
                cell.alignment = data_align
        # Case "KHAC ACTION": khong to nen mau (giu data trang nhu yeu cau) ma
        # danh dau bang chu Action in dam mau do.
        if f.check_type == "shadow" and f.same_action is False:
            action_cell = ws.cell(row=r, column=HEADERS.index("Action") + 1)
            action_cell.font = Font(name=RESULT_FONT_NAME, size=RESULT_FONT_SIZE,
                                    bold=True, color="FFC00000")

    end_col = get_column_letter(len(HEADERS))
    ws.auto_filter.ref = f"A1:{end_col}{ws.max_row}"
    ws.freeze_panes = "A2"

    widths = [22, 28, 18, 28, 28, 24, 10, 10, 60, 36, 22, 12, 16, 18, 40]
    for i, w in enumerate(widths, start=1):
        ws.column_dimensions[chr(ord("A") + i - 1)].width = w

    wb.save(out_path)


def _export_csv(findings, out_path, service_info):
    with open(out_path, "w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(HEADERS)
        for f in findings:
            w.writerow(_row_values(f, service_info))


# ============================================================================
# DOC LAI FILE DE IMPORT (Mục 5/Mục 6)
# ============================================================================
def parse_import_file(path: str, log_func=None) -> List[Tuple[str, str, str]]:
    """
    Doc file .xlsx da export (hoac ban admin da sua), validate:
      - Phai co header dung ten cot (khong phan biet hoa/thuong, tu trim).
        Thieu cot 'Name Rule' / 'Loại' / 'Vi tri Rule' -> raise loi ro rang, khong doan.
      - Dong thieu Name Rule (rong) -> bo qua + log canh bao, khong loi toan file.
    Tra ve List[(rule_name, finding_type, vi_tri)] cho GUI xu ly tiep (loc loai co
    Import + popup xac nhan xoa + delete candidate) - `vi_tri` dung de dựng xpath (0.8).
    """
    log = log_func or (lambda msg: None)

    from openpyxl import load_workbook

    if not os.path.isfile(path):
        raise ValueError(f"Khong tim thay file import: {path}")

    try:
        wb = load_workbook(path, data_only=True, read_only=False)
    except Exception as e:
        raise ValueError(f"Khong doc duoc file Excel '{os.path.basename(path)}': {e}")

    ws = wb.active
    if ws.max_row < 1 or ws.max_column < 1:
        raise ValueError("File Excel rong - khong co header nao.")

    headers: List[str] = []
    for cell in ws[1]:
        headers.append((cell.value or "").strip())
    norm = {h.lower(): idx for idx, h in enumerate(headers)}

    name_col = None
    for key, idx in norm.items():
        if key == "name rule":
            name_col = idx
            break
    loai_col = None
    for key, idx in norm.items():
        if key in ("loại", "loại (finding type)", "loại (finding type)"):
            loai_col = idx
            break
    vi_tri_col = None
    for key, idx in norm.items():
        if key == "vi tri rule":
            vi_tri_col = idx
            break
    if name_col is None:
        raise ValueError("File import thieu cot bat buoc 'Name Rule' - khong the doc.")
    if loai_col is None:
        raise ValueError("File import thieu cot bat buoc 'Loại (Finding Type)' - khong the doc.")
    if vi_tri_col is None:
        raise ValueError("File import thieu cot bat buoc 'Vi tri Rule' - khong the doc.")

    result: List[Tuple[str, str, str]] = []
    for row in ws.iter_rows(min_row=2, values_only=True):
        name = ""
        if name_col < len(row) and row[name_col] is not None:
            name = str(row[name_col]).strip()
        loai = ""
        if loai_col < len(row) and row[loai_col] is not None:
            loai = str(row[loai_col]).strip()
        vi_tri = ""
        if vi_tri_col < len(row) and row[vi_tri_col] is not None:
            vi_tri = str(row[vi_tri_col]).strip()
        if not name:
            log("CANH BAO: bo qua dong khong co Name Rule khi Import.")
            continue
        result.append((name, loai, vi_tri))

    if not result:
        log("CANH BAO: file import khong co dong du lieu hop le nao (chi header).")
    return result


def build_service_info_for_export(
    service_objects: Dict[str, ServiceObject],
    service_groups: Dict[str, ServiceGroup],
) -> Dict[str, List[Tuple[Optional[str], str]]]:
    """Tien loi encode (load) dich cho gui.py goi khi co config that."""
    return build_service_info(service_objects, service_groups)