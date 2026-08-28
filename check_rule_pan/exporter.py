# -*- coding: utf-8 -*-
from typing import List, Optional
import openpyxl
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from .matcher import RowResult, MissingItem, MissingPort

GREEN_FONT, GREEN_FILL = "FF006100", "FFC6EFCE"
ORANGE_FONT, ORANGE_FILL = "FF9C6500", "FFFFEB9C"
RED_FONT, RED_FILL = "FF9C0006", "FFFFC7CE"
BLUE_FONT, BLUE_FILL = "FF1F4E79", "FFDCE6F1"
CANDIDATE_FONT, CANDIDATE_FILL = "FF0B5394", "FF9FE2E0"
ZONE_FONT, ZONE_FILL = "FF5F1A8C", "FFE4CCFF"
GREY_FONT = "FF666666"
HEADER_FILL = "FF305496"
HEADER_FONT = "FFFFFFFF"
FONT_NAME = "Times New Roman"
FONT_SIZE = 12

NAME_RULE_COL_CHARS = 30
VI_TRI_COL_CHARS = 20
FIELD_COL_CHARS = 50
PORT_COL_CHARS = 24


def _f(color=None, bold=False, italic=False, size=FONT_SIZE):
    return InlineFont(rFont=FONT_NAME, color=color, b=bold, i=italic, sz=str(size))


def _consolidate(items: List[MissingItem]):
    order = {'in_rule': [], 'exists': []}
    groups = {'in_rule': {}, 'exists': {}, 'new': [], 'candidate': []}
    for m in items:
        if m.status in ('in_rule', 'exists'):
            bucket = groups[m.status]
            if m.existing_name not in bucket:
                bucket[m.existing_name] = []
                order[m.status].append(m.existing_name)
            bucket[m.existing_name].append(m)
        elif m.status == 'candidate':
            groups['candidate'].append(m)
        else:
            groups['new'].append(m)
    return order, groups


def _group_consecutive_runs(items: List[MissingItem]) -> List[List[MissingItem]]:
    if not items:
        return []
    ordered = sorted(items, key=lambda m: m.ip_int)
    runs = [[ordered[0]]]
    for m in ordered[1:]:
        if m.ip_int == runs[-1][-1].ip_int + 1:
            runs[-1].append(m)
        else:
            runs.append([m])
    return runs


def _build_field_lines(items: List[MissingItem]) -> List[TextBlock]:
    """Dung cho o Source/Dest. Quy tac hien thi (theo yeu cau):
    - in_rule (da nam san trong group cua rule dang xet, KHONG can lam gi them): mau
      XANH LA - neu cover HET input thi ghi gon "cover full IP(s)"; neu chi cover 1
      PHAN thi liet ke ro CAC IP CU THE dang duoc group nay cover (khong chi ghi so
      luong), de nguoi doc biet ngay IP nao da xong, IP nao con thieu.
    - exists (IP da ton tai duoi dang 1 object/group KHAC tren thiet bi, CHUA nam
      trong group cua rule dang xet - CAN duoc them vao rule): mau CAM (khac han
      in_rule) - de phan biet ngay group nao da co san trong rule (xanh la) va group
      nao con can bo sung vao rule (cam). CHI ghi ten object, khong ghi them chi tiet
      coverage - vi o Name Rule da co nhan "+ ADD SOURCE/DEST" roi, nhac lai o day la
      thua.
    - new (chua ton tai o dau): giu nguyen "- ... -> TAO MOI" (do), bo phan chu thich
      "(Range, N IP lien tiep)" thua thai."""
    if not items:
        return []
    blocks: List[TextBlock] = []
    order, groups = _consolidate(items)

    for name in order['in_rule']:
        members = groups['in_rule'][name]
        kind = members[0].existing_kind
        if kind == 'any':
            blocks.append(TextBlock(_f(GREEN_FONT, bold=True), "\u2022 any "))
            blocks.append(TextBlock(_f(GREEN_FONT), "(rule cho phep tat ca)\n"))
            continue
        pct = members[0].group_coverage_pct
        if pct == 100:
            detail = "cover full IP(s)"
        else:
            ip_list = ", ".join(m.display for m in members)
            detail = f"cover: {ip_list}"
        blocks.append(TextBlock(_f(GREEN_FONT, bold=True), f"\u2022 {name} "))
        blocks.append(TextBlock(_f(GREEN_FONT), f"({detail})\n"))

    for name in order['exists']:
        members = groups['exists'][name]
        kind = members[0].existing_kind
        if kind == 'any':
            blocks.append(TextBlock(_f(ORANGE_FONT, bold=True), "\u2022 any\n"))
            continue
        blocks.append(TextBlock(_f(ORANGE_FONT, bold=True), f"\u2022 {name}\n"))

    candidate_items = groups['candidate']
    if candidate_items:
        for run in _group_consecutive_runs(candidate_items):
            if len(run) == 1:
                blocks.append(TextBlock(_f(CANDIDATE_FONT), f"- {run[0].display} "))
                blocks.append(TextBlock(_f(CANDIDATE_FONT, bold=True), "\u2192 CANDICATE\n"))
            else:
                blocks.append(TextBlock(_f(CANDIDATE_FONT), f"- {run[0].display}-{run[-1].display} "))
                blocks.append(TextBlock(_f(CANDIDATE_FONT, bold=True), "\u2192 CANDICATE\n"))

    new_items = groups['new']
    if new_items:
        plain_new = [m for m in new_items if not m.is_range_input]
        range_input_new = [m for m in new_items if m.is_range_input]
        for run in _group_consecutive_runs(plain_new):
            if len(run) == 1:
                blocks.append(TextBlock(_f(RED_FONT), f"- {run[0].display} "))
                blocks.append(TextBlock(_f(RED_FONT, bold=True), "\u2192 TAO MOI\n"))
            else:
                blocks.append(TextBlock(_f(RED_FONT), f"- {run[0].display}-{run[-1].display} "))
                blocks.append(TextBlock(_f(RED_FONT, bold=True), "\u2192 TAO MOI\n"))
        for m in range_input_new:
            blocks.append(TextBlock(_f(RED_FONT), f"- {m.display} "))
            blocks.append(TextBlock(_f(RED_FONT, bold=True), "\u2192 TAO MOI\n"))
    return blocks


def _estimate_wrapped_lines(text: str, chars_per_line: int) -> int:
    if not text:
        return 1
    total = 0
    for line in text.split("\n"):
        total += max(1, -(-max(len(line), 1) // chars_per_line))
    return max(total, 1)


def _compute_action_level(res: RowResult) -> str:
    """shadow_warning (co rule deny/drop nam TRUOC cung khop) luon keo ket qua xuong
    muc 'add' (mau cam) - du khong con muc thieu source/dest/port nao khac - vi khong
    the coi la FULL MATCH dang tin cay duoc khi con nghi ngo bi che khuat.

    used_candidate_rule (co item duoc "cuu" boi CANDIDATE config chua commit) LUON keo
    ket qua xuong muc 'candidate_config' (mau xanh ngoc/candidate rieng) - kiem tra
    TRUOC ca 'none' de KHONG BAO GIO hien FULL MATCH xanh la khi ket qua co phu thuoc
    vao du kien candidate chua co hieu luc that."""
    if res.tier == 'INVALID':
        return 'invalid'
    if res.tier == 'SAME_SUBNET':
        return 'same_subnet'
    if res.tier == 'LIVE_MATCH':
        # SUA LOI (phat hien qua bao cao "Live Match da FULL MATCH nhung output van
        # bao + ADD SOURCE/DEST" - loi lap lai thuong xuyen): LIVE_MATCH la KET QUA
        # XAC THUC TUYET DOI tu chinh firewall that (PAN-OS Test Policy Match da xac
        # nhan action=allow cho DUNG to hop Source/Dest/Port dang xet) - PHAI LUON
        # duoc coi la FULL MATCH ('none'), BAT KE source_report/dest_report/
        # missing_ports the hien gi. Truoc day ham nay KHONG co nhanh rieng cho
        # LIVE_MATCH, nen roi xuong nhanh chung o cuoi (dung chung voi TOP1-3) - o do
        # 1 tinh huong CO THAT se xay ra: khi try_live_match() khong doi chieu duoc
        # ten rule ma API tra ve voi rule_infos cuc bo (matched_rule_info=None - vd do
        # sai lech nho giua ten rule/khong tim thay trong file cau hinh dang dung -
        # xem try_live_match trong matcher.py), src_report/dst_report duoc build voi
        # rule_members=[] RONG -> MOI IP deu roi vao nhanh du phong cua
        # build_live_match_field_report va bi gan NHAM status='new'/'exists' (dung
        # trong TOP1-3 co nghia "chua co trong rule", nhung O DAY hoan toan sai vi
        # firewall THAT SU DA xac nhan allow) -> khien 'add' bi tra ve va hien nham
        # "+ ADD SOURCE/DEST" cho 1 dong ROI DA duoc xac thuc FULL MATCH. Da tai hien
        # va kiem chung bang du lieu that (xem PaloRuleSearchSuite_TaiLieu.md muc
        # XIV) - source_report/dest_report cua LIVE_MATCH TU NAY TRO DI CHI con y
        # nghia THAM KHAO/hien thi (biet ket qua khop qua object/group nao NEU do
        # duoc), KHONG BAO GIO duoc dung de quyet dinh can '+ ADD' hay khong nua.
        return 'none'
    if res.used_candidate_rule:
        return 'candidate_config'
    if res.tier == 'TOP4':
        # near_top2/near_top3: da tim duoc 1 rule CU THE + Port da khop du, chi thieu
        # dung 1 ben (Source hoac Dest) - coi nhu 1 dang 'add' (cam), vi day la goi y
        # THUC SU actionable (+ ADD SOURCE/DEST vao dung 1 rule), khac han truong hop
        # khong tim duoc gi lien quan (do). 'generic' (Port khong khop/chi cover 1
        # phan ca 2 ben) va truong hop khong tim duoc rule nao van la 'no_rule' (do) -
        # dung 'Chua co Rule - can tao moi' CHI con la truong hop CUOI CUNG that su.
        if res.nearest_rule_kind in ('near_top2', 'near_top3'):
            return 'near_match'
        return 'no_rule'
    items = res.source_report + res.dest_report
    needs_add = any(m.status in ('new', 'exists') for m in items) or res.missing_ports
    if needs_add or res.shadow_warning:
        return 'add'
    return 'none'


def build_name_rule_cell(res: RowResult):
    action = _compute_action_level(res)

    if action == 'invalid':
        text = res.note or 'Du lieu khong hop le'
        return CellRichText([TextBlock(_f(GREY_FONT, italic=True), text)]), \
            _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'same_subnet':
        text = "Khong can tao Rule"
        blocks = [TextBlock(_f(BLUE_FONT, bold=True), text)]
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    # Khong co rule THAT nao tren running (TOP4) nhung CANDIDATE config (chua commit) da
    # co san mot phan/toan bo dieu kien - hien nhan rieng thay vi "Chua co Rule", va van
    # liet ke ro con thieu gi THAT SU (item van 'new'/con missing_ports THAT).
    if action == 'candidate_config' and res.rule is None:
        text = "CANDICATE CONFIG"
        blocks = [TextBlock(_f(CANDIDATE_FONT, bold=True), text)]
        needs = []
        if any(m.status in ('new', 'exists') for m in res.source_report):
            needs.append('ADD SOURCE')
        if any(m.status in ('new', 'exists') for m in res.dest_report):
            needs.append('ADD DEST')
        if res.missing_ports:
            needs.append('ADD PORT')
        for label in needs:
            extra = f"\n+ {label}"
            blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
            text += extra
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'near_match':
        # near_top2/near_top3 (xem _find_nearest_candidate_rule trong matcher.py): da
        # xac dinh 1 rule CU THE co Port du + 1 ben (Source hoac Dest) da khop du, chi
        # thieu dung 1 ben con lai -> hien GIONG HET dinh dang '+ ADD SOURCE/DEST' that
        # (o duoi, danh cho TOP1.1/TOP2/TOP3) de admin nhan ra ngay day la goi y hanh
        # dong cu the, KEM 1 dong xam nhac ro day la GOI Y (chua qua kiem tra exact-
        # scope tuyet doi nhu TOP2/TOP3 that) can admin tu xac nhan truoc khi ap dung.
        label = 'ADD SOURCE' if res.nearest_rule_kind == 'near_top2' else 'ADD DEST'
        rule_name = res.nearest_rule.name if res.nearest_rule else "Unknown Rule"
        blocks = [TextBlock(_f(ORANGE_FONT, bold=True), rule_name)]
        text = rule_name
        extra = f"\n+ {label}"
        blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
        text += extra
        caveat = f"\n(GAN DUNG - can xac nhan: {res.nearest_detail})" if res.nearest_detail else \
            "\n(GAN DUNG - can admin xac nhan truoc khi ap dung)"
        blocks.append(TextBlock(_f(GREY_FONT, italic=True), caveat))
        text += caveat
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'no_rule' or res.rule is None:
        # 'generic' (xem _find_nearest_candidate_rule): co tim duoc 1 rule lien quan
        # MOT PHAN (vd Dest+Source khop nhung Port sai hoan toan - khac loai traffic)
        # nhung KHONG du ro rang de goi y "+ ADD" cu the -> van hien ten rule + mo ta
        # tham khao, nhung giu mau DO (khac 'near_match' o tren) vi day khong phai 1
        # goi y hanh dong dang tin cay. Neu KHONG tim duoc gi lien quan chut nao (
        # res.nearest_rule is None) -> day moi la truong hop CUOI CUNG that su, hien
        # dung "Chua co Rule - can tao moi".
        if res.nearest_rule is not None and res.nearest_rule_kind == 'generic':
            line1 = "\u26A0 Chua co Rule khop du - GAN NHAT:"
            detail_line = f"{res.nearest_rule.name} ({res.nearest_detail})"
            blocks = [TextBlock(_f(RED_FONT, bold=True), line1),
                      TextBlock(_f(ORANGE_FONT, bold=True), "\n" + detail_line)]
            text = line1 + "\n" + detail_line
            return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

        text = "\u26A0 Chua co Rule - can tao moi"
        blocks = [TextBlock(_f(RED_FONT, bold=True), text)]
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    rule_name = res.rule.name if res.rule else "Unknown Rule"
    blocks: List[TextBlock] = []
    text = ""

    if res.shadow_warning:
        # res.shadow_warning = ten cua rule deny/drop dang che khuat (xem matcher.py)
        line1 = f"-BLOCK BOI RULE: {res.shadow_warning}"
        line2 = f"-MATCH RULE: {rule_name}"
        blocks.append(TextBlock(_f(RED_FONT, bold=True), line1))
        blocks.append(TextBlock(_f(RED_FONT, bold=True), "\n" + line2))
        text = line1 + "\n" + line2
    elif action == 'none':
        text = f"\u2713 FULL MATCH: {rule_name}"
        blocks = [TextBlock(_f(GREEN_FONT, bold=True), text)]
    else:
        # action in ('add', 'candidate_config') va van co rule THAT tren running - giu
        # nguyen ten rule that (khong thay bang "CANDICATE CONFIG"), cac item duoc
        # candidate ho tro se tu hien mau xanh candidate rieng trong o Source/Dest/Port.
        text = rule_name
        blocks = [TextBlock(_f(ORANGE_FONT, bold=True), text)]

    if action in ('add', 'candidate_config'):
        needs = []
        if any(m.status in ('new', 'exists') for m in res.source_report):
            needs.append('ADD SOURCE')
        if any(m.status in ('new', 'exists') for m in res.dest_report):
            needs.append('ADD DEST')
        if res.missing_ports:
            needs.append('ADD PORT')
        for label in needs:
            extra = f"\n+ {label}"
            blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
            text += extra

    if res.rule and res.rule.disabled:
        extra = "\n\u26A0 RULE DANG DISABLED"
        blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
        text += extra

    if res.zone_warning:
        extra = f"\n\u26A0 THIEU ZONE: {res.zone_warning}"
        blocks.append(TextBlock(_f(ZONE_FONT, bold=True), extra))
        text += extra

    return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)


def build_field_cell(items: List[MissingItem]):
    blocks = _build_field_lines(items)
    if not blocks:
        return None, 1
    last = blocks[-1]
    if last.text.endswith("\n"):
        blocks[-1] = TextBlock(last.font, last.text[:-1])
    full_text = "".join(b.text for b in blocks)
    return CellRichText(blocks), _estimate_wrapped_lines(full_text, FIELD_COL_CHARS)


def build_port_cell(missing_ports: List[MissingPort], candidate_ports: Optional[List[MissingPort]] = None):
    candidate_ports = candidate_ports or []
    if not missing_ports and not candidate_ports:
        return None, 1
    blocks: List[TextBlock] = []
    for m in missing_ports:
        pdisp = str(m.start) if m.start == m.end else f"{m.start}-{m.end}"
        proto = (m.protocol or 'tcp').upper()
        if m.status == 'exists':
            # SUA LOI (08/2026): da co san 1 Service object dai dien CHINH XAC tren
            # thiet bi (xem find_existing_service_representation) - chi can ADD vao
            # rule, KHONG can tao Service object moi -> mau CAM + ghi ro ten object,
            # dung dinh dang giong het cach hien 'exists' cua Source/Dest o
            # _build_field_lines (khac han 'new' mau DO "-> TAO MOI").
            blocks.append(TextBlock(_f(ORANGE_FONT), f"- {proto}/{pdisp} "))
            blocks.append(TextBlock(_f(ORANGE_FONT, bold=True), f"\u2192 DA CO ({m.existing_name})\n"))
        else:
            blocks.append(TextBlock(_f(RED_FONT), f"- {proto}/{pdisp} "))
            blocks.append(TextBlock(_f(RED_FONT, bold=True), "\u2192 TAO MOI\n"))
    for m in candidate_ports:
        pdisp = str(m.start) if m.start == m.end else f"{m.start}-{m.end}"
        proto = (m.protocol or 'tcp').upper()
        blocks.append(TextBlock(_f(CANDIDATE_FONT), f"- {proto}/{pdisp} "))
        blocks.append(TextBlock(_f(CANDIDATE_FONT, bold=True), "\u2192 CANDICATE\n"))
    last = blocks[-1]
    if last.text.endswith("\n"):
        blocks[-1] = TextBlock(last.font, last.text[:-1])
    full_text = "".join(b.text for b in blocks)
    return CellRichText(blocks), _estimate_wrapped_lines(full_text, PORT_COL_CHARS)


def _action_fill(action: str) -> Optional[PatternFill]:
    if action == 'none':
        return PatternFill('solid', fgColor=GREEN_FILL)
    if action == 'add' or action == 'near_match':
        return PatternFill('solid', fgColor=ORANGE_FILL)
    if action == 'no_rule':
        return PatternFill('solid', fgColor=RED_FILL)
    if action == 'same_subnet':
        return PatternFill('solid', fgColor=BLUE_FILL)
    return None


def _set_text_cell(cell):
    """Ep dinh dang o la TEXT ('@') - tranh truong hop Excel hieu nham noi dung bat dau
    bang ky tu '-' (vd '- 10.31.8.106 -> TAO MOI') la mot cong thuc/tham chieu o (vd
    '=B11') gay loi khi nguoi dung click/copy o. Ap dung cho MOI o du lieu."""
    cell.number_format = '@'


def export_results(headers: List[str], results: List[RowResult], out_path: str,
                    source_col_idx: int = None, dest_col_idx: int = None, port_col_idx: int = None):
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Ket qua kiem tra"

    thin = Side(style='thin', color='B7B7B7')
    border = Border(left=thin, right=thin, top=thin, bottom=thin)
    wrap = Alignment(wrap_text=True, vertical='top', horizontal='left')
    center = Alignment(wrap_text=True, vertical='top', horizontal='center')
    base_font = Font(name=FONT_NAME, size=FONT_SIZE)

    out_headers = ["Name Rule", "Vi tri Rule", "Source", "Dest", "Port"] + list(headers)
    for j, h in enumerate(out_headers, start=1):
        c = ws.cell(row=1, column=j, value=h)
        c.font = Font(name=FONT_NAME, size=FONT_SIZE, color=HEADER_FONT, bold=True)
        c.fill = PatternFill('solid', fgColor=HEADER_FILL)
        c.alignment = Alignment(vertical='center', horizontal='center', wrap_text=True)
        c.border = border
    ws.freeze_panes = "A2"

    for i, res in enumerate(results, start=2):
        action = _compute_action_level(res)
        fill = _action_fill(action)

        name_cell, name_lines = build_name_rule_cell(res)
        c1 = ws.cell(row=i, column=1, value=name_cell)
        c1.alignment = wrap
        c1.border = border
        c1.font = base_font
        _set_text_cell(c1)
        if res.zone_warning:
            c1.fill = PatternFill('solid', fgColor=ZONE_FILL)
        elif fill:
            c1.fill = fill

        vi_tri_val = res.rule.vi_tri if res.rule else ""
        c_vi = ws.cell(row=i, column=2, value=vi_tri_val)
        c_vi.alignment = center
        c_vi.border = border
        c_vi.font = base_font
        _set_text_cell(c_vi)
        if vi_tri_val.startswith("Shared"):
            c_vi.fill = PatternFill('solid', fgColor="FFF2F2F2")

        src_cell, src_lines = build_field_cell(res.source_report)
        c2 = ws.cell(row=i, column=3, value=src_cell if src_cell is not None else "")
        c2.alignment = wrap
        c2.border = border
        c2.font = base_font
        _set_text_cell(c2)

        dst_cell, dst_lines = build_field_cell(res.dest_report)
        c3 = ws.cell(row=i, column=4, value=dst_cell if dst_cell is not None else "")
        c3.alignment = wrap
        c3.border = border
        c3.font = base_font
        _set_text_cell(c3)

        port_cell, port_lines = build_port_cell(res.missing_ports)
        c4 = ws.cell(row=i, column=5, value=port_cell if port_cell is not None else "")
        c4.alignment = wrap
        c4.border = border
        c4.font = base_font
        _set_text_cell(c4)

        for j, val in enumerate(res.row.extra_values, start=6):
            cell = ws.cell(row=i, column=j, value=val)
            cell.alignment = wrap
            cell.border = border
            cell.font = base_font
            _set_text_cell(cell)

        n_lines = max(name_lines, src_lines, dst_lines, port_lines, 1)
        ws.row_dimensions[i].height = max(16, min(17 * n_lines + 6, 400))

    widths = [NAME_RULE_COL_CHARS, VI_TRI_COL_CHARS, FIELD_COL_CHARS, FIELD_COL_CHARS, PORT_COL_CHARS] + \
        [max(12, min(len(str(h)) + 4, 28)) for h in headers]
    for j, w in enumerate(widths, start=1):
        ws.column_dimensions[get_column_letter(j)].width = w

    legend = wb.create_sheet("Chu thich")
    legend_rows = [
        ("Muc", "Y nghia"),
        ("Mau XANH LA", "FULL MATCH - Rule da du dieu kien, moi Source/Dest/Port deu da san sang, KHONG can lam gi them"),
        ("Mau CAM", "1 trong 2 truong hop: (a) Da tim duoc Rule phu hop nhung con it nhat 1 muc can BO SUNG, "
         "HOAC co canh bao CHE KHUAT; (b) GAN DUNG - da xac dinh 1 Rule cu the co Port DA KHOP DU va 1 ben "
         "(Source hoac Dest) DA KHOP DU, chi thieu dung 1 ben con lai (nhan '+ ADD SOURCE'/'+ ADD DEST' kem "
         "dong xam '(GAN DUNG - can xac nhan: ...)') - CAN ADMIN TU XAC NHAN truoc khi ap dung, vi rule nay "
         "RONG HON input nen chua qua duoc kiem tra an toan tuyet doi nhu Mau CAM loai (a)."),
        ("Mau DO", "KHONG tim duoc Rule nao du dieu kien - can tao Rule moi HOAC bo sung. Neu o Name Rule co "
         "dong '\u26A0 Chua co Rule khop du - GAN NHAT: <ten Rule> (...)' nghia la co 1 Rule lien quan MOT PHAN "
         "(vd Dest+Source khop nhung Port sai hoan toan - khac loai traffic/service) nhung KHONG du ro rang de "
         "goi y '+ ADD' cu the - chi mang tinh tham khao. Chi khi Name Rule ghi dung '\u26A0 Chua co Rule - can "
         "tao moi' (khong co dong nao khac kem theo) moi la truong hop THUC SU khong tim duoc gi lien quan."),
        ("Mau XANH DUONG", "Source va Dest nam CUNG 1 subnet - traffic khong di qua Firewall - Khong can tao Rule"),
        ("Dong '-BLOCK BOI RULE: X / -MATCH RULE: Y' (do)", "Ket qua nay den tu thuat toan LOCAL (khong phai Live "
         "Match): co rule deny/drop ten X nam TRUOC rule Y trong rulebase, cung khop dung traffic nay. PAN-OS luon "
         "ap dung rule DAU TIEN khop - rule Y (bao la match) co the dang bi rule X che khuat. Can chay lai Live "
         "Match tren thiet bi de xac nhan chinh xac, KHONG nen tin tuong ket qua nay."),
        ("Nhan 'ADD SOURCE/DEST/PORT' (do)", "Hien ngay trong o Name Rule khi con thieu"),
        ("O Source/Dest - chu xanh la co '(cover full IP(s))' hoac '(cover: <IP...>)'", "Object/group DA NAM SAN "
         "trong rule dang xet. 'cover full' = da cover HET cac IP dau vao. 'cover: <IP...>' = chi cover 1 PHAN, "
         "liet ke ro nhung IP cu the da duoc cover boi group nay."),
        ("O Source/Dest - chu CAM CHI co ten object (khong co chi tiet)", "IP nay DA ton tai duoi dang 1 "
         "object/group KHAC tren thiet bi nhung CHUA nam trong group cua rule dang xet - CAN duoc them vao rule "
         "(khong can tao moi tu dau). Mau CAM de phan biet ro voi mau XANH LA (da nam san trong rule, khong can "
         "lam gi them) - xem nhan 'ADD SOURCE/DEST' o cot Name Rule de biet ro con thieu gi."),
        ("Ky hieu '- ... \u2192 TAO MOI' (do)", "Gia tri IP/Port nay CHUA ton tai o bat ky dau tren thiet bi"),
        ("Ky hieu '- ... \u2192 DA CO (ten Service)' (cam, cot Port)", "Port nay CHUA nam trong Rule dang xet, "
         "nhung DA CO SAN 1 Service object dai dien CHINH XAC tren thiet bi (ten hien kem theo) - CHI can them "
         "Service do vao Rule, KHONG can tao Service object moi."),
        ("Mau TIM (cot Name Rule)", "Rule da tim duoc DU dieu kien Source/Dest/Port nhung THIEU Source Zone "
         "hoac Dest Zone - can bo sung Zone vao rule de traffic thuc su duoc cho phep. Zone duoc tool TU DONG "
         "suy ra tu IP dua tren cau hinh Interface/Zone that tren thiet bi (khong phai nguoi dung nhap tay); "
         "zone 'any' luon duoc coi la du."),
        ("CANDIDATE CONFIG - Mau xanh ngoc (Panorama, 0.4)", "Canh bao tham khao: object/rule da ton tai trong candidate-config CHUA COMMIT cua Panorama - chi dung de biet truoc, KHONG dung de ket luan traffic da duoc phep. Panorama co 2 tang commit: 'Commit to Panorama' roi moi 'Commit and Push' xuong Firewall - can lam ca 2 buoc."),
        ("Cot 'Vi tri Rule' (Panorama, 0.3)", "Cho biet rule nam o dau trong thu tu danh gia thuc: Shared-PRE -> DG-chain-PRE -> Local (neu co) -> DG-chain-POST -> Shared-POST. Chung 1 ten rule co the xuat hien o nhieu vi tri khac nhau."),
        ("Nguyen tac quan trong nhat", "CHI object/group KHOP CHINH XAC mới duoc chap nhan"),
        ("Luu y Source/Dest", "LUON hien day du trang thai cho TUNG IP trong file input"),
        ("Luu y Port", "Chi hien cac Port CON THIEU/can tao moi"),
    ]
    colors = [None, GREEN_FILL, ORANGE_FILL, RED_FILL, BLUE_FILL, ORANGE_FILL, None, None, ORANGE_FILL, None,
              ORANGE_FILL, ZONE_FILL, CANDIDATE_FILL, None, None, None, None]
    for r, (row, fillc) in enumerate(zip(legend_rows, colors), start=1):
        for cidx, val in enumerate(row, start=1):
            cell = legend.cell(row=r, column=cidx, value=val)
            cell.font = Font(name=FONT_NAME, size=FONT_SIZE, bold=(r == 1),
                              color=HEADER_FONT if r == 1 else None)
            cell.alignment = Alignment(wrap_text=True, vertical='top')
            if r == 1:
                cell.fill = PatternFill('solid', fgColor=HEADER_FILL)
            elif fillc and cidx == 1:
                cell.fill = PatternFill('solid', fgColor=fillc)
        if r > 1:
            legend.row_dimensions[r].height = 32
    legend.column_dimensions['A'].width = 32
    legend.column_dimensions['B'].width = 100

    wb.save(out_path)
    return out_path
