# -*- coding: utf-8 -*-
from typing import List, Optional
import openpyxl
from openpyxl.cell.rich_text import CellRichText, TextBlock
from openpyxl.cell.text import InlineFont
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

from .matcher import RowResult, MissingItem, MissingPort, LIVE_MATCH_SKIP_SCALE

GREEN_FONT, GREEN_FILL = "FF006100", "FFC6EFCE"
ORANGE_FONT, ORANGE_FILL = "FF9C6500", "FFFFEB9C"
RED_FONT, RED_FILL = "FF9C0006", "FFFFC7CE"
BLUE_FONT, BLUE_FILL = "FF1F4E79", "FFDCE6F1"
CANDIDATE_FONT, CANDIDATE_FILL = "FF0B5394", "FF9FE2E0"
WIDE_MATCH_FONT, WIDE_MATCH_FILL = "FF0B5394", "FFDDEBF7"   # xanh duong nhat hon CANDIDATE, phan biet
                                                            # ro voi GREEN (full match tuyet doi qua
                                                            # exact-scope) va ORANGE (near/add)
ZONE_FONT, ZONE_FILL = "FF5F1A8C", "FFE4CCFF"
GREY_FONT = "FF666666"
GROUP_COVER_LIGHT_FONT = "FFED7D31"   # cam nhat: group cover cho input dang RANGE
RANGE_EXIST_FONT = "FF00A651"        # xanh la: range object da ton tai, CHUA co trong rule
HEADER_FILL = "FF305496"
HEADER_FONT = "FFFFFFFF"
FONT_NAME = "Times New Roman"
FONT_SIZE = 12

NAME_RULE_COL_CHARS = 30
# BAN PANORAMA (require.md 0.3): them 1 cot 'Vi tri Rule' ngay sau 'Name Rule'
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


_EXIST_LABEL = {'host': 'host exist', 'range': 'range exist', 'wide': 'subnet exist'}


def _build_field_lines(items: List[MissingItem],
                        unparsed: Optional[List[str]] = None) -> List[TextBlock]:
    """Dung cho o Source/Dest. Quy tac hien thi (theo yeu cau):
    - in_rule (da nam san trong group cua rule dang xet, KHONG can lam gi them): mau
      XANH LA - neu cover HET input thi ghi gon "cover full IP(s)"; neu chi cover 1
      PHAN thi liet ke ro CAC IP CU THE dang duoc group nay cover (khong chi ghi so
      luong), de nguoi doc biet ngay IP nao da xong, IP nao con thieu.
    - exists (IP da ton tai duoi dang 1 object/group KHAC tren thiet bi, CHUA nam
      trong group cua rule dang xet - CAN duoc them vao rule): mau CAM (khac han
      in_rule) - de phan biet ngay group nao da co san trong rule (xanh la) va group
      nao con can bo sung vao rule (cam). Liet ke ro CAC IP CU THE ma group/object
      nay cover (giong het in_rule, chi khac mau) - neu cover HET input thi ghi gon
      "cover full IP(s)"; xem nhan "+ ADD SOURCE/DEST" o cot Name Rule de biet ro
      con thieu gi.
    - new (chua ton tai o dau): giu nguyen "- ... -> TAO MOI" (do), bo phan chu thich
      "(Range, N IP lien tiep)" thua thai.
    SUA LOI (09/2026 - gom nhom/sap xep Source-Dest khi input lon xon): bo hoan toan
    nhanh rut gon "is_mixed -> chi in ten group" cu (gay hien tuong nhin thay
    chi ten group ma khong biet IP nao thuoc group nao); tu nay MOI group
    in_rule/exists LUON kem chi tiet IP cu the. Moi danh sach IP hien thi deu duoc
    sort TUONG MINH theo ip_int tai day (khong an theo thu tu du lieu nguon), thu
    tu cac bullet group voi nhau sap theo IP nho nhat ma group do cover (tang dan)."""
    unparsed = unparsed or []
    if not items and not unparsed:
        return []
    blocks: List[TextBlock] = []
    # SUA LOI (10/2026): token input KHONG doc duoc phai hien ngay dau o Source/Dest
    # (truoc day bi loai am tham o classify_row, admin khong he biet 1 dai IP cua
    # request da bien mat khoi ket qua).
    for tok in unparsed:
        blocks.append(TextBlock(_f(RED_FONT), f"- {tok} "))
        blocks.append(TextBlock(_f(RED_FONT, bold=True),
                                 "\u2192 KHONG DOC DUOC (sai dinh dang - kiem tra lai o input)\n"))
    if not items:
        return blocks
    order, groups = _consolidate(items)

    def _sorted_group_names(status: str):
        names = list(order[status])
        # SUA LOI (09/2026): sap bullet group theo IP nho nhat group do cover
        # (tang dan) de doc tu tren xuong la doc theo thu tu IP tang dan.
        def _min_ip(nm):
            ms = groups[status][nm]
            return min(m.ip_int for m in ms) if ms else 10 ** 18
        # 'any' khong co IP cu the -> luon giu dau tien.
        anys = [n for n in names if groups[status][n] and groups[status][n][0].existing_kind == 'any']
        rest = [n for n in names if n not in anys]
        rest.sort(key=_min_ip)
        return anys + rest

    def _detail_text(members) -> str:
        pct = members[0].group_coverage_pct
        if pct == 100:
            return "cover full IP(s)"
        # SUA LOI (09/2026): sort TUONG MINH theo ip_int tai diem hien thi.
        ordered = sorted(members, key=lambda m: m.ip_int)
        ip_list = ", ".join(m.display for m in ordered)
        return f"cover: {ip_list}"

    for name in _sorted_group_names('in_rule'):
        members = groups['in_rule'][name]
        kind = members[0].existing_kind
        if kind == 'any':
            blocks.append(TextBlock(_f(GREEN_FONT, bold=True), "\u2022 any "))
            blocks.append(TextBlock(_f(GREEN_FONT), "(rule cho phep tat ca)\n"))
            continue
        detail = _detail_text(members)
        blocks.append(TextBlock(_f(GREEN_FONT, bold=True), f"\u2022 {name} "))
        blocks.append(TextBlock(_f(GREEN_FONT), f"({detail})\n"))

    for name in _sorted_group_names('exists'):
        members = groups['exists'][name]
        kind = members[0].existing_kind
        if kind == 'any':
            blocks.append(TextBlock(_f(ORANGE_FONT, bold=True), "\u2022 any\n"))
            continue
        # MOI loai input (IP don / range / subnet): group cover = cam nhat; object da ton
        # tai (khong thuoc group nao) = xanh la, in DAY DU ten object. Status van la
        # 'exists' nen Name Rule/ADD SOURCE khong doi; text '({detail})' giu nguyen.
        if kind == 'group':
            detail = _detail_text(members)
            blocks.append(TextBlock(_f(GROUP_COVER_LIGHT_FONT, bold=True), f"\u2022 {name} "))
            blocks.append(TextBlock(_f(GROUP_COVER_LIGHT_FONT), f"({detail})\n"))
            continue
        if kind in _EXIST_LABEL:
            detail = _detail_text(members)
            blocks.append(TextBlock(_f(RANGE_EXIST_FONT, bold=True), f"\u2022 {name} "))
            blocks.append(TextBlock(_f(RANGE_EXIST_FONT), f"({detail}) - {_EXIST_LABEL[kind]}, can ADD vao rule\n"))
            continue
        # SUA LOI (09/2026 - hien chi tiet exists): truoc day chi in ten group
        # (khong kem IP nao) nen khong the doi chieu IP nao thuoc group nao;
        # nay hien ro nhu in_rule (chi khac mau cam), giu rut gon khi cover 100%.
        detail = _detail_text(members)
        blocks.append(TextBlock(_f(ORANGE_FONT, bold=True), f"\u2022 {name} "))
        blocks.append(TextBlock(_f(ORANGE_FONT), f"({detail})\n"))

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


def _live_skip_caveat(res: RowResult) -> Optional[str]:
    """Dong caveat rieng ve Live Match (SUA LOI 09/2026 - minh bach Live Match):
    hien khi Live Match DA DUOC BAT nhung khong hoan tat cho dong nay. Ap dung
    cho MOI action level (ke ca 'none'/FULL MATCH LOCAL tu TOP1) vi day la thong
    tin ve QUA TRINH kiem tra, doc lap voi ket luan cuoi cung. 2 nhom cau chu
    KHAC NHAU (y nghia voi admin khac nhau):
    - scale_limit: CHUA goi API lan nao (vuot gioi han quy mo) - "chua kiem tra".
    - inconclusive: DA goi API nhung loi/khong dong nhat - "da kiem tra, co van de".
    Tra ve None (= khong hien) khi Live Match chua bat tu dau (matcher khong set
    2 field nay neu thieu mgmt_ip/api_key) hoac Live Match thanh cong.
    GHI CHU (fix dinh dang Name Rule): caller _append_live_skip_caveat tu nay
    CHI con duoc goi o cac nhanh action KHONG lien quan toi "+ ADD"
    (invalid/same_subnet/wide_full_match/none/no_rule)."""
    reason = getattr(res, 'live_match_skip_reason', None)
    if not reason:
        return None
    detail = getattr(res, 'live_match_skip_detail', None) or 'khong ro ly do'
    if reason == LIVE_MATCH_SKIP_SCALE:
        return (f"\n[Live Match CHUA duoc thu: {detail}. "
                f"Tang gioi han to hop hoac tach nho dong request roi chay lai.]")
    return (f"\n[Live Match DA chay nhung khong ket luan duoc: {detail}. "
            f"Xem log.txt de biet chi tiet tung to hop.]")


def _append_live_skip_caveat(blocks, text: str, res: RowResult) -> str:
    """Noi dong caveat Live Match (neu co) vao blocks/text cua o Name Rule.

    GHI CHU (fix dinh dang Name Rule): ham nay tu nay CHI con duoc goi o cac
    nhanh action KHONG lien quan toi "+ ADD" (invalid/same_subnet/
    wide_full_match/none/no_rule) - 3 nhanh 'add'/'candidate_config'/
    'near_match' co y KHONG goi de o Name Rule chi hien ten rule + dong hanh
    dong dang "LABEL: gia_tri" (xem _format_add_line)."""
    caveat = _live_skip_caveat(res)
    if caveat:
        blocks.append(TextBlock(_f(GREY_FONT, italic=True), caveat))
        text += caveat
    return text


def _format_add_line(label: str, res: RowResult) -> str:
    """SUA LOI: bo hoan toan res.row.raw_dest/raw_port - khong lien quan gi den
    label dang xu ly, day la nguyen nhan dong ADD SOURCE bi hien nham thanh
    Dest IP + Port cua ca dong. Moi label CHI hien dung phan du lieu cua chinh
    no, dang "LABEL: gia_tri" (khong con noi bang dau '|' voi cac field khac).
    SUA LOI (09/2026 - sap xep khi input lon xon): sort TUONG MINH theo ip_int
    tai diem hien thi (khong an theo gia dinh du lieu nguon da sort san)."""
    if label == 'ADD SOURCE':
        ordered = sorted((m for m in res.source_report
                          if m.status in ('new', 'exists')), key=lambda m: m.ip_int)
        ip = ', '.join(m.display for m in ordered)
    elif label == 'ADD DEST':
        ordered = sorted((m for m in res.dest_report
                          if m.status in ('new', 'exists')), key=lambda m: m.ip_int)
        ip = ', '.join(m.display for m in ordered)
    else:  # ADD PORT
        ip = ', '.join(
            f"{p.protocol or '?'}/{p.start}" if p.start == p.end
            else f"{p.protocol or '?'}/{p.start}-{p.end}"
            for p in res.missing_ports)
    return f"{label}: {ip}"


def _compute_action_level(res: RowResult) -> str:
    """SUA LOI (10/2026): neu dong con token Source/Dest KHONG doc duoc (bi loai khoi
    phep so khop) thi KHONG BAO GIO tra 'none' (xanh la FULL MATCH) - ket luan chi dung
    cho phan input doc duoc, phai de mau cam de admin kiem tra lai o input. Xem
    RowResult.unparsed_source/_dest.

    shadow_warning (co rule deny/drop nam TRUOC cung khop) luon keo ket qua xuong
    muc 'add' (mau cam) - du khong con muc thieu source/dest/port nao khac - vi khong
    the coi la FULL MATCH dang tin cay duoc khi con nghi ngo bi che khuat.

    used_candidate_rule (co item duoc "cuu" boi CANDIDATE config chua commit) LUON keo
    ket qua xuong muc 'candidate_config' (mau xanh ngoc/candidate rieng) - kiem tra
    TRUOC ca 'none' de KHONG BAO GIO hien FULL MATCH xanh la khi ket qua co phu thuoc
    vao du kien candidate chua co hieu luc that.

    'wide_full_match' (SUA LOI 09/2026): TOP4 + near_top2/near_top3 nhung CA HAI ben
    + Port deu da cover du qua wide-match (res.nearest_fully_covered is True, tuc
    nearest_missing_side is None - khong con gi de "+ ADD") - chi thieu dung dieu
    kien an toan exact-scope vi rule dung object RONG (subnet/group). Hien mau xanh
    duong rieng + "DA DUOC CHO PHEP", KHAC 'near_match' (mau cam, that su con thieu
    1 ben) va KHAC 'none' (mau xanh la, full match tuyet doi qua exact-scope hoac
    LIVE_MATCH xac thuc truc tiep tu firewall)."""
    has_unparsed = bool(getattr(res, 'unparsed_source', None) or
                        getattr(res, 'unparsed_dest', None))

    if res.tier == 'INVALID':
        return 'invalid'
    if res.tier == 'SAME_SUBNET':
        return 'same_subnet'
    if res.tier == 'LIVE_MATCH':
        # SUA LOI (v3 - Live Match dung som): tu v3, LIVE_MATCH khong con dam
        # bao da test HET moi combo cua dong (chi can 1 combo allow la du de
        # xac dinh rule, dung ngay) - nen source_report/dest_report GIO DAY co
        # the phan anh THAT SU con thieu 1 phan (vd 15/16 IP da duoc xac nhan
        # qua 1 combo test that + doi chieu tinh voi member cua rule, con
        # `.195` khong khop member nao) - PHAI dua vao source_report/
        # dest_report de quyet dinh can '+ ADD' hay khong, nhu TOP1-3, KHAC
        # HOAN TOAN voi truoc day (ep cung 'none' bat ke report).
        #
        # NGOAI LE giu nguyen tinh than ban fix cu: neu KHONG tim duoc
        # matched_rule_info trong file cau hinh local (API tra ve 1 ten rule
        # khong khop rule nao o local - try_live_match() danh dau bang
        # SecurityRule(index=-1, ...) gia lap), thi source_report/dest_report
        # duoc build voi rule_members=[] RONG se khien MOI IP bi gan NHAM
        # 'new' - truong hop nay VAN phai coi la FULL MATCH ('none'), vi
        # firewall THAT SU da xac nhan allow, chi la khong doi chieu duoc voi
        # file cau hinh dang dung ma thoi (khong lien quan gi den con thieu
        # IP nao that su).
        if res.rule is not None and getattr(res.rule, 'index', -1) == -1:
            return 'none'
        items = res.source_report + res.dest_report
        needs_add = any(m.status in ('new', 'exists') for m in items) or res.missing_ports
        if needs_add or has_unparsed:
            return 'add'
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
            # SUA LOI (09/2026 - wide_full_match): near nhung CA HAI ben + Port deu da
            # du (chi thieu exact-scope vi object rong) -> tang hien thi rieng, KHONG
            # con la "GAN DUNG - can xac nhan" mau cam nua.
            if getattr(res, 'nearest_fully_covered', False) is True:
                return 'wide_full_match'
            return 'near_match'
        return 'no_rule'
    items = res.source_report + res.dest_report
    needs_add = any(m.status in ('new', 'exists') for m in items) or res.missing_ports
    # SUA LOI (10/2026 - doi xung voi 'wide_full_match' da co cho near_top2/near_top3):
    # TOP2 chi bat buoc Dest cover du + exact-scope + Port du, TOP3 doi xung - KHONG he
    # xet ben con lai. Khi matcher xac nhan ben "gia dinh con thieu" THUC RA da duoc
    # chinh rule nay cover DU 100% (res.wide_fully_covered, thuong qua 1 subnet rong ma
    # tang bao cao LOCAL co y khong tinh la in_rule theo nguyen tac exact-only) thi
    # KHONG con gi de bo sung -> hien 'DA DUOC CHO PHEP' (xanh duong + khuyen nghi xac
    # nhan Live Match) thay vi mau cam "+ ADD SOURCE/DEST" + "TAO MOI" SAI.
    # Van giu 'add' khi co shadow_warning (nghi ngo bi che khuat - khong duoc tran an).
    if res.tier in ('TOP2', 'TOP3') and getattr(res, 'wide_fully_covered', False) \
            and not res.missing_ports and not res.shadow_warning and not has_unparsed:
        return 'wide_full_match'
    if needs_add or res.shadow_warning or has_unparsed:
        return 'add'
    # ZONE (10/2026): zone la dieu kien match BAT BUOC cua PAN-OS. Truoc day ham
    # nay KHONG HE doc zone_warning/zone_verdict, nen mot dong lech zone van tra
    # ve 'none' = TO XANH LA "FULL MATCH" du firewall that se chan.
    if getattr(res, 'zone_verdict', None) == 'mismatch' or res.zone_warning:
        return 'add'
    # S5: co rule deny/drop dung TRUOC se khop traffic nay -> khong the la FULL
    # MATCH dang tin cay (cung tinh than voi shadow_warning da co).
    if getattr(res, 'blocking_deny_rule', None):
        return 'add'
    return 'none'


def build_name_rule_cell(res: RowResult):
    """Vo boc quanh _build_name_rule_cell_core(): noi them dong "PHAM VI KHONG DO
    DUOC" cho MOI nhanh action.

    Vi sao phai boc o day chu khong chen vao tung nhanh: ham core co 8 nhanh
    `action` va moi nhanh tu `return` rieng. Lan dau tao chen vao 1 nhanh thi dong
    nay KHONG hien o nhanh 'near_match' - dung cai nhanh ma cong chan
    _scope_trustworthy() demote xuong, tuc dung cho can noi nhat. Boc 1 lan o ngoai
    thi khong the bo sot nhanh nao.

    Day la lop BAO CAO: KHONG doi action/mau/ket luan (viec chan da lam o
    matcher._scope_trustworthy()). Dong TOP1 "khong can lam gi" van xanh la - xem
    quyet dinh thiet ke o docstring _scope_trustworthy()."""
    cell, lines = _build_name_rule_cell_core(res)
    cell, lines = _append_blast_radius(cell, lines, res)
    cell, lines = _append_blocking_deny(cell, lines, res)
    cell, lines = _append_broad_service(cell, lines, res)
    cell, lines = _append_zone_mismatch(cell, lines, res)
    cell, lines = _append_zone_unknown(cell, lines, res)
    if not (getattr(res, 'untrusted_scope', False) and res.untrusted_scope_detail):
        return cell, lines
    extra = f"\n\u26A0 PHAM VI KHONG DO DUOC: {res.untrusted_scope_detail}"
    blocks = list(cell)
    blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _append_blast_radius(cell, lines, res: RowResult):
    """S4: in HAU QUA cua chinh de xuat "+ ADD" ngay canh de xuat do.

    Mot dong "+ ADD SOURCE" khong chi them 1 IP vao 1 rule: no cap cho IP do quyen
    di tói TOAN BO Dest cua rule, tren TOAN BO port cua rule. Khong mau nao, canh
    bao nao doi duoc hanh vi nguoi phe duyet bang viec cho ho thay con so do ngay
    luc ky."""
    if not getattr(res, 'blast_radius', None):
        return cell, lines
    extra = f"\n\u2192 PHAM VI ANH HUONG: {res.blast_radius}"
    blocks = list(cell)
    blocks.append(TextBlock(_f(ZONE_FONT, bold=False), extra))
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _append_blocking_deny(cell, lines, res: RowResult):
    """S5: rule deny/drop dung TRUOC diem chen se khop traffic nay.

    Cau hoi quyet dinh cua moi request moi thuong khong phai "co rule allow chua"
    ma "phia tren co deny nao chan truoc khong". Truoc 10/2026, cac dong KHONG chon
    duoc rule allow nao (TOP4 / "can tao Rule moi") hoan toan khong duoc kiem deny
    -> admin tao rule moi dat duoi mot deny da khop san roi bao "da them rule ma
    van khong thong"."""
    if not getattr(res, 'blocking_deny_detail', None):
        return cell, lines
    # P2 (chi co o ban Panorama): deny o Shared-PRE thi KHONG rule nao trong Device
    # Group dung truoc duoc -> nhan phai noi dung ban chat, khong phai "dat len tren".
    if getattr(res, 'blocked_at_shared_pre', False):
        nhan = "KHONG THE CAP PHEP TU DEVICE GROUP NAY"
    elif getattr(res, 'blocked_at_shared_post', False):
        # B4: nguoc dau voi P2 - o day THEM RULE VAO DG LA GIAI PHAP, nen nhan phai
        # khac han de admin khong di xin quyen Panorama mot cach khong can thiet.
        nhan = "BI CHAN O SHARED-POST (them rule vao Device Group la giai quyet duoc)"
    else:
        nhan = "BI CHAN TRUOC"
    extra = f"\n\u26D4 {nhan}: {res.blocking_deny_detail}"
    blocks = list(cell)
    blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _append_broad_service(cell, lines, res: RowResult):
    """Dong thong tin: "traffic nay THUC TE da duoc phep boi 1 rule Service=any".

    KHONG phai ket luan cua dong (luat II.2.2: rule service=any khong bao gio duoc
    lam ket qua), nen khong doi action/mau. Nhung im lang thi sai: truoc 10/2026
    nhanh TOP1.1 khong kiem Service nen tool con di khuyen "+ ADD PORT" vao chinh
    rule service=any - mot change VO NGHIA, va con lam rule do trong co chu dich
    khien lan audit sau kho bat hon."""
    if not getattr(res, 'broad_service_rule', None):
        return cell, lines
    extra = (f"\n\u2139 LUU Y: traffic nay THUC TE da duoc phep boi rule "
             f"'{res.broad_service_rule}' (Service=any, Source/Dest khop dung "
             f"request). Theo luat, rule qua rong KHONG duoc dung lam ket qua - "
             f"xem tab CHECK AUDIT (Overly Permissive) de don rule do, va "
             f"TUYET DOI khong them port vao no (khong co tac dung).")
    blocks = list(cell)
    blocks.append(TextBlock(_f(GREY_FONT, italic=True), extra))
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _append_zone_mismatch(cell, lines, res: RowResult):
    """In ly do "THIEU ZONE" cho CAC NHANH MA CORE KHONG IN.

    _compute_zone_warning() tu truoc gio chi duoc goi o 4 diem return cua
    TOP1/1.1/2/3. Nhung cong chan zone (10/2026) demote rule lech zone xuong nhanh
    TOP4 - dung nhanh ma core KHONG in zone_warning - nen dong bi demote hien ten
    rule MA KHONG NEU LY DO. Admin khong the biet vi sao, va se di tao rule trung
    thay vi sua zone cua rule da co. Day la lan thu hai dung loi "ban va vo hinh",
    nen lan nay in o lop ngoai nhu _append_zone_unknown.

    Chan in trung: neu core DA in dong THIEU ZONE roi thi khong in lai."""
    if not res.zone_warning:
        return cell, lines
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    if "THIEU ZONE" in old_text.upper():
        return cell, lines
    extra = f"\n\u26A0 THIEU ZONE: {res.zone_warning}"
    blocks = list(cell)
    blocks.append(TextBlock(_f(ZONE_FONT, bold=True), extra))
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _append_zone_unknown(cell, lines, res: RowResult):
    """Trang thai ZONE_UNKNOWN truoc day IM LANG hoan toan (coi nhu zone da khop).

    Nay phai noi ro: "chua kiem duoc zone" KHAC "zone da khop". Khong demote tier
    (xem docstring matcher._zone_verdict) - chi de nguoi doc khong hieu nham rang
    tool da kiem zone xong roi."""
    if getattr(res, 'zone_verdict', None) != 'unknown':
        return cell, lines
    if not getattr(res, 'zone_unknown_detail', None):
        return cell, lines
    extra = f"\n\u2139 CHUA KIEM DUOC ZONE: {res.zone_unknown_detail}"
    blocks = list(cell)
    blocks.append(TextBlock(_f(GREY_FONT, italic=True), extra))
    old_text = "".join(getattr(b, 'text', '') or '' for b in cell)
    return CellRichText(blocks), _estimate_wrapped_lines(old_text + extra,
                                                          NAME_RULE_COL_CHARS)


def _build_name_rule_cell_core(res: RowResult):
    action = _compute_action_level(res)

    if action == 'invalid':
        text = res.note or 'Du lieu khong hop le'
        caveat = _live_skip_caveat(res)
        if caveat:
            text += caveat
        return CellRichText([TextBlock(_f(GREY_FONT, italic=True), text)]), \
            _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'same_subnet':
        text = "Khong can tao Rule"
        blocks = [TextBlock(_f(BLUE_FONT, bold=True), text)]
        text = _append_live_skip_caveat(blocks, text, res)
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
            extra = "\n" + _format_add_line(label, res)
            blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
            text += extra
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'wide_full_match':
        # SUA LOI (09/2026): near_top2/near_top3 nhung khong con gi de "+ ADD" (ca 2
        # ben + Port deu da cover du, chi vi rule dung Source/Dest dang RONG nen
        # khong qua duoc exact-scope) - thong diep phai ro rang la "DA duoc cho phep",
        # kem 1 dong khuyen nghi xac minh (khong phai yeu cau bo sung). Dat TRUOC
        # nhanh 'near_match' de khong roi nham vao mau cam "GAN DUNG" nua.
        # TOP4/near_* dung res.nearest_rule; TOP2/TOP3 (SUA LOI 10/2026) co rule THAT
        # trong res.rule - uu tien res.rule.
        matched = res.rule or res.nearest_rule
        rule_name = matched.name if matched else "Unknown Rule"
        text = f"{rule_name}\nDA DUOC CHO PHEP"
        blocks = [TextBlock(_f(WIDE_MATCH_FONT, bold=True), rule_name),
                  TextBlock(_f(WIDE_MATCH_FONT, bold=True), "\nDA DUOC CHO PHEP")]
        caveat = "\n(Khuyen nghi chay Live Match de xac nhan tuyet doi.)"
        blocks.append(TextBlock(_f(GREY_FONT, italic=True), caveat))
        text += caveat
        text = _append_live_skip_caveat(blocks, text, res)
        return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

    if action == 'near_match':
        # near_top2/near_top3 (xem _find_nearest_candidate_rule trong matcher.py): da
        # xac dinh 1 rule CU THE co Port du + 1 ben (Source hoac Dest) da khop du, chi
        # thieu dung 1 ben con lai -> hien dinh dang hanh dong cu the de admin nhan
        # ra ngay day la goi y hanh dong (o duoi, danh cho TOP1.1/TOP2/TOP3).
        #
        # SUA LOI (bao cao "Full match cho input nhung output van bao thieu Source" -
        # vd rule co Dest 5/5 khop + Source 23/23 khop + Port du nhung van bi gan nhan
        # '+ ADD SOURCE'): nhan ADD SOURCE/DEST TRUOC DAY duoc gan CUNG chi dua vao
        # res.nearest_rule_kind (near_top2 -> luon 'ADD SOURCE', near_top3 -> luon 'ADD
        # DEST'), BAT KE ben do THUC TE da duoc chinh rule nay cover DU hay chua (near_
        # top2 chi dam bao Dest da du, KHONG noi gi ve Source - Source co the da du roi
        # qua 1 subnet/wide rong nhu Net_10.0.0.0/8). Nay dung res.nearest_missing_side
        # (matcher.py da tinh: None neu ben do THUC RA da khop du 100%) de quyet dinh co
        # hien nhan ADD hay khong - neu ca 2 ben deu da khop du (chi con thieu dieu
        # kien an toan 'exact-scope' cua tier That TOP2/TOP3), KHONG con gi de "them" nen
        # KHONG hien nhan do.
        #
        # FIX DINH DANG (o Name Rule chi hien thong tin can thiet): moi dong ADD theo
        # khuon "{LABEL} | {DEST} | {PORT} | {IP}" (xem _format_add_line) thay vi
        # "+ {label}" tran; BO dong caveat xam "(GAN DUNG...)" va KHONG noi them dong
        # Live Match skip o nhanh nay (chi tiet IP/port day du da co o 3 cot
        # Source/Dest/Port rieng).
        rule_name = res.nearest_rule.name if res.nearest_rule else "Unknown Rule"
        blocks = [TextBlock(_f(ORANGE_FONT, bold=True), rule_name)]
        text = rule_name
        if res.nearest_missing_side is not None:
            label = 'ADD SOURCE' if res.nearest_missing_side == 'source' else 'ADD DEST'
            extra = "\n" + _format_add_line(label, res)
            blocks.append(TextBlock(_f(RED_FONT, bold=True), extra))
            text += extra
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
            detail_line = res.nearest_rule.name
            blocks = [TextBlock(_f(RED_FONT, bold=True), line1),
                      TextBlock(_f(ORANGE_FONT, bold=True), "\n" + detail_line)]
            text = line1 + "\n" + detail_line
            text = _append_live_skip_caveat(blocks, text, res)
            return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)

        text = "\u26A0 Chua co Rule - can tao moi"
        blocks = [TextBlock(_f(RED_FONT, bold=True), text)]
        text = _append_live_skip_caveat(blocks, text, res)
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
            extra = "\n" + _format_add_line(label, res)
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

    # Caveat Live Match (neu co) - CHI ap dung cho nhanh 'none'/FULL MATCH LOCAL
    # con lai di toi day; 'add'/'candidate_config' co y KHONG noi caveat nay de
    # o Name Rule chi hien thong tin can hanh dong (xem _append_live_skip_caveat).
    if action not in ('add', 'candidate_config'):
        text = _append_live_skip_caveat(blocks, text, res)

    return CellRichText(blocks), _estimate_wrapped_lines(text, NAME_RULE_COL_CHARS)


def build_field_cell(items: List[MissingItem], unparsed: Optional[List[str]] = None):
    blocks = _build_field_lines(items, unparsed)
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
    if action == 'wide_full_match':
        return PatternFill('solid', fgColor=WIDE_MATCH_FILL)
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

    # BAN PANORAMA (0.3): chen cot 'Vi tri Rule' o vi tri 2 - cho biet rule nam o
    # dau trong thu tu danh gia that (Shared-PRE / <DG>-PRE / Local / <DG>-POST /
    # Shared-POST). Cac cot con lai DICH SANG PHAI 1 o, khong doi noi dung gi.
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

        # BAN PANORAMA: lay vi tri cua rule DUOC CHON (TOP1-3/LIVE_MATCH) hoac cua
        # rule GAN DUNG NHAT (TOP4/near_*) - de dong near_match cung biet rule goi y
        # nam o Shared hay DG nao, pre hay post.
        vi_tri_rule = res.rule or res.nearest_rule
        vi_tri_val = getattr(vi_tri_rule, 'vi_tri', '') if vi_tri_rule is not None else ''
        c_vi = ws.cell(row=i, column=2, value=vi_tri_val)
        c_vi.alignment = center
        c_vi.border = border
        c_vi.font = base_font
        _set_text_cell(c_vi)
        if vi_tri_val.startswith("Shared"):
            c_vi.fill = PatternFill('solid', fgColor="FFF2F2F2")

        src_cell, src_lines = build_field_cell(res.source_report,
                                                getattr(res, 'unparsed_source', None))
        c2 = ws.cell(row=i, column=3, value=src_cell if src_cell is not None else "")
        c2.alignment = wrap
        c2.border = border
        c2.font = base_font
        _set_text_cell(c2)

        dst_cell, dst_lines = build_field_cell(res.dest_report,
                                                getattr(res, 'unparsed_dest', None))
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
         "RONG HON input nen chua qua duoc kiem tra an toan tuyet doi nhu Mau CAM loai (a). "
         "Loai (b) CHI ap dung khi THAT SU con thieu 1 ben (nearest_missing_side khac None)."),
        ("Mau XANH DUONG NHAT (DA DUOC CHO PHEP)", "near_top2/near_top3 nhung CA HAI ben Source+Dest VA Port "
         "deu DA cover du qua wide-match (khong con gi de '+ ADD'), chi thieu dung dieu kien an toan "
         "exact-scope vi rule dung Source/Dest dang RONG (subnet/group). Ten rule + dong 'DA DUOC CHO PHEP' "
         "kem dong xam khuyen nghi chay Live Match de xac nhan tuyet doi. KHAC Mau XANH LA (FULL MATCH tuyet "
         "doi qua exact-scope hoac LIVE_MATCH) va KHAC Mau CAM (GAN DUNG that su con thieu 1 ben)."),
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
        ("O Source/Dest - chu CAM co '(cover full IP(s))' hoac '(cover: <IP...>)'", "IP nay DA ton tai duoi dang 1 "
         "object/group KHAC tren thiet bi nhung CHUA nam trong group cua rule dang xet - CAN duoc them vao rule "
         "(khong can tao moi tu dau). 'cover full' = group nay cover HET cac IP dau vao. 'cover: <IP...>' = "
         "liet ke ro nhung IP cu the ma group nay cover (sap xep tang dan, gom theo group). Mau CAM de phan "
         "biet ro voi mau XANH LA (da nam san trong rule, khong can lam gi them) - xem nhan 'ADD SOURCE/DEST' "
         "o cot Name Rule de biet ro con thieu gi."),
        ("Ky hieu '- ... \u2192 TAO MOI' (do)", "Gia tri IP/Port nay CHUA ton tai o bat ky dau tren thiet bi"),
        ("Ky hieu '- ... \u2192 DA CO (ten Service)' (cam, cot Port)", "Port nay CHUA nam trong Rule dang xet, "
         "nhung DA CO SAN 1 Service object dai dien CHINH XAC tren thiet bi (ten hien kem theo) - CHI can them "
         "Service do vao Rule, KHONG can tao Service object moi."),
        ("Mau TIM (cot Name Rule)", "Rule da tim duoc DU dieu kien Source/Dest/Port nhung THIEU Source Zone "
         "hoac Dest Zone - can bo sung Zone vao rule de traffic thuc su duoc cho phep. Zone duoc tool TU DONG "
         "suy ra tu IP dua tren cau hinh Interface/Zone that tren thiet bi (khong phai nguoi dung nhap tay); "
         "zone 'any' luon duoc coi la du."),
        ("Caveat Live Match (xam, cot Name Rule)", "Chi hien khi Live Match DA DUOC BAT (co Management IP + API "
         "Key) nhung khong hoan tat cho dong nay - ap dung cho MOI action level vi day la thong tin ve QUA "
         "TRINH kiem tra: '[Live Match CHUA duoc thu: ...]' = vuot gioi han quy mo, CHUA goi API lan nao "
         "(tang 'Gioi han to hop Live Match' hoac tach nho dong request roi chay lai); '[Live Match DA chay "
         "nhung khong ket luan duoc: ...]' = DA goi API nhung loi/timeout, 1 combo bi deny, hoac khop nhieu "
         "rule khac nhau (xem log.txt chi tiet tung to hop). Khong hien khi chua bat Live Match tu dau."),
        ("Cot 'Vi tri Rule' (PANORAMA, 0.3)", "Cho biet rule nam o dau trong THU TU DANH GIA THAT cua "
         "PAN-OS: Shared-PRE -> <DG to tien>-PRE -> ... -> <DG hien tai>-PRE -> Local (rule cuc bo tren "
         "firewall, neu co) -> <DG hien tai>-POST -> ... -> <DG to tien>-POST -> Shared-POST. CUNG 1 ten "
         "rule co the ton tai o nhieu vi tri khac nhau - cot nay cho biet chinh xac rule nao dang duoc noi toi."),
        ("CANDIDATE CONFIG (PANORAMA, 0.4)", "Canh bao THAM KHAO: object/rule da ton tai trong candidate-config "
         "CHUA COMMIT cua Panorama - KHONG dung de ket luan traffic da duoc phep. Panorama co 2 TANG COMMIT: "
         "'Commit to Panorama' roi moi 'Commit and Push' xuong firewall - phai lam CA 2 buoc thi rule moi co "
         "hieu luc that."),
        ("Nguyen tac quan trong nhat", "CHI object/group KHOP CHINH XAC mới duoc chap nhan"),
        ("Luu y Source/Dest", "LUON hien day du trang thai cho TUNG IP trong file input"),
        ("Luu y Port", "Chi hien cac Port CON THIEU/can tao moi"),
    ]
    colors = [None, GREEN_FILL, ORANGE_FILL, WIDE_MATCH_FILL, RED_FILL, BLUE_FILL, ORANGE_FILL, None, None, ORANGE_FILL, None,
              ORANGE_FILL, ZONE_FILL, None, None, CANDIDATE_FILL, None, None, None]
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
