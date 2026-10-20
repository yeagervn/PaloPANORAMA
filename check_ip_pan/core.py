# -*- coding: utf-8 -*-
"""
core.py - Thanh phan nen tang: hang so + template Excel nhung san, exception
tuy chinh, data model (dataclass), va cac ham tien ich xu ly IP/CIDR.
(Gop tu config.py + exceptions.py + models.py + ip_utils.py cu)
"""

import os
import sys
import io
import re
import base64
import logging
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple

# ============================================================================
# CAU HINH / HANG SO / TEMPLATE EXCEL NHUNG SAN / LOGGING
# ============================================================================
APP_NAME = "PaloRuleSearch"
APP_TITLE = "Palo Alto Rule Search Tool"
DEFAULT_TIMEOUT = 30          # giay, cho moi HTTP request toi firewall
DEFAULT_WORKERS = max(30, (os.cpu_count() or 4) * 2)   # toi thieu 30, hoac CPU*2

# Thu muc goc: neu da dong goi thanh .exe (PyInstaller), lay thu muc chua file .exe
# Neu chay bang python truc tiep, lay thu muc chua script .py
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# "check_ip" subfolder rieng: khi dong goi chung 1 Suite voi tool CHECK RULE,
# tranh 2 tool cung ghi de len 1 thu muc output/1 file log.txt chung (moi tool
# hoan toan doc lap ve noi luu ket qua/log, dung yeu cau "tach biet hoan toan").
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "check_ip")
LOG_PATH = os.path.join(OUTPUT_DIR, "log.txt")

# Cac cot bo sung se duoc ghi THEM vao ben phai 4 cot co san cua template
# (Name Rule / Source IP / Dest IP / Service), de dam bao xuat FULL thong tin
# Rule theo yeu cau, ma khong pha vo style/vi tri 4 cot goc cua template.
EXTRA_HEADERS = [
    "Matched Side", "UUID", "Source Zone", "Destination Zone",
    "Application", "Action", "Security Profile", "Log Setting", "Schedule",
    "Description", "Tag", "Disabled", "Target", "HIP", "Source User",
]

# 3 cot nay CHI duoc chen (ngay sau Name Rule) khi nguoi dung co dua vao 1 file
# Log doi chieu (Source IP/Dest IP/Port thuc te lay tu he thong log). Neu
# khong co file Log, khong chen - giu nguyen 100% cau truc cu.
LOG_EXTRA_HEADERS = ["Log Source IP", "Log Dest IP", "Log Port"]

# Template Excel CO DINH (form output mau da duoc xac nhan la ban chuan) -
# nhung sau bang base64 ngay trong script, KHONG can nguoi dung chon file
# template moi lan chay nua. Neu sau nay can doi template, chi can thay noi
# dung bien nay (co the tao lai bang: base64.b64encode(open(path,"rb").read())).
_EMBEDDED_TEMPLATE_B64 = (
    "UEsDBBQABgAIAAAAIQBi7p1oXgEAAJAEAAATAAgCW0NvbnRlbnRfVHlwZXNdLnhtbCCiBAIooAACAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACslMtOwzAQRfdI/EPkLUrcskAINe2CxxIqUT7AxJPG"
    "qmNbnmlp/56J+xBCoRVqN7ESz9x7MvHNaLJubbaCiMa7UgyLgcjAVV4bNy/Fx+wlvxcZknJaWe+gFBtAMRlfX41mmwCYcbfDUjRE"
    "4UFKrBpoFRY+gOOd2sdWEd/GuQyqWqg5yNvB4E5W3hE4yqnTEOPRE9RqaSl7XvPjLUkEiyJ73BZ2XqVQIVhTKWJSuXL6l0u+cyi4"
    "M9VgYwLeMIaQvQ7dzt8Gu743Hk00GrKpivSqWsaQayu/fFx8er8ojov0UPq6NhVoXy1bnkCBIYLS2ABQa4u0Fq0ybs99xD8Vo0zL"
    "8MIg3fsl4RMcxN8bZLqej5BkThgibSzgpceeRE85NyqCfqfIybg4wE/tYxx8bqbRB+QERfj/FPYR6brzwEIQycAhJH2H7eDI6Tt7"
    "7NDlW4Pu8ZbpfzL+BgAA//8DAFBLAwQUAAYACAAAACEAtVUwI/QAAABMAgAACwAIAl9yZWxzLy5yZWxzIKIEAiigAAIAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKySTU/DMAyG70j8h8j31d2QEEJL"
    "d0FIuyFUfoBJ3A+1jaMkG92/JxwQVBqDA0d/vX78ytvdPI3qyCH24jSsixIUOyO2d62Gl/pxdQcqJnKWRnGs4cQRdtX11faZR0p5"
    "KHa9jyqruKihS8nfI0bT8USxEM8uVxoJE6UchhY9mYFaxk1Z3mL4rgHVQlPtrYawtzeg6pPPm3/XlqbpDT+IOUzs0pkVyHNiZ9mu"
    "fMhsIfX5GlVTaDlpsGKecjoieV9kbMDzRJu/E/18LU6cyFIiNBL4Ms9HxyWg9X9atDTxy515xDcJw6vI8MmCix+o3gEAAP//AwBQ"
    "SwMEFAAGAAgAAAAhAIE+lJfzAAAAugIAABoACAF4bC9fcmVscy93b3JrYm9vay54bWwucmVscyCiBAEooAABAAAAAAAAAAAAAAAA"
    "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"
)


def _get_template_bytes() -> io.BytesIO:
    """Giai ma template Excel nhung san thanh file nam trong bo nho (khong dong
    tram xuong dia), dung truc tiep voi openpyxl.load_workbook()."""
    return io.BytesIO(base64.b64decode(_EMBEDDED_TEMPLATE_B64))


def setup_logger(log_path: str) -> logging.Logger:
    """Ghi log.txt: moi dong co timestamp. Khong crash neu khong the tao file log."""
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)
    except OSError:
        # Neu khong ghi duoc file log (vi du thu muc bi khoa quyen), van tiep tuc chay,
        # chi la se khong co log.txt. Khong duoc phep crash chuong trinh vi ly do nay.
        logger.addHandler(logging.NullHandler())
    return logger

# ============================================================================
# EXCEPTIONS
# ============================================================================
class PanApiError(Exception):
    """Loi API tong quat. user_message la text than thien de hien Popup cho nguoi dung."""
    def __init__(self, message: str, user_message: str = None):
        super().__init__(message)
        self.user_message = user_message or message


class PanConnectionError(PanApiError):
    pass


class PanTimeoutError(PanApiError):
    pass


class PanAuthError(PanApiError):
    pass

# ============================================================================
# DATA MODELS (dataclass)
# ============================================================================
@dataclass
class AddressObject:
    name: str
    kind: str          # 'ip-netmask' | 'ip-range' | 'fqdn' | 'unknown'
    raw_value: str


@dataclass
class AddressGroup:
    name: str
    kind: str                              # 'static' | 'dynamic'
    members: List[str] = field(default_factory=list)   # danh sach member (static)
    filter_expr: str = ""                  # tag filter expression (dynamic)


@dataclass
class ServiceObject:
    name: str
    protocol: str    # 'tcp' | 'udp' | 'unknown'
    port: str        # raw port string, vd '1521', '80,8080', '1521-1522'


@dataclass
class ServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)


@dataclass
class LogEntry:
    """1 dong traffic THAT lay tu file Log doi chieu (Source IP/Dest IP/Port)."""
    source_ip: str
    dest_ip: str
    port: str


@dataclass
class SecurityRule:
    index: int
    name: str
    uuid: str = ""
    from_zones: List[str] = field(default_factory=list)
    to_zones: List[str] = field(default_factory=list)
    source: List[str] = field(default_factory=list)
    destination: List[str] = field(default_factory=list)
    application: List[str] = field(default_factory=list)
    service: List[str] = field(default_factory=list)
    action: str = ""
    security_profile: str = ""
    log_setting: str = ""
    schedule: str = ""
    description: str = ""
    tags: List[str] = field(default_factory=list)
    disabled: bool = False
    target: str = ""
    hip: str = ""
    source_user: List[str] = field(default_factory=list)
    # Vi tri RPAN entry (bản Panorama) - gia tri: 'Shared-PRE' | '<DG>'-PRE |
    # '<DG>'-POST | 'Shared-POST' | '' (bản Firewall đơn không dùng, để rỗng).
    vi_tri: str = ""


@dataclass
class NatRule:
    """1 NAT Rule (rulebase/nat/rules/entry) - gom ca Source Translation va
    Destination Translation (ho tro dynamic-ip-and-port / dynamic-ip /
    static-ip / destination-translation / dynamic-destination-translation)."""
    index: int
    name: str
    uuid: str = ""
    from_zones: List[str] = field(default_factory=list)
    to_zones: List[str] = field(default_factory=list)
    to_interface: str = ""
    source: List[str] = field(default_factory=list)
    destination: List[str] = field(default_factory=list)
    service: str = "any"
    nat_type: str = "ipv4"
    disabled: bool = False
    description: str = ""
    tags: List[str] = field(default_factory=list)

    # Source Translation
    src_xlate_type: str = ""            # "" | "dynamic-ip-and-port" | "dynamic-ip" | "static-ip"
    src_xlate_addresses: List[str] = field(default_factory=list)   # translated-address member(s)
    src_xlate_interface: str = ""       # dynamic-ip-and-port kieu interface-address
    src_xlate_interface_ip: str = ""    # ip gan kem interface-address (co the la Address Object)
    src_xlate_bidirectional: bool = False   # static-ip <bi-directional>

    # Destination Translation
    dst_xlate_type: str = ""            # "" | "static" | "dynamic"
    dst_xlate_address: str = ""
    dst_xlate_port: str = ""

    # Vi tri RPAN entry (bản Panorama) - giong SecurityRule.vi_tri.
    vi_tri: str = ""


# Header cho file xuat rieng cua bang NAT (workbook/CSV moi, khong dung
# template Security Rule vi cau truc cot khac hoan toan). Cot "Nguon Rule"
# them BAT BUOC (III.7): cho biet rule nam o pre/post-rulebase cua Shared hay
# Device Group nao (khong con 1 vsys duy nhat de ngam dinh).
NAT_HEADERS = [
    "Rule Name", "Nguon Rule", "UUID", "Disabled", "Tag", "Description",
    "Source Zone", "Destination Zone", "To Interface",
    "Source Address", "Destination Address", "Service", "NAT Type",
    "Source Translation Type", "Source Translated Address", "Source Bi-Directional",
    "Destination Translation Type", "Destination Translated Address", "Destination Translated Port",
]

# ============================================================================
# IP / CIDR UTILITIES (bao gom ho tro input dang RANGE)
# ============================================================================
# Gioi han an toan khi nguoi dung nhap 1 range IP (vd A-B) o muc Input IP -
# tranh truong hop go nham 1 range qua rong (vd het 1 subnet /8) lam "no" ra
# hang trieu IP can tim, gay treo/cham chuong trinh.
MAX_INPUT_RANGE_SIZE = 65536


# SUA LOI (10/2026 - "input dang IP range tren device da co nhung tool khong doc
# duoc"): o "Danh sach IP can tim" truoc day CHI nhan dung 1 dinh dang
# "IP1-IP2" voi dau tru ASCII va KHONG co khoang trang. Thuc te file/clipboard cua
# nguoi dung hay co: "10.1.1.1 - 10.1.1.5" (co khoang trang - bi parse_ip_list_input()
# tach thanh 3 token roi chi tim duoc 2 dau mut!), en/em dash do Excel/Word tu doi,
# dang rut gon octet cuoi "10.1.1.100-110", dung '~'/'..'/'to', kem '/32'.
# 2 pattern duoi day dung CHUNG cho ca buoc chuan hoa (_normalize_range_text) va buoc
# "no" range (_expand_range_token). LUU Y KIEN TRUC: check_ip KHONG BAO GIO import
# check_rule (va nguoc lai) - day la ban sao doc lap co y, dung nguyen tac 3 package
# cach ly 100%.
_IPV4_TXT = r"\d{1,3}(?:\.\d{1,3}){3}"
_RANGE_SEP_TXT = r"(?:[-\u2010\u2011\u2012\u2013\u2014\u2015\u2212~]|\.{2,}|\bto\b)"
_RANGE_FULL_RE = re.compile(r"^(%s)(?:/32)?\s*%s\s*(%s)(?:/32)?$"
                            % (_IPV4_TXT, _RANGE_SEP_TXT, _IPV4_TXT), re.IGNORECASE)
_RANGE_SHORT_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})(?:/32)?\s*%s\s*(\d{1,3})(?:/32)?$"
                             % _RANGE_SEP_TXT, re.IGNORECASE)
# Dung de GOM lai 1 range da bi khoang trang lam vo truoc khi tach token. Chi dung
# [ \t]* (KHONG dung \s*) de khong bao gio gom 2 IP nam o 2 DONG khac nhau.
_RANGE_INLINE_RE = re.compile(
    r"(%s)(?:/32)?[ \t]*%s[ \t]*(%s|\d{1,3})(?:/32)?"
    % (_IPV4_TXT, _RANGE_SEP_TXT, _IPV4_TXT), re.IGNORECASE)


def _normalize_range_text(text: str) -> str:
    """Gom moi dang range "IP <dau phan cach> IP/octet" thanh dang chuan "IP1-IP2"
    (khong khoang trang) TRUOC khi parse_ip_list_input() tach token theo
    khoang trang/dau phay - neu khong, "10.1.1.1 - 10.1.1.5" se bi tach thanh
    3 token va chi tim duoc dung 2 dau mut (mat het IP o giua)."""
    def _join(m):
        a, b = m.group(1), m.group(2)
        if "." not in b:  # dang rut gon octet cuoi: 10.1.1.100-110
            b = "%s.%s" % (a.rsplit(".", 1)[0], b)
        return "%s-%s" % (a, b)
    return _RANGE_INLINE_RE.sub(_join, text or "")


def _expand_range_token(tok: str) -> Optional[List[str]]:
    """Neu tok la 1 range (vd '10.100.10.102-10.100.10.108', '10.100.10.102-108',
    hoac dung en-dash/'~'/'..'/'to'), tra ve danh sach IP CU THE trong khoang do
    (bao gom ca 2 dau). Tra ve None neu tok khong phai dinh dang range hop le (de
    con thu parse nhu 1 IP don o noi goi)."""
    tok = (tok or "").replace("\u00a0", " ").strip()
    m = _RANGE_FULL_RE.match(tok)
    if m:
        a_txt, b_txt = m.group(1), m.group(2)
    else:
        m = _RANGE_SHORT_RE.match(tok)
        if not m:
            return None
        a_txt = "%s.%s" % (m.group(1), m.group(2))
        b_txt = "%s.%s" % (m.group(1), m.group(3))
    try:
        start_ip = ipaddress.ip_address(a_txt)
        end_ip = ipaddress.ip_address(b_txt)
    except ValueError:
        return None
    if start_ip.version != end_ip.version or int(start_ip) > int(end_ip):
        return None
    ip_cls = type(start_ip)
    count = int(end_ip) - int(start_ip) + 1
    if count > MAX_INPUT_RANGE_SIZE:
        return None  # range qua rong - coi nhu khong hop le, tranh "no" qua nhieu IP
    return [str(ip_cls(i)) for i in range(int(start_ip), int(end_ip) + 1)]


def parse_ip_list_input(text: str) -> Tuple[List[str], List[str]]:
    """
    Parse danh sach IP nguoi dung paste vao (xuong dong / tab / khoang trang /
    dau phay / copy truc tiep tu Excel). Tu dong loai bo dong trong va IP trung
    (giu thu tu xuat hien dau tien).

    Ho tro CA dinh dang RANGE IP go thang tay, vi du:
        10.100.10.102-10.100.10.108
    se duoc tu dong "no" ra thanh tung IP rieng le (10.100.10.102,
    10.100.10.103, ..., 10.100.10.108) de dua vao danh sach tim, giong het
    nhu nguoi dung go tung dong 1 IP.

    Tra ve: (danh_sach_ip_hop_le, danh_sach_dong_khong_hop_le)
    """
    tokens = re.split(r"[\s,;]+", _normalize_range_text(text).strip())
    seen: Set[str] = set()
    valid: List[str] = []
    invalid: List[str] = []
    for tok in tokens:
        tok = tok.strip()
        if not tok:
            continue

        expanded = _expand_range_token(tok)
        if expanded is not None:
            for norm in expanded:
                if norm not in seen:
                    seen.add(norm)
                    valid.append(norm)
            continue

        try:
            norm = str(ipaddress.ip_address(tok))
            if norm not in seen:
                seen.add(norm)
                valid.append(norm)
        except ValueError:
            invalid.append(tok)
    return valid, invalid


def build_run_plan(ip_text: str, logfile_path: str, nat_mode_full: bool,
                    nat_ip_text: str, nat_format: str, worker_count_raw) -> Tuple[dict, List[str]]:
    """Lap ke hoach + kiem tra input cho 1 luot bam nut "Check / Export" cua tab
    CHECK IP (10/2026 - gop 2 nut "Check" va "Export NAT" thanh 1).

    HAM THUAN TUY (khong dung tkinter, khong doc widget) de co the unit-test duoc
    toan bo luat quyet dinh - GUI chi lam viec doc widget roi goi vao day.

    LUAT (dung yeu cau nguoi dung):
      - Check Rule (muc 2 + 3) chay khi: muc 2 co IT NHAT 1 IP hop le HOAC muc 3 co
        File Log. De trong CA HAI -> bo qua phan nay, KHONG phai loi.
      - Export NAT (muc 4) chay khi: chon "Yes (Full)" (khong can nhap IP), HOAC chon
        "No (Search)" VA co it nhat 1 IP hop le. De trong o Search -> bo qua phan
        nay, KHONG phai loi.
      - Nhap ca 2 ben -> chay CA HAI trong cung 1 luot (xuat 2 file).
      - Khong ben nao co du lieu -> errors, chan lai.
      - O CO chu nhung KHONG co IP nao hop le -> errors (nguoi dung dinh tim that
        nhung go sai dinh dang, KHONG duoc im lang bo qua).

    Tra ve (plan, errors). errors rong = chay duoc."""
    errors: List[str] = []

    valid_ips, invalid_ips = parse_ip_list_input(ip_text or "")
    if (ip_text or "").strip() and not valid_ips:
        errors.append("Muc 2: khong co IP nao hop le (vd sai dinh dang: "
                      + ", ".join(invalid_ips[:5]) + ").")

    logfile_path = (logfile_path or "").strip()
    if logfile_path:
        if not os.path.isfile(logfile_path):
            errors.append(f"Muc 3: khong tim thay file\n{logfile_path}")
        elif os.path.splitext(logfile_path)[1].lower() not in (".xlsx", ".csv"):
            ext = os.path.splitext(logfile_path)[1] or "khong co duoi"
            errors.append(f"Muc 3: File Log chi ho tro .xlsx hoac .csv (dang chon: {ext}).")

    nat_ips, nat_invalid = parse_ip_list_input(nat_ip_text or "")
    if (nat_ip_text or "").strip() and not nat_ips:
        errors.append("Muc 4: khong co IP nao hop le (vd sai dinh dang: "
                      + ", ".join(nat_invalid[:5]) + ").")

    do_rule = bool(valid_ips) or bool(logfile_path)
    do_nat = bool(nat_mode_full) or bool(nat_ips)

    if not do_rule and not do_nat:
        errors.append(
            "Chua co gi de chay. Can IT NHAT 1 trong 2:\n"
            "  - Muc 2 (danh sach IP) va/hoac muc 3 (File Log)  -> Check Rule\n"
            "  - Muc 4: chon 'Yes (Full)', hoac 'No (Search)' + nhap IP  -> Export NAT")

    try:
        worker_count = int(worker_count_raw)
    except (ValueError, TypeError):
        worker_count = DEFAULT_WORKERS
    worker_count = max(20, min(50, worker_count))

    plan = {
        "do_rule": do_rule,
        "do_nat": do_nat,
        "valid_ips": valid_ips,
        "invalid_ips": invalid_ips,
        "logfile_path": logfile_path,
        "nat_mode_full": bool(nat_mode_full),
        "nat_format": (nat_format or "xlsx"),
        # Yes (Full): IP nhap CHI de highlight. No (Search): IP nhap de LOC rule.
        "nat_highlight_ips": nat_ips if nat_mode_full else [],
        "nat_filter_ips": [] if nat_mode_full else nat_ips,
        "nat_invalid": nat_invalid,
        "worker_count": worker_count,
    }
    return plan, errors


def describe_run_plan(plan: dict) -> str:
    """1 dong mo ta luot chay sap toi, hien canh nut Run de nguoi dung biet TRUOC
    khi bam la se chay cai gi (khong con phai doan nut nao lam viec gi)."""
    parts = []
    if plan.get("do_rule"):
        n = len(plan.get("valid_ips") or [])
        detail = f"{n} IP" if n else "File Log"
        if n and plan.get("logfile_path"):
            detail += " + File Log"
        parts.append(f"Check Rule ({detail})")
    if plan.get("do_nat"):
        parts.append("Export NAT ({})".format(
            "Full" if plan.get("nat_mode_full")
            else f"Search {len(plan.get('nat_filter_ips') or [])} IP"))
    if not parts:
        return "Chua co gi de chay (xem muc 2/3/4)"
    return "Se chay: " + " + ".join(parts)


def is_literal_ip_or_cidr(s: str) -> bool:
    """True neu s la mot IP hoac CIDR literal (khong phai ten object/group)."""
    try:
        ipaddress.ip_network(s.strip(), strict=False)
        return True
    except ValueError:
        return False


def netmask_to_match_value(value: str) -> Optional[str]:
    """
    Quy tac quan trong (muc 10 spec): CHI chap nhan Exact Host Object.
    - ip-netmask la host don (/32 hoac /128, hoac khong co '/') -> tra ve IP chuan hoa.
    - ip-netmask la subnet rong hon (/24, /16, ...) -> REJECT, tra ve None
      (khong duoc coi la match, du input IP co nam trong subnet do).
    """
    value = value.strip()
    try:
        network = ipaddress.ip_network(value, strict=False)
        if network.num_addresses == 1:
            return str(network.network_address)
        return None
    except ValueError:
        return None


def parse_ip_range(value: str) -> Optional[Tuple[int, int]]:
    """Parse object kieu 'ip-range': '10.10.10.1-10.10.10.50' -> (start_int, end_int).
    ip-range LUON duoc tinh la exact match neu input nam trong khoang, bat ke do rong."""
    try:
        start_s, end_s = value.strip().split("-", 1)
        start_ip = ipaddress.ip_address(start_s.strip())
        end_ip = ipaddress.ip_address(end_s.strip())
        return (int(start_ip), int(end_ip))
    except (ValueError, AttributeError):
        return None
