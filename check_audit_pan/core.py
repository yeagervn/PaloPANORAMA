# -*- coding: utf-8 -*-
"""
core.py - Thanh phan nen tang cua CHECK AUDIT: hang so (bao gom
UNUSED_RULE_THRESHOLD_DAYS=30), exception tu dong, data model (dataclass
Finding/RuleSnapshot/RuleHitStat), logger, va cac ham tien ich IP/Service.

KHONG import tu check_rule/check_ip - write lai rieng (doc lap 100%).
"""

import os
import sys
import logging
import ipaddress
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict

# ============================================================================
# HANG SO
# ============================================================================
APP_NAME = "CheckAudit"
DEFAULT_TIMEOUT = 30          # giay, cho moi HTTP request toi firewall

# Thu muc goc: neu da dong goi thanh .exe (PyInstaller), lay thu muc chua .exe.
# Neu chay bang python truc tiep, lay thu muc chua script .py.
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Subfolder rieng cho check_audit - khong dung chung output/log voi check_rule/
# va check_ip/ (moi tool doc lap hoan toan ve noi luu ket qua/log).
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "check_audit")
LOG_PATH = os.path.join(OUTPUT_DIR, "log.txt")

# Nguong "khong co hits" de phan loai UNUSED trong Shadow Rules (D10).
# CO DINH 30 ngay - KHONG cho nguoi dung chinh sua tren GUI o v1.
UNUSED_RULE_THRESHOLD_DAYS = 30

# Chuoi Device Group thua ke (0.2): [Shared, DG-to-tien-xa-nhat, ..., DG-hien-tai].
# Duoc tinh boi resolve_devicegroup_chain() trong pan_api, dung cho object layering
# (0.2) va rulebase assembly (0.3). Giu TEN chuan: 'shared' la lop goc luon tien to.
DEVICEGROUP_CHAIN = ["shared"]

# Nhan cac loai check / cac tieu chi cua Shadow Rules.
CHECK_TYPE_SHADOW = "shadow"
CHECK_TYPE_DISABLED = "disabled"
CHECK_TYPE_OVERLY = "overly_permissive"
# Rule CHET: <target> tro toi serial KHONG thuoc Device Group nay, nen rule
# khong duoc push xuong firewall nao ca - no trong nhu dang chay. Hay gap sau
# khi thay the thiet bi (RMA) ma quen sua target.
CHECK_TYPE_TARGET_SAI = "target_sai"
CHECK_TYPE_LABELS = {
    CHECK_TYPE_SHADOW: "Shadow Rules",
    CHECK_TYPE_DISABLED: "Disabled Rules",
    CHECK_TYPE_OVERLY: "Overly Permissive Rules",
    CHECK_TYPE_TARGET_SAI: "Rule CHET (target sai serial)",
}

SHADOW_UNREACHABLE = "UNREACHABLE"
SHADOW_UNUSED = "UNUSED"

# ----------------------------------------------------------------------------
# LOGGING
# ----------------------------------------------------------------------------
def setup_logger(log_path: str = LOG_PATH) -> logging.Logger:
    """Ghi log.txt: moi dong co timestamp. Khong crash neu khong the tao file log."""
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    # Dong handler cu TRUOC khi bo di, neu khong file log cua lan setup
    # truoc bi giu mo (ro file descriptor khi goi setup_logger nhieu lan).
    for _h in list(logger.handlers):
        logger.removeHandler(_h)
        try:
            _h.close()
        except Exception:
            pass
    try:
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logger.addHandler(fh)
    except OSError:
        # Khong ghi duoc file log (vi du thu muc bi khoa quyen) - van tiep tuc chay.
        logger.addHandler(logging.NullHandler())
    return logger


# ============================================================================
# EXCEPTIONS
# ============================================================================
class PanApiError(Exception):
    """Loi API tong quat. user_message la text than thien de hien Popup."""
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
# DATA MODELS
# ============================================================================
@dataclass
class Finding:
    """1 phat hien cua CHECK AUDIT. check_type: 'shadow' | 'disabled' | 'overly_permissive'."""
    check_type: str
    rule_name: str
    rule_uuid: str
    rule_index: int
    source: List[str]                        # raw entries (chua resolve), vd ['any']
    destination: List[str]
    service: List[str]                       # raw, vd ['any'], ['TCP_1521']
    action: str
    disabled: bool
    detail: str

    # CHI set khi check_type == 'shadow':
    shadow_reasons: List[str] = field(default_factory=list)   # subset {'UNREACHABLE','UNUSED'}
    shadowed_by_rule_name: Optional[str] = None      # chi set neu 'UNREACHABLE' in shadow_reasons
    shadowed_by_rule_index: Optional[int] = None
    same_action: Optional[bool] = None               # True = CUNG action (it rui ro), False = KHAC action

    # Vi tri rule trong rulebase Panorama (Shared-PRE/<DG>-PRE/<DG>-POST/Shared-POST) -
    # dung de Export/Import dựng đúng xpath (IV.5/IV.6). Dien tu RuleSnapshot.
    vi_tri: str = ""

    # CHI set neu 'UNUSED' in shadow_reasons (du lieu tu Policy Optimizer rule-hit-count):
    hit_count: Optional[int] = None
    last_hit_date: Optional[str] = None              # ISO 'YYYY-MM-DD', None neu chua tung co hit
    rule_creation_date: Optional[str] = None         # ISO, None neu API khong tra ve
    no_hit_days: Optional[int] = None                # so ngay KHONG co hit tinh toi thoi diem Check


@dataclass
class RuleSnapshot:
    """Boc hoan toan 1 Security Rule (bien the rieng cua check_audit, khong
    import tu check_rule/check_ip). Giu du field goc + 3 truong resolved dung
    cho thuat toan shadow (duoc detectors.py do vao truoc khi chay)."""
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
    disabled: bool = False
    # Vi tri rule trong rulebase Panorama (Shared-PRE/<DG>-PRE/<DG>-POST/Shared-POST) +
    # rulebase ('pre'/'post') de dung xpath DELETE (0.8).
    vi_tri: str = ""
    rulebase: str = ""
    # TARGET / INSTALL-ON (10/2026): rule co the chi duoc push xuong VAI firewall
    # cu the. He thong that co rule target rieng tung site, nen lay rule cua site
    # B di che rule cua site A roi khuyen xoa la lam mat dich vu o site A.
    # Rong = ap cho MOI firewall cua Device Group.
    target_devices: List[str] = field(default_factory=list)
    target_negate: bool = False
    # Ket qua GroupResolver/ServiceResolver (dien vao trong detectors):
    resolved_source: Optional[object] = None
    resolved_destination: Optional[object] = None
    resolved_service: Optional[object] = None


@dataclass
class RuleHitStat:
    """1 dong thong ke hit-count cua 1 rule, lay tu API show rule-hit-count
    (Policy Optimizer). Timestamp epoch -> datetime; tra ve properties ISO date."""
    hit_count: Optional[int]
    last_hit_timestamp: Optional[object]            # datetime | None
    rule_creation_timestamp: Optional[object]       # datetime | None
    # P1 (10/2026) - RUI RO CAO NHAT CUA CA SUITE da sua o day.
    # Hit-count tren Panorama la so lieu CUA TUNG FIREWALL, nhung 1 rule trong
    # Device Group duoc push xuong MOI firewall cua DG do. Truoc ban va, tool chi
    # doc hit-count cua DUNG 1 serial (o "Target Firewall") roi ket luan UNUSED ->
    # Import se DELETE rule khoi candidate cua DG -> commit xong la cac firewall
    # KHAC trong cung DG mat rule dang chay.
    # 2 field duoi day ghi lai PHAM VI BANG CHUNG: da doc duoc hit-count tu nhung
    # firewall nao (devices_seen) va firewall nao KHONG doc duoc (devices_missing).
    devices_seen: tuple = ()
    devices_missing: tuple = ()

    @property
    def hits_known(self) -> bool:
        """Bang chung hit-count co DAY DU khong.

        False khi co firewall trong pham vi query ma khong doc duoc so lieu (loi
        API, hoac tra ve OK nhung khong co dong nao cho rule nay - vd rule chua
        duoc push tói no). Luc do "khong biet" KHAC "bang 0", va TUYET DOI khong
        duoc ket luan UNUSED - dung phan biet da ap cho _scope_trustworthy() ben
        CHECK RULE.

        Ca 2 field rong = ban dung tay/1 firewall (moi test cu, ban standalone) ->
        coi nhu DA BIET, giu nguyen hanh vi cu."""
        return not self.devices_missing

    @property
    def evidence_scope(self) -> str:
        """Mot cau noi ro da kiem nhung firewall nao - de ghi vao Finding/log, vi
        'UNUSED' ma khong noi pham vi la ket luan khong the kiem chung lai."""
        if not self.devices_seen and not self.devices_missing:
            return ""
        parts = []
        if self.devices_seen:
            parts.append(f"da doc hit-count tu {len(self.devices_seen)} firewall: "
                         f"{', '.join(self.devices_seen)}")
        if self.devices_missing:
            parts.append(f"KHONG doc duoc tu {len(self.devices_missing)} firewall: "
                         f"{', '.join(self.devices_missing)}")
        return " | ".join(parts)

    @property
    def last_hit_date(self) -> Optional[str]:
        return self.last_hit_timestamp.strftime("%Y-%m-%d") if self.last_hit_timestamp else None

    @property
    def rule_creation_date(self) -> Optional[str]:
        return self.rule_creation_timestamp.strftime("%Y-%m-%d") if self.rule_creation_timestamp else None


# ----------------------------------------------------------------------------
# MO HINH OBJECT/GROUP (ban rieng cua check_audit, dung cho resolver.py)
# ----------------------------------------------------------------------------
@dataclass
class AddressObject:
    name: str
    kind: str                 # 'host' | 'range' | 'wide' | 'fqdn' | 'unknown'
    start: int = 0            # host/range/wide (rang buoc IP dang int)
    end: int = 0
    raw: str = ""


@dataclass
class AddressGroup:
    name: str
    members: List[str] = field(default_factory=list)


@dataclass
class ServiceObject:
    name: str
    protocol: str             # 'tcp' | 'udp' | '' (khong xac dinh duoc)
    port_raw: str = ""


@dataclass
class ServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)


# ============================================================================
# IP / CIDR UTILITIES
# ============================================================================
def parse_cidr_or_ip(value: str) -> Optional[Tuple[int, int]]:
    """Parse 1 IP hay CIDR literal -> (start_int, end_int). Tra None neu khong hop le."""
    value = value.strip()
    try:
        net = ipaddress.ip_network(value, strict=False)
        return (int(net.network_address), int(net.broadcast_address))
    except ValueError:
        return None


def parse_ip_range(value: str) -> Optional[Tuple[int, int]]:
    """Parse dang 'IP1-IP2' -> (start_int, end_int). Tra None neu khong hop le."""
    value = value.strip()
    try:
        a, b = value.split("-", 1)
        start = int(ipaddress.ip_address(a.strip()))
        end = int(ipaddress.ip_address(b.strip()))
        if start > end:
            return None
        return (start, end)
    except ValueError:
        return None


def is_literal_ip(name: str) -> bool:
    """True neu name la 1 IP/CIDR literal (khong phai ten object/group)."""
    return parse_cidr_or_ip(name) is not None


# ============================================================================
# SERVICE FORMAT (D8 - chi ap dung cho cot Port cua export/GUI)
# ============================================================================
def parse_service_port(port_raw: str) -> List[Tuple[int, int]]:
    """Bien 1 chuoi port raw ('1521' | '80,8080' | '1521-1522') thanh danh
    sach range (start, end). Khong parse duoc -> list rong."""
    out: List[Tuple[int, int]] = []
    for token in (port_raw or "").split(","):
        token = token.strip()
        if not token:
            continue
        if "-" in token:
            parts = token.split("-")
            try:
                a, b = int(parts[0]), int(parts[-1])
                out.append((min(a, b), max(a, b)))
            except ValueError:
                continue
        else:
            try:
                n = int(token)
                out.append((n, n))
            except ValueError:
                continue
    return out


def format_service_entry(entry: str, proto: Optional[str], port: str) -> str:
    """Ap dung dung D8:
    - 'any' / 'application-default' -> giu nguyen.
    - UDP -> 'UDP/<port>'.
    - TCP hoac khong xac dinh protocol -> chi so port (khong them tien to TCP/).
    Neu khong co thong tin port -> roi sang ten entry de khop thuc te."""
    if entry == "any" or entry == "application-default":
        return entry
    port_number = port.strip() if port else ""
    if not port_number:
        return entry
    if proto == "udp":
        return f"UDP/{port_number}"
    # TCP hoac khong ro protocol -> chi so port
    return port_number


def build_service_info(
    service_objects: Dict[str, ServiceObject],
    service_groups: Dict[str, ServiceGroup],
) -> Dict[str, List[Tuple[Optional[str], str]]]:
    """Bien bang Service Object/Group -> map ten (ke ca ten group, da de quy
    mo rong member) -> danh sach (protocol, port). Dung cho cot Port (D8).
    Group khong tim thay member hop le se nam ngoai map (formatter dung ten)."""
    result: Dict[str, List[Tuple[Optional[str], str]]] = {}
    for obj in service_objects.values():
        result.setdefault(obj.name, []).append((obj.protocol, obj.port_raw))

    resolved_groups: Dict[str, List[Tuple[Optional[str], str]]] = {}

    def expand(grp_name: str, visiting: frozenset) -> List[Tuple[Optional[str], str]]:
        if grp_name in resolved_groups:
            return resolved_groups[grp_name]
        if grp_name in visiting:
            return []
        grp = service_groups.get(grp_name)
        if grp is None:
            return []
        acc: List[Tuple[Optional[str], str]] = []
        for m in grp.members:
            if m in service_objects:
                acc += result.get(m, [])
            elif m in service_groups:
                acc += expand(m, visiting | {grp_name})
            else:
                acc.append((None, m))
        resolved_groups[grp_name] = acc
        return acc

    for grp in service_groups.values():
        result[grp.name] = expand(grp.name, frozenset())
    return result


def format_service_entries(
    entries: List[str],
    service_info: Optional[Dict[str, List[Tuple[Optional[str], str]]]] = None,
) -> str:
    """Format toan bo list service cua 1 rule theo D8 (dua tren service_info neu
    co; khong co thi giu ten entry). Tra ve chuoi phan tach bang dau phay."""
    parts: List[str] = []
    for entry in entries:
        if service_info and entry in service_info:
            infos = service_info[entry]
            if infos:
                protos = {p for p, _ in infos}
                sub = []
                for proto, port in infos:
                    sub.append(format_service_entry(entry, proto, port))
                if len(infos) > 1 and len(protos) > 1:
                    # Group lan protocol - de nguoi doc tu loc (khong ghep nham)
                    parts.append(", ".join(sub))
                else:
                    parts.append(sub[0])
                continue
        parts.append(format_service_entry(entry, None, ""))
    return ", ".join(parts)