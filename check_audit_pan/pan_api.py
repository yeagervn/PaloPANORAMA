# -*- coding: utf-8 -*-
"""
pan_api.py - Ket noi PAN-OS XML API (PANORAMA) + doc/parse rulebase Security tu XML
running-config + 2 ham/method RIENG cua CHECK AUDIT (ban Panorama):
  - delete_rule_candidate(): xoa 1 rule tren CANDIDATE CONFIG (action=delete,
    TUYET DOI KHONG commit/khong push - D6/0.4).
  - fetch_rule_hit_count(): doc thong ke Policy Optimizer (op show
    rule-hit-count) cho nhanh UNUSED cua Shadow Rules (D10) - best-effort,
    bat buoc target=<serial> (0.7), loi thi tra {} khong raise.

Viet doc lap cho package nay (khong import tu check_rule/check_ip).
"""

import ipaddress
import logging
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3

from .core import (
    DEFAULT_TIMEOUT,
    PanApiError, PanConnectionError, PanTimeoutError, PanAuthError,
    RuleSnapshot, RuleHitStat,
    AddressObject, AddressGroup, ServiceObject, ServiceGroup,
    parse_cidr_or_ip, parse_ip_range,
)

logger = logging.getLogger("CheckAudit")


# ============================================================================
# PAN-OS XML API CLIENT
# ============================================================================
class PanApiClient:
    """Client goi PAN-OS XML API (https://<firewall>/api/). Nguoi dung da co san API Key."""

    def __init__(self, host: str, api_key: str, verify_ssl: bool = False, timeout: int = DEFAULT_TIMEOUT):
        host = host.strip()
        if not host.startswith("http://") and not host.startswith("https://"):
            host = "https://" + host
        self.base_url = host.rstrip("/") + "/api/"
        self.api_key = api_key.strip()
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.session = requests.Session()
        if not verify_ssl:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _request(self, params: dict) -> ET.Element:
        call_params = dict(params)
        call_params["key"] = self.api_key
        try:
            resp = self.session.get(
                self.base_url, params=call_params,
                timeout=self.timeout, verify=self.verify_ssl,
            )
        except requests.exceptions.ConnectTimeout as e:
            raise PanTimeoutError(str(e), "Timeout: khong ket noi duoc toi Firewall trong thoi gian cho phep.")
        except requests.exceptions.ReadTimeout as e:
            raise PanTimeoutError(str(e), "Timeout: Firewall khong phan hoi kip thoi gian.")
        except requests.exceptions.SSLError as e:
            raise PanConnectionError(str(e), "Loi SSL Certificate. Neu Firewall dung chung chi tu ky, hay bo tick 'Kiem tra SSL Certificate'.")
        except requests.exceptions.ConnectionError as e:
            raise PanConnectionError(str(e), "Cannot connect Firewall: khong the ket noi (kiem tra lai Management IP / duong truyen mang).")
        except requests.exceptions.RequestException as e:
            raise PanApiError(str(e), f"Loi ket noi toi Firewall: {e}")

        try:
            root = ET.fromstring(resp.content)
        except ET.ParseError as e:
            raise PanApiError(str(e), "Phan hoi tu Firewall khong hop le (khong phai XML). Kiem tra lai Management IP.")

        status = root.get("status")
        if status != "success":
            code = root.get("code", "")
            msg_el = root.find(".//msg")
            msg = (msg_el.text or "").strip() if msg_el is not None else "Unknown error"
            if code == "403":
                raise PanAuthError(msg, f"Invalid API Key hoac Permission Denied (code 403): {msg}")
            raise PanApiError(msg, f"API Error (code {code}): {msg}")
        return root

    def test_connection(self) -> str:
        """Kiem tra ket noi + API Key hop le bang <show><system><info>. Tra hostname."""
        root = self._request({"type": "op", "cmd": "<show><system><info></info></system></show>"})
        hostname_el = root.find(".//hostname")
        return hostname_el.text.strip() if hostname_el is not None and hostname_el.text else "N/A"

    def fetch_running_config(self) -> ET.Element:
        """Doc FULL running configuration (dang ACTIVE, khong phai candidate) trong 1 API call duy nhat."""
        root = self._request({"type": "config", "action": "show", "xpath": "/config"})
        config_el = root.find(".//config")
        if config_el is None:
            raise PanApiError("No <config> element in response", "Khong doc duoc cau hinh tu Firewall (phan hoi rong).")
        return config_el

    def delete_rule_candidate(self, devicegroup: str, rulebase: str, rule_name: str) -> bool:
        """
        Xoa 1 Security Rule tren CANDIDATE CONFIG cua PANORAMA (0.8).
        KHONG bao gio goi commit / no push - D6/0.4.

        `rulebase` nhan 1 trong: 'pre' | 'post' | 'shared-pre' | 'shared-post'.
        Dung de dựng đúng xpath pre-rulebase/post-rulebase cua Device Group hoac Shared.
        Ra loi thi nem PanApiError voi user_message than thien (gui.py bat loi, tiep tuc
        cac rule con lai - "Continue").
        """
        if rulebase in ("pre", "post"):
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{devicegroup}']"
                f"/{rulebase}-rulebase/security/rules/entry[@name='{rule_name}']"
            )
        elif rulebase in ("shared-pre", "shared-post"):
            tag = "pre-rulebase" if rulebase == "shared-pre" else "post-rulebase"
            xpath = (
                f"/config/shared/{tag}/security/rules/entry[@name='{rule_name}']"
            )
        else:
            raise PanApiError(
                f"Unknown rulebase '{rulebase}'",
                f"rulebase khong hop le: '{rulebase}' (can la pre/post/shared-pre/shared-post).",
            )
        params = {"type": "config", "action": "delete", "xpath": xpath}
        try:
            self._request(params)
        except PanApiError as e:
            raise PanApiError(
                str(e),
                f"Xoa rule '{rule_name}' ({rulebase}/{devicegroup}) tren Candidate Config that bai: {e.user_message}",
            )
        return True

    def disable_rule_candidate(self, devicegroup: str, rulebase: str, rule_name: str) -> bool:
        """
        DISABLE 1 Security Rule tren CANDIDATE CONFIG (thay vi xoa) - danh cho
        Shadow Rules co hit_count==0 (IV.4 phan biet: shadow-0-hit -> disable,
        disabled -> delete, overly -> export only).

        Thuc hien bang `type=config&action=set&xpath=.../disabled&element=<disabled>yes</disabled>`.
        KHONG commit, KHONG push - giong delete_rule_candidate (D6/0.4).
        """
        if rulebase in ("pre", "post"):
            xpath = (
                f"/config/devices/entry[@name='localhost.localdomain']"
                f"/device-group/entry[@name='{devicegroup}']"
                f"/{rulebase}-rulebase/security/rules/entry[@name='{rule_name}']/disabled"
            )
        elif rulebase in ("shared-pre", "shared-post"):
            tag = "pre-rulebase" if rulebase == "shared-pre" else "post-rulebase"
            xpath = (
                f"/config/shared/{tag}/security/rules/entry[@name='{rule_name}']/disabled"
            )
        else:
            raise PanApiError(
                f"Unknown rulebase '{rulebase}'",
                f"rulebase khong hop le: '{rulebase}' (can la pre/post/shared-pre/shared-post).",
            )
        params = {"type": "config", "action": "set", "xpath": xpath, "element": "<disabled>yes</disabled>"}
        try:
            self._request(params)
        except PanApiError as e:
            raise PanApiError(
                str(e),
                f"Disable rule '{rule_name}' ({rulebase}/{devicegroup}) tren Candidate Config that bai: {e.user_message}",
            )
        return True

    def fetch_rule_hit_count_multi(self, serials, log_func=None,
                                   extra_shared_serials=None):
        """P1 (10/2026): doc hit-count tren **MOI firewall** duoc truyen vao roi GOP.

        Vi sao bat buoc: hit-count la so lieu cua TUNG firewall, nhung 1 rule trong
        Device Group duoc push xuong MOI firewall cua DG. Doc 1 serial roi ket luan
        UNUSED = de xuat XOA mot rule co the dang chay tren cac firewall khac. Day la
        duong duy nhat trong ca suite co the pha production.

        Cach gop cho moi khoa (rule_name, vi_tri):
          - hit_count                 = TONG hit cua cac firewall doc duoc (dung
                                        >0 o BAT KY firewall nao la rule con song)
          - last_hit_timestamp        = MOI NHAT trong cac firewall
          - rule_creation_timestamp   = SOM NHAT (rule co the duoc push tai thoi
                                        diem khac nhau)
          - devices_seen / devices_missing: pham vi bang chung (xem
            RuleHitStat.hits_known) - firewall nao loi API, HOAC tra ve OK nhung
            khong co dong nao cho rule do, deu vao devices_missing.

        Chi phi TUYEN TINH theo so firewall (4 lenh pham vi x N serial), khong nhan
        theo so rule. Khong co serial nao -> tra {} va log canh bao (y nhu ban 1
        serial khi thieu target).
        """
        log = log_func or (lambda msg: None)
        serials = [x for x in dict.fromkeys(serials or []) if x]
        # B2 (10/2026): rule o Shared-PRE/Shared-POST ap cho **MOI** firewall
        # Panorama quan ly, khong chi cac con trong Device Group dang chon. Nen voi
        # rule Shared, "0 hit tren moi con trong DG" VAN CHUA DU bang chung.
        # Cach lam de dung ma khong no chi phi API: voi cac con NGOAI DG, chi hoi 2
        # lenh pham vi <shared> (khong hoi 2 lenh device-group) - xem
        # fetch_rule_hit_count(only_shared=True).
        #   Chi phi = 4 x N_trong_DG + 2 x N_ngoai_DG  (toi thieu de ket luan dung)
        extra_shared = [x for x in dict.fromkeys(extra_shared_serials or [])
                        if x and x not in serials]
        if not serials:
            log("CANH BAO: khong xac dinh duoc firewall nao de doc Rule Hit Count "
                "(can Target Firewall hoac Device Group co thiet bi) - bo qua nhanh UNUSED.")
            return {}

        per_device = {}
        failed = []
        for ser, chi_shared in ([(x, False) for x in serials]
                                + [(x, True) for x in extra_shared]):
            try:
                per_device[ser] = self.fetch_rule_hit_count(ser, log_func=log_func,
                                                             only_shared=chi_shared)
            except Exception as e:       # pragma: no cover - fetch da tu boc try
                failed.append(ser)
                log(f"CANH BAO: khong doc duoc hit-count tu firewall {ser} ({e}) - "
                    f"cac rule lien quan se KHONG duoc ket luan UNUSED.")
                continue
            if not per_device[ser]:
                # Tra ve rong = khong co bang chung tu con nay (fetch da log ly do)
                failed.append(ser)

        all_keys = set()
        for d in per_device.values():
            all_keys |= set(d.keys())

        result = {}
        for key in all_keys:
            total = 0
            any_count = False
            last_ts = None
            created_ts = None
            seen, missing = [], []
            # B2: PHAM VI BANG CHUNG phu thuoc vi tri cua rule.
            #   - rule Shared-PRE/Shared-POST: ap cho MOI firewall -> phai co bang
            #     chung tu CA cac con ngoai DG
            #   - rule trong Device Group: chi ap cho cac con cua DG -> chi can
            #     bang chung tu `serials`
            _vi_tri = key[1] if isinstance(key, tuple) and len(key) > 1 else ''
            _can_kiem = (serials + extra_shared) if str(_vi_tri).startswith('Shared-') \
                else serials
            for ser in _can_kiem:
                st = per_device.get(ser, {}).get(key)
                if st is None:
                    missing.append(ser)
                    continue
                seen.append(ser)
                if st.hit_count:
                    total += st.hit_count
                    any_count = True
                if st.last_hit_timestamp is not None and \
                        (last_ts is None or st.last_hit_timestamp > last_ts):
                    last_ts = st.last_hit_timestamp
                if st.rule_creation_timestamp is not None and \
                        (created_ts is None or st.rule_creation_timestamp < created_ts):
                    created_ts = st.rule_creation_timestamp
            result[key] = RuleHitStat(
                hit_count=(total if any_count else 0),
                last_hit_timestamp=last_ts,
                rule_creation_timestamp=created_ts,
                devices_seen=tuple(seen),
                devices_missing=tuple(missing),
            )

        n_khong_du = sum(1 for st in result.values() if not st.hits_known)
        log(f"Rule Hit Count: da doc tren {len(serials)} firewall "
            f"({', '.join(serials)}); {len(result)} rule co so lieu"
            + (f"; {n_khong_du} rule THIEU bang chung (se KHONG ket luan UNUSED)"
               if n_khong_du else ""))
        return result

    def fetch_rule_hit_count(self, target_serial: str, log_func=None,
                             only_shared: bool = False) -> Dict[Tuple[str, str], RuleHitStat]:
        """
        Best-effort (0.7/D10): doc thong ke hit-count cua TOAN BO Security Rule tren
        Target Firewall (Policy Optimizer). BAT BUOC co target_serial; thieu -> tra {}
        ngay khong goi API. Loi API -> log canh bao + tra {} (KHONG raise) - nhanh
        UNUSED se bi bo qua, nhanh UNREACHABLE van chay binh thuong.

        *SỬA 2026-09-02 (lỗ hổng D9):* truoc đây trả Dict[str, RuleHitStat] khoá theo tên thuần,
        nay trả Dict[Tuple[str,str], RuleHitStat] khoá (rule_name, vi_tri) để phân biệt 2 rule
        cùng tên ở 2 Device Group khác nhau (Panorama cho phép trùng tên, standalone không).
        vi_tri ∈ {Shared-PRE, Shared-POST, <DG>-PRE, <DG>-POST} (IV.5). Dùng `target=<serial>`
        + device-group context vi 1 rule DG co the khac nhau giua cac firewall trong cung DG.
        """
        log = log_func or (lambda msg: None)
        if not target_serial:
            log(
                "CANH BAO: chua chon Target Firewall (Serial) nen khoi doc Rule Hit Count "
                "(a.nh huong nhanh UNUSED trong Shadow Rules) - bo qua."
            )
            return {}
        result: Dict[Tuple[str, str], RuleHitStat] = {}
        # SỬA 2026-09-02 audit #2: cmd cũ sai cú pháp (device-group-name/serial/rule-base generic + wildcard).
        # Đúng theo PAN-OS SDK: phải gọi riêng pre và post, dùng target=<serial> ở tầng request.
        # Chi phí CO DINH 4 lenh (khong phu thuoc so DG/so rule):
        #   device-group wildcard pre/post  +  shared pre/post
        # LUU Y (da kiem thu trong testlab): nhanh <shared> la BEST-EFFORT. Tren Panorama
        # that, neu schema khong ho tro node <shared> cho rule-hit-count thi lenh nay bi
        # tu choi -> da boc try/except: chi log canh bao va di tiep, KHONG raise, cac rule
        # trong Device Group van co hit-count binh thuong. Khong co nhanh nay thi rule
        # Shared-PRE/Shared-POST vinh vien khong bao gio co hit-count => tieu chi UNUSED
        # khong bao gio ap dung cho rule Shared (bo sot). Da chon danh doi 2 call de tranh.
        scopes = [
            ("device-group wildcard", "pre",
             "<show><rule-hit-count><device-group><entry name='*'>"
             "<pre-rulebase><entry name='security'><rules><all/></rules></entry></pre-rulebase>"
             "</entry></device-group></rule-hit-count></show>"),
            ("device-group wildcard", "post",
             "<show><rule-hit-count><device-group><entry name='*'>"
             "<post-rulebase><entry name='security'><rules><all/></rules></entry></post-rulebase>"
             "</entry></device-group></rule-hit-count></show>"),
            ("shared", "pre",
             "<show><rule-hit-count><shared>"
             "<pre-rulebase><entry name='security'><rules><all/></rules></entry></pre-rulebase>"
             "</shared></rule-hit-count></show>"),
            ("shared", "post",
             "<show><rule-hit-count><shared>"
             "<post-rulebase><entry name='security'><rules><all/></rules></entry></post-rulebase>"
             "</shared></rule-hit-count></show>"),
        ]
        if only_shared:
            # B2 (10/2026): voi firewall NGOAI Device Group dang chon, ta chi can
            # bang chung cho rule o pham vi Shared (Shared-PRE/Shared-POST) - vi
            # chi rule Shared moi ap cho chung. Bo 2 lenh device-group di: chi phi
            # cho moi con ngoai DG giam tu 4 lenh xuong 2.
            scopes = [t for t in scopes if t[0] == 'shared']
        for scope_label, rb, cmd in scopes:
            try:
                root = self._request({"type": "op", "cmd": cmd, "target": target_serial})
            except Exception as e:
                log(
                    "CANH BAO: Khong lay duoc du lieu Policy Optimizer (rule-hit-count) "
                    f"[{scope_label} / {rb}-rulebase] - tieu chi UNUSED se bi bo qua cho "
                    f"pham vi nay. ({e})"
                )
                logger.warning("Policy Optimizer rule-hit-count %s/%s failed: %s",
                               scope_label, rb, e)
                continue
            default_dg = "shared" if scope_label == "shared" else None

            parent_map = {c: p for p in root.iter() for c in p}
            for entry in root.iter("entry"):
                name = entry.get("name")
                if not name:
                    continue
                parent = parent_map.get(entry)
                is_rule = False
                if entry.find("hit-count") is not None or entry.find("hit_count") is not None or entry.find("last-hit-timestamp") is not None:
                    is_rule = True
                elif parent is not None and parent.tag == "rules":
                    is_rule = True
                if not is_rule:
                    continue
                vi_tri = _hit_entry_vi_tri(entry, parent_map, log)
                # Nếu vi_tri suy được nhưng suffix không khớp rb hiện tại, ưu tiên rb hiện tại khi entry không có pre/post ancestor rõ ràng
                if vi_tri and rb == "pre" and vi_tri.endswith("POST"):
                    # hit entry này thực ra thuộc post nhưng đang ở loop pre -> bỏ qua, sẽ lấy ở loop post
                    continue
                if vi_tri and rb == "post" and vi_tri.endswith("PRE"):
                    continue
                if not vi_tri:
                    # fallback: nếu không suy được, dùng rb hiện tại + DG từ child nếu có
                    dg_el = entry.find("device-group")
                    dg = (dg_el.text.strip() if dg_el is not None and dg_el.text
                          else (default_dg or "unknown"))
                    if dg.lower() == "shared":
                        vi_tri = f"Shared-{rb.upper()}"
                    elif dg != "unknown":
                        vi_tri = f"{dg}-{rb.upper()}"
                    else:
                        log(f"CANH BAO: hit-count rule '{name}' không suy được vi_tri ({rb}), bỏ qua")
                        continue
                key = (name, vi_tri)
                result[key] = RuleHitStat(
                    hit_count=_safe_int(entry, ("hit-count", "hit_count")),
                    last_hit_timestamp=_safe_ts(entry, ("last-hit-timestamp", "last-hit")),
                    rule_creation_timestamp=_safe_ts(entry, ("rule-creation-timestamp", "rule-created")),
                )
        if not result:
            log("CANH BAO: API rule-hit-count tra ve rong (khong co du lieu rule nao).")
        return result

    def fetch_current_rule_states(self, log_func=None) -> Optional[Dict[Tuple[str, str], dict]]:
        """
        Xác minh lại tồn tại/trạng thái rule ngay trước khi ghi (IV.8), dùng Candidate Config
        (action=get) - NGOẠI LỆ có chủ đích so với 0.4: cần trạng thái mới nhất kể cả thay đổi
        candidate chưa commit của người khác. Chỉ dùng để xác minh, không dùng cho thuật toán LOCAL.

        Gọi đúng 4 lệnh action=get CỐ ĐỊNH (không phụ thuộc số DG/rule), xpath WILDCARD bỏ [@name='DG']:
          1. /config/shared/pre-rulebase/security/rules
          2. /config/shared/post-rulebase/security/rules
          3. /config/devices/entry[@name='localhost.localdomain']/device-group/entry/pre-rulebase/security/rules
          4. /config/devices/entry[@name='localhost.localdomain']/device-group/entry/post-rulebase/security/rules
        Với (3)/(4): response có nhiều <device-group><entry name='DG_X'>...<rules><entry name='RULE_Y'>,
        PHẢI parse giữ DG cha (không findall phẳng). Dựng vi_tri Shared-PRE/<DG>-PRE/<DG>-POST/Shared-POST.
        Với mỗi rule đọc luôn disabled/source/destination/service/action trong cùng response (không thêm call).
        Trả Dict[(rule_name, vi_tri) -> {disabled, source, destination, service, action}] hoặc None nếu lỗi bất kỳ.
        Best-effort, không commit, chi phí cố định 4 call.
        """
        log = log_func or (lambda msg: None)
        result: Dict[Tuple[str, str], dict] = {}
        xpaths = [
            ("/config/shared/pre-rulebase/security/rules", "Shared-PRE"),
            ("/config/shared/post-rulebase/security/rules", "Shared-POST"),
            ("/config/devices/entry[@name='localhost.localdomain']/device-group/entry/pre-rulebase/security/rules", None),  # wildcard DG PRE
            ("/config/devices/entry[@name='localhost.localdomain']/device-group/entry/post-rulebase/security/rules", None), # wildcard DG POST
        ]
        for xpath, shared_label in xpaths:
            try:
                root = self._request({"type": "config", "action": "get", "xpath": xpath})
            except Exception as e:
                log(f"CANH BAO: fetch_current_rule_states lỗi xpath {xpath}: {e} -> bỏ xác minh batch")
                logger.warning("fetch_current_rule_states failed xpath %s: %s", xpath, e)
                return None
            # Parse tuỳ loại
            if shared_label is not None:
                # Shared: root có <config><shared><pre-rulebase>... hoặc <result><config>...
                config_el = root.find(".//config")
                if config_el is None:
                    config_el = root
                shared_el = config_el.find("shared")
                if shared_el is None:
                    # Có thể response đã là <shared> trực tiếp
                    shared_el = root.find(".//shared")
                if shared_el is not None:
                    # shared_el là container cho parse_security_rules_in
                    rules = parse_security_rules_in(shared_el, shared_label, "pre" if "pre-rulebase" in xpath else "post")
                    for r in rules:
                        key = (r.name, r.vi_tri)
                        result[key] = {"disabled": r.disabled, "source": list(r.source), "destination": list(r.destination), "service": list(r.service), "action": r.action}
                else:
                    # fallback: tìm trực tiếp các rules entry
                    for entry in root.findall(".//rules/entry"):
                        name = entry.get("name")
                        if not name:
                            continue
                        disabled_el = entry.find("disabled")
                        disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"
                        result[(name, shared_label)] = {"disabled": disabled, "source": _members(entry, "source"), "destination": _members(entry, "destination"), "service": _members(entry, "service"), "action": (entry.find("action").text.strip() if entry.find("action") is not None and entry.find("action").text else "")}
            else:
                # Wildcard DG: cần giữ DG cha
                # root có <config><devices><entry name=localhost><device-group><entry name=DG1><pre-rulebase>...
                # Duyệt theo cấu trúc lồng nhau
                is_pre = "pre-rulebase" in xpath
                label_suffix = "PRE" if is_pre else "POST"
                rulebase = "pre" if is_pre else "post"
                # Tìm tất cả device-group entry
                for dg_entry in root.findall(".//device-group/entry"):
                    dg_name = dg_entry.get("name")
                    if not dg_name:
                        continue
                    vi_tri = f"{dg_name}-{label_suffix}"
                    rules = parse_security_rules_in(dg_entry, vi_tri, rulebase)
                    for r in rules:
                        key = (r.name, r.vi_tri)
                        result[key] = {"disabled": r.disabled, "source": list(r.source), "destination": list(r.destination), "service": list(r.service), "action": r.action}
        return result


# ============================================================================
# DIEU HUONG + PARSE CAU HINH (PANORAMA)
# ============================================================================
def get_devicegroup_list(config_root: ET.Element) -> List[str]:
    """Lay danh sach ten Device Group (theo thu tu xuat hien). Panorama luu DG
    trong /config/devices/entry[@name=...]/device-group/entry."""
    names: List[str] = []
    seen: Set[str] = set()
    for dg_el in config_root.findall('.//device-group/entry'):
        nm = dg_el.get('name')
        if nm and nm not in seen:
            seen.add(nm)
            names.append(nm)
    return names


def devicegroup_device_serials(config_root: ET.Element, dg_name: str) -> List[str]:
    """Serial cua cac firewall duoc gan vao 1 Device Group.

    Vi sao viet RIENG o day thay vi dung lai ham cung ten ben check_rule_pan: 3
    package cua suite nay **doc lap 100%** ve code/namespace (co
    tests/test_panorama_infra.py::test_3_package_khong_import_lan_nhau khoa lai).
    Lan dau tao import cheo tu check_rule_pan va test do da bat ngay.

    Luu y xpath (dung bay da ghi o PHAN 0, muc 6): config Panorama co Device Group
    o HAI noi - /config/devices/.../device-group/entry (chua object + rulebase
    THAT) va /config/readonly/... (ban sao chi-doc, thuong CHI co <parent-dg>, va
    KHONG co <devices>). Lay phai ban readonly thi se tra ve rong -> tool tuong DG
    khong co firewall nao -> roi ve dung cai loi P1 dang sua. Nen o day UU TIEN
    TUYET DOI nhanh ngoai <readonly>.
    """
    if not dg_name:
        return []
    candidates = []
    for parent in config_root.iter():
        if parent.tag != 'device-group':
            continue
        in_readonly = False
        # ElementTree khong co con tro len cha -> xac dinh readonly bang cach do
        # lai tu goc (re so luong node nho nhu config Panorama)
        for ro in config_root.iter('readonly'):
            if parent in list(ro.iter()):
                in_readonly = True
                break
        for dg_el in parent.findall('entry'):
            if dg_el.get('name') == dg_name:
                candidates.append((in_readonly, dg_el))
    if not candidates:
        return []
    candidates.sort(key=lambda t: t[0])      # False (ngoai readonly) truoc
    serials: List[str] = []
    for _ro, dg_el in candidates:
        dev = dg_el.find('devices')
        if dev is None:
            continue
        for d in dev.findall('entry'):
            nm = d.get('name')
            if nm and nm not in serials:
                serials.append(nm)
        if serials:
            break
    return serials


def _readonly_ids(config_root: ET.Element) -> set:
    """id() cua moi phan tu nam trong <readonly>.

    ElementTree khong co con tro len cha, nen muon biet mot <entry> co nam
    trong nhanh readonly hay khong thi phai danh dau truoc tu goc.
    """
    out = set()
    for ro in config_root.iter("readonly"):
        for el in ro.iter():
            out.add(id(el))
    return out


def _devicegroup_entries(config_root: ET.Element) -> Dict[str, ET.Element]:
    """{ten DG: phan tu XML}, UU TIEN TUYET DOI nhanh NGOAI <readonly>.

    BAY DA DAM PHAI (sua 10/2026): config Panorama co device-group o HAI noi
      - /config/devices/entry/device-group/entry   -> co object + rulebase THAT
      - /config/readonly/devices/.../device-group/entry -> ban sao chi-doc,
        thuong CHI co <parent-dg>, KHONG co object nao
    Ban cu lay `findall(".//device-group/entry")` roi `setdefault` - tuc la lay
    cai nao GAP TRUOC. Tren thiet bi that <readonly> hay nam TRUOC <devices>,
    nen tool vo duoc ban rong va bao "khong tim thay object" cho ca nhung
    object dang nam so so trong DG do.
    """
    ro = _readonly_ids(config_root)
    primary: Dict[str, ET.Element] = {}
    fallback: Dict[str, ET.Element] = {}
    for dg_parent in config_root.iter("device-group"):
        for entry in dg_parent.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            (fallback if id(entry) in ro else primary).setdefault(name, entry)
    for name, entry in fallback.items():
        primary.setdefault(name, entry)
    return primary


def _dg_parents_from_config(config_root: ET.Element) -> Dict[str, Optional[str]]:
    """{ten DG: ten DG cha}. Khong co cha -> con truc tiep cua Shared.

    Quan he cha-con thuong CHI nam o ban <readonly>, nen phai quet CA HAI
    nhanh. Va quan trong: mot entry KHONG co <parent-dg> thi KHONG duoc ghi de
    len quan he da tim thay o nhanh kia - ban cu dung `parents[name] = parent`
    (gan de) nen ban /devices (khong co parent-dg) xoa mat quan he vua doc tu
    /readonly, va ca cay Device Group sup xuong con mot tang.
    """
    parents: Dict[str, Optional[str]] = {}
    for dg_parent in config_root.iter("device-group"):
        for entry in dg_parent.findall("entry"):
            name = entry.get("name")
            if not name:
                continue
            parents.setdefault(name, None)
            parent_el = entry.find("parent-dg")
            if parent_el is None:
                parent_el = next(iter(entry.iter("parent-dg")), None)
            if parent_el is not None and parent_el.text and parent_el.text.strip():
                parents[name] = parent_el.text.strip()
    return parents


def resolve_devicegroup_chain(config_root: ET.Element, dg_name: str) -> List[str]:
    """Tra ve chuoi ten theo thu tu thua ke (0.2):
       [Shared, DG-goc-nhat, ..., DG-cha-truc-tiep, DG-hien-tai]
    Shared LUON LA LOP GOC (tang nen) bat ke DG co cha hay khong (0.2).
    SỬA 2026-09-02 audit: thêm visited chặn cycle nhiều cấp (A->B->C->A), trước đây chỉ chặn parent==cur."""
    parents = _dg_parents_from_config(config_root)
    chain: List[str] = []
    cur = dg_name or ""
    visited: Set[str] = set()
    while cur:
        if cur in visited:
            break  # cycle nhiều cấp
        visited.add(cur)
        chain.append(cur)
        parent = parents.get(cur)
        if not parent or parent == cur:
            break
        cur = parent
    chain.reverse()
    chain = ["shared"] + chain
    return chain


def get_shared_element(config_root: ET.Element) -> ET.Element:
    shared = config_root.find("shared")
    return shared if shared is not None else ET.Element("shared")


def parse_security_rules_in(container: ET.Element, label: str, rulebase: str) -> List[RuleSnapshot]:
    """Doc cac truong can thiet tu 1 container (shared hoac 1 device-group entry),
    tai `rulebase` -rulebase/security/rules. `label` la vi tu STRING cho cot
    "Vi tri Rule" (vd 'Shared-PRE', '<DG>-POST'). `rulebase` = 'pre'|'post'.
    Can than: Panorama luu duoi `pre-rulebase`/`post-rulebase` (khac vs `rulebase`
    cua Firewall don)."""
    tag = f"{rulebase}-rulebase"
    rulebase_el = container.find(tag)
    if rulebase_el is None:
        # fallback (mot so cau truc) - dung <rulebase> truc tiep
        rulebase_el = container.find("rulebase")
        if rulebase_el is None:
            return []
    security = rulebase_el.find("security")
    if security is None:
        return []
    rules_parent = security.find("rules")
    if rules_parent is None:
        return []

    rules: List[RuleSnapshot] = []
    for idx, entry in enumerate(rules_parent.findall("entry")):
        name = entry.get("name") or f"(unnamed-{idx})"
        uuid = entry.get("uuid") or ""
        disabled_el = entry.find("disabled")
        disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"
        action_el = entry.find("action")
        action = (action_el.text or "").strip() if action_el is not None and action_el.text else ""

        rules.append(RuleSnapshot(
            index=idx,
            name=name,
            uuid=uuid,
            from_zones=_members(entry, "from"),
            to_zones=_members(entry, "to"),
            source=_members(entry, "source"),
            destination=_members(entry, "destination"),
            application=_members(entry, "application"),
            service=_members(entry, "service"),
            action=action,
            disabled=disabled,
            vi_tri=label,
            rulebase=rulebase,
        ))
    return rules


def assemble_security_rules(config_root: ET.Element, dg_name: str) -> List[RuleSnapshot]:
    """Lap rap rulebase security theo DUNG 6 buoc 0.3:
      1. Shared PRE-rulebase
      2. DG to tien xa nhat -> ... -> DG cha -> DG hien tai, PRE-rulebase
      3. (local rules tren firewall - khong co o Panorama, bo qua)
      4. DG hien tai -> DG cha -> ... -> DG to tien xa nhat, POST-rulebase (NGUOC)
      5. Shared POST-rulebase
    Index cuoi cung gan lai tang dan theo dung thu tu lap rap nay."""
    chain = resolve_devicegroup_chain(config_root, dg_name)
    dg_names = [nm for nm in chain if nm not in ("shared", "Shared")]

    shared = get_shared_element(config_root)
    dg_elements: Dict[str, object] = {}
    for dg_el in config_root.findall('.//device-group/entry'):
        nm = dg_el.get('name')
        if nm:
            dg_elements.setdefault(nm, dg_el)

    assembled: List[RuleSnapshot] = []

    # 1. Shared PRE
    assembled += parse_security_rules_in(shared, "Shared-PRE", "pre")

    # 2. DG chain PRE (to tien -> hien tai)
    for nm in dg_names:
        el = dg_elements.get(nm)
        if el is not None:
            assembled += parse_security_rules_in(el, f"{nm}-PRE", "pre")

    # 3. (bo qua local rules - Panorama khong co)

    # 4. DG chain POST (hien tai -> to tien)
    for nm in reversed(dg_names):
        el = dg_elements.get(nm)
        if el is not None:
            assembled += parse_security_rules_in(el, f"{nm}-POST", "post")

    # 5. Shared POST
    assembled += parse_security_rules_in(shared, "Shared-POST", "post")

    for i, r in enumerate(assembled):
        r.index = i
    return assembled


def parse_devicegroup_objects(
    config_root: ET.Element,
    dg_name: str,
) -> Dict[str, object]:
    """Nap cac bang Address Object/Group + Service Object/Group cho 1 Device Group
    theo chuoi thua ke (0.2): Shared -> DG goc nhat -> ... -> DG hien tai, lop SAU
    (gan hon) ghi de lop TRUOC neu trung ten.
    Tra ve dict: address_objects, address_groups, service_objects, service_groups."""
    chain = resolve_devicegroup_chain(config_root, dg_name)
    shared = get_shared_element(config_root)

    containers: List[ET.Element] = []
    for nm in chain:
        if nm in ("shared", "Shared"):
            containers.append(shared)
        else:
            for dg_el in config_root.findall('.//device-group/entry'):
                if dg_el.get('name') == nm:
                    containers.append(dg_el)
                    break
            else:
                containers.append(None)

    addr_objects: Dict[str, AddressObject] = {}
    addr_groups: Dict[str, AddressGroup] = {}
    svc_objects: Dict[str, ServiceObject] = {}
    svc_groups: Dict[str, ServiceGroup] = {}
    for c in containers:
        if c is None:
            continue
        addr_objects.update(parse_address_objects(c))
        addr_groups.update(parse_address_groups(c))
        svc_objects.update(parse_service_objects(c))
        svc_groups.update(parse_service_groups(c))

    return {
        "address_objects": addr_objects,
        "address_groups": addr_groups,
        "service_objects": svc_objects,
        "service_groups": svc_groups,
    }



def parse_address_objects(container: ET.Element) -> Dict[str, AddressObject]:
    result: Dict[str, AddressObject] = {}
    addr_parent = container.find("address")
    if addr_parent is None:
        return result
    for entry in addr_parent.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        ipnm = entry.find("ip-netmask")
        iprg = entry.find("ip-range")
        fqdn = entry.find("fqdn")
        if ipnm is not None and ipnm.text:
            bounds = parse_cidr_or_ip(ipnm.text)
            if bounds is None:
                result[name] = AddressObject(name, "unknown", raw=ipnm.text.strip())
            elif bounds[0] == bounds[1]:
                result[name] = AddressObject(name, "host", bounds[0], bounds[1], ipnm.text.strip())
            else:
                result[name] = AddressObject(name, "wide", bounds[0], bounds[1], ipnm.text.strip())
        elif iprg is not None and iprg.text:
            bounds = parse_ip_range(iprg.text)
            if bounds is None:
                result[name] = AddressObject(name, "unknown", raw=iprg.text.strip())
            else:
                result[name] = AddressObject(name, "range", bounds[0], bounds[1], iprg.text.strip())
        elif fqdn is not None and fqdn.text:
            result[name] = AddressObject(name, "fqdn", raw=fqdn.text.strip())
        else:
            result[name] = AddressObject(name, "unknown", raw="")
    return result


def parse_address_groups(container: ET.Element) -> Dict[str, AddressGroup]:
    result: Dict[str, AddressGroup] = {}
    grp_parent = container.find("address-group")
    if grp_parent is None:
        return result
    for entry in grp_parent.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        static_el = entry.find("static")
        members = [m.text for m in static_el.findall("member") if m.text] if static_el is not None else []
        result[name] = AddressGroup(name, members)
    return result


def parse_service_objects(container: ET.Element) -> Dict[str, ServiceObject]:
    result: Dict[str, ServiceObject] = {}
    parent = container.find("service")
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        protocol_el = entry.find("protocol")
        proto, port = "", ""
        if protocol_el is not None:
            tcp_el = protocol_el.find("tcp")
            udp_el = protocol_el.find("udp")
            target_el = tcp_el if tcp_el is not None else udp_el
            if target_el is not None:
                proto = "tcp" if tcp_el is not None else "udp"
                port_el = target_el.find("port")
                port = port_el.text.strip() if port_el is not None and port_el.text else ""
        result[name] = ServiceObject(name, proto, port)
    return result


def parse_service_groups(container: ET.Element) -> Dict[str, ServiceGroup]:
    result: Dict[str, ServiceGroup] = {}
    parent = container.find("service-group")
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        members_el = entry.find("members")
        members = [m.text for m in members_el.findall("member") if m.text] if members_el is not None else []
        result[name] = ServiceGroup(name, members)
    return result


def _members(el: Optional[ET.Element], tag: str) -> List[str]:
    if el is None:
        return []
    parent = el.find(tag)
    if parent is None:
        return []
    return [m.text for m in parent.findall("member") if m.text]


# ============================================================================
# TEMPLATE-BASED ZONE LOOKUP (0.6) - giong check_rule_pan, best-effort
# ============================================================================
def parse_interface_subnets(root) -> List[Tuple[int, int, int, str]]:
    """Parse Interface/Subnet tu Template (best-effort, vo hieu im lang neu loi)."""
    out: List[Tuple[int, int, int, str]] = []
    try:
        net = root.find('devices/entry/network')
        if net is None:
            net = root.find('network')
        if net is None:
            return out
        iface_root = net.find('interface')
        if iface_root is None:
            return out
        for entry in iface_root.iter('entry'):
            name = entry.get('name')
            if not name:
                continue
            ip_el = entry.find('ip')
            if ip_el is None:
                ip_el = entry.find('layer3/ip')
            if ip_el is None:
                continue
            for ip_entry in ip_el.findall('entry'):
                addr = ip_entry.get('name')
                if not addr or '/' not in addr:
                    continue
                try:
                    net_obj = ipaddress.ip_network(addr, strict=False)
                except ValueError:
                    continue
                out.append((int(net_obj.network_address), int(net_obj.broadcast_address),
                            net_obj.prefixlen, name))
    except Exception:
        return []
    return out


def parse_zones(container) -> Dict[str, List[str]]:
    """Parse Zone -> List interface tu Template (defensive)."""
    out: Dict[str, List[str]] = {}
    try:
        if container is None:
            return out
        zone_root = container.find('zone')
        if zone_root is None:
            return out
        for zentry in zone_root.findall('entry'):
            zname = zentry.get('name')
            if not zname:
                continue
            members: List[str] = []
            net_el = zentry.find('network')
            if net_el is not None:
                for mode_tag in ('layer3', 'layer2', 'virtual-wire', 'tap'):
                    mode_el = net_el.find(mode_tag)
                    if mode_el is not None:
                        members.extend(_members(mode_el))
            out[zname] = members
    except Exception:
        return {}
    return out


def resolve_templates_for_serial(root, target_serial) -> List[ET.Element]:
    """Danh sach phan tu Template ap dung cho firewall co serial nay, theo thu tu
    UU TIEN TANG DAN (phan tu sau de phan tu truoc khi trung).

    SUA LOI (10/2026): ban truoc tra cuu NGUOC CHIEU - no tim
    `/config/devices/entry[@name=<serial>]` roi doc the <template> ben trong. Tren
    Panorama nhanh `/config/devices/entry` la chinh PANORAMA (ten
    'localhost.localdomain'), KHONG co entry theo serial firewall -> ham luon tra
    None, nghia la tinh nang Zone KHONG BAO GIO chay. Quan he that duoc luu NGUOC
    LAI: moi Template / Template Stack co 1 danh sach thiet bi
        template/entry[@name=T]/devices/entry[@name=<serial>]
        template-stack/entry[@name=S]/devices/entry[@name=<serial>]
    nen phai QUET template/template-stack va xem serial co trong <devices> khong.

    Template Stack duoc uu tien; cac template thanh vien liet ke trong
    <templates><member>, thu tu TREN = uu tien CAO hon -> tra ve DAO NGUOC de ben
    goi nap tuan tu thi cai uu tien cao nhat ghi de sau cung. Khong tim thay -> []
    (tinh nang zone tu vo hieu im lang, 0.6)."""
    if not target_serial:
        return []
    target_serial = target_serial.strip()

    templates: Dict[str, ET.Element] = {}
    for t_root in root.iter('template'):
        for e in t_root.findall('entry'):
            nm = e.get('name')
            if nm:
                templates.setdefault(nm, e)

    def _has_device(entry) -> bool:
        dev = entry.find('devices')
        if dev is None:
            return False
        if any(d.get('name') == target_serial for d in dev.findall('entry')):
            return True
        # mot so ban export dung <member> thay vi <entry name=...>
        return any(m.text and m.text.strip() == target_serial
                   for m in dev.findall('member'))

    for ts_root in root.iter('template-stack'):
        for e in ts_root.findall('entry'):
            if not _has_device(e):
                continue
            members = []
            tpl_el = e.find('templates')
            if tpl_el is not None:
                members = [m.text.strip() for m in tpl_el.findall('member')
                           if m.text and m.text.strip()]
            out = [templates[m] for m in reversed(members) if m in templates]
            return out or [e]
    for nm, e in templates.items():
        if _has_device(e):
            return [e]
    return []


def resolve_template_for_serial(root, target_serial) -> Optional[ET.Element]:
    """Tuong thich nguoc: tra ve DUY NHAT template uu tien cao nhat (hoac None)."""
    scopes = resolve_templates_for_serial(root, target_serial)
    return scopes[-1] if scopes else None


# ============================================================================
# HAM MODULE-LEVEL cho GUI (Panorama - IV.6)
# ============================================================================
def delete_rule_candidate(panorama_ip: str, api_key: str, devicegroup: str, rulebase: str,
                          rule_name: str, verify_ssl: bool = False) -> bool:
    """Xoa 1 rule tren Candidate Config cua Panorama. KHONG commit, KHONG push (D6/0.4)."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.delete_rule_candidate(devicegroup, rulebase, rule_name)


def disable_rule_candidate(panorama_ip: str, api_key: str, devicegroup: str, rulebase: str,
                           rule_name: str, verify_ssl: bool = False) -> bool:
    """Disable 1 rule tren Candidate Config (shadow hit_count==0 -> disable thay vi delete). KHONG commit, KHONG push."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.disable_rule_candidate(devicegroup, rulebase, rule_name)


def fetch_rule_hit_count(panorama_ip: str, api_key: str, target_serial: str,
                         verify_ssl: bool = False, log_func=None) -> Dict[Tuple[str, str], RuleHitStat]:
    """Best-effort (0.7): tra Dict[(name, vi_tri) -> RuleHitStat]; thieu target -> {} ngay (khong
    goi API); loi thi tra {} (khong raise). Đã sửa 2026-09-02 khoá theo (name, vi_tri) (D9)."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.fetch_rule_hit_count(target_serial, log_func=log_func)


def get_panorama_device_serials(panorama_ip: str, api_key: str,
                                verify_ssl: bool = False, log_func=None):
    """B2 (10/2026): serial cua MOI firewall Panorama dang quan ly.

    Dung de xac dinh pham vi bang chung cho rule o `Shared-PRE`/`Shared-POST` -
    nhung rule do ap cho MOI firewall, khong chi cac con trong Device Group dang
    chon, nen "0 hit tren moi con trong DG" VAN CHUA DU de ket luan UNUSED.

    Viet RIENG o day (khong import tu check_rule_pan) vi 3 package cua suite doc
    lap 100% - co tests/test_panorama_infra.py::test_3_package_khong_import_lan_nhau
    khoa lai. Loi/khong ho tro -> tra [] va log canh bao; luc do rule Shared se
    thieu bang chung -> khong ket luan UNUSED (dung huong an toan)."""
    log = log_func or (lambda msg: None)
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    try:
        root = client._request({"type": "op",
                                "cmd": "<show><devices><all/></devices></show>"})
    except Exception as e:
        log(f"CANH BAO: khong liet ke duoc cac firewall Panorama quan ly ({e}) - "
            f"rule o pham vi Shared se THIEU bang chung nen KHONG duoc ket luan UNUSED.")
        return []
    out = []
    for e in root.iter("entry"):
        sn = e.findtext("serial") or e.get("name")
        if sn and sn.strip() and sn.strip() not in out:
            out.append(sn.strip())
    return out


def fetch_rule_hit_count_multi(panorama_ip: str, api_key: str, serials,
                               verify_ssl: bool = False, log_func=None,
                               extra_shared_serials=None):
    """P1 + B2 (10/2026): hit-count GOP tren moi firewall can kiem.

    `serials`               = cac firewall cua Device Group dang chon (hoi du 4 lenh)
    `extra_shared_serials`  = cac firewall KHAC ma Panorama quan ly (chi hoi 2 lenh
                              pham vi <shared>) - bat buoc de ket luan UNUSED cho
                              rule o Shared-PRE/Shared-POST, vi rule do ap cho MOI
                              firewall chu khong chi cac con trong DG.

    Dung ham nay thay cho fetch_rule_hit_count() o moi noi ket luan UNUSED. Xem
    PanApiClient.fetch_rule_hit_count_multi() va RuleHitStat.hits_known."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.fetch_rule_hit_count_multi(
        serials, log_func=log_func, extra_shared_serials=extra_shared_serials)


def fetch_current_rule_states(panorama_ip: str, api_key: str, verify_ssl: bool = False, log_func=None) -> Optional[Dict[Tuple[str, str], dict]]:
    """
    Xác minh batch 4 lệnh wildcard action=get trên Candidate Config (IV.8), không commit.
    Ngoại lệ có chủ đích so với 0.4: dùng action=get để thấy cả thay đổi candidate chưa commit.
    Trả Dict[(name, vi_tri)->{disabled, source, destination, service, action}] hoặc None nếu lỗi bất kỳ.
    """
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.fetch_current_rule_states(log_func=log_func)


# ============================================================================
# PHU TRO HIT-COUNT VI_TRI (D9) - suy vi_tri cho hit entry
# ============================================================================
def _hit_entry_vi_tri(entry: ET.Element, parent_map: dict, log_func=None) -> Optional[str]:
    """
    Suy vi_tri Shared-PRE/Shared-POST/<DG>-PRE/<DG>-POST cho 1 rule hit entry.
    Thử theo thứ tự:
      1) Con <device-group> / <vsys> / <location> trong entry
      2) Tổ tiên device-group entry name + pre/post ancestor
      3) Tổ tiên shared + pre/post
    Trả None nếu không suy được (log cảnh báo).
    """
    log = log_func or (lambda msg: None)
    # 1) child device-group
    for tag in ("device-group", "device_group", "vsys", "location"):
        el = entry.find(tag)
        if el is not None and el.text and el.text.strip():
            dg = el.text.strip()
            # nếu dg là vsys name, coi như DG? fallback
            # thử tìm rulebase child
            rb_el = entry.find("rulebase")
            if rb_el is not None and rb_el.text:
                rb = rb_el.text.strip().lower()
                suffix = "POST" if "post" in rb else "PRE"
            else:
                suffix = "PRE"
            if dg.lower() == "shared":
                return f"Shared-{suffix}"
            return f"{dg}-{suffix}"
    # 2) walk parent_map lên tìm device-group entry hoặc shared
    cur = entry
    dg_name = None
    is_pre = None
    while cur in parent_map:
        cur = parent_map[cur]
        if cur.tag == "pre-rulebase":
            is_pre = True
        elif cur.tag == "post-rulebase":
            is_pre = False
        elif cur.tag == "entry" and cur.get("name"):
            # kiểm tra parent của entry này có phải device-group không
            parent = parent_map.get(cur)
            if parent is not None and parent.tag == "device-group":
                dg_name = cur.get("name")
                break
            # nếu parent là shared
            if parent is not None and parent.tag == "shared":
                dg_name = "shared"
                break
        elif cur.tag == "shared":
            dg_name = "shared"
            break
        elif cur.tag == "device-group":
            # trường hợp entry là device-group container, không có name, tiếp tục
            continue
    if dg_name is not None:
        if dg_name.lower() == "shared":
            suffix = "PRE" if is_pre is True else ("POST" if is_pre is False else "PRE")
            return f"Shared-{suffix}"
        suffix = "PRE" if is_pre is True else ("POST" if is_pre is False else "PRE")
        return f"{dg_name}-{suffix}"
    # 3) fallback: nếu không tìm được DG, thử tìm vsys-like parent
    # Nếu vẫn không được, trả None để caller bỏ qua
    return None


# ============================================================================
# PHU TRO PARSE GIA TRI HIT-COUNT (defensive)
# ============================================================================
def _safe_int(entry: ET.Element, tags: tuple) -> Optional[int]:
    for tag in tags:
        el = entry.find(tag)
        if el is not None and el.text:
            try:
                v = int(el.text.strip())
                if v > 0:
                    return v
                return None  # 0 / khong co hit -> None (dung D10/Mục 4.4)
            except ValueError:
                return None
    return None


def _safe_ts(entry: ET.Element, tags: tuple):
    """Timestamp epoch giay -> datetime. 0 hoac thieu field -> None."""
    for tag in tags:
        el = entry.find(tag)
        if el is not None and el.text:
            text = el.text.strip()
            if text and text != "0" and text != "-1":
                try:
                    return datetime.fromtimestamp(int(text))
                except (ValueError, OSError, OverflowError):
                    return None
    return None