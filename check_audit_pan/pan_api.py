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

    def fetch_rule_hit_count(self, target_serial: str, log_func=None) -> Dict[str, RuleHitStat]:
        """
        Best-effort (0.7/D10): doc thong ke hit-count cua TOAN BO Security Rule tren
        Target Firewall (Policy Optimizer). BAT BUOC co target_serial; thieu -> tra {}
        ngay khong goi API. Loi API -> log canh bao + tra {} (KHONG raise) - nhanh
        UNUSED se bi bo qua, nhanh UNREACHABLE van chay binh thuong.

        Dung `target=<serial>` + device-group context vi 1 rule DG co the khac nhau giua
        cac firewall trong cung DG.
        """
        log = log_func or (lambda msg: None)
        if not target_serial:
            log(
                "CANH BAO: chua chon Target Firewall (Serial) nen khoi doc Rule Hit Count "
                "(a.nh huong nhanh UNUSED trong Shadow Rules) - bo qua."
            )
            return {}
        cmd = (
            "<show><rule-hit-count><device-group>"
            f"<entry name='*'><device-group-name>"
            f"<entry name='*'><serial>{target_serial}</serial>"
            "<rule-base><entry name='security'><rules><all/></rules></entry></rule-base>"
            "</entry></device-group-name></entry>"
            "</device-group></rule-hit-count></show>"
        )
        try:
            root = self._request({"type": "op", "cmd": cmd, "target": target_serial})
        except Exception as e:
            log(
                "CANH BAO: Khong lay duoc du lieu Policy Optimizer (rule-hit-count) - "
                "tieu chi UNUSED trong Shadow Rules se bi bo qua, cac tieu chi khac "
                f"van chay binh thuong. ({e})"
            )
            logger.warning("Policy Optimizer rule-hit-count failed: %s", e)
            return {}

        result: Dict[str, RuleHitStat] = {}
        rules_el = root.find(".//rules")
        source_el = rules_el if rules_el is not None else root
        for entry in source_el.findall(".//entry"):
            name = entry.get("name")
            if not name:
                continue
            result[name] = RuleHitStat(
                hit_count=_safe_int(entry, ("hit-count", "hit_count")),
                last_hit_timestamp=_safe_ts(entry, ("last-hit-timestamp", "last-hit")),
                rule_creation_timestamp=_safe_ts(entry, ("rule-creation-timestamp", "rule-created")),
            )
        if not result:
            log("CANH BAO: API rule-hit-count tra ve rong (khong co du lieu rule nao).")
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


def _dg_parents_from_config(config_root: ET.Element) -> Dict[str, Optional[str]]:
    """Map {ten_dg: ten_dg_cha_or_None}. Doc <settings><parent-dg> cua moi DG."""
    parents: Dict[str, Optional[str]] = {}
    for dg_el in config_root.findall('.//device-group/entry'):
        name = dg_el.get('name')
        if not name:
            continue
        parent = None
        parent_el = dg_el.find('.//parent-dg')
        if parent_el is not None and parent_el.text and parent_el.text.strip():
            parent = parent_el.text.strip()
        parents[name] = parent
    if not parents:
        for name in get_devicegroup_list(config_root):
            parents.setdefault(name, None)
    return parents


def resolve_devicegroup_chain(config_root: ET.Element, dg_name: str) -> List[str]:
    """Tra ve chuoi ten theo thu tu thua ke (0.2):
       [Shared, DG-goc-nhat, ..., DG-cha-truc-tiep, DG-hien-tai]
    Shared LUON LA LOP GOC (tang nen) bat ke DG co cha hay khong (0.2)."""
    parents = _dg_parents_from_config(config_root)
    chain: List[str] = []
    cur = dg_name or ""
    while cur:
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


def resolve_template_for_serial(root, target_serial) -> Optional[ET.Element]:
    """Best-effort: tra ve Template/Template Stack ap dung cho serial."""
    def _find_template_entry(tname):
        for t in root.findall(".//template/entry"):
            if t.get('name') == tname:
                return t
        for ts in root.findall(".//template-stack/entry"):
            if ts.get('name') == tname:
                return ts
        return None

    dev_el = None
    for d in root.findall("./devices/entry"):
        if d.get('name') == target_serial:
            dev_el = d
            break
    if dev_el is not None:
        t_el = dev_el.find('.//template')
        if t_el is not None and t_el.text and t_el.text.strip():
            scope = _find_template_entry(t_el.text.strip())
            if scope is not None:
                return scope
        ts_el = dev_el.find('.//template-stack')
        if ts_el is not None and ts_el.text and ts_el.text.strip():
            scope = _find_template_entry(ts_el.text.strip())
            if scope is not None:
                return scope
        # Panorama moi: devices/<serial>/template-stack via member list
        for ts in root.findall(".//template-stack/entry"):
            for m in ts.findall(".//devices/member"):
                if m.text and m.text.strip() == target_serial:
                    return ts
    return None


# ============================================================================
# HAM MODULE-LEVEL cho GUI (Panorama - IV.6)
# ============================================================================
def delete_rule_candidate(panorama_ip: str, api_key: str, devicegroup: str, rulebase: str,
                          rule_name: str, verify_ssl: bool = False) -> bool:
    """Xoa 1 rule tren Candidate Config cua Panorama. KHONG commit, KHONG push (D6/0.4)."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.delete_rule_candidate(devicegroup, rulebase, rule_name)


def fetch_rule_hit_count(panorama_ip: str, api_key: str, target_serial: str,
                         verify_ssl: bool = False, log_func=None) -> Dict[str, RuleHitStat]:
    """Best-effort (0.7): tra Dict[name -> RuleHitStat]; thieu target -> {} ngay (khong
    goi API); loi thi tra {} (khong raise)."""
    client = PanApiClient(panorama_ip, api_key, verify_ssl=verify_ssl)
    return client.fetch_rule_hit_count(target_serial, log_func=log_func)


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