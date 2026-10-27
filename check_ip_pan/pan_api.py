# -*- coding: utf-8 -*-
"""
pan_api.py - Ket noi PAN-OS XML API + doc/parse cau hinh (Address/Service
Object/Group, Security Rule) tu XML running-config.
(Gop tu pan_api_client.py + config_parser.py cu)
"""

import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Set, Tuple

import requests
import urllib3

from .core import (
    DEFAULT_TIMEOUT,
    PanApiError, PanConnectionError, PanTimeoutError, PanAuthError,
    AddressObject, AddressGroup, ServiceObject, ServiceGroup, SecurityRule, NatRule,
)

# ============================================================================
# PAN-OS XML API CLIENT
# ============================================================================
class PanApiClient:
    """
    Client goi PAN-OS XML API (https://<firewall>/api/).
    Nguoi dung da co san API Key (khong can keygen tu username/password).
    """

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
        """Kiem tra ket noi + API Key hop le bang lenh show system info. Tra ve hostname."""
        root = self._request({"type": "op", "cmd": "<show><system><info></info></system></show>"})
        hostname_el = root.find(".//hostname")
        return hostname_el.text.strip() if hostname_el is not None and hostname_el.text else "N/A"

    def fetch_running_config(self) -> ET.Element:
        """
        Doc FULL running configuration (cau hinh THUC TE dang active tren thiet bi,
        khong phai candidate config chua commit) trong DUY NHAT 1 API call,
        tranh anti-pattern goi API lap lai nhieu lan tung phan nho.
        """
        root = self._request({"type": "config", "action": "show", "xpath": "/config"})
        config_el = root.find(".//config")
        if config_el is None:
            raise PanApiError("No <config> element in response", "Khong doc duoc cau hinh tu Firewall (phan hoi rong).")
        return config_el

    def fetch_registered_ip(self) -> Dict[str, Set[str]]:
        """
        Best-effort: lay bang registered-ip -> tag, dung de resolve Dynamic Address
        Group (neu firewall ho tro / co du quyen). Loi o day KHONG lam crash chuong
        trinh - chi bo qua Dynamic Address Group, tiep tuc chay binh thuong.
        """
        try:
            root = self._request({
                "type": "op",
                "cmd": "<show><object><registered-ip><all/></registered-ip></object></show>",
            })
        except PanApiError:
            return {}
        result: Dict[str, Set[str]] = {}
        for entry in root.findall(".//entry"):
            ip = entry.get("ip")
            if not ip:
                continue
            tags = {m.text for m in entry.findall(".//member") if m.text}
            result.setdefault(ip, set()).update(tags)
        return result

# ============================================================================
# DIEU HUONG + PARSE XML CAU HINH
# ============================================================================
def get_vsys_list(config_root: ET.Element) -> List[str]:
    """!!! KHONG PHAI bo chon pham vi cua ban PANORAMA !!!
    Pham vi cua ban Panorama la DEVICE GROUP - dung `get_devicegroup_list()`.
    Ham nay doc `/config/devices/entry/vsys/entry`, ma tren Panorama nhanh do la
    chinh PANORAMA (localhost.localdomain), KHONG phai firewall duoc quan ly.
    Giu lai CHI de doc vsys that cua 1 thiet bi khi can tham so `vsys` cho Live
    Match (0.5) va cho test tuong thich - TUYET DOI khong dung lam dropdown pham vi."""
    """Lay danh sach ten VSYS truc tiep tu running-config da tai (khong can goi API rieng)."""
    names: List[str] = []
    devices = config_root.find("devices")
    if devices is None:
        return names
    for dev_entry in devices.findall("entry"):
        vsys_parent = dev_entry.find("vsys")
        if vsys_parent is None:
            continue
        for vsys_entry in vsys_parent.findall("entry"):
            n = vsys_entry.get("name")
            if n:
                names.append(n)
    return names


def get_vsys_element(config_root: ET.Element, vsys_name: str) -> Optional[ET.Element]:
    """Xem canh bao o get_vsys_list() - khong dung lam nguon object cua ban Panorama
    (object nam o Shared + chuoi Device Group, xem merge_layered_objects)."""
    devices = config_root.find("devices")
    if devices is None:
        return None
    for dev_entry in devices.findall("entry"):
        vsys_parent = dev_entry.find("vsys")
        if vsys_parent is None:
            continue
        for vsys_entry in vsys_parent.findall("entry"):
            if vsys_entry.get("name") == vsys_name:
                return vsys_entry
    return None


def get_shared_element(config_root: ET.Element) -> ET.Element:
    shared = config_root.find("shared")
    return shared if shared is not None else ET.Element("shared")


# ============================================================================
# DEVICE GROUP PHAI HUONG (Panorama - bản CHECK IP)
# ============================================================================
def get_devicegroup_list(config_root: ET.Element) -> List[str]:
    """Liet ke ten tat ca Device Group trong config Panorama (khong gom 'shared')."""
    names: List[str] = []
    seen = set()
    for dg_el in config_root.findall(".//device-group/entry"):
        nm = dg_el.get("name")
        if nm and nm not in seen:
            seen.add(nm)
            names.append(nm)
    return names


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


def resolve_devicegroup_chain(config_root: ET.Element, dg_name: str
                              ) -> Tuple[List[str], List[Optional[ET.Element]]]:
    """Tra ve (danh sach ten theo Shared->...->DG cha->DG hien tai, danh sach
    phan tu XML tuong ung). Shared LUON LA LOP GOC (tang nen - 0.2)."""
    parents = _dg_parents_from_config(config_root)
    chain_names: List[str] = []
    cur = dg_name
    visited = set()
    while cur:
        if cur in visited:
            break
        visited.add(cur)
        chain_names.append(cur)
        parent = parents.get(cur)
        if not parent or parent == cur:
            break
        cur = parent
    chain_names.reverse()
    chain_names = ["shared"] + chain_names

    dg_elements = _devicegroup_entries(config_root)
    chain_els: List[Optional[ET.Element]] = []
    for nm in chain_names:
        if nm == "shared" or nm == "Shared":
            chain_els.append(config_root.find("shared"))
        else:
            chain_els.append(dg_elements.get(nm))
    return chain_names, chain_els


def collect_all_object_layers(config_root: ET.Element
                              ) -> "List[Tuple[str, Dict, Dict]]":
    """(ten tang, address_objects, address_groups) cho SHARED + MOI Device Group.

    VI SAO CAN CA NHUNG DG NGOAI CHUOI DANG CHON
    ============================================
    Object tren Panorama la tap CHA: cai gi firewall thay thi Panorama deu co,
    va con nhieu hon. Nen khi nguoi dung go mot IP/ten co that ma tool bao
    "khong tim thay", loi la o TOOL - va cau tra loi dung khong phai mot cau
    ra dieu kien ("co the no nam o DG khac") ma la mot cau KHANG DINH: no nam
    o DG nao.

    Ca config Panorama da nam san trong bo nho (`config_root`), nen quet het
    moi Device Group KHONG ton them mot lenh API nao.
    """
    out = []
    shared = config_root.find("shared")
    if shared is not None:
        out.append(("shared", parse_address_objects(shared),
                    parse_address_groups(shared)))
    for name, el in sorted(_devicegroup_entries(config_root).items()):
        out.append((name, parse_address_objects(el), parse_address_groups(el)))
    return out


def merge_layered_objects(config_root: ET.Element, dg_name: str) -> Dict[str, Dict]:
    """Nạp toàn bộ Address/Service Object+Group theo 0.2: Shared truoc, DG xa
    DE DG gan hon neu trung ten. Tra ve dict:
      {'address_objects':..., 'address_groups':..., 'service_objects':..., 'service_groups':...}
    """
    _, chain_els = resolve_devicegroup_chain(config_root, dg_name)
    merged = {
        "address_objects": {},
        "address_groups": {},
        "service_objects": {},
        "service_groups": {},
    }
    for el in chain_els:
        if el is None:
            continue
        merged["address_objects"].update(parse_address_objects(el))
        merged["address_groups"].update(parse_address_groups(el))
        merged["service_objects"].update(parse_service_objects(el))
        merged["service_groups"].update(parse_service_groups(el))
    return merged


def _parse_security_rules_rulebase(container: ET.Element, label: str, rulebase: str
                                   ) -> List[SecurityRule]:
    """Parse 1 pre-rulebase HOAC post-rulebase cua 1 container (shared / device-group
    entry). container phai chua <{rulebase}-rulebase>. Gan vi_tri = '<label>-PRE/POST'.
    Giữ nguyên parse logic 1 dòng (không đổi so với bản gốc) - chi khac xpath nguon."""
    prefix = "PRE" if rulebase == "pre" else "POST"
    rb = container.find(f"{rulebase}-rulebase")
    if rb is None:
        return []
    security = rb.find("security")
    if security is None:
        return []
    rules_parent = security.find("rules")
    if rules_parent is None:
        return []
    return _parse_security_rules_from_rules_el(rules_parent, f"{label}-{prefix}")


def _parse_security_rules_from_rules_el(rules_parent: ET.Element, vi_tri: str
                                        ) -> List[SecurityRule]:
    """Doc day du cac truong cua Security Policy tu 1 <rules> (da co vi_tri)."""
    rules: List[SecurityRule] = []
    for idx, entry in enumerate(rules_parent.findall("entry")):
        name = entry.get("name") or f"(unnamed-{idx})"
        uuid = entry.get("uuid") or ""
        disabled_el = entry.find("disabled")
        disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"
        action_el = entry.find("action")
        action = (action_el.text or "").strip() if action_el is not None and action_el.text else ""
        desc_el = entry.find("description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
        log_el = entry.find("log-setting")
        log_setting = log_el.text.strip() if log_el is not None and log_el.text else ""
        sched_el = entry.find("schedule")
        schedule = sched_el.text.strip() if sched_el is not None and sched_el.text else ""

        rule = SecurityRule(
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
            security_profile=_parse_profile_setting(entry),
            log_setting=log_setting,
            schedule=schedule,
            description=description,
            tags=_members(entry, "tag"),
            disabled=disabled,
            target=_parse_target(entry),
            hip=_parse_hip(entry),
            source_user=_members(entry, "source-user"),
            vi_tri=vi_tri,
        )
        rules.append(rule)
    return rules


def assemble_security_rules(config_root: ET.Element, dg_name: str) -> List[SecurityRule]:
    """Lắp ráp Security Policy theo DUNG 6 buoc 0.3 (khong tinh Local rule cua
    firewall vi tool nay khong co Target Firewall - xem III.10):
      1. Shared PRE-rulebase
      2. DG to tien xa nhat -> ... -> DG hien tai, PRE-rulebase
      3. DG hien tai -> DG cha truc tiep -> ... -> DG to tien xa nhat, POST-rulebase
      4. Shared POST-rulebase
    Index cuoi duoc gan lai tang dan theo dung thu tu nay."""
    chain_names, chain_els = resolve_devicegroup_chain(config_root, dg_name)
    dg_only_els = [el for el, nm in zip(chain_els, chain_names) if nm not in ("shared", "Shared")]
    dg_only_names = [nm for nm in chain_names if nm not in ("shared", "Shared")]

    assembled: List[SecurityRule] = []
    shared_el = config_root.find("shared")

    if shared_el is not None:
        assembled += _parse_security_rules_rulebase(shared_el, "Shared", "pre")

    for el, nm in zip(dg_only_els, dg_only_names):
        if el is not None:
            assembled += _parse_security_rules_rulebase(el, nm, "pre")

    for el, nm in zip(reversed(dg_only_els), reversed(dg_only_names)):
        if el is not None:
            assembled += _parse_security_rules_rulebase(el, nm, "post")

    if shared_el is not None:
        assembled += _parse_security_rules_rulebase(shared_el, "Shared", "post")

    for i, r in enumerate(assembled):
        r.index = i
    return assembled


def parse_security_rules(vsys_el: ET.Element) -> List[SecurityRule]:
    """Doc `<rulebase><security><rules>` kieu Firewall standalone (khong pre/post).
    Tren PANORAMA cau truc nay KHONG ton tai o Device Group - chi dung khi doc rule
    CUC BO cua chinh 1 firewall (0.3 buoc 3). Rulebase cua Device Group phai dung
    `assemble_security_rules()`."""
    """(giu cho tuong thich nguoc) Doc Security Policy cua 1 container co the co
    <rulebase> phang (bản Firewall đơn). Bản Panorama nen dung assemble_security_rules."""
    rulebase = vsys_el.find("rulebase")
    if rulebase is None:
        return []
    security = rulebase.find("security")
    if security is None:
        return []
    rules_parent = security.find("rules")
    if rules_parent is None:
        return []
    return _parse_security_rules_from_rules_el(rules_parent, "")


# ============================================================================
# XML PARSING: Address Object / Address Group / Security Rule
# ============================================================================

def _members(el: Optional[ET.Element], tag: str) -> List[str]:
    """Doc danh sach <tag><member>...</member></tag>."""
    if el is None:
        return []
    parent = el.find(tag)
    if parent is None:
        return []
    return [m.text for m in parent.findall("member") if m.text]


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
            result[name] = AddressObject(name, "ip-netmask", ipnm.text.strip())
        elif iprg is not None and iprg.text:
            result[name] = AddressObject(name, "ip-range", iprg.text.strip())
        elif fqdn is not None and fqdn.text:
            result[name] = AddressObject(name, "fqdn", fqdn.text.strip())
        else:
            result[name] = AddressObject(name, "unknown", "")
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
        dynamic_el = entry.find("dynamic")
        if static_el is not None:
            members = [m.text for m in static_el.findall("member") if m.text]
            result[name] = AddressGroup(name, "static", members=members)
        elif dynamic_el is not None:
            filt_el = dynamic_el.find("filter")
            filt = filt_el.text.strip() if filt_el is not None and filt_el.text else ""
            result[name] = AddressGroup(name, "dynamic", filter_expr=filt)
        else:
            result[name] = AddressGroup(name, "static", members=[])
    return result


def parse_service_objects(container: ET.Element) -> Dict[str, ServiceObject]:
    """Doc Service Object (vd TCP_1521 = tcp/1521) de sau nay 'break' Service
    trong rule ra dung protocol/port that, khong chi hien ten object."""
    result: Dict[str, ServiceObject] = {}
    parent = container.find("service")
    if parent is None:
        return result
    for entry in parent.findall("entry"):
        name = entry.get("name")
        if not name:
            continue
        protocol_el = entry.find("protocol")
        proto, port = "unknown", ""
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
    """Service Group dung tag <members><member> (KHAC voi Address Group dung
    <static><member>) - da tra cuu lai schema chinh thuc PAN-OS de xac nhan."""
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



def _parse_profile_setting(entry: ET.Element) -> str:
    ps = entry.find("profile-setting")
    if ps is None:
        return ""
    grp = ps.find("group")
    if grp is not None:
        members = [m.text for m in grp.findall("member") if m.text]
        if members:
            return "Group: " + ", ".join(members)
        return ""
    profs = ps.find("profiles")
    if profs is not None:
        parts = []
        for child in profs:
            members = [m.text for m in child.findall("member") if m.text]
            if members:
                parts.append(f"{child.tag}: {', '.join(members)}")
        return "; ".join(parts)
    return ""


def _parse_target(entry: ET.Element) -> str:
    target_el = entry.find("target")
    if target_el is None:
        return ""
    devices_el = target_el.find("devices")
    if devices_el is None:
        return ""
    serials = [d.get("name") for d in devices_el.findall("entry") if d.get("name")]
    return ", ".join(serials)


def _parse_hip(entry: ET.Element) -> str:
    parts = []
    src_hip = _members(entry, "source-hip")
    dst_hip = _members(entry, "destination-hip")
    if src_hip:
        parts.append("Src: " + ", ".join(src_hip))
    if dst_hip:
        parts.append("Dst: " + ", ".join(dst_hip))
    return "; ".join(parts)


# ============================================================================
# XML PARSING: NAT Rule (rulebase/nat/rules)
# ============================================================================
def _parse_source_translation(entry: ET.Element) -> Dict[str, object]:
    """Doc <source-translation> - ho tro 3 kieu PAN-OS: dynamic-ip-and-port
    (translated-address list HOAC interface-address), dynamic-ip
    (translated-address list), static-ip (1 dia chi + bi-directional)."""
    result = {
        "type": "", "addresses": [], "interface": "", "interface_ip": "", "bidirectional": False,
    }
    st = entry.find("source-translation")
    if st is None:
        return result

    dipp = st.find("dynamic-ip-and-port")
    if dipp is not None:
        result["type"] = "dynamic-ip-and-port"
        ta = dipp.find("translated-address")
        if ta is not None:
            result["addresses"] = [m.text for m in ta.findall("member") if m.text]
        ia = dipp.find("interface-address")
        if ia is not None:
            iface_el = ia.find("interface")
            ip_el = ia.find("ip")
            result["interface"] = iface_el.text.strip() if iface_el is not None and iface_el.text else ""
            result["interface_ip"] = ip_el.text.strip() if ip_el is not None and ip_el.text else ""
        return result

    dip = st.find("dynamic-ip")
    if dip is not None:
        result["type"] = "dynamic-ip"
        ta = dip.find("translated-address")
        if ta is not None:
            result["addresses"] = [m.text for m in ta.findall("member") if m.text]
        return result

    sip = st.find("static-ip")
    if sip is not None:
        result["type"] = "static-ip"
        ta = sip.find("translated-address")
        if ta is not None and ta.text:
            result["addresses"] = [ta.text.strip()]
        bd = sip.find("bi-directional")
        result["bidirectional"] = bd is not None and (bd.text or "").strip().lower() == "yes"
        return result

    return result


def _parse_destination_translation(entry: ET.Element) -> Dict[str, str]:
    """Doc <destination-translation> (static) hoac <dynamic-destination-translation>."""
    result = {"type": "", "address": "", "port": ""}

    dt = entry.find("destination-translation")
    if dt is not None:
        result["type"] = "static"
        addr_el = dt.find("translated-address")
        port_el = dt.find("translated-port")
        result["address"] = addr_el.text.strip() if addr_el is not None and addr_el.text else ""
        result["port"] = port_el.text.strip() if port_el is not None and port_el.text else ""
        return result

    ddt = entry.find("dynamic-destination-translation")
    if ddt is not None:
        result["type"] = "dynamic"
        addr_el = ddt.find("translated-address")
        port_el = ddt.find("translated-port")
        result["address"] = addr_el.text.strip() if addr_el is not None and addr_el.text else ""
        result["port"] = port_el.text.strip() if port_el is not None and port_el.text else ""
        return result

    return result


def _parse_nat_rules_from_rules_el(rules_parent: ET.Element, vi_tri: str) -> List[NatRule]:
    """
    Doc bang NAT Rule tu 1 <rules> (da co vi_tri): Rule Name, UUID, Zone,
    Source/Destination Address (raw - se resolve/break ra value that o buoc
    export, giong het cach lam voi Security Rule), Service, Source
    Translation (dynamic-ip-and-port / dynamic-ip / static-ip) va
    Destination Translation (static / dynamic). Khong crash neu thieu truong -
    NAT rule co the co rat nhieu bien the (No NAT / bidirectional / interface
    binding...), luon tra ve gia tri rong thay vi loi.
    """
    rules: List[NatRule] = []
    for idx, entry in enumerate(rules_parent.findall("entry")):
        name = entry.get("name") or f"(unnamed-{idx})"
        uuid = entry.get("uuid") or ""
        disabled_el = entry.find("disabled")
        disabled = disabled_el is not None and (disabled_el.text or "").strip().lower() == "yes"
        desc_el = entry.find("description")
        description = desc_el.text.strip() if desc_el is not None and desc_el.text else ""
        svc_el = entry.find("service")
        service = svc_el.text.strip() if svc_el is not None and svc_el.text else "any"
        to_iface_el = entry.find("to-interface")
        to_interface = to_iface_el.text.strip() if to_iface_el is not None and to_iface_el.text else ""
        nat_type = entry.get("nat-type") or (entry.findtext("nat-type") or "ipv4")

        src_xlate = _parse_source_translation(entry)
        dst_xlate = _parse_destination_translation(entry)

        rule = NatRule(
            index=idx,
            name=name,
            uuid=uuid,
            from_zones=_members(entry, "from"),
            to_zones=_members(entry, "to"),
            to_interface=to_interface,
            source=_members(entry, "source"),
            destination=_members(entry, "destination"),
            service=service,
            nat_type=nat_type,
            disabled=disabled,
            description=description,
            tags=_members(entry, "tag"),
            src_xlate_type=src_xlate["type"],
            src_xlate_addresses=src_xlate["addresses"],
            src_xlate_interface=src_xlate["interface"],
            src_xlate_interface_ip=src_xlate["interface_ip"],
            src_xlate_bidirectional=src_xlate["bidirectional"],
            dst_xlate_type=dst_xlate["type"],
            dst_xlate_address=dst_xlate["address"],
            dst_xlate_port=dst_xlate["port"],
            vi_tri=vi_tri,
        )
        rules.append(rule)
    return rules


def _parse_nat_rules_rulebase(container: ET.Element, label: str, rulebase: str
                              ) -> List[NatRule]:
    """Parse 1 pre-rulebase HOAC post-rulebase cua 1 container (shared / device-group
    entry). container phai chua <{rulebase}-rulebase>. Gan vi_tri = '<label>-PRE/POST'."""
    prefix = "PRE" if rulebase == "pre" else "POST"
    rb = container.find(f"{rulebase}-rulebase")
    if rb is None:
        return []
    nat = rb.find("nat")
    if nat is None:
        return []
    rules_parent = nat.find("rules")
    if rules_parent is None:
        return []
    return _parse_nat_rules_from_rules_el(rules_parent, f"{label}-{prefix}")


def assemble_nat_rules(config_root: ET.Element, dg_name: str) -> List[NatRule]:
    """Lắp ráp NAT Rulebase theo 0.3 (ap dung tuong tu Security Rule): Shared-PRE ->
    DG chain-PRE -> DG chain-POST (reverse) -> Shared-POST. Index gan lai tang dan."""
    chain_names, chain_els = resolve_devicegroup_chain(config_root, dg_name)
    dg_only_els = [el for el, nm in zip(chain_els, chain_names) if nm not in ("shared", "Shared")]
    dg_only_names = [nm for nm in chain_names if nm not in ("shared", "Shared")]

    assembled: List[NatRule] = []
    shared_el = config_root.find("shared")

    if shared_el is not None:
        assembled += _parse_nat_rules_rulebase(shared_el, "Shared", "pre")

    for el, nm in zip(dg_only_els, dg_only_names):
        if el is not None:
            assembled += _parse_nat_rules_rulebase(el, nm, "pre")

    for el, nm in zip(reversed(dg_only_els), reversed(dg_only_names)):
        if el is not None:
            assembled += _parse_nat_rules_rulebase(el, nm, "post")

    if shared_el is not None:
        assembled += _parse_nat_rules_rulebase(shared_el, "Shared", "post")

    for i, r in enumerate(assembled):
        r.index = i
    return assembled


