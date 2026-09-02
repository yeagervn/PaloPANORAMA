# -*- coding: utf-8 -*-
import ipaddress
import re
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict

import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants & Patterns
_RANGE_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){3})\s*-\s*(\d{1,3}(?:\.\d{1,3}){3})$')
_PORTLESS_APPLICATIONS = {"icmp", "ping", "traceroute", "icmpv6"}

# PAN-OS 'test security-policy-match' yeu cau protocol la SO HIEU IP protocol
# (khong phai chuoi 'tcp'/'udp'). TCP=6, UDP=17, ICMP=1.
_PROTOCOL_NUMBERS = {'tcp': 6, 'udp': 17, 'icmp': 1}

_LIVE_MATCH_SEMAPHORE = threading.BoundedSemaphore(8)
_SEMAPHORE_LOCK = threading.Lock()


def configure_live_match_concurrency(n: int):
    global _LIVE_MATCH_SEMAPHORE
    n = max(5, min(40, int(n)))
    with _SEMAPHORE_LOCK:
        _LIVE_MATCH_SEMAPHORE = threading.BoundedSemaphore(n)


_SESSION = requests.Session()
_SESSION.mount('https://', requests.adapters.HTTPAdapter(pool_connections=25, pool_maxsize=25, max_retries=0))


# =========================================================================
# IP / PORT PARSING UTILITIES (GIO NGUYEN 100% so vs bản Firewall)
# =========================================================================

def split_multi_value(cell) -> List[str]:
    if cell is None:
        return []
    s = str(cell)
    if s.strip().lower() in ('nan', 'none'):
        return []
    for sep in (';', '\n', '\r', '\t'):
        s = s.replace(sep, ',')
    parts = [p.strip().strip(',') for p in s.split(',')]
    return [p for p in parts if p]


def parse_ip_token(tok: str) -> dict:
    tok = tok.strip()
    m = _RANGE_RE.match(tok)
    if m:
        try:
            a = int(ipaddress.IPv4Address(m.group(1)))
            b = int(ipaddress.IPv4Address(m.group(2)))
            if a > b:
                a, b = b, a
            return {'raw': tok, 'kind': 'range', 'start': a, 'end': b, 'display': tok}
        except Exception:
            return {'raw': tok, 'kind': 'invalid', 'start': None, 'end': None, 'display': tok}
    try:
        net = ipaddress.ip_network(tok, strict=False)
        start = int(net.network_address)
        end = int(net.broadcast_address)
        kind = 'host' if net.num_addresses == 1 else 'cidr'
        return {'raw': tok, 'kind': kind, 'start': start, 'end': end, 'display': tok}
    except Exception:
        return {'raw': tok, 'kind': 'invalid', 'start': None, 'end': None, 'display': tok}


def parse_port_token(tok: str) -> Optional[Tuple[int, int]]:
    tok = tok.strip()
    tok2 = re.sub(r'(?i)^(tcp|udp)[/:\s]+', '', tok)
    tok2 = re.sub(r'(?i)[/:\s]+(tcp|udp)$', '', tok2)
    tok2 = tok2.strip()
    m = re.match(r'^(\d+)\s*-\s*(\d+)$', tok2)
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        if a > b:
            a, b = b, a
        return (a, b)
    if re.match(r'^\d+(\.0)?$', tok2):
        return (int(float(tok2)), int(float(tok2)))
    return None


def detect_protocol(tok: str) -> Optional[str]:
    tok = tok.strip().lower()
    if tok.startswith('tcp') or tok.endswith('tcp'):
        return 'tcp'
    if tok.startswith('udp') or tok.endswith('udp'):
        return 'udp'
    return None


def is_literal_ip_or_cidr(name: str) -> Optional[dict]:
    name = (name or '').strip()
    if not name:
        return None
    try:
        net = ipaddress.ip_network(name, strict=False)
        return {'start': int(net.network_address), 'end': int(net.broadcast_address),
                'num': net.num_addresses}
    except Exception:
        return None


# =========================================================================
# DATA MODELS
# =========================================================================

@dataclass
class AddressObject:
    name: str
    kind: str  # 'host' | 'wide' | 'range' | 'fqdn' | 'unknown'
    start: Optional[int] = None
    end: Optional[int] = None
    display: str = ''


@dataclass
class AddressGroup:
    name: str
    members: List[str] = field(default_factory=list)


@dataclass
class ServiceObject:
    name: str
    protocol: str  # 'tcp' | 'udp' | 'unknown'
    port_raw: str = ''
    ranges: List[Tuple[int, int]] = field(default_factory=list)


@dataclass
class ServiceGroup:
    name: str
    members: List[str] = field(default_factory=list)


@dataclass
class SecurityRule:
    index: int
    name: str
    source: List[str]
    destination: List[str]
    service: List[str]
    application: List[str]
    action: str
    disabled: bool
    from_zones: List[str] = field(default_factory=lambda: ['any'])
    to_zones: List[str] = field(default_factory=lambda: ['any'])
    # BAN PANORAMA: them 2 truong mo ta VI TRI cua rule (Shared/DG + pre/post) - bat
    # buoc vi khong con 1 vsys phang. Khong doi bat ky logic tier/shadow nao - chi
    # them thong tin vi tri de hien thi/gia thich.
    vi_tri: str = ''          # 'Shared-PRE' | '<DG>'-PRE | '<DG>'-POST | 'Shared-POST' | 'Local'
    rulebase: str = 'pre'     # 'pre' | 'post'


# =========================================================================
# XML PARSING LOGIC (parse theo container: shared HOAC 1 device-group entry)
# =========================================================================

def _text(el, default=''):
    return el.text.strip() if (el is not None and el.text) else default


def _members(el) -> List[str]:
    if el is None:
        return []
    return [m.text.strip() for m in el.findall('member') if m.text and m.text.strip()]


def parse_address_objects(container) -> Dict[str, AddressObject]:
    out = {}
    if container is None:
        return out
    addr = container.find('address')
    if addr is None:
        return out
    for e in addr.findall('entry'):
        name = e.get('name')
        nm = e.find('ip-netmask')
        rg = e.find('ip-range')
        fq = e.find('fqdn')
        if nm is not None and nm.text:
            val = nm.text.strip()
            try:
                net = ipaddress.ip_network(val, strict=False)
                if net.num_addresses == 1:
                    out[name] = AddressObject(name, 'host', int(net.network_address),
                                               int(net.network_address), val)
                else:
                    out[name] = AddressObject(name, 'wide', int(net.network_address),
                                               int(net.broadcast_address), val)
            except Exception:
                out[name] = AddressObject(name, 'unknown', display=val)
        elif rg is not None and rg.text:
            val = rg.text.strip()
            try:
                a, b = val.split('-', 1)
                start = int(ipaddress.IPv4Address(a.strip()))
                end = int(ipaddress.IPv4Address(b.strip()))
                if start > end:
                    start, end = end, start
                out[name] = AddressObject(name, 'range', start, end, val)
            except Exception:
                out[name] = AddressObject(name, 'unknown', display=val)
        elif fq is not None and fq.text:
            out[name] = AddressObject(name, 'fqdn', display=fq.text.strip())
        else:
            out[name] = AddressObject(name, 'unknown')
    return out


def parse_address_groups(container) -> Dict[str, AddressGroup]:
    out = {}
    if container is None:
        return out
    ag = container.find('address-group')
    if ag is None:
        return out
    for e in ag.findall('entry'):
        name = e.get('name')
        st = e.find('static')
        members = _members(st) if st is not None else []
        out[name] = AddressGroup(name, members)
    return out


def parse_service_objects(container) -> Dict[str, ServiceObject]:
    out = {}
    if container is None:
        return out
    svc = container.find('service')
    if svc is None:
        return out
    for e in svc.findall('entry'):
        name = e.get('name')
        proto_el = e.find('protocol')
        protocol = 'unknown'
        port_raw = ''
        if proto_el is not None:
            tcp = proto_el.find('tcp')
            udp = proto_el.find('udp')
            if tcp is not None:
                protocol = 'tcp'
                port_raw = _text(tcp.find('port'))
            elif udp is not None:
                protocol = 'udp'
                port_raw = _text(udp.find('port'))
        ranges = []
        for part in port_raw.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                try:
                    a, b = part.split('-', 1)
                    ranges.append((int(a), int(b)))
                except Exception:
                    pass
            elif part.isdigit():
                ranges.append((int(part), int(part)))
        out[name] = ServiceObject(name, protocol, port_raw, ranges)
    return out


def parse_service_groups(container) -> Dict[str, ServiceGroup]:
    out = {}
    if container is None:
        return out
    sg = container.find('service-group')
    if sg is None:
        return out
    for e in sg.findall('entry'):
        name = e.get('name')
        members_el = e.find('members')
        members = _members(members_el) if members_el is not None else []
        out[name] = ServiceGroup(name, members)
    return out


def _parse_security_rules_from_rules_el(rules_el, vi_tri, rulebase) -> List[SecurityRule]:
    """Parse toan bo <entry> trong 1 <rules> (cua 1 pre/post-rulebase) thanh List[SecurityRule].
    Index se duoc gan lai o buoc lắp ráp 0.3 (khong dung index tang dan tai day)."""
    out = []
    for e in rules_el.findall('entry'):
        name = e.get('name')
        source = _members(e.find('source')) or ['any']
        destination = _members(e.find('destination')) or ['any']
        service = _members(e.find('service')) or ['any']
        application = _members(e.find('application')) or ['any']
        from_zones = _members(e.find('from')) or ['any']
        to_zones = _members(e.find('to')) or ['any']
        action = _text(e.find('action'), 'allow')
        disabled = _text(e.find('disabled')).lower() == 'yes'
        out.append(SecurityRule(-1, name, source, destination, service, application,
                                 action, disabled, from_zones, to_zones, vi_tri, rulebase))
    return out


def parse_security_rules_in(container, vi_tri, rulebase) -> List[SecurityRule]:
    """Parse 1 pre-rulebase HOAC post-rulebase cua 1 container (shared / device-group).
    container phai chua <pre-rulebase> hoac <post-rulebase> truc tiep."""
    rb = container.find(f'{rulebase}-rulebase')
    if rb is None:
        return []
    sec = rb.find('security')
    if sec is None:
        return []
    rules_el = sec.find('rules')
    if rules_el is None:
        return []
    return _parse_security_rules_from_rules_el(rules_el, vi_tri, rulebase)


def list_devicegroups(root) -> List[str]:
    """Liet ke ten tat ca Device Group trong config Panorama."""
    names = []
    for dg_el in root.findall('.//device-group/entry'):
        nm = dg_el.get('name')
        if nm:
            names.append(nm)
    seen = set()
    uniq = []
    for n in names:
        if n not in seen:
            seen.add(n)
            uniq.append(n)
    return uniq


def _dg_parents_from_config(root) -> Dict[str, Optional[str]]:
    """Xac dinh cha cua moi Device Group bang cach doc phan tu <parent-dg> trong phan
    tu device-group (neu co trong config readonly). Khong co thong tin cha -> coi la
    device group goc (con truc tiep cua Shared)."""
    parents: Dict[str, Optional[str]] = {}
    for dg_el in root.findall('.//device-group/entry'):
        name = dg_el.get('name')
        if not name:
            continue
        parent = None
        # <settings><parent-dg>... hoac <entry><parent-dg>...
        parent_el = dg_el.find('.//parent-dg')
        if parent_el is not None and parent_el.text and parent_el.text.strip():
            parent = parent_el.text.strip()
        parents[name] = parent
    if not parents:
        # Neu khong parse duoc, moi DG la goc tu Shared
        for name in list_devicegroups(root):
            parents.setdefault(name, None)
    return parents


def resolve_devicegroup_chain(root, dg_name) -> Tuple[List[str], List]:
    """Tra ve (danh sach ten theo thu tu Shared->...->DG cha->DG hien tai, danh sach
    phan tu XML tuong ung theo cung thu tu). Theo 0.2:
      [Shared, DG goc-nhat, ..., DG cha truc tiep, DG hien tai]

    Shared LUON LA LOP GOC (tang nen) bat ke DG co cha hay khong - moi object cua
    Shared deu co hieu luc tren toan Panorama nen phai co mat dau tien trong chuoi
    thua ke (0.2)."""
    parents = _dg_parents_from_config(root)
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
    chain_names.reverse()       # (DG goc nhat) -> ... -> DG hien tai
    chain_names = ['shared'] + chain_names  # Always prepend Shared base layer

    dg_elements: Dict[str, object] = {}
    for dg_el in root.findall('.//device-group/entry'):
        nm = dg_el.get('name')
        if nm:
            dg_elements.setdefault(nm, dg_el)
    chain_els: List = []
    for nm in chain_names:
        if nm == 'shared' or nm == 'Shared':
            shared = root.find('shared')
            chain_els.append(shared)
        else:
            chain_els.append(dg_elements.get(nm))
    return chain_names, chain_els


# =========================================================================
# OBJECT LAYERING (0.2): Shared truoc, DG gan hon DE sau -> DE sau thang
# =========================================================================

def _layer_objects(layers: List) -> dict:
    """layers: list cac container XML (shared hoac device-group entry) theo thu tu
    Shared -> ... -> DG hien tai. Entry cua layer SAU DE layer TRUOC neu trung ten."""
    merged = {
        'address_objects': {},
        'address_groups': {},
        'service_objects': {},
        'service_groups': {},
    }
    for layer in layers:
        if layer is None:
            continue
        merged['address_objects'].update(parse_address_objects(layer))
        merged['address_groups'].update(parse_address_groups(layer))
        merged['service_objects'].update(parse_service_objects(layer))
        merged['service_groups'].update(parse_service_groups(layer))
    return merged


# =========================================================================
# RULEBASE ASSEMBLY (0.3): 6 buoc dung thu tu PAN-OS danh gia
# =========================================================================

def assemble_security_rules_panorama(root, dg_name, local_rules: Optional[List[SecurityRule]] = None
                                     ) -> List[SecurityRule]:
    """Lắp ráp rulebase theo DUNG 6 buoc 0.3:
      1. Shared PRE-rulebase
      2. DG to tien xa nhat -> ... -> DG cha truc tiep -> DG hien tai, PRE-rulebase
      3. Rule cuc bo tren chinh firewall (neu co truyen local_rules)
      4. DG hien tai -> DG cha truc tiep -> ... -> DG to tien xa nhat, POST-rulebase
         (chiều NGUOC lai so voi PRE)
      5. Shared POST-rulebase
      6. (Default rule - khong co trong config)
    Index cuoi cung duoc gan lai tang dan theo dung thu tu lắp ráp nay.
    """
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name)
    # chain_els: [Shared(r), DG goc, ..., DG hien tai]
    # Bo shared ra khoi mang de lay DG-only (theo thu tu to tien -> hien tai)
    dg_only_els = [el for el, nm in zip(chain_els, chain_names) if nm not in ('shared', 'Shared')]
    dg_only_names = [nm for nm in chain_names if nm not in ('shared', 'Shared')]

    assembled: List[SecurityRule] = []

    # 1. Shared PRE
    shared_el = root.find('shared')
    if shared_el is not None:
        assembled += parse_security_rules_in(shared_el, 'Shared-PRE', 'pre')

    # 2. DG chain PRE (to tien -> hien tai)
    for el, nm in zip(dg_only_els, dg_only_names):
        if el is not None:
            assembled += parse_security_rules_in(el, f'{nm}-PRE', 'pre')

    # 3. Local rules (tuy chon)
    if local_rules:
        for r in local_rules:
            r.vi_tri = 'Local'
            r.rulebase = 'post'  # local nam giua pre va post
        assembled += list(local_rules)

    # 4. DG chain POST (hien tai -> to tien)
    for el, nm in zip(reversed(dg_only_els), reversed(dg_only_names)):
        if el is not None:
            assembled += parse_security_rules_in(el, f'{nm}-POST', 'post')

    # 5. Shared POST
    if shared_el is not None:
        assembled += parse_security_rules_in(shared_el, 'Shared-POST', 'post')

    # Gan lai index tang dan theo dung thu tu lắp ráp
    for i, r in enumerate(assembled):
        r.index = i
    return assembled


@dataclass
class NatRule:
    index: int
    name: str
    source: List[str]
    destination: List[str]
    service: str
    to_interface: str = "any"
    disabled: bool = False
    vi_tri: str = ""
    rulebase: str = "pre"


def _parse_nat_rules_from_rules_el(rules_el, vi_tri, rulebase) -> List[NatRule]:
    out = []
    for e in rules_el.findall('entry'):
        name = e.get('name')
        source = _members(e.find('source')) or ['any']
        destination = _members(e.find('destination')) or ['any']
        service = _text(e.find('service'), 'any')
        to_if = _text(e.find('to-interface'), 'any')
        disabled = _text(e.find('disabled')).lower() == 'yes'
        out.append(NatRule(-1, name, source, destination, service, to_if, disabled, vi_tri, rulebase))
    return out


def parse_nat_rules_in(container, vi_tri, rulebase) -> List[NatRule]:
    rb = container.find(f'{rulebase}-rulebase')
    if rb is None:
        return []
    nat = rb.find('nat')
    if nat is None:
        return []
    rules_el = nat.find('rules')
    if rules_el is None:
        return []
    return _parse_nat_rules_from_rules_el(rules_el, vi_tri, rulebase)


def assemble_nat_rules_panorama(root, dg_name) -> List[NatRule]:
    """Lắp ráp NAT rulebase theo đúng 6 bước 0.3 (pre/post, Shared + DG chain)."""
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name)
    dg_only_els = [el for el, nm in zip(chain_els, chain_names) if nm not in ('shared', 'Shared')]
    dg_only_names = [nm for nm in chain_names if nm not in ('shared', 'Shared')]
    assembled: List[NatRule] = []
    shared_el = root.find('shared')
    if shared_el is not None:
        assembled += parse_nat_rules_in(shared_el, 'Shared-PRE', 'pre')
    for el, nm in zip(dg_only_els, dg_only_names):
        if el is not None:
            assembled += parse_nat_rules_in(el, f'{nm}-PRE', 'pre')
    for el, nm in zip(reversed(dg_only_els), reversed(dg_only_names)):
        if el is not None:
            assembled += parse_nat_rules_in(el, f'{nm}-POST', 'post')
    if shared_el is not None:
        assembled += parse_nat_rules_in(shared_el, 'Shared-POST', 'post')
    for i, r in enumerate(assembled):
        r.index = i
    return assembled


# =========================================================================
# TEMPLATE-BASED ZONE LOOKUP (0.6): nguon Interface/Zone nam trong Template
# =========================================================================

def parse_interface_subnets(root) -> List[Tuple[int, int, int, str]]:
    """Giong ban goc nhung parse tu 1 <network> (cua Template). ROOT day la 1 phan tu
    template/entry HOAC 1 container chua <network>. Tra ve list rong neu khong parse
    duoc - tinh nang zone-lookup tu dong vo hieu (dung tinh than phong thu cua ban goc)."""
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
    """Giong ban goc nhung parse tu <zone> cua 1 container (Template). Phong thu tuong
    tu - loi/cau truc khac -> dict rong."""
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


def resolve_template_for_serial(root, target_serial) -> Optional:
    """Tra ve phan tu Template (hoac Template Stack) ap dung cho firewal co serial
    'target_serial'. Panorama map serial -> template qua '/config/devices/entry[@name=
    serial]' va dich vu template. Day la phuong thuc BEST-EFFORT:
      - Neu tim thay template găn voi serial -> parse Interface/Zone tu do.
      - Neu khong -> tra ve None (tinh nang zone tu dong vo hieu im lang, 0.6).

    Thu tu tra cuu:
      1. /config/devices/entry[@name=serial] -> 1 trong 2 thuoc tinh chi template/stack
      2. /config/devices/entry[@name=serial]/vsys/entry/... (khong dung duoc o day)
    """

    def _find_template_entry(tname):
        for t in root.findall(".//template/entry"):
            if t.get('name') == tname:
                return t
        for ts in root.findall(".//template-stack/entry"):
            if ts.get('name') == tname:
                return ts
        return None

    # Tim node device cua serial nay. Panorama luu o /config/devices/entry
    dev_el = None
    for d in root.findall("./devices/entry"):
        if d.get('name') == target_serial:
            dev_el = d
            break
    if dev_el is not None:
        # Tim tham chieu template
        t_el = dev_el.find('.//template')
        if t_el is not None and t_el.text:
            scope = _find_template_entry(t_el.text.strip())
            if scope is not None:
                return scope
        ts_el = dev_el.find('.//template-stack')
        if ts_el is not None and ts_el.text:
            scope = _find_template_entry(ts_el.text.strip())
            if scope is not None:
                return scope
    return None


def parse_config_root(root, dg_name: Optional[str] = None,
                      target_serial: Optional[str] = None, local_rules: Optional[List[SecurityRule]] = None):
    if root.tag != 'config':
        raise ValueError("Du lieu XML khong dung dinh dang PAN-OS config (thieu the goc <config>).")

    dg_list = list_devicegroups(root)
    if dg_name is None:
        dg_name = dg_list[0] if dg_list else None

    # 0.2: object layering theo chuoi DG
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name or '')
    merged = _layer_objects(chain_els)

    # 0.3: lắp ráp rulebase theo 6 buoc
    rules = assemble_security_rules_panorama(root, dg_name, local_rules=local_rules) if dg_name else []

    # 0.6: zone tu Template cua Target Firewall
    interface_subnets = []
    zones = {}
    template_scope = None
    if target_serial:
        template_scope = resolve_template_for_serial(root, target_serial)
        if template_scope is not None:
            interface_subnets = parse_interface_subnets(template_scope)
            zones = parse_zones(template_scope)

    return {
        'devicegroup_list': dg_list,
        'devicegroup_used': dg_name,
        'devicegroup_chain': chain_names,
        'address_objects': merged['address_objects'],
        'address_groups': merged['address_groups'],
        'service_objects': merged['service_objects'],
        'service_groups': merged['service_groups'],
        'rules': rules,
        'zones': zones,
        'interface_subnets': interface_subnets,
        'target_serial': target_serial,
    }


# =========================================================================
# API TRUY XUAT (dau vao /output - redirect toi Panorama)
# =========================================================================

def _extract_config(resp_text):
    """Lay the <config> tu phan hoi API, tra ve XML string."""
    root = ET.fromstring(resp_text)
    if root.get("status") != "success":
        msg_el = root.find(".//msg/line") or root.find(".//msg")
        err = (msg_el.text.strip() if msg_el is not None and msg_el.text else None) or "khong ro nguyen nhan"
        raise RuntimeError(f"PANORAMA tu choi yeu cau: {err}")
    result_el = root.find("result")
    config_el = result_el.find("config") if result_el is not None else None
    if config_el is None:
        raise RuntimeError("Phan hoi thanh cong nhung khong thay the <config>")
    return ET.tostring(config_el, encoding="unicode")


def fetch_panorama_config_xml(panorama_ip: str, api_key: str, timeout: int = 60) -> str:
    """Lay RUNNING config (action=show) toan bo cay Panorama (Shared + moi Device Group)."""
    if requests is None:
        raise RuntimeError("Thieu thu vien 'requests'. Cai dat bang: pip install requests")
    url = f"https://{panorama_ip.strip()}/api/"
    params = {"type": "config", "action": "show", "key": api_key}
    try:
        resp = requests.get(url, params=params, verify=False, timeout=timeout)
    except requests.exceptions.SSLError as e:
        raise RuntimeError(f"Loi SSL khi ket noi toi {panorama_ip}: {e}")
    except requests.exceptions.ConnectTimeout:
        raise RuntimeError(f"Ket noi toi {panorama_ip} bi timeout sau {timeout}s.")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Khong ket noi duoc toi {panorama_ip}: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Loi khi goi API toi {panorama_ip}: {e}")
    if resp.status_code != 200:
        raise RuntimeError(f"PANORAMA tra ve HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        return _extract_config(resp.content)
    except ET.ParseError as e:
        raise RuntimeError(f"Phan hoi tu Panorama khong phai XML hop le ({e}).")


def fetch_candidate_config_xml(panorama_ip: str, api_key: str, timeout: int = 60) -> str:
    """Lay CANDIDATE config (action=get) - toan bo cay gop ca thay doi chua commit."""
    if requests is None:
        raise RuntimeError("Thieu thu vien 'requests'. Cai dat bang: pip install requests")
    url = f"https://{panorama_ip.strip()}/api/"
    params = {"type": "config", "action": "get", "xpath": "/config", "key": api_key}
    try:
        resp = requests.get(url, params=params, verify=False, timeout=timeout)
    except requests.exceptions.SSLError as e:
        raise RuntimeError(f"Loi SSL khi ket noi toi {panorama_ip}: {e}")
    except requests.exceptions.ConnectTimeout:
        raise RuntimeError(f"Ket noi toi {panorama_ip} bi timeout sau {timeout}s.")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Khong ket noi duoc toi {panorama_ip}: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Loi khi goi API toi {panorama_ip}: {e}")
    if resp.status_code != 200:
        raise RuntimeError(f"PANORAMA tra ve HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        return _extract_config(resp.content)
    except ET.ParseError as e:
        raise RuntimeError(f"Phan hoi tu Panorama khong phai XML hop le ({e}).")


def get_panorama_devicegroups(panorama_ip: str, api_key: str, timeout: int = 30) -> List[str]:
    """Lay danh sach Device Group tu Panorama (op command show devicegroups)."""
    if requests is None:
        raise RuntimeError("Thieu thu vien 'requests'.")
    url = f"https://{panorama_ip.strip()}/api/"
    cmd = "<show><devicegroups/></show>"
    params = {"type": "op", "cmd": cmd, "key": api_key}
    try:
        resp = requests.get(url, params=params, verify=False, timeout=timeout)
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Loi khi goi API toi {panorama_ip}: {e}")
    if resp.status_code != 200:
        raise RuntimeError(f"PANORAMA tra ve HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        root = ET.fromstring(resp.content)
    except ET.ParseError as e:
        raise RuntimeError(f"Phan hoi devicegroup khong phai XML hop le ({e}).")
    names = []
    # <result><devicegroups><entry name="...">...
    for e in root.findall('.//devicegroup/entry') or root.findall('.//entry'):
        nm = e.get('name')
        if nm and nm not in names:
            names.append(nm)
    # Neu khong co devicegroup, tra ve list rong (GUI tu doc tu config)
    return names


def load_pan_config(xml_path: str, dg_name: Optional[str] = None,
                    target_serial: Optional[str] = None):
    tree = ET.parse(xml_path)
    return parse_config_root(tree.getroot(), dg_name, target_serial)


def load_pan_config_from_xml_string(xml_text: str, dg_name: Optional[str] = None,
                                     target_serial: Optional[str] = None):
    root = ET.fromstring(xml_text)
    return parse_config_root(root, dg_name, target_serial)


# =========================================================================
# CANDIDATE CONFIG (0.4) - doc vi tri de diff
# =========================================================================

def parse_candidate_config(candidate_xml_text: str, dg_name: Optional[str] = None,
                           target_serial: Optional[str] = None) -> dict:
    """Doc CANDIDATE config (Panorama) thanh dict TACH BIET voi cfg running - KHONG
    merge bat ky thu gi. Xem ban goc de hieu ly do tach biet nghiem ngat: rule/object
    candidate duoc resolve RIENG, chi dung cho lop canh bao tham khao."""
    root = ET.fromstring(candidate_xml_text)
    dg_list = list_devicegroups(root)
    if dg_name is None:
        dg_name = dg_list[0] if dg_list else None
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name or '')
    merged = _layer_objects(chain_els)
    rules = assemble_security_rules_panorama(root, dg_name, local_rules=None) if dg_name else []
    return {
        'address_objects': merged['address_objects'],
        'address_groups': merged['address_groups'],
        'service_objects': merged['service_objects'],
        'service_groups': merged['service_groups'],
        'rules': rules,
    }


def diff_candidate_config(cfg: dict, cand_cfg: dict) -> dict:
    """Giong het ban goc - so sanh truc tiep tung field de loc xuong CHI con rule/object
    THAT SU moi/thay doi so voi running. Khong doi logic."""
    def _rule_changed(r_run: Optional[SecurityRule], r_cand: SecurityRule) -> bool:
        if r_run is None:
            return True
        return (sorted(r_cand.source) != sorted(r_run.source) or
                sorted(r_cand.destination) != sorted(r_run.destination) or
                sorted(r_cand.service) != sorted(r_run.service) or
                sorted(r_cand.application) != sorted(r_run.application) or
                r_cand.action != r_run.action or
                r_cand.disabled != r_run.disabled)

    running_rules_by_name = {r.name: r for r in cfg.get('rules', [])}
    diff_rules = [r for r in cand_cfg['rules'] if _rule_changed(running_rules_by_name.get(r.name), r)]

    def _addr_obj_changed(a: Optional[AddressObject], b: AddressObject) -> bool:
        return a is None or a.kind != b.kind or a.start != b.start or a.end != b.end

    def _addr_grp_changed(a: Optional[AddressGroup], b: AddressGroup) -> bool:
        return a is None or sorted(a.members) != sorted(b.members)

    def _svc_obj_changed(a: Optional[ServiceObject], b: ServiceObject) -> bool:
        return a is None or a.protocol != b.protocol or sorted(a.ranges) != sorted(b.ranges)

    def _svc_grp_changed(a: Optional[ServiceGroup], b: ServiceGroup) -> bool:
        return a is None or sorted(a.members) != sorted(b.members)

    diff_addr_objs = {n: o for n, o in cand_cfg['address_objects'].items()
                       if _addr_obj_changed(cfg['address_objects'].get(n), o)}
    diff_addr_groups = {n: g for n, g in cand_cfg['address_groups'].items()
                         if _addr_grp_changed(cfg['address_groups'].get(n), g)}
    diff_svc_objs = {n: o for n, o in cand_cfg['service_objects'].items()
                      if _svc_obj_changed(cfg['service_objects'].get(n), o)}
    diff_svc_groups = {n: g for n, g in cand_cfg['service_groups'].items()
                        if _svc_grp_changed(cfg['service_groups'].get(n), g)}
    return {
        'address_objects': diff_addr_objs,
        'address_groups': diff_addr_groups,
        'service_objects': diff_svc_objs,
        'service_groups': diff_svc_groups,
        'rules': diff_rules,
    }


# =========================================================================
# LIVE TEST POLICY MATCH (0.5) - bat buoc target=<serial>
# =========================================================================

def fetch_security_policy_match(
    panorama_ip: str,
    api_key: str,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str = "tcp",
    vsys: str = "vsys1",
    target_serial: Optional[str] = None,
    timeout: int = 10,
    log_func=None
) -> dict | None:
    """Goi API Live Test Policy Match qua PANORAMA (proxy den dataplane firewall).

    BAT BUOC truyen target_serial (0.5) - khong co target, ham nay phai duoc goi boi
    nguoi goi truoc (classify_row/try_live_match loai bo tier LIVE_MATCH ngay tu dau),
    nhung de phong thu van kiem tra lai o day va tra None + log canh bao.
    """
    combo_label = f"{source_ip}->{dest_ip}:{dest_port}/{protocol}"

    def _log(msg):
        if log_func:
            try:
                log_func(msg)
            except Exception:
                pass

    if not target_serial:
        _log(f"[Live Match] {combo_label}: thieu Target Firewall (serial) - bo qua Live Match "
             f"(can Target de Panorama proxy request xuong dataplane).")
        return None

    proto_key = (protocol or 'tcp').strip().lower()
    proto_num = _PROTOCOL_NUMBERS.get(proto_key)
    if proto_num is None:
        _log(f"[Live Match] {combo_label}: protocol '{protocol}' khong xac dinh duoc "
             f"so hieu IP protocol - mac dinh dung TCP (6).")
        proto_num = 6

    cmd_xml = (
        f"<test><security-policy-match>"
        f"<source>{source_ip}</source>"
        f"<destination>{dest_ip}</destination>"
        f"<destination-port>{dest_port}</destination-port>"
        f"<protocol>{proto_num}</protocol>"
        f"</security-policy-match></test>"
    )
    url = f"https://{panorama_ip}/api/"
    params = {
        "type": "op",
        "cmd": cmd_xml,
        "key": api_key,
        "target": target_serial,
        "vsys": vsys
    }

    try:
        with _LIVE_MATCH_SEMAPHORE:
            resp = _SESSION.get(url, params=params, verify=False, timeout=timeout)
        if resp.status_code != 200:
            _log(f"[Live Match] {combo_label}: HTTP {resp.status_code} - {resp.text[:300]}")
            return None

        root = ET.fromstring(resp.content)
        if root.attrib.get("status") != "success":
            msg_el = root.find(".//msg/line")
            if msg_el is None:
                msg_el = root.find(".//msg")
            err = (msg_el.text.strip() if msg_el is not None and msg_el.text else None) or "khong ro nguyen nhan"
            _log(f"[Live Match] {combo_label}: Panorama/firewall tu choi yeu cau - {err}")
            return None

        rule_entry = root.find(".//rules/entry")
        if rule_entry is not None:
            rule_name = rule_entry.attrib.get("name", "")
            action_elem = rule_entry.find("action")
            action = action_elem.text.strip().lower() if action_elem is not None and action_elem.text else "allow"
            return {"rule_name": rule_name, "action": action}

        match_elem = root.find(".//security-policy-match/entry")
        if match_elem is None:
            match_elem = root.find(".//result")
        if match_elem is not None:
            rule_name = match_elem.attrib.get("name", "") or match_elem.findtext("rule", "")
            action = match_elem.findtext("action", "allow").lower()
            if rule_name:
                return {"rule_name": rule_name, "action": action}

        _log(f"[Live Match] {combo_label}: khong tim thay <rules>/<entry> trong phan hoi. "
             f"Raw: {ET.tostring(root, encoding='unicode')[:500]}")

    except Exception as e:
        _log(f"[Live Match] {combo_label}: exception khi goi API - {e}")
        return None

    return None
