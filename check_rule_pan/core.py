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
# SUA LOI (10/2026 - "input dang IP range tren device da co nhung tool khong doc duoc"):
# truoc day CHI nhan dung 1 dinh dang range "A.B.C.D-A.B.C.D" voi dau tru ASCII. Moi
# bien the khac ma file request thuc te cua nguoi dung hay co (Excel/Word tu dong doi
# '-' thanh en-dash, thoi quen go rut gon octet cuoi "10.1.1.100-110", dung '~'/'..'/
# 'to', dinh kem '/32') deu bi parse_ip_token() tra ve kind='invalid' va bi
# classify_row() LOAI BO AM THAM khoi src_ranges/dst_ranges - dong request mat han dai
# IP do (hoac roi ve INVALID) nen bao cao "can ADD/TAO MOI" du doi tuong da ton tai.
# Nay chuan hoa truoc khi parse; TAT CA dinh dang cu van parse y nguyen nhu truoc
# (thay doi chi theo huong 'invalid' -> 'range', khong bao gio nguoc lai).
_IPV4_TXT = r'\d{1,3}(?:\.\d{1,3}){3}'
# Cac dau phan cach range gap thuc te: tru ASCII, hyphen/en/em/figure dash + minus sign
# Unicode (Excel/Word autocorrect), '~', '..'/'...', va tu khoa 'to'.
_RANGE_SEP_TXT = r'(?:[-\u2010\u2011\u2012\u2013\u2014\u2015\u2212~]|\.{2,}|\bto\b)'
# Dang DAY DU: "10.1.1.100 - 10.1.1.110" (cho phep hau to /32 moi dau, nhu khi admin
# copy tu bang co san dang host/32).
_RANGE_RE = re.compile(r'^(%s)(?:/32)?\s*%s\s*(%s)(?:/32)?$'
                        % (_IPV4_TXT, _RANGE_SEP_TXT, _IPV4_TXT), re.IGNORECASE)
# Dang RUT GON octet cuoi: "10.1.1.100-110" (rat pho bien trong request noi bo).
_RANGE_SHORT_RE = re.compile(r'^(\d{1,3}(?:\.\d{1,3}){2})\.(\d{1,3})(?:/32)?\s*%s\s*(\d{1,3})(?:/32)?$'
                              % _RANGE_SEP_TXT, re.IGNORECASE)
_PORTLESS_APPLICATIONS = {"icmp", "ping", "traceroute", "icmpv6"}

# PAN-OS 'test security-policy-match' yeu cau protocol la SO HIEU IP protocol
# (khong phai chuoi 'tcp'/'udp'). TCP=6, UDP=17, ICMP=1.
# Xem: https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA10g000000ClQSCA0
_PROTOCOL_NUMBERS = {'tcp': 6, 'udp': 17, 'icmp': 1}

# Gioi han so ket noi API dong thoi THUC SU toi mgmt-plane cua firewall, doc lap voi
# so Thread xu ly cuc bo (co the len toi 70) va so combo Live Match song song moi dong
# (toi da 30) - de tranh ban hang tram request cung luc gay timeout hang loat.
# Gia tri co the duoc dieu chinh boi GUI qua configure_live_match_concurrency().
_LIVE_MATCH_SEMAPHORE = threading.BoundedSemaphore(8)
_SEMAPHORE_LOCK = threading.Lock()


def configure_live_match_concurrency(n: int):
    """Cho phep GUI dieu chinh so ket noi Live Match dong thoi toi mgmt-plane dua theo
    'So luong Thread' nguoi dung nhap - nhung van kep trong khoang an toan (5-40) de
    khong lap lai su co timeout hang loat do ban qua nhieu request cung luc."""
    global _LIVE_MATCH_SEMAPHORE
    n = max(5, min(40, int(n)))
    with _SEMAPHORE_LOCK:
        _LIVE_MATCH_SEMAPHORE = threading.BoundedSemaphore(n)


# Session dung chung, bat/duy tri ket noi TCP+TLS (keep-alive) toi firewall thay vi
# moi request tu bat tay SSL rieng - giam dang ke do tre khi test nhieu port lien tiep.
_SESSION = requests.Session()
_SESSION.mount('https://', requests.adapters.HTTPAdapter(pool_connections=25, pool_maxsize=25, max_retries=0))


# =========================================================================
# IP / PORT PARSING UTILITIES
# =========================================================================

def split_multi_value(cell) -> List[str]:
    """Tach 1 cell co the chua nhieu gia tri (phan cach boi , ; xuong dong)."""
    if cell is None:
        return []
    s = str(cell)
    if s.strip().lower() in ('nan', 'none'):
        return []
    for sep in (';', '\n', '\r', '\t'):
        s = s.replace(sep, ',')
    parts = [p.strip().strip(',') for p in s.split(',')]
    return [p for p in parts if p]


def split_ip_tokens(cell) -> List[str]:
    """Nhu split_multi_value() nhung them 1 buoc an toan danh RIENG cho o Source/Dest.

    Thuc te file request hay co o chi cach nhau bang KHOANG TRANG (khong dau phay),
    vd "10.1.1.1 10.2.2.2" - truoc day ca o bi coi la 1 token, parse that bai va bi
    loai bo am tham. split_multi_value() KHONG the tach theo khoang trang vo dieu
    kien vi se pha vo chinh dinh dang range "10.1.1.1 - 10.1.1.5".

    Nguyen tac: CHI tach theo khoang trang khi (a) ca token parse that bai, VA (b)
    sau khi tach, MOI manh deu parse duoc. Neu con bat ky manh nao khong hop le thi
    GIU NGUYEN token goc de no duoc bao cao la "khong doc duoc" (khong doan bua).
    """
    out: List[str] = []
    for part in split_multi_value(cell):
        if parse_ip_token(part)['kind'] != 'invalid':
            out.append(part)
            continue
        pieces = [x for x in re.split(r'\s+', part.strip()) if x]
        if len(pieces) > 1 and all(parse_ip_token(x)['kind'] != 'invalid' for x in pieces):
            out.extend(pieces)
        else:
            out.append(part)
    return out


def _normalize_ip_token(tok) -> str:
    """Chuan hoa 1 token IP truoc khi parse: bo khoang trang la (ke ca non-breaking
    space U+00A0 hay gap khi copy tu web/Word), bo dau nhay don Excel chen truoc o
    dang text, bo dau ngoac/nhay bao quanh. KHONG doi noi dung IP/range."""
    s = '' if tok is None else str(tok)
    s = s.replace('\u00a0', ' ').replace('\u2007', ' ').replace('\u202f', ' ')
    s = s.strip().strip('\'"')
    s = s.strip()
    if s.startswith('(') and s.endswith(')'):
        s = s[1:-1].strip()
    return s


def parse_ip_token(tok: str) -> dict:
    """Phan loai 1 token IP tu file input cua user.

    Tra ve kind: 'host' | 'cidr' | 'range' | 'invalid'. Ho tro cac dinh dang range
    thuc te (xem _RANGE_RE/_RANGE_SHORT_RE): day du "A.B.C.D-A.B.C.D", rut gon octet
    cuoi "A.B.C.D-E", dau phan cach la en/em dash, '~', '..', 'to', co the kem '/32'.
    """
    tok = _normalize_ip_token(tok)
    if not tok:
        return {'raw': tok, 'kind': 'invalid', 'start': None, 'end': None, 'display': tok}

    a_txt = b_txt = None
    m = _RANGE_RE.match(tok)
    if m:
        a_txt, b_txt = m.group(1), m.group(2)
    else:
        m = _RANGE_SHORT_RE.match(tok)
        if m:
            # "10.1.1.100-110" -> 10.1.1.100 .. 10.1.1.110 (giu nguyen 3 octet dau)
            a_txt = f"{m.group(1)}.{m.group(2)}"
            b_txt = f"{m.group(1)}.{m.group(3)}"

    if a_txt is not None:
        try:
            a = int(ipaddress.IPv4Address(a_txt))
            b = int(ipaddress.IPv4Address(b_txt))
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
    """Tra ve (start,end) hoac None neu khong parse duoc."""
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
    """Neu 'name' la 1 IP/CIDR go thang, tra ve info."""
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
    # Dynamic Address Group (<dynamic><filter>): thanh vien duoc gan theo TAG luc
    # runtime (registered-ip), KHONG nam trong file cau hinh. Truoc 10/2026 ham
    # parse_address_groups() chi doc <static> nen DAG ra members=[] -> resolve ra 0
    # DIA CHI, khong mot canh bao nao -> _is_exactly_scoped() coi field chua DAG la
    # "khop chinh xac 1:1 voi request" trong khi thuc te no con cover ca tap tag
    # (co the hang tram host). Co nay de resolver danh dau unresolved tuong minh.
    dynamic: bool = False
    dynamic_filter: str = ''


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
    # --- BAN PANORAMA (require.md 0.3) ---
    # `vi_tri`: nhan vi tri THAT cua rule trong thu tu danh gia da lap rap, vd
    #   'Shared-PRE' | '<DG>-PRE' | 'Local' | '<DG>-POST' | 'Shared-POST'.
    # `rulebase`: 'pre' | 'post' (dung de dung lai dung xpath khi thao tac candidate).
    # `dg`: ten Device Group so huu rule ('shared' neu la rule Shared).
    # 3 truong nay CHI de hien thi/dung xpath - KHONG tham gia bat ky luat tier nao.
    vi_tri: str = ''
    rulebase: str = ''
    dg: str = ''


# =========================================================================
# XML PARSING LOGIC
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
        dyn = e.find('dynamic')
        if dyn is not None:
            filt = dyn.find('filter')
            out[name] = AddressGroup(
                name, members, dynamic=True,
                dynamic_filter=(filt.text or '').strip() if filt is not None else '')
        else:
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


def _parse_security_rules_from_rules_el(rules_el, vi_tri: str, rulebase: str,
                                         dg: str) -> List[SecurityRule]:
    """Parse moi <entry> trong 1 <rules>. Logic doc TUNG TRUONG giu NGUYEN VAN ban
    Firewall standalone - chi them 3 nhan vi tri (vi_tri/rulebase/dg). `index` dat
    tam -1, duoc gan lai o buoc lap rap (assemble_security_rules_panorama) de phan
    anh DUNG thu tu PAN-OS danh gia."""
    out: List[SecurityRule] = []
    if rules_el is None:
        return out
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
                                 action, disabled, from_zones, to_zones,
                                 vi_tri=vi_tri, rulebase=rulebase, dg=dg))
    return out


def parse_security_rules_in(container, vi_tri: str, rulebase: str,
                            dg: str = '') -> List[SecurityRule]:
    """Doc 1 pre-rulebase HOAC post-rulebase cua 1 container (phan tu <shared> hoac
    1 device-group/entry). Tra ve [] neu container khong co nhanh do - dung tinh than
    phong thu cua ban goc (thieu du lieu thi bo qua, khong raise)."""
    if container is None:
        return []
    rb = container.find(f'{rulebase}-rulebase')
    if rb is None:
        return []
    sec = rb.find('security')
    if sec is None:
        return []
    return _parse_security_rules_from_rules_el(sec.find('rules'), vi_tri, rulebase, dg)


def parse_security_rules(container) -> List[SecurityRule]:
    """TUONG THICH NGUOC + rule CUC BO tren chinh firewall (require.md 0.3 buoc 3):
    doc <rulebase><security><rules> kieu Firewall standalone (khong pre/post). Tren
    Panorama cau truc nay KHONG ton tai o Device Group - ham nay chi dung khi nguoi
    dung nap them 1 file config cua chinh firewall de tinh ca rule local."""
    if container is None:
        return []
    rulebase = container.find('rulebase')
    if rulebase is None:
        return []
    sec = rulebase.find('security')
    if sec is None:
        return []
    out = _parse_security_rules_from_rules_el(sec.find('rules'), 'Local', 'local', '')
    for i, r in enumerate(out):
        r.index = i
    return out


def parse_interface_subnets(root) -> List[Tuple[int, int, int, str]]:
    """Tra ve list (start_ip, end_ip, prefix_len, interface_name) cho MOI interface co
    dia chi IP L3 (ethernet, subinterface, vlan, loopback, tunnel, aggregate...).

    Dung .iter('entry') thay vi .find() theo tung cap co dinh - vi PAN-OS co nhieu loai
    interface khac nhau (ethernet/vlan/loopback/tunnel/ae), deu nam long trong
    <network><interface> nhung do sau khac nhau (subinterface nam trong <units>). Dung
    .iter() de khong phu thuoc cung nhac vao 1 cau truc co dinh, ben hon voi cac bien
    the cau hinh khac nhau.

    THIET KE PHONG THU: neu cau truc XML thuc te khac gia dinh (vd phien ban PAN-OS
    khac, hoac dang export khac), ham nay se don gian tra ve list RONG thay vi loi -
    tinh nang zone-lookup se tu dong bi vo hieu hoa (khong canh bao gi ca), KHONG anh
    huong gi den cac tinh nang khac dang chay dung.
    """
    out: List[Tuple[int, int, int, str]] = []
    try:
        # BAN PANORAMA (0.6): nguon Interface nam trong TEMPLATE, khong nam trong
        # Device Group. Tu 1 <template><entry> duong dan that la
        #   template/entry/config/devices/entry/network
        # (them 1 tang <config> so voi firewall standalone). Thu lan luot cac dang
        # hay gap, cuoi cung fallback .iter() de khong phu thuoc cung nhac 1 cau truc.
        net = None
        for path in ('config/devices/entry/network', 'devices/entry/network', 'network'):
            net = root.find(path)
            if net is not None:
                break
        if net is None:
            net = next(root.iter('network'), None)
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
    """Tra ve {zone_name: [interface_name, ...]}. Gom ca layer3/layer2/virtual-wire/
    tap (chi layer3 co IP nen chi layer3 thuc su huu ich cho zone-lookup theo IP,
    nhung van gom du de khong bo sot) - GIU NGUYEN logic ban Firewall standalone.

    BAN PANORAMA (0.6): nguon doi tu <vsys><entry><zone> sang TEMPLATE. Trong 1
    Template, <zone> nam o template/entry/config/devices/entry/vsys/entry/zone, va
    1 Template co the chua NHIEU vsys -> gom TAT CA nhanh <zone> ben duoi roi hop
    lai, thay vi chi find('zone') 1 tang. Phong thu tuong tu ban goc: loi/cau truc
    khac -> tra ve dict rong (tinh nang zone tu dong vo hieu, khong canh bao)."""
    out: Dict[str, List[str]] = {}
    try:
        if container is None:
            return out
        direct = container.find('zone')
        zone_roots = [direct] if direct is not None else list(container.iter('zone'))
        for zone_root in zone_roots:
            if zone_root is None:
                continue
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
                # Nhieu vsys co the khai bao cung ten zone -> hop member, khong de len nhau.
                if zname in out:
                    for m in members:
                        if m not in out[zname]:
                            out[zname].append(m)
                else:
                    out[zname] = members
    except Exception:
        return {}
    return out


# =========================================================================
# BAN PANORAMA - PHAN CAP DEVICE GROUP (require.md 0.2)
#
# Firewall standalone: object = "shared truoc, vsys de sau".
# Panorama:            object = "Shared truoc, roi DG to tien -> ... -> DG hien tai",
#                      DG cang GAN DG dang thao tac cang THANG (de sau cung).
# Toan bo resolver/matcher/index KHONG doi 1 dong - chi doi NGUON NAP object.
# =========================================================================

SHARED_NAMES = ('shared', 'Shared')


def _devicegroup_entries(root):
    """Tra ve {ten_DG: phan tu XML} cua MOI device-group.

    CAN THAN (edge case that): config Panorama co 2 noi chua device-group/entry:
      - /config/devices/entry[@name='localhost.localdomain']/device-group/entry
        -> CHUA object + pre/post-rulebase THAT (day la cai ta can)
      - /config/readonly/devices/.../device-group/entry
        -> ban SAO chi-doc, thuong CHI chua <parent-dg> (quan he cha-con)
    Neu lay nham ban readonly thi DG se "rong khong co rule nao" - nen o day uu
    tien tuyet doi nhanh KHONG nam trong <readonly>."""
    primary: Dict[str, object] = {}
    fallback: Dict[str, object] = {}
    readonly_ids = set()
    ro = root.find('readonly')
    if ro is not None:
        for el in ro.iter('entry'):
            readonly_ids.add(id(el))
    for dg_el in root.iter('device-group'):
        for e in dg_el.findall('entry'):
            nm = e.get('name')
            if not nm:
                continue
            if id(e) in readonly_ids:
                fallback.setdefault(nm, e)
            else:
                primary.setdefault(nm, e)
    for nm, e in fallback.items():
        primary.setdefault(nm, e)
    return primary


def list_devicegroups(root) -> List[str]:
    """Ten moi Device Group co trong config Panorama (giu thu tu xuat hien, khong trung)."""
    return list(_devicegroup_entries(root).keys())


def _dg_parents_from_config(root) -> Dict[str, Optional[str]]:
    """{ten_DG: ten_DG_cha} doc tu <parent-dg>. Quan he cha-con thuong nam o ban
    <readonly> nen o day quet CA HAI nhanh (readonly lan chinh) - khong co
    <parent-dg> thi DG do la con truc tiep cua Shared (parent = None)."""
    parents: Dict[str, Optional[str]] = {}
    for dg_el in root.iter('device-group'):
        for e in dg_el.findall('entry'):
            nm = e.get('name')
            if not nm:
                continue
            parents.setdefault(nm, None)
            pel = e.find('parent-dg')
            if pel is None:
                pel = next((x for x in e.iter('parent-dg')), None)
            if pel is not None and pel.text and pel.text.strip():
                parents[nm] = pel.text.strip()
    return parents


def resolve_devicegroup_chain(root, dg_name: Optional[str]) -> Tuple[List[str], List]:
    """Tra ve (ten_theo_thu_tu, phan_tu_XML_theo_thu_tu) cua chuoi thua ke (0.2):

        ['shared', <DG to tien xa nhat>, ..., <DG cha truc tiep>, <DG hien tai>]

    Shared LUON la lop goc (moi object Shared co hieu luc toan Panorama). Nap theo
    dung thu tu nay roi `dict.update` thi entry sau DE entry truoc - y het co che
    "vsys de shared" cua ban Firewall, chi thay 1 tang vsys bang N tang DG.

    An toan voi cau hinh hong: vong cha-con (A->B->A) duoc cat bang `visited`;
    DG khong ton tai -> chuoi chi con ['shared']."""
    parents = _dg_parents_from_config(root)
    entries = _devicegroup_entries(root)

    chain_names: List[str] = []
    cur = dg_name
    visited = set()
    while cur and cur not in SHARED_NAMES:
        if cur in visited:          # vong cha-con hong -> cat
            break
        visited.add(cur)
        if cur in entries or cur == dg_name:
            chain_names.append(cur)
        parent = parents.get(cur)
        if not parent or parent == cur:
            break
        cur = parent
    chain_names.reverse()                      # to tien xa nhat -> DG hien tai
    chain_names = ['shared'] + chain_names     # Shared luon la lop nen

    chain_els: List = []
    for nm in chain_names:
        chain_els.append(root.find('shared') if nm in SHARED_NAMES else entries.get(nm))
    return chain_names, chain_els


def _layer_objects(layers: List) -> dict:
    """Nap object theo chuoi layer Shared -> ... -> DG hien tai; entry cua layer SAU
    DE entry layer TRUOC neu trung ten (0.2)."""
    merged = {'address_objects': {}, 'address_groups': {},
              'service_objects': {}, 'service_groups': {}}
    for layer in layers:
        if layer is None:
            continue
        merged['address_objects'].update(parse_address_objects(layer))
        merged['address_groups'].update(parse_address_groups(layer))
        merged['service_objects'].update(parse_service_objects(layer))
        merged['service_groups'].update(parse_service_groups(layer))
    return merged


# =========================================================================
# BAN PANORAMA - LAP RAP RULEBASE DUNG THU TU PAN-OS DANH GIA (0.3)
# =========================================================================

def assemble_security_rules_panorama(root, dg_name: Optional[str],
                                      local_rules: Optional[List[SecurityRule]] = None
                                      ) -> List[SecurityRule]:
    """Lap rap rulebase theo DUNG 6 buoc cua 0.3:

        1. Shared PRE-rulebase
        2. DG to tien xa nhat -> ... -> DG cha truc tiep -> DG hien tai, PRE
        3. Rule CUC BO tren chinh firewall (chi khi truyen `local_rules`)
        4. DG hien tai -> DG cha truc tiep -> ... -> DG to tien xa nhat, POST
           (chieu NGUOC LAI so voi PRE - con danh gia TRUOC cha o post-rulebase)
        5. Shared POST-rulebase
        6. Default rule (intrazone/interzone-default - khong nam trong config)

    `index` duoc gan lai tang dan theo DUNG thu tu lap rap nay, vi moi thuat toan
    tier/shadow cua ban goc deu dua vao "index nho hon = PAN-OS danh gia truoc".
    Khong doi 1 dong logic tier/shadow nao."""
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name)
    dg_pairs = [(nm, el) for nm, el in zip(chain_names, chain_els)
                if nm not in SHARED_NAMES]
    shared_el = root.find('shared')

    assembled: List[SecurityRule] = []

    # 1. Shared PRE
    assembled += parse_security_rules_in(shared_el, 'Shared-PRE', 'pre', 'shared')

    # 2. DG chain PRE: to tien -> hien tai
    for nm, el in dg_pairs:
        assembled += parse_security_rules_in(el, f'{nm}-PRE', 'pre', nm)

    # 3. Rule cuc bo tren chinh firewall (tuy chon)
    for r in (local_rules or []):
        r.vi_tri = r.vi_tri or 'Local'
        r.rulebase = 'local'
        assembled.append(r)

    # 4. DG chain POST: hien tai -> to tien (NGUOC so voi PRE)
    for nm, el in reversed(dg_pairs):
        assembled += parse_security_rules_in(el, f'{nm}-POST', 'post', nm)

    # 5. Shared POST
    assembled += parse_security_rules_in(shared_el, 'Shared-POST', 'post', 'shared')

    for i, r in enumerate(assembled):
        r.index = i
    return assembled


# =========================================================================
# BAN PANORAMA - ZONE AWARENESS QUA TEMPLATE (0.6)
# =========================================================================

def resolve_templates_for_serial(root, target_serial: Optional[str]) -> List:
    """Tra ve danh sach phan tu Template ap dung cho firewall co serial nay, theo
    thu tu UU TIEN TANG DAN (phan tu sau de phan tu truoc khi trung).

    CACH TRA CUU DUNG CUA PANORAMA (day la cho ban truoc lam NGUOC): Panorama
    KHONG luu "serial -> template" o /config/devices/entry[@name=<serial>] (nhanh
    do la chinh Panorama, ten 'localhost.localdomain'). Quan he that duoc luu
    NGUOC LAI - moi Template / Template Stack co 1 danh sach thiet bi:
        /config/devices/entry/template/entry[@name=T]/devices/entry[@name=<serial>]
        /config/devices/entry/template-stack/entry[@name=S]/devices/entry[@name=<serial>]
    Nen phai QUET cac template/template-stack va xem serial co nam trong danh sach
    <devices> cua no khong.

    Template Stack duoc uu tien: stack liet ke cac template thanh vien trong
    <templates><member>, thu tu TREN = uu tien CAO hon -> tra ve theo thu tu DAO
    NGUOC de ben goi cu `update`/noi tiep thi cai uu tien cao nhat ghi de sau cung.
    Khong tim thay -> [] (tinh nang zone tu dong vo hieu, im lang - 0.6)."""
    if not target_serial:
        return []
    target_serial = target_serial.strip()

    templates: Dict[str, object] = {}
    for t_root in root.iter('template'):
        for e in t_root.findall('entry'):
            nm = e.get('name')
            if nm:
                templates.setdefault(nm, e)

    def _has_device(entry) -> bool:
        dev = entry.find('devices')
        if dev is None:
            return False
        return any(d.get('name') == target_serial for d in dev.findall('entry'))

    # 1) Template Stack chua serial nay
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
            if out:
                return out
            return [e]      # stack khong liet ke member -> dung chinh no
    # 2) Template gan truc tiep serial nay
    for nm, e in templates.items():
        if _has_device(e):
            return [e]
    return []


def resolve_template_for_serial(root, target_serial: Optional[str]):
    """Tuong thich nguoc: tra ve DUY NHAT template uu tien cao nhat (hoac None)."""
    scopes = resolve_templates_for_serial(root, target_serial)
    return scopes[-1] if scopes else None


def devicegroup_devices(root, dg_name: Optional[str]) -> List[str]:
    """Danh sach serial cua cac firewall duoc gan vao 1 Device Group
    (/config/devices/.../device-group/entry[@name=DG]/devices/entry/@name).
    Dung de KIEM TRA CHEO Target Firewall nguoi dung nhap co thuc su thuoc DG dang
    chon hay khong - 1 edge case rat de sai khi Panorama quan ly nhieu firewall."""
    if not dg_name:
        return []
    el = _devicegroup_entries(root).get(dg_name)
    if el is None:
        return []
    dev = el.find('devices')
    if dev is None:
        return []
    return [d.get('name') for d in dev.findall('entry') if d.get('name')]


# =========================================================================
# PARSE CONFIG ROOT (ban Panorama)
# =========================================================================

def parse_config_root(root, dg_name: Optional[str] = None,
                      target_serial: Optional[str] = None,
                      local_rules: Optional[List[SecurityRule]] = None):
    if root.tag != 'config':
        raise ValueError("Du lieu XML khong dung dinh dang PAN-OS config (thieu the goc <config>).")

    dg_list = list_devicegroups(root)
    if dg_name is None:
        dg_name = dg_list[0] if dg_list else None

    # 0.2 - object theo chuoi thua ke Shared -> ... -> DG hien tai
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name)
    merged = _layer_objects(chain_els)

    # 0.3 - rulebase lap rap dung thu tu danh gia
    rules = assemble_security_rules_panorama(root, dg_name, local_rules=local_rules)

    # 0.6 - zone lay tu Template cua Target Firewall (khong co target -> tu vo hieu)
    interface_subnets: List[Tuple[int, int, int, str]] = []
    zones: Dict[str, List[str]] = {}
    template_names: List[str] = []
    for scope in resolve_templates_for_serial(root, target_serial):
        nm = scope.get('name')
        if nm:
            template_names.append(nm)
        interface_subnets += parse_interface_subnets(scope)
        zones.update(parse_zones(scope))

    return {
        'devicegroup_list': dg_list,
        'devicegroup_used': dg_name,
        'devicegroup_chain': chain_names,
        'devicegroup_devices': devicegroup_devices(root, dg_name),
        'address_objects': merged['address_objects'],
        'address_groups': merged['address_groups'],
        'service_objects': merged['service_objects'],
        'service_groups': merged['service_groups'],
        'rules': rules,
        'zones': zones,
        'interface_subnets': interface_subnets,
        'target_serial': target_serial,
        'template_used': template_names,
    }


def load_pan_config(xml_path: str, dg_name: Optional[str] = None,
                    target_serial: Optional[str] = None):
    tree = ET.parse(xml_path)
    return parse_config_root(tree.getroot(), dg_name, target_serial)


def load_pan_config_from_xml_string(xml_text: str, dg_name: Optional[str] = None,
                                     target_serial: Optional[str] = None):
    root = ET.fromstring(xml_text)
    return parse_config_root(root, dg_name, target_serial)


def _api_error_message(root) -> str:
    """Lay thong bao loi tu phan hoi API.

    LUU Y (bay kinh dien cua ElementTree): KHONG duoc viet
        root.find(".//msg/line") or root.find(".//msg")
    vi `Element.__bool__` tra ve False khi phan tu KHONG CO con - ma <line> thuong
    la the la (chi co text) -> bieu thuc `or` luon roi sang ve phai, lam mat thong
    bao loi that. Phai kiem tra `is None` tuong minh."""
    for path in (".//msg/line", ".//msg", ".//line"):
        el = root.find(path)
        if el is not None and el.text and el.text.strip():
            return el.text.strip()
    # <msg> co nhieu <line> con -> noi lai
    msg_el = root.find(".//msg")
    if msg_el is not None:
        lines = [x.text.strip() for x in msg_el.iter() if x.text and x.text.strip()]
        if lines:
            return " | ".join(lines)
    return "khong ro nguyen nhan"


def _panorama_get(panorama_ip: str, params: dict, timeout: int, what: str):
    """1 lan goi GET toi Panorama + bao loi tieng Viet thong nhat. Tra ve Element goc."""
    if requests is None:
        raise RuntimeError("Thieu thu vien 'requests'. Cai dat bang: pip install requests")
    url = f"https://{panorama_ip.strip()}/api/"
    try:
        resp = _SESSION.get(url, params=params, verify=False, timeout=timeout)
    except requests.exceptions.SSLError as e:
        raise RuntimeError(f"Loi SSL khi ket noi toi Panorama {panorama_ip}: {e}")
    except requests.exceptions.ConnectTimeout:
        raise RuntimeError(f"Ket noi toi Panorama {panorama_ip} bi timeout sau {timeout}s.")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Khong ket noi duoc toi Panorama {panorama_ip}: {e}")
    except requests.exceptions.RequestException as e:
        raise RuntimeError(f"Loi khi goi API toi Panorama {panorama_ip}: {e}")
    if resp.status_code != 200:
        raise RuntimeError(f"Panorama tra ve HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        return ET.fromstring(resp.content)
    except ET.ParseError as e:
        raise RuntimeError(f"Phan hoi tu Panorama ({what}) khong phai XML hop le ({e}).")


def _extract_config_el(root, what: str) -> str:
    if root.get("status") != "success":
        raise RuntimeError(f"Panorama tu choi yeu cau ({what}): {_api_error_message(root)}")
    result_el = root.find("result")
    config_el = result_el.find("config") if result_el is not None else None
    if config_el is None:
        raise RuntimeError(f"Phan hoi thanh cong ({what}) nhung khong thay the <config>")
    return ET.tostring(config_el, encoding="unicode")


def fetch_panorama_config_xml(panorama_ip: str, api_key: str, timeout: int = 60) -> str:
    """Lay RUNNING config cua PANORAMA (`action=show`) - toan bo cay: Shared + moi
    Device Group + Template + readonly (quan he cha-con DG).

    BAN PANORAMA (0.4): "running config" o day la config DA COMMIT VAO PANORAMA -
    CHUA chac da duoc push xuong firewall. Van la nguon duy nhat cho moi thuat toan
    LOCAL, dung vai tro "sole authority" nhu ban goc.

    TUONG THICH API: ban Firewall standalone goi `action=show` KHONG kem `xpath` va
    chay tot. Mot so phien ban PAN-OS/Panorama lai bat buoc co `xpath` - nen o day
    thu dung cach da duoc kiem chung truoc, that bai thi thu lai voi `xpath=/config`
    (cach ghi trong tai lieu chinh thuc) truoc khi bao loi."""
    base = {"type": "config", "action": "show", "key": api_key}
    root = _panorama_get(panorama_ip, base, timeout, "running-config")
    if root.get("status") != "success":
        root = _panorama_get(panorama_ip, dict(base, xpath="/config"), timeout, "running-config")
    return _extract_config_el(root, "running-config")


def fetch_candidate_config_xml(panorama_ip: str, api_key: str, timeout: int = 60) -> str:
    """Lay CANDIDATE config cua Panorama (`action=get`, toan bo cay gom ca thay doi
    CHUA commit). Vai tro y het ban goc (II.5 overlay tham khao) - chi doi nguon.

    Ham nay HOAN TOAN doc lap voi fetch_panorama_config_xml() de khong anh huong
    luong lay running-config."""
    params = {"type": "config", "action": "get", "xpath": "/config", "key": api_key}
    root = _panorama_get(panorama_ip, params, timeout, "candidate-config")
    return _extract_config_el(root, "candidate-config")


def get_panorama_devicegroups(panorama_ip: str, api_key: str, timeout: int = 30) -> List[str]:
    """Danh sach Device Group qua op-command `<show><devicegroups/></show>` (0.8).

    Phan hoi that co dang:
        <response><result><devicegroups><entry name="DG1"><devices>...
    Chu y: the bao ngoai la **devicegroups** (SO NHIEU). Ban truoc tim
    `.//devicegroup/entry` (so it) nen luon rong, roi fallback `.//entry` - va
    `.//entry` lai bat trung ca <devices><entry name="<serial>"> ben trong, bien
    SERIAL thanh "ten Device Group". Day la loi NGHIEM TRONG (chon nham DG) nen o
    day chi nhan dung nhanh devicegroups/entry; khong tim thay -> tra ve [] de GUI
    tu doc danh sach DG tu chinh config (duong di tin cay hon)."""
    params = {"type": "op", "cmd": "<show><devicegroups/></show>", "key": api_key}
    try:
        root = _panorama_get(panorama_ip, params, timeout, "devicegroups")
    except RuntimeError:
        return []
    if root.get("status") != "success":
        return []
    names: List[str] = []
    for container in root.iter('devicegroups'):
        for e in container.findall('entry'):
            nm = e.get('name')
            if nm and nm not in names:
                names.append(nm)
    return names


def get_panorama_devices(panorama_ip: str, api_key: str, timeout: int = 30) -> List[Tuple[str, str]]:
    """Danh sach firewall Panorama dang quan ly: [(serial, hostname), ...].

    Dung de BIEN o "Target Firewall (Serial)" tu go tay thanh dropdown chon - go
    nham 1 ky tu serial thi Live Match/Zone/Hit-count im lang khong chay, rat kho
    phat hien. Op-command `<show><devices><all/></devices></show>` tra ve ca thiet
    bi dang offline; loi/khong ho tro -> tra ve [] (GUI tu cho go tay nhu cu)."""
    params = {"type": "op", "cmd": "<show><devices><all/></devices></show>", "key": api_key}
    try:
        root = _panorama_get(panorama_ip, params, timeout, "devices")
    except RuntimeError:
        return []
    if root.get("status") != "success":
        return []
    out: List[Tuple[str, str]] = []
    seen = set()
    for devices_el in root.iter('devices'):
        for e in devices_el.findall('entry'):
            serial = (e.findtext('serial') or e.get('name') or '').strip()
            if not serial or serial in seen:
                continue
            seen.add(serial)
            hostname = (e.findtext('hostname') or '').strip()
            out.append((serial, hostname))
    return out


def parse_candidate_config(candidate_xml_text: str, dg_name: Optional[str] = None,
                           target_serial: Optional[str] = None) -> dict:
    """Doc CANDIDATE config (rule + object/group dang cho commit) thanh 1 dict HOAN TOAN
    TACH BIET voi cfg (running) - KHONG merge/ghi de bat ky thu gi vao cfg.

    Ly do tach biet nghiem ngat: neu gop object/group candidate thang vao pool dung de
    resolve rule RUNNING, 1 group dang duoc rule running tham chieu ma co them member
    MOI tren candidate (chua commit) se khien rule running do bi tinh SAI la da cover
    luon member moi - trong khi thuc te CHUA (chi khi commit moi co hieu luc). Vi vay:
    - Rule/object/group RUNNING (dung cho TOP1-TOP4/LIVE_MATCH/shadow-check) LUON resolve
      tren dung du lieu RUNNING, khong bi anh huong boi candidate.
    - Rule/object/group CANDIDATE duoc resolve rieng, tren dung du lieu CANDIDATE (da la
      trang thai day du du kien sau commit, khong can merge voi running vi PAN-OS luon
      tra ve toan bo cay cau hinh moi lan goi, khong phai diff).
    - Ket qua tra ve o day CHI dung cho lop canh bao tham khao rieng (xem
      matcher.apply_candidate_overlay), khong bao gio duoc gan vao cfg.

    BAN PANORAMA (0.4): doc theo DUNG cau truc Device Group - object nap theo chuoi
    thua ke Shared -> ... -> DG hien tai (0.2), rule lap rap dung thu tu danh gia
    (0.3). Canh bao hien thi phai noi ro Panorama co 2 TANG COMMIT (xem exporter).
    """
    root = ET.fromstring(candidate_xml_text)
    chain_names, chain_els = resolve_devicegroup_chain(root, dg_name)
    merged = _layer_objects(chain_els)
    addr_objs = merged['address_objects']
    addr_groups = merged['address_groups']
    svc_objs = merged['service_objects']
    svc_groups = merged['service_groups']
    rules: List[SecurityRule] = assemble_security_rules_panorama(root, dg_name)

    return {
        'address_objects': addr_objs,
        'address_groups': addr_groups,
        'service_objects': svc_objs,
        'service_groups': svc_groups,
        'rules': rules,
    }


def diff_candidate_config(cfg: dict, cand_cfg: dict) -> dict:
    """PAN-OS candidate-config API luon tra ve TOAN BO cay cau hinh (running + thay doi
    chua commit gop chung), KHONG PHAI mot ban diff. Neu dung thang cand_cfg (tu
    parse_candidate_config) de overlay, gan nhu MOI rule/object cua candidate se TRUNG
    voi running (vi phan lon khong doi) - khien apply_candidate_overlay tim thay
    "coverage" qua chinh nhung rule/object VON DA TON TAI tu truoc (qua subnet rong,
    giong het co che TOP2/TOP3), roi gan nham la "moi tu candidate". Day la nguyen nhan
    khien HAU HET item 'new' bi bao sai thanh 'candidate'.

    Ham nay loc cand_cfg xuong CHI con nhung rule/object/group THAT SU moi hoac da thay
    doi so voi running (so sanh truc tiep tung field) - dung ket qua nay (khong phai
    cand_cfg goc) cho apply_candidate_overlay."""

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


def fetch_security_policy_match(
    mgmt_ip: str,
    api_key: str,
    source_ip: str,
    dest_ip: str,
    dest_port: int,
    protocol: str = "tcp",
    vsys: str = "vsys1",
    timeout: int = 10,
    log_func=None,
    target_serial: Optional[str] = None,
) -> dict | None:
    """Goi API Live Test Policy Match QUA PANORAMA (proxy xuong dataplane firewall).

    BAN PANORAMA (require.md 0.5): `test security-policy-match` chay tren DATAPLANE
    cua 1 firewall cu the - Panorama KHONG tu tra loi duoc. Moi loi goi BAT BUOC kem
    `target=<serial firewall>`; `vsys` la vsys THAT tren chinh firewall do (Device
    Group chi anh xa gan dung, KHONG thay the vsys that). Thieu target -> tra None
    ngay, khong goi API (tang tren da chan truoc, day chi la lop bao ve thu hai).

    Tra ve dict {'rule_name': str, 'action': str} hoac None neu loi/khong khop.
    Neu duoc truyen log_func, moi truong hop tra ve None deu duoc log kem ly do cu the
    (HTTP loi, firewall tu choi, khong parse duoc phan hoi, exception...) de de doi chieu
    thay vi bi "nuot" am tham roi roi thang xuong thuat toan local.
    """
    combo_label = f"{source_ip}->{dest_ip}:{dest_port}/{protocol}"

    def _log(msg):
        if log_func:
            try:
                log_func(msg)
            except Exception:
                pass

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
    if not target_serial:
        _log("[Live Match] Thieu Target Firewall (serial) - Panorama khong tu chay "
             "test security-policy-match duoc, bo qua tier LIVE_MATCH.")
        return None

    url = f"https://{mgmt_ip}/api/"
    params = {
        "type": "op",
        "cmd": cmd_xml,
        "key": api_key,
        "vsys": vsys,
        # BAN PANORAMA (0.5): bat buoc - Panorama forward request xuong dung firewall nay.
        "target": target_serial.strip(),
    }

    try:
        with _LIVE_MATCH_SEMAPHORE:
            resp = _SESSION.get(url, params=params, verify=False, timeout=timeout)
        if resp.status_code != 200:
            _log(f"[Live Match] {combo_label}: HTTP {resp.status_code} - {resp.text[:300]}")
            return None

        root = ET.fromstring(resp.content)
        if root.attrib.get("status") != "success":
            err = _api_error_message(root)
            _log(f"[Live Match] {combo_label}: Panorama/firewall {target_serial} tu choi "
                 f"yeu cau - {err}")
            return None

        # Parse ket qua tim security rule matching
        # PAN-OS structure: <result><rules><entry name="..."><action>allow</action>...</entry></rules></result>
        rule_entry = root.find(".//rules/entry")
        if rule_entry is not None:
            rule_name = rule_entry.attrib.get("name", "")
            action_elem = rule_entry.find("action")
            action = action_elem.text.strip().lower() if action_elem is not None and action_elem.text else "allow"
            return {"rule_name": rule_name, "action": action}

        # Structure du phong
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