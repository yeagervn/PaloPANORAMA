# -*- coding: utf-8 -*-
import threading
from dataclasses import dataclass, field
from typing import Optional, List, Tuple, Dict, Set, FrozenSet
from .core import AddressObject, AddressGroup, ServiceObject, ServiceGroup, is_literal_ip_or_cidr, _PORTLESS_APPLICATIONS

MAX_WIDE_SUBNET_ADDRESSES = 2 ** 16


@dataclass
class ResolvedAddr:
    exact_singles: Set[int] = field(default_factory=set)
    exact_ranges: List[Tuple[int, int]] = field(default_factory=list)
    wide_ranges: List[Tuple[int, int]] = field(default_factory=list)
    is_any: bool = False
    unresolved: Set[str] = field(default_factory=set)
    member_details: List[Tuple[Optional[str], str, str]] = field(default_factory=list)

    def covers_exact(self, ip_int: int) -> bool:
        return self.covers_range_exact(ip_int, ip_int)

    def covers_wide(self, ip_int: int) -> bool:
        return self.covers_range_wide(ip_int, ip_int)

    def covers_range_exact(self, start: int, end: int) -> bool:
        if self.is_any:
            return True
        if start == end and start in self.exact_singles:
            return True
        for a, b in self.exact_ranges:
            if a <= start and end <= b:
                return True
        return False

    def covers_range_wide(self, start: int, end: int) -> bool:
        if self.covers_range_exact(start, end):
            return True
        for a, b in self.wide_ranges:
            if a <= start and end <= b:
                return True
        return False

    def has_exact_member(self, start: int, end: int) -> bool:
        """Group/object nay co dung MOT member (bat ky loai host/range/wide) co
        bounds KHOP TUYET DOI voi [start,end] hay khong.

        MUC DICH KHAC voi covers_range_exact/covers_range_wide: 2 ham do dung de
        tra loi "rule/group nay da COVER (cho phep) duoc IP/dai nay chua" - co
        chu y loai bo wide_ranges de tranh false positive (vd group co subnet /8
        khong the coi la da allow san moi IP ben trong).

        Ham nay dung cho MUC DICH KHAC HAN: "group da co SAN 1 MEMBER dai dien
        CHINH XAC cho dai dang xet input hay chua" (vd input subnet 10.18.48.0/24
        trung khop tuyet doi voi 1 member wide/netmask trong group) - dung de bao
        cao "khoi phai tao object moi", KHONG lien quan gi toi viec rule da cho
        phep hay chua. Vi la KHOP TUYET DOI (khong phai "bao trum long leo") nen
        khong bi loi chon nham member qua rong nhu covers_range_wide.
        """
        if start == end and start in self.exact_singles:
            return True
        for a, b in self.exact_ranges:
            if a == start and b == end:
                return True
        for a, b in self.wide_ranges:
            if a == start and b == end:
                return True
        return False

    def total_address_count(self) -> float:
        """Tong so DIA CHI IP THUC SU (khong khu trung lap chinh xac 100%, nhung du
        chinh xac de xep hang do 'chat' cua 1 dai dien) ma ResolvedAddr nay bao phu -
        KHAC voi 'so member khai bao' (vd 1 group co 2 member dang RANGE, moi range
        span 2 dia chi, se cho ra 4 o day, chu khong phai 2). Dung de xac dinh dung
        'group nay co phai la dai dien 1:1 CHINH XAC cho tap IP dang xet hay khong' -
        vi 1 group co so member khai bao == so IP duoc cover VAN CO THE co du dia chi
        thua (member la range/wide chua nhieu hon 1 dia chi) neu chi so sanh theo so
        luong member. 'any' luon coi la rong vo han (khong bao gio la dai dien chinh
        xac)."""
        if self.is_any:
            return float('inf')
        total = len(self.exact_singles)
        for a, b in self.exact_ranges:
            total += (b - a + 1)
        for a, b in self.wide_ranges:
            total += (b - a + 1)
        return total

    def merge(self, other: 'ResolvedAddr'):
        self.exact_singles |= other.exact_singles
        self.exact_ranges += other.exact_ranges
        self.wide_ranges += other.wide_ranges
        self.is_any = self.is_any or other.is_any
        self.unresolved |= other.unresolved
        self.member_details += other.member_details
    
    def covers_range_wide_confirmed(self, start: int, end: int) -> bool:
        """Chi dung khi xay bao cao minh bach cho tier LIVE_MATCH (da duoc PAN-OS
        Test Policy Match xac nhan ALLOW).

        Khac voi covers_range_exact/covers_range_wide (dung cho thuat toan LOCAL, luon
        loai bo subnet rong): o day CHAP NHAN ca truong hop chi cover qua subnet rong /
        'any', vi dung/sai luc nay da do chinh firewall quyet dinh - "object nao chiu
        trach nhiem" chi con la thong tin tham khao/doi chieu.
        """
        if self.is_any:
            return True
        if self.covers_range_exact(start, end):
            return True
        for a, b in self.wide_ranges:
            if a <= start and end <= b:
                return True
        return False


class GroupResolver:
    def __init__(self, address_objects: Dict[str, AddressObject],
                 address_groups: Dict[str, AddressGroup], log_func=None):
        self.address_objects = address_objects
        self.address_groups = address_groups
        self.log = log_func or (lambda msg: None)
        self._cache: Dict[str, ResolvedAddr] = {}
        self._lock = threading.Lock()
        self._inflight: Dict[str, threading.Event] = {}

    def resolve(self, name: str, visiting: FrozenSet[str] = frozenset()) -> ResolvedAddr:
        if name == 'any':
            r = ResolvedAddr()
            r.is_any = True
            return r

        with self._lock:
            if name in self._cache:
                return self._cache[name]
            ev = self._inflight.get(name)
            if ev is None:
                ev = threading.Event()
                self._inflight[name] = ev
                owner = True
            else:
                owner = False
        if not owner:
            ev.wait()
            with self._lock:
                return self._cache.get(name, ResolvedAddr())

        if name in visiting:
            self.log(f"CANH BAO: circular reference tai '{name}' - bo qua")
            result = ResolvedAddr()
        else:
            result = self._compute(name, visiting | {name})

        with self._lock:
            self._cache[name] = result
            ev.set()
            del self._inflight[name]
        return result

    def _compute(self, name: str, visiting: FrozenSet[str]) -> ResolvedAddr:
        r = ResolvedAddr()

        lit = is_literal_ip_or_cidr(name)
        if lit is not None:
            if lit['num'] == 1:
                r.exact_singles.add(lit['start'])
                r.member_details.append((None, name, 'exact_host'))
            else:
                r.wide_ranges.append((lit['start'], lit['end']))
                r.member_details.append((None, name, 'wide_subnet'))
            return r

        obj = self.address_objects.get(name)
        if obj is not None:
            if obj.kind == 'host':
                r.exact_singles.add(obj.start)
                r.member_details.append((name, obj.display, 'exact_host'))
            elif obj.kind == 'range':
                r.exact_ranges.append((obj.start, obj.end))
                r.member_details.append((name, obj.display, 'exact_range'))
            elif obj.kind == 'wide':
                r.wide_ranges.append((obj.start, obj.end))
                r.member_details.append((name, obj.display, 'wide_subnet'))
            elif obj.kind == 'fqdn':
                r.unresolved.add(name)
                r.member_details.append((name, obj.display, 'fqdn'))
                self.log(f"CANH BAO: object '{name}' la FQDN, khong resolve duoc ra IP")
            else:
                r.unresolved.add(name)
                self.log(f"CANH BAO: object '{name}' khong xac dinh duoc kieu")
            return r

        grp = self.address_groups.get(name)
        if grp is not None:
            if not grp.members:
                self.log(f"CANH BAO: address-group '{name}' rong")
            for m in grp.members:
                sub = self.resolve(m, visiting)
                r.merge(sub)
            return r

        r.unresolved.add(name)
        self.log(f"CANH BAO: khong tim thay Object/Group '{name}'")
        return r


@dataclass
class ResolvedService:
    exact_ports: Set[Tuple[str, int]] = field(default_factory=set)
    ranges: List[Tuple[str, int, int]] = field(default_factory=list)
    is_any: bool = False
    is_appdefault_portless: bool = False
    member_details: List[Tuple[Optional[str], str]] = field(default_factory=list)

    def covers(self, proto: str, port: int) -> bool:
        if self.is_appdefault_portless:
            return False
        if (proto, port) in self.exact_ports:
            return True
        for p, a, b in self.ranges:
            if p == proto and a <= port <= b:
                return True
        if proto is None:
            for (p, pt) in self.exact_ports:
                if pt == port:
                    return True
            for p, a, b in self.ranges:
                if a <= port <= b:
                    return True
        return False


# PAN-OS chinh thuc chi co 2 predefined service: service-http, service-https - KHONG
# xuat hien trong file config export (khac voi object do admin tu tao) nen ServiceResolver
# truoc gio khong biet toi chung, luon bao "khong tim thay". Mot so admin cung hay dat
# rule/group tham chieu bang ten ngan "http"/"https" (khong co tien to "service-") - them
# ca 2 dang de bao phu thuc te thuong gap.
_PREDEFINED_SERVICES = {
    'service-http': ('tcp', 80, 80),
    'service-https': ('tcp', 443, 443),
    'http': ('tcp', 80, 80),
    'https': ('tcp', 443, 443),
}


class ServiceResolver:
    def __init__(self, service_objects: Dict[str, ServiceObject],
                 service_groups: Dict[str, ServiceGroup], log_func=None):
        self.service_objects = service_objects
        self.service_groups = service_groups
        self.log = log_func or (lambda msg: None)
        self._cache: Dict[str, ResolvedService] = {}

    def resolve_name(self, name: str, visiting: FrozenSet[str] = frozenset()) -> ResolvedService:
        if name == 'any':
            r = ResolvedService()
            r.is_any = True
            return r
        if name in self._cache:
            return self._cache[name]
        if name in visiting:
            self.log(f"CANH BAO: circular reference service tai '{name}'")
            return ResolvedService()

        r = ResolvedService()
        obj = self.service_objects.get(name)
        if obj is not None:
            proto = obj.protocol if obj.protocol in ('tcp', 'udp') else None
            if obj.ranges:
                for a, b in obj.ranges:
                    if a == b:
                        r.exact_ports.add((proto, a))
                    else:
                        r.ranges.append((proto, a, b))
                r.member_details.append((name, f"{proto or '?'}/{obj.port_raw}"))
            self._cache[name] = r
            return r

        grp = self.service_groups.get(name)
        if grp is not None:
            for m in grp.members:
                sub = self.resolve_name(m, visiting | {name})
                r.exact_ports |= sub.exact_ports
                r.ranges += sub.ranges
                r.is_any = r.is_any or sub.is_any
                r.member_details += sub.member_details
            self._cache[name] = r
            return r

        pre = _PREDEFINED_SERVICES.get(name.strip().lower()) if name else None
        if pre is not None:
            proto, a, b = pre
            if a == b:
                r.exact_ports.add((proto, a))
            else:
                r.ranges.append((proto, a, b))
            r.member_details.append((name, f"{proto}/{a}" if a == b else f"{proto}/{a}-{b}"))
            self._cache[name] = r
            return r

        self.log(f"CANH BAO: khong tim thay Service/Group '{name}'")
        self._cache[name] = r
        return r

    def resolve_rule_service(self, service_names: List[str], rule_applications: List[str]) -> ResolvedService:
        r = ResolvedService()
        for nm in service_names:
            if nm == 'application-default':
                apps = set(a.lower() for a in rule_applications)
                if apps and apps.issubset(_PORTLESS_APPLICATIONS):
                    r.is_appdefault_portless = True
                    r.member_details.append((None, f"application-default ({','.join(rule_applications)})"))
                else:
                    r.member_details.append((None, f"application-default ({','.join(rule_applications)})"))
                continue
            sub = self.resolve_name(nm)
            r.exact_ports |= sub.exact_ports
            r.ranges += sub.ranges
            r.is_any = r.is_any or sub.is_any
            r.member_details += sub.member_details
        return r