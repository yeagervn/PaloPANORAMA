# -*- coding: utf-8 -*-
import threading
from bisect import bisect_right
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
    _iv_cache: dict = field(default_factory=dict, repr=False, compare=False)

    def _merged(self, include_wide: bool) -> List[Tuple[int, int]]:
        """Union cac interval lien ke/chong lan (exact_singles + exact_ranges, va them
        wide_ranges neu include_wide). Cache lazy; merge() xoa cache."""
        key = 'w' if include_wide else 'e'
        got = self._iv_cache.get(key)
        if got is not None:
            return got
        ivs = [(x, x) for x in self.exact_singles] + list(self.exact_ranges)
        if include_wide:
            ivs += list(self.wide_ranges)
        ivs.sort()
        out: List[Tuple[int, int]] = []
        for a, b in ivs:
            if out and a <= out[-1][1] + 1:
                if b > out[-1][1]:
                    out[-1] = (out[-1][0], b)
            else:
                out.append((a, b))
        self._iv_cache[key] = out
        return out

    def _merged_starts(self, include_wide: bool):
        """TOI UU (10/2026): danh sach cac diem BAT DAU cua _merged(), cache cung cho
        de tra cuu bang bisect O(log n) thay cho quet tuyen tinh O(n) - _merged() da
        sort va cac interval roi nhau hoan toan (merge khi a <= prev_end+1) nen chi
        co DUNG 1 interval co the chua start: interval cuoi cung co a <= start.
        Cung ky thuat da dung o check_audit/resolver.py. merge() xoa ca cache nay."""
        key = 'ws' if include_wide else 'es'
        got = self._iv_cache.get(key)
        if got is None:
            got = [a for a, _b in self._merged(include_wide)]
            self._iv_cache[key] = got
        return got

    def _covers_union(self, start: int, end: int, include_wide: bool) -> bool:
        ivs = self._merged(include_wide)
        if not ivs:
            return False
        i = bisect_right(self._merged_starts(include_wide), start) - 1
        return i >= 0 and end <= ivs[i][1]

    def covers_range_exact_union(self, start: int, end: int) -> bool:
        """Nhu covers_range_exact nhung tinh theo HOP cac member exact (host+range)
        lien ke/chong lan. Khong tinh wide_ranges."""
        if self.is_any:
            return True
        return self._covers_union(start, end, False)

    def covers_range_wide_union(self, start: int, end: int) -> bool:
        if self.is_any:
            return True
        return self._covers_union(start, end, True)

    def covers_input_exact(self, start: int, end: int) -> bool:
        """COVERAGE CHUAN cho 1 TOKEN INPUT (host / range / CIDR) o thuat toan LOCAL -
        dung thay cho covers_range_exact() tai moi cho quyet dinh "field nay da cover
        duoc token input nay chua" (chon tier TOP1-TOP4 va bao cao in_rule).

        SUA LOI (10/2026 - "input dang IP range tren device da co nhung tool bao can
        ADD/TAO MOI"): covers_range_exact() chi xet TUNG member RIENG LE, nen 1 dai
        input (vd 10.1.1.100-110) duoc rule cover DU nho HOP nhieu member lien ke
        (11 host object, hoac 2 range object 100-104 + 105-110) van bi coi la CHUA
        cover -> tool goi y ADD/TAO MOI oan. Day la dung ban chat bug ma
        covers_range_exact_union() da sinh ra de xu ly (nhung truoc do chi duoc ap
        dung o tang BAO CAO, khong ap vao tang chon tier - gay lech giua 2 tang).

        2 nhanh, CA HAI deu exact-only (KHONG he noi long nguyen tac "subnet rong
        khong duoc tinh la cover" cua thiet ke goc):
        1. covers_range_exact_union(): hop cac member EXACT (host + ip-range) lien
           ke/chong lan; wide_ranges (ip-netmask rong) BI LOAI nhu truoc.
        2. has_exact_member(): field co dung 1 member voi bounds KHOP TUYET DOI
           [start,end] - ke ca member la ip-netmask (vd input '10.1.1.0/24' va rule
           dung dung object Net_10.1.1.0/24). Day KHONG phai "suy dien tu object
           rong hon": bounds trung khit 1:1 nen khong the cap quyen rong hon input.

        Voi token input la 1 IP DON (start == end), ham nay cho ket qua Y HET
        covers_range_exact() cu (hop interval khong sinh ra diem moi; has_exact_member
        cua 1 diem = 'start in exact_singles' - tap con cua covers_range_exact) ->
        toan bo hanh vi voi input IP don KHONG doi mot chut nao.
        """
        if start == end:
            # TOI UU + an toan: voi 1 IP don, covers_range_exact() da tuong duong
            # TUYET DOI (xem doan cuoi docstring) va re hon han (tra cuu set O(1)
            # thay vi hop interval) - di thang nhanh cu.
            return self.covers_range_exact(start, end)
        if self.covers_range_exact_union(start, end):
            return True
        # has_exact_member() cho dai [start,end] (start != end) chi con y nghia o
        # wide_ranges: member exact (host/ip-range) co bounds TRUNG KHIT thi da duoc
        # covers_range_exact_union() o tren bat het - khong can quet lai.
        for a, b in self.wide_ranges:
            if a == start and b == end:
                return True
        return False

    def covers_input_wide(self, start: int, end: int) -> bool:
        """Ban 'wide' cua covers_input_exact() - CHAP NHAN them subnet rong, dung o
        dung nhung cho truoc day goi covers_range_wide() (dem so token input ma 1 ben
        da cover de xet dest_full/source_full, _describe_nearest_rule, shadow-check).
        covers_range_wide_union() da bao gom ca has_exact_member (bounds trung khit
        luon nam trong 1 interval cua _merged(True))."""
        if start == end:
            return self.covers_range_wide(start, end)   # tuong duong tuyet doi, re hon
        return self.covers_range_wide_union(start, end)

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

    def union_address_count(self) -> float:
        """So dia chi THUC SU sau khi khu trung lap/chong lan (union exact + wide). Chi dung de
        so sanh exact-scope voi request (cung da khu trung lap) - KHONG thay total_address_count."""
        if self.is_any:
            return float('inf')
        return sum(b - a + 1 for a, b in self._merged(True))

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
        self._iv_cache.clear()

    def covers_range_wide_confirmed(self, start: int, end: int) -> bool:
        """Chi dung khi xay bao cao minh bach cho tier LIVE_MATCH (da duoc PAN-OS
        Test Policy Match xac nhan ALLOW).

        Khac voi covers_range_exact/covers_range_wide (dung cho thuat toan LOCAL, luon
        loai bo subnet rong): o day CHAP NHAN ca truong hop chi cover qua subnet rong /
        'any', vi dung/sai luc nay da do chinh firewall quyet dinh - "object nao chiu
        trach nhiem" chi con la thong tin tham khao/doi chieu.
        """
        return self.covers_range_wide_union(start, end)


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

        if name in visiting:
            self.log(f"CANH BAO: circular reference tai '{name}' - bo qua")
            # Taint (10/2026): truoc day tra ve ResolvedAddr() RONG, nghia la 0 dia
            # chi va KHONG danh dau gi -> field chua vong lap nay bi coi la
            # exact-scope. Cau hinh hong thi pham vi that la KHONG XAC DINH.
            r = ResolvedAddr()
            r.unresolved.add(name)
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

        result = ResolvedAddr()
        try:
            result = self._compute(name, visiting | {name})
        except Exception as ex:  # khong de worker khac cho vo han
            self.log(f"CANH BAO: loi resolve '{name}': {ex!r}")
        finally:
            with self._lock:
                self._cache[name] = result
                ev.set()
                self._inflight.pop(name, None)
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
            if getattr(grp, 'dynamic', False):
                # Dynamic Address Group: thanh vien gan theo tag luc runtime, KHONG
                # co trong file cau hinh. Phai danh dau unresolved - neu khong thi
                # DAG = 0 dia chi im lang va lam _is_exactly_scoped() DAT SAI.
                r.unresolved.add(name)
                r.member_details.append((name, grp.dynamic_filter or 'dynamic', 'dag'))
                self.log(f"CANH BAO: address-group '{name}' la DYNAMIC (filter: "
                         f"{grp.dynamic_filter or 'khong ro'}) - thanh vien gan theo tag "
                         f"luc runtime, khong doc duoc tu file cau hinh")
                if not grp.members:
                    return r
            elif not grp.members:
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
    # B3 (10/2026) - lo hong cung ho voi S1 nhung o phia SERVICE. Truoc day
    # ResolvedService KHONG co field nay, va 3 duong tra ve 0 PORT ma khong danh
    # dau gi: service/group khong tim thay, circular reference, va service object
    # khong co dai port doc duoc. Lech CA HAI huong:
    #   - an toan nhung sai: rule bi coi la IT PORT hon -> khuyen "+ ADD PORT" cho
    #     port ma rule DA cho phep (admin them port object trung lap)
    #   - NGUY HIEM: _ports_covered_for_shadow() coi 0 port la "khong cover" ->
    #     BO SOT canh bao "co deny chan truoc" khi rule deny dung service group
    #     khong doc duoc
    unresolved: Set[str] = field(default_factory=set)

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
# SUA 10/2026 theo xac nhan tu he thong that: `service-http` la HAI port roi
# rac 80 VA 8080 - KHONG phai dai 80-8080. Viet nham thanh dai thi no se phu
# luon tcp/1521, tcp/3389... tuc la bao "da duoc phep" cho gan nhu moi thu.
# Vi vay cau truc o day la DANH SACH tung dai, khong phai mot dai duy nhat.
_PREDEFINED_SERVICES = {
    'service-http': [('tcp', 80, 80), ('tcp', 8080, 8080)],
    'service-https': [('tcp', 443, 443)],
    'http': [('tcp', 80, 80)],
    'https': [('tcp', 443, 443)],
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
            r = ResolvedService()
            r.unresolved.add(name)       # B3: khong duoc im lang 0 port
            return r

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
            else:
                # B3: co object nhung KHONG doc duoc dai port nao (vd protocol la
                # dang tool chua hieu). 0 port im lang chinh la cai gay ra ca 2
                # huong sai - phai danh dau.
                r.unresolved.add(name)
                self.log(f"CANH BAO: service '{name}' khong doc duoc dai port nao")
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
                r.unresolved |= sub.unresolved      # B3: lan truyen len tren
            self._cache[name] = r
            return r

        pre = _PREDEFINED_SERVICES.get(name.strip().lower()) if name else None
        if pre is not None:
            for proto, a, b in pre:
                if a == b:
                    r.exact_ports.add((proto, a))
                else:
                    r.ranges.append((proto, a, b))
                r.member_details.append(
                    (name, f"{proto}/{a}" if a == b else f"{proto}/{a}-{b}"))
            self._cache[name] = r
            return r

        self.log(f"CANH BAO: khong tim thay Service/Group '{name}'")
        r.unresolved.add(name)           # B3: khong duoc im lang 0 port
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
            sub = self.resolve_name(nm)
            r.exact_ports |= sub.exact_ports
            r.ranges += sub.ranges
            r.is_any = r.is_any or sub.is_any
            r.member_details += sub.member_details
            # B3 (10/2026): PHAI mang theo unresolved len tren. Thieu dong nay thi
            # resolve_name() co danh dau cung vo nghia - chinh build_rule_infos() di
            # qua ham NAY de dung ri.service, nen co nay se bi mat sach. (Da bi dung
            # 1 lan: va resolve_name xong ma 2 ca test van do.)
            r.unresolved |= sub.unresolved
        return r