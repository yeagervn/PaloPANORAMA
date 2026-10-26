# -*- coding: utf-8 -*-
"""
where_used.py - "Check Object": 1 IP (hoac 1 ten object) dang nam trong Address
Object nao, Address Group nao, va Security/NAT Rule nao dang dung toi chung.

VI SAO CAN, KHI DA CO SEARCH RULE O MUC 2
=========================================
Muc 2 tra loi "rule nao khop IP nay" va DUNG lai o do. Nguoi van hanh con mot
cau hoi nua, hay hon va kho hon: *"IP nay dang nam trong object/group nao?"* -
vi do moi la cho phai SUA khi muon them/bot quyen, va la cho giai thich duoc
*vi sao* mot IP dang di duoc (hay khong di duoc).

BA KIEU "LIEN QUAN", KHONG DUOC TRON
====================================
    THEO THAM CHIEU  - rule GOI TEN object/group co chua IP, hoac go THANG
                       dung IP do vao o Source/Destination.
    THEO GIA TRI     - rule KHONG goi ten gi lien quan, nhung o cua no co 1
                       value PHU IP nay (subnet rong, vd 10.0.0.0/8).
    CHI VI 'any'     - o cua rule la 'any'. Ky thuat ma noi thi no phu moi IP,
                       nhung liet ke chung chung voi 2 nhom tren thi 1 rulebase
                       binh thuong se ra hang tram dong vo nghia.

Tron 3 nhom lam 1 la hong theo ca 3 huong. Tool giu rieng 3 nhom va noi ro
nhom nao la nhom nao - dung dung tinh than muc 10 cua spec (EXACT-HOST ONLY
cho ket qua chinh, subnet rong chi la thong tin tham khao).

BON CHO PAN-OS KHAC HAN CHECK POINT (va deu da thanh test rieng)
===============================================================
1. **IP go THANG vao rule.** PAN-OS cho phep go `10.1.1.5` vao o Source ma
   khong can tao Address Object. Do la "neu dich danh" - phai tinh la THAM
   CHIEU, du khong co object nao mang ten.
2. **FQDN Object.** Khong resolve ra IP duoc, nen cau "object nao mang IP nay"
   voi FQDN la KHONG BIET, khong phai "khong". Tool noi ra thay vi im lang bo.
3. **Dynamic Address Group.** Thanh vien den tu registered-ip tag luc CHAY,
   khong nam trong config. Khong lay duoc tag tu firewall thi thanh vien la
   KHONG BIET - va do cung la luc ket qua "khong thay dung o dau" nguy hiem
   nhat, vi no trong y het su that.
4. **Chuoi Device Group (override nhieu tang).** Cung 1 ten co the ton tai o
   Shared, o DG cha, VA o DG dang chon - ban GAN NHAT thang (luat 0.2). Sua
   ban o tang xa se KHONG doi gi o DG nay. Day la cho de sai nhat cua ban
   Panorama: nguoi dung sua dung ten object, dung gia tri, nhung sai TANG.

NGOAI RA, BAN PANORAMA CON IN THEM VI TRI RULE
==============================================
Moi rule deu thuoc mot trong 4 vi tri: Shared-PRE, <DG>-PRE, <DG>-POST,
Shared-POST. Thu tu do quyet dinh rule nao an rule nao, nen ket qua Where Used
thieu cot vi tri la thieu dung thu nguoi doc can de biet "sua o dau cho dung".
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Set, Tuple

from .core import (AddressGroup, AddressObject, NatRule, SecurityRule,
                   is_literal_ip_or_cidr, parse_ip_range)

# Tran do sau khi di nguoc len cay group. Config that co the long vong (PAN-OS
# chan phan lon truong hop nhung API van co the nhan), nen van phai co tran.
MAX_GROUP_DEPTH = 12

KIND_REF = "ref"
KIND_VALUE = "value"
KIND_ANY = "any"


@dataclass
class ObjectHit:
    """1 Address Object mang gia tri dang hoi."""
    name: str
    kind: str                  # ip-netmask | ip-range | fqdn | unknown
    value: str
    exact: bool                # True = neu dich danh (host /32 hoac ip-range)
    note: str = ""

    @property
    def kind_text(self) -> str:
        if self.kind == "fqdn":
            return "FQDN - KHONG xac dinh duoc"
        return "neu dich danh" if self.exact else "subnet rong co chua"


@dataclass
class GroupHit:
    name: str
    group_kind: str            # static | dynamic
    depth: int                 # 1 = chua truc tiep
    path: List[str] = field(default_factory=list)
    note: str = ""

    @property
    def path_text(self) -> str:
        return " > ".join(self.path)


@dataclass
class RuleHit:
    rule_index: int
    rule_name: str
    kind: str                  # ref | value | any
    sides: List[str] = field(default_factory=list)   # source / destination
    action: str = ""
    disabled: bool = False
    via: str = ""              # ten object/group (hoac IP literal) lam rule dinh
    # Vi tri Panorama: Shared-PRE | <DG>-PRE | <DG>-POST | Shared-POST. Thu tu
    # nay quyet dinh rule nao an rule nao, nen thieu no la thieu dung thu nguoi
    # doc can de biet phai sua o dau.
    vi_tri: str = ""

    @property
    def side_text(self) -> str:
        return " + ".join(self.sides)


@dataclass
class NatHit:
    rule_index: int
    rule_name: str
    kind: str                  # ref | value | any
    sides: List[str] = field(default_factory=list)   # Source / Destination /
    disabled: bool = False                           # Source Translated / ...
    via: str = ""
    vi_tri: str = ""

    @property
    def side_text(self) -> str:
        return " + ".join(self.sides)


@dataclass
class UsageReport:
    query: str
    objects: List[ObjectHit] = field(default_factory=list)
    groups: List[GroupHit] = field(default_factory=list)
    rules_by_reference: List[RuleHit] = field(default_factory=list)
    rules_by_value: List[RuleHit] = field(default_factory=list)
    rules_by_any: List[RuleHit] = field(default_factory=list)
    nat_hits: List[NatHit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.objects or self.groups or self.rules_by_reference
                    or self.rules_by_value or self.nat_hits)

    @property
    def total_rules(self) -> int:
        return (len(self.rules_by_reference) + len(self.rules_by_value)
                + len(self.rules_by_any))


# ============================================================================
# CHI MUC NGUOC: member -> group CHA
# ============================================================================
def build_parent_index(address_groups: Dict[str, AddressGroup]) -> Dict[str, Set[str]]:
    """{ten member: {ten group cha truc tiep}} - CHI cho group static.

    Group dynamic khong co member trong config (thanh vien tinh luc chay tu
    registered-ip tag), nen khong the dung o chi muc nay - xem
    `dynamic_groups_with_ip`.

    Lap 1 lan roi di nguoc len, thay vi moi lan hoi lai quet toan kho: tren
    kho vai nghin object khac biet la giay voi phut.
    """
    index: Dict[str, Set[str]] = {}
    for parent, grp in address_groups.items():
        if grp.kind != "static":
            continue
        for member in grp.members:
            if member:
                index.setdefault(member, set()).add(parent)
    return index


def walk_up(names: Sequence[str], parents: Dict[str, Set[str]],
            address_groups: Optional[Dict[str, AddressGroup]] = None,
            max_depth: int = MAX_GROUP_DEPTH) -> List[GroupHit]:
    """Di nguoc len cay group. Chong long vong bang tap da tham."""
    address_groups = address_groups or {}
    out: List[GroupHit] = []
    seen: Set[str] = set(names)
    frontier: List[Tuple[str, List[str]]] = [(n, [n]) for n in names]
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        nxt: List[Tuple[str, List[str]]] = []
        for name, path in frontier:
            for parent in sorted(parents.get(name, ())):
                if parent in seen:
                    continue
                seen.add(parent)
                grp = address_groups.get(parent)
                out.append(GroupHit(name=parent,
                                    group_kind=(grp.kind if grp else "static"),
                                    depth=depth, path=path + [parent]))
                nxt.append((parent, path + [parent]))
        frontier = nxt
    if frontier:
        for name, _path in frontier:
            out.append(GroupHit(name=name, group_kind="static", depth=max_depth,
                                path=[name],
                                note=f"cham tran {max_depth} cap - CON group cha "
                                     f"chua di het, ket qua ben duoi co the thieu"))
    return out


# ============================================================================
# TIM OBJECT MANG 1 DIA CHI
# ============================================================================
def _object_ranges(obj: AddressObject) -> Optional[Tuple[int, int]]:
    """Khoang dia chi THAT cua 1 object, KE CA subnet rong. None = khong doc duoc."""
    if obj.kind == "ip-netmask":
        try:
            net = ipaddress.ip_network(obj.raw_value.strip(), strict=False)
            return int(net.network_address), int(net.broadcast_address)
        except ValueError:
            return None
    if obj.kind == "ip-range":
        return parse_ip_range(obj.raw_value)
    return None


def find_objects_with_ip(address_objects: Dict[str, AddressObject], ip: str
                         ) -> Tuple[List[ObjectHit], List[str]]:
    """Moi Address Object ma gia tri cua no CHUA dia chi nay.

    Tra (danh sach hit, danh sach ten object FQDN). FQDN duoc tra RIENG vi no
    la "khong biet" chu khong phai "khong" - goi nhap no vao danh sach hit thi
    nguoi doc tuong tool da kiem tra xong.
    """
    try:
        ip_int = int(ipaddress.ip_address(ip))
    except ValueError:
        return [], []

    hits: List[ObjectHit] = []
    fqdns: List[str] = []
    for name, obj in address_objects.items():
        if obj.kind == "fqdn":
            fqdns.append(name)
            continue
        rng = _object_ranges(obj)
        if rng is None or not (rng[0] <= ip_int <= rng[1]):
            continue
        # ip-range LUON la "neu dich danh" (giong quy uoc san co cua tool:
        # nguoi viet neu ro hai dau mut la co chu dich), ip-netmask chi exact
        # khi la host don.
        exact = (obj.kind == "ip-range") or (rng[0] == rng[1])
        hits.append(ObjectHit(name=name, kind=obj.kind, value=obj.raw_value,
                              exact=exact))
    hits.sort(key=lambda h: (not h.exact, h.name))
    return hits, sorted(fqdns)


def dynamic_groups_with_ip(address_groups: Dict[str, AddressGroup], resolver, ip: str
                           ) -> Tuple[List[GroupHit], List[str]]:
    """Dynamic Address Group nao dang CHUA dia chi nay (theo registered-ip tag).

    Tra (hit, danh sach DAG khong danh gia duoc). Thanh vien DAG la trang thai
    LUC CHAY, khong nam trong config - nen khong lay duoc tag tu firewall thi
    cau tra loi la KHONG BIET, phai noi ra.
    """
    hits: List[GroupHit] = []
    unknown: List[str] = []
    has_tags = bool(getattr(resolver, "registered_ip_tags", None))
    for name, grp in address_groups.items():
        if grp.kind != "dynamic":
            continue
        if not has_tags:
            unknown.append(name)
            continue
        try:
            resolved = resolver.resolve(name)
        except Exception:                           # noqa: BLE001
            unknown.append(name)
            continue
        if ip in resolved.exact_ips:
            hits.append(GroupHit(
                name=name, group_kind="dynamic", depth=1, path=[ip, name],
                note="thanh vien tinh LUC CHAY tu registered-ip tag, khong nam "
                     "trong config - filter: " + (grp.filter_expr or "(trong)")))
    hits.sort(key=lambda h: h.name)
    return hits, sorted(unknown)


# ============================================================================
# RULE: THAM CHIEU / THEO GIA TRI / CHI VI 'any'
# ============================================================================
def _literal_is_exactly(entry: str, ip_int: int) -> bool:
    """O rule go THANG dung dia chi nay (host don), khong phai subnet rong."""
    if not is_literal_ip_or_cidr(entry):
        return False
    try:
        net = ipaddress.ip_network(entry.strip(), strict=False)
    except ValueError:
        return False
    return net.num_addresses == 1 and int(net.network_address) == ip_int


def _join_all(names: Sequence[str], keep: int = 3) -> str:
    """Ghep ten lam rule dinh, cat bot thi PHAI noi ra con bao nhieu.

    Cat im lang la kieu sai te nhat cua mot tinh nang tra cuu: nguoi doc tuong
    da thay het roi di ket luan.
    """
    uniq = sorted(set(names))
    if len(uniq) <= keep:
        return ", ".join(uniq)
    return ", ".join(uniq[:keep]) + f" (+{len(uniq) - keep} nua)"


def _side_kind(entries: Sequence[str], interest: Set[str], ip_int: Optional[int],
               resolver, range_cache: Dict[str, List[Tuple[int, int]]]
               ) -> Tuple[Optional[str], str]:
    """1 o (Source hoac Destination) lien quan toi dia chi dang hoi kieu gi?

    Tra (kind, 'vi sao'). Uu tien THAM CHIEU > GIA TRI > any: 1 o co the vua
    goi ten object vua co them 'any', va khi do THAM CHIEU moi la thong tin
    dang doc.
    """
    from .matching_engine import _collect_ranges     # tranh import vong

    via_ref: List[str] = []
    via_value: List[str] = []
    has_any = False
    for entry in entries:
        if entry == "any":
            has_any = True
            continue
        if entry in interest:
            via_ref.append(entry)
            continue
        if ip_int is not None and _literal_is_exactly(entry, ip_int):
            via_ref.append(entry + " (go thang vao rule)")
            continue
        if ip_int is None:
            continue
        for start, end in _collect_ranges(entry, resolver, range_cache):
            if start <= ip_int <= end:
                via_value.append(entry)
                break
    if via_ref:
        return KIND_REF, _join_all(via_ref)
    if via_value:
        return KIND_VALUE, _join_all(via_value)
    if has_any:
        return KIND_ANY, "any"
    return None, ""


def _scan_rules(rules: Sequence[SecurityRule], interest: Set[str],
                ip_int: Optional[int], resolver,
                range_cache: Dict[str, List[Tuple[int, int]]]
                ) -> Tuple[List[RuleHit], List[RuleHit], List[RuleHit]]:
    by_ref: List[RuleHit] = []
    by_value: List[RuleHit] = []
    by_any: List[RuleHit] = []
    for rule in rules:
        sides: Dict[str, str] = {}
        vias: List[str] = []
        for side, entries in (("Source", rule.source), ("Destination", rule.destination)):
            kind, via = _side_kind(entries, interest, ip_int, resolver, range_cache)
            if kind is not None:
                sides[side] = kind
                if via:
                    vias.append(f"{side}: {via}")
        if not sides:
            continue
        # Rule duoc xep theo o MANH NHAT cua no: dinh vi 1 ben bang ten object
        # thi do la rule tham chieu, du ben kia chi la 'any'.
        kinds = set(sides.values())
        worst = KIND_REF if KIND_REF in kinds else (
            KIND_VALUE if KIND_VALUE in kinds else KIND_ANY)
        hit = RuleHit(rule_index=rule.index, rule_name=rule.name, kind=worst,
                      sides=sorted(sides), action=rule.action,
                      disabled=rule.disabled, via=" | ".join(vias),
                      vi_tri=getattr(rule, "vi_tri", ""))
        (by_ref if worst == KIND_REF else
         by_value if worst == KIND_VALUE else by_any).append(hit)
    return by_ref, by_value, by_any


def _scan_nat(nat_rules: Sequence[NatRule], interest: Set[str],
              ip_int: Optional[int], resolver,
              range_cache: Dict[str, List[Tuple[int, int]]]) -> List[NatHit]:
    """NAT rule nao dang dung toi dia chi/object nay - XET CA O DA DICH.

    O da dich moi la cho tra loi "IP nay ra ngoai thanh gi", va no la o hay bi
    bo sot nhat khi di tim "con nay dang NAT o dau".
    """
    out: List[NatHit] = []
    for rule in nat_rules or []:
        src_xlate = list(rule.src_xlate_addresses)
        if rule.src_xlate_interface_ip:
            src_xlate.append(rule.src_xlate_interface_ip)
        dst_xlate = [rule.dst_xlate_address] if rule.dst_xlate_address else []

        sides: Dict[str, str] = {}
        vias: List[str] = []
        for side, entries in (("Source", rule.source),
                              ("Destination", rule.destination),
                              ("Source Translated", src_xlate),
                              ("Destination Translated", dst_xlate)):
            if not entries:
                continue
            kind, via = _side_kind(entries, interest, ip_int, resolver, range_cache)
            if kind is None or kind == KIND_ANY:
                # 'any' o NAT rule gan nhu dong nghia "moi rule" - khong dua
                # vao, neu khong bang NAT nao cung ra het so dong.
                continue
            sides[side] = kind
            if via:
                vias.append(f"{side}: {via}")
        if not sides:
            continue
        kinds = set(sides.values())
        worst = KIND_REF if KIND_REF in kinds else KIND_VALUE
        out.append(NatHit(rule_index=rule.index, rule_name=rule.name, kind=worst,
                          sides=sorted(sides), disabled=rule.disabled,
                          via=" | ".join(vias), vi_tri=getattr(rule, "vi_tri", "")))
    return out


# ============================================================================
# HAI DUONG VAO
# ============================================================================
def where_used_ip(ip: str,
                  address_objects: Dict[str, AddressObject],
                  address_groups: Dict[str, AddressGroup],
                  rules: Sequence[SecurityRule],
                  resolver,
                  nat_rules: Optional[Sequence[NatRule]] = None,
                  parents: Optional[Dict[str, Set[str]]] = None,
                  layer_of: Optional[Dict[str, List[str]]] = None,
                  range_cache: Optional[Dict[str, List[Tuple[int, int]]]] = None
                  ) -> UsageReport:
    """Tra 1 DIA CHI: object nao mang no, group nao chua, rule nao dung toi."""
    report = UsageReport(query=ip)
    range_cache = {} if range_cache is None else range_cache
    try:
        ip_int: Optional[int] = int(ipaddress.ip_address(ip))
    except ValueError:
        report.notes.append(f"'{ip}' khong phai dia chi IPv4/IPv6 hop le.")
        return report

    report.objects, fqdns = find_objects_with_ip(address_objects, ip)
    exact_names = [h.name for h in report.objects if h.exact]
    wide_names = [h.name for h in report.objects if not h.exact]

    parents = build_parent_index(address_groups) if parents is None else parents
    # Cay group in ra di tu MOI object mang dia chi nay (ke ca subnet rong) -
    # nguoi van hanh can biet ca cac group chua subnet do.
    report.groups = walk_up(exact_names + wide_names, parents, address_groups)
    dyn_hits, dyn_unknown = dynamic_groups_with_ip(address_groups, resolver, ip)
    report.groups.extend(dyn_hits)

    # Nhung nhanh THAM CHIEU chi tinh tu object NEU DICH DANH + group di len tu
    # chung + DAG dang chua IP. Rule tro vao 1 subnet rong KHONG phai "co tham
    # chieu toi host nay"; gop vao day thi moi IP deu "duoc rule 10.0.0.0/8
    # tham chieu" va 3 nhom mat het y nghia.
    interest: Set[str] = set(exact_names) | {h.name for h in dyn_hits}
    if exact_names:
        interest |= {g.name for g in walk_up(exact_names, parents, address_groups)}

    report.rules_by_reference, report.rules_by_value, report.rules_by_any = _scan_rules(
        rules, interest, ip_int, resolver, range_cache)
    report.nat_hits = _scan_nat(nat_rules or [], interest, ip_int, resolver, range_cache)

    _add_notes(report, exact_names, wide_names, fqdns, dyn_unknown, layer_of)
    return report


def where_used_object(name: str,
                      address_objects: Dict[str, AddressObject],
                      address_groups: Dict[str, AddressGroup],
                      rules: Sequence[SecurityRule],
                      resolver,
                      nat_rules: Optional[Sequence[NatRule]] = None,
                      parents: Optional[Dict[str, Set[str]]] = None,
                      layer_of: Optional[Dict[str, List[str]]] = None,
                      range_cache: Optional[Dict[str, List[Tuple[int, int]]]] = None
                      ) -> UsageReport:
    """Tra 1 OBJECT/GROUP theo TEN - dung nghia "Where Used".

    Tra theo ten thi KHONG suy dien theo gia tri: hoi "ai dung object nay" ma
    tra ve ca nhung rule chi tinh co 1 subnet trum len gia tri cua no la tra ve
    thu nguoi hoi khong hoi.
    """
    report = UsageReport(query=name)
    range_cache = {} if range_cache is None else range_cache

    obj = address_objects.get(name)
    grp = address_groups.get(name)
    if obj is None and grp is None:
        report.notes.append(
            f"Khong co Address Object/Group nao ten '{name}' trong chuoi Device "
            f"Group nay (Shared -> DG cha -> DG dang chon). Kiem tra lai chinh ta, "
            f"hoac object nam o Device Group khac.")
        return report

    if obj is not None:
        rng = _object_ranges(obj)
        report.objects = [ObjectHit(
            name=name, kind=obj.kind, value=obj.raw_value,
            exact=bool(rng and (obj.kind == "ip-range" or rng[0] == rng[1])),
            note="" if rng or obj.kind != "fqdn"
                 else "FQDN - khong resolve ra IP de doi chieu")]
    else:
        report.objects = [ObjectHit(
            name=name, kind=f"address-group ({grp.kind})",
            value=(", ".join(grp.members[:8]) if grp.kind == "static"
                   else grp.filter_expr),
            exact=True,
            note="" if grp.kind == "static"
                 else "Dynamic Address Group - thanh vien tinh LUC CHAY")]

    parents = build_parent_index(address_groups) if parents is None else parents
    report.groups = walk_up([name], parents, address_groups)

    interest = {name} | {g.name for g in report.groups}
    by_ref, _by_value, by_any = _scan_rules(rules, interest, None, resolver, range_cache)
    report.rules_by_reference = by_ref
    report.rules_by_any = by_any
    report.nat_hits = _scan_nat(nat_rules or [], interest, None, resolver, range_cache)

    _layer_note(report, name, layer_of)
    if not report.rules_by_reference and not report.nat_hits:
        report.notes.append(
            f"'{name}' KHONG duoc Security Rule/NAT Rule nao trong pham vi Device "
            f"Group nay (ca pre lan post-rulebase) goi ten. "
            f"Luu y: tool moi quet Security + NAT rulebase - chua quet Policy Based "
            f"Forwarding, Decryption, QoS, DoS, Authentication - nen chua du de di xoa.")
    return report


def _layer_note(report: UsageReport, name: str,
                layer_of: Optional[Dict[str, List[str]]]) -> None:
    """Noi ro object nay duoc dinh nghia o TANG nao cua chuoi Device Group.

    `layer_of[name]` la danh sach tang theo dung thu tu Shared -> DG cha ->
    ... -> DG dang chon. Tang CUOI thang (luat 0.2). Day la cho de sai nhat
    cua ban Panorama: nguoi dung sua dung ten, dung gia tri, nhung sai TANG -
    sua xong khong hieu vi sao khong co tac dung gi.
    """
    if layer_of is None:
        return
    layers = layer_of.get(name)
    if not layers:
        return
    if len(layers) > 1:
        report.notes.append(
            f"'{name}' duoc dinh nghia o {len(layers)} tang: "
            + " -> ".join(layers)
            + f". Ban cua '{layers[-1]}' dang THANG (override). Sua ban o "
            + ", ".join(layers[:-1]) + " se KHONG doi gi o Device Group nay.")
    elif layers[0].lower() == "shared":
        report.notes.append(
            f"'{name}' la object o SHARED - sua no anh huong MOI Device Group.")


def _add_notes(report: UsageReport, exact_names: List[str], wide_names: List[str],
               fqdns: List[str], dyn_unknown: List[str],
               layer_of: Optional[Dict[str, List[str]]]) -> None:
    if not exact_names and report.objects:
        report.notes.append(
            "Khong co Address Object nao NEU DICH DANH dia chi nay - chi co "
            "subnet rong chua no. Muon sua quyen cho rieng IP nay thi phai TAO "
            "object moi, khong sua duoc cai dang co.")
    elif not report.objects:
        report.notes.append(
            "Khong co Address Object nao mang dia chi nay. Rule cho phep no "
            "(neu co) nam o nhom THEO GIA TRI hoac CHI VI 'any' ben duoi.")
    if wide_names:
        report.notes.append(
            "Object chua-theo-subnet (" + ", ".join(wide_names[:3])
            + (f", +{len(wide_names) - 3}" if len(wide_names) > 3 else "")
            + ") KHONG tinh vao nhom THEO THAM CHIEU - rule dung chung nam o "
              "nhom THEO GIA TRI.")
    if fqdns:
        report.notes.append(
            f"Co {len(fqdns)} FQDN Object ({', '.join(fqdns[:3])}"
            + (f", +{len(fqdns) - 3}" if len(fqdns) > 3 else "")
            + ") KHONG resolve ra IP de doi chieu - dia chi nay CO THE nam "
              "trong do ma tool khong biet.")
    if dyn_unknown:
        report.notes.append(
            f"Co {len(dyn_unknown)} Dynamic Address Group ({', '.join(dyn_unknown[:3])}"
            + (f", +{len(dyn_unknown) - 3}" if len(dyn_unknown) > 3 else "")
            + ") KHONG danh gia duoc vi chua lay duoc registered-ip tag tu "
              "firewall - dia chi nay CO THE dang la thanh vien cua chung.")
    if report.rules_by_any:
        report.notes.append(
            f"Co {len(report.rules_by_any)} rule dinh CHI VI o cua no la 'any' - "
            f"tach rieng, khong tron vao 2 nhom tren.")
    for name in exact_names:
        _layer_note(report, name, layer_of)


# ============================================================================
# IN RA MAN HINH (muc 5 GUI) - hien THANG cho nguoi dung, khong bat mo file
# ============================================================================
def format_report(report: UsageReport, max_rules: int = 25,
                  max_items: int = 200) -> List[str]:
    """Dung cac dong chu de do thang vao o Log cua GUI.

    Nguoi dung noi ro: "enter vao tool dung cai tinh nang where used co the in
    ra TRUC TIEP cho nguoi dung" - nen ket qua phai doc duoc ngay tren man
    hinh, file Excel chi la ban luu.

    HAI LUAT CUNG CUA PHAN IN NAY
    =============================
    1. **Khong bao gio cat im lang.** Cat bot bao nhieu dong thi phai in ra
       dung so do kem cho xem day du. Mot tinh nang tra cuu ma cat im lang thi
       nguoi doc tuong da thay het roi di ket luan - sai kieu nguy hiem nhat.
    2. **Object va Group co tran RIENG, cao hon han rule** (`max_items`, mac
       dinh 200). Hai muc do chinh la CAU TRA LOI cua tinh nang nay ("IP nay
       nam trong nhung object/group nao"); cat chung o 25 nhu rule la cat dung
       cho nguoi ta can doc. File Excel/CSV thi KHONG cat gi het.
    """
    def _more(total: int, shown: int, what: str) -> None:
        if total > shown:
            lines.append(f"       ... va {total - shown} {what} nua "
                         f"(da cat bot de o Log khong tran - xem DAY DU trong "
                         f"file Excel/CSV)")

    lines: List[str] = [f"  >> {report.query}"]
    if report.objects:
        lines.append(f"     Address Object ({len(report.objects)}):")
        for hit in report.objects[:max_items]:
            lines.append(f"       - {hit.name}  [{hit.kind}] {hit.value}"
                         f"  ({hit.kind_text})")
        _more(len(report.objects), max_items, "object")
    if report.groups:
        lines.append(f"     Address Group ({len(report.groups)}):")
        for hit in report.groups[:max_items]:
            extra = f"  <- {hit.note}" if hit.note else ""
            lines.append(f"       - {hit.name}  [{hit.group_kind}, cap {hit.depth}]"
                         f"  {hit.path_text}{extra}")
        _more(len(report.groups), max_items, "group")
    for title, bucket in (("Security Rule - THEO THAM CHIEU", report.rules_by_reference),
                          ("Security Rule - THEO GIA TRI", report.rules_by_value)):
        if not bucket:
            continue
        lines.append(f"     {title} ({len(bucket)}):")
        for hit in bucket[:max_rules]:
            flag = " [DISABLED]" if hit.disabled else ""
            where = f"  @{hit.vi_tri}" if hit.vi_tri else ""
            lines.append(f"       - #{hit.rule_index} {hit.rule_name}{where}"
                         f"  [{hit.action}]{flag}  {hit.side_text}  {hit.via}")
        _more(len(bucket), max_rules, "rule")
    if report.rules_by_any:
        lines.append(f"     Security Rule - CHI VI 'any': {len(report.rules_by_any)} rule "
                     f"(khong liet ke o day - xem DAY DU trong file Excel/CSV)")
    if report.nat_hits:
        lines.append(f"     NAT Rule ({len(report.nat_hits)}):")
        for hit in report.nat_hits[:max_rules]:
            flag = " [DISABLED]" if hit.disabled else ""
            where = f"  @{hit.vi_tri}" if hit.vi_tri else ""
            lines.append(f"       - #{hit.rule_index} {hit.rule_name}{where}{flag}"
                         f"  {hit.side_text}  {hit.via}")
        _more(len(report.nat_hits), max_rules, "NAT rule")
    for note in report.notes:
        lines.append(f"     (!) {note}")
    if report.empty and not report.notes:
        lines.append("     Khong tim thay gi lien quan.")
    return lines
