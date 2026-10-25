# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_resolver_contract.py).
"""
"""
B6 (10/2026): LUOI CHAN CAU TRUC cho ca 2 lo hong S1 va B3.

S1 va B3 cung mot ban chat: mot object khong resolve duoc ra gia tri thi dong gop
**0** vao ket qua, va neu khong co ai danh dau thi phep so sanh phia tren ket luan
SAI (exact-scope dat sai / bo sot deny chan truoc). Ca 2 da duoc va, nhung ban va
chi manh bang viec `unresolved` duoc dien **DUNG** o moi duong.

File nay khong kiem mot ca cu the nao ca. No kiem **HOP DONG** cua resolver:

    Voi MOI dang object/service, ket qua resolve phai HOAC mang gia tri that
    (dia chi / port), HOAC danh dau ten do vao `unresolved`. KHONG duoc im lang
    tra ve rong.

Vi sao can: neu sau nay ai them mot loai object moi (vd `ip-wildcard`,
`external-list`, region object) ma quen danh dau, thi lo hong S1/B3 **quay lai
nguyen ven** va **khong mot ca test nao do** - vi cac ca kia deu viet cho tung
loai object cu the da biet. Day la test duy nhat bat duoc loai hoi quy do.

Cach viet: liet ke tung `kind` cua AddressObject tu CHINH ma nguon
(`AddressObject.kind` co comment liet ke day du) va tung duong cua
ServiceResolver, roi khang dinh hop dong tren.
"""

import ipaddress
import unittest

from check_rule_pan.core import AddressObject, AddressGroup, ServiceObject, ServiceGroup
from check_rule_pan.resolver import GroupResolver, ServiceResolver


def _ip(s):
    return int(ipaddress.ip_address(s))


def _co_gia_tri_dia_chi(r) -> bool:
    return bool(r.is_any or r.exact_singles or r.exact_ranges or r.wide_ranges)


def _co_gia_tri_port(r) -> bool:
    return bool(r.is_any or r.exact_ports or r.ranges or r.is_appdefault_portless)


class TestHopDongAddressResolver(unittest.TestCase):
    """MOI kind cua AddressObject: hoac ra dia chi, hoac vao unresolved."""

    # Lay dung tu comment liet ke trong AddressObject.kind
    KINDS = ("host", "wide", "range", "fqdn", "unknown")

    def _obj(self, kind):
        if kind == "host":
            return AddressObject("O", kind, start=_ip("10.0.0.1"), end=_ip("10.0.0.1"),
                                 display="10.0.0.1")
        if kind == "wide":
            return AddressObject("O", kind, start=_ip("10.0.0.0"),
                                 end=_ip("10.0.0.255"), display="10.0.0.0/24")
        if kind == "range":
            return AddressObject("O", kind, start=_ip("10.0.0.1"),
                                 end=_ip("10.0.0.9"), display="10.0.0.1-10.0.0.9")
        return AddressObject("O", kind, display="x")       # fqdn / unknown

    def test_moi_kind_hoac_ra_dia_chi_hoac_vao_unresolved(self):
        for kind in self.KINDS:
            with self.subTest(kind=kind):
                r = GroupResolver({"O": self._obj(kind)}, {}).resolve("O")
                self.assertTrue(
                    _co_gia_tri_dia_chi(r) or r.unresolved,
                    f"kind='{kind}' tra ve RONG va KHONG danh dau unresolved - "
                    f"day chinh la lo hong S1: 0 dia chi im lang lam "
                    f"_is_exactly_scoped() dat sai")

    def test_kind_la_mot_chuoi_la_cung_phai_vao_unresolved(self):
        """Mo phong "ai do them loai object moi ma quen xu ly"."""
        r = GroupResolver({"O": AddressObject("O", "ip-wildcard", display="x")}, {}).resolve("O")
        self.assertTrue(r.unresolved,
                        "kind khong nhan ra duoc PHAI vao unresolved, neu khong thi "
                        "them 1 loai object moi la lo hong S1 quay lai ma khong test nao do")

    def test_object_khong_ton_tai(self):
        r = GroupResolver({}, {}).resolve("KHONG-CO")
        self.assertTrue(r.unresolved)

    def test_group_dong_DAG(self):
        grps = {"G": AddressGroup("G", members=[], dynamic=True, dynamic_filter="'tag'")}
        r = GroupResolver({}, grps).resolve("G")
        self.assertTrue(r.unresolved)

    def test_circular_reference(self):
        grps = {"A": AddressGroup("A", members=["B"]), "B": AddressGroup("B", members=["A"])}
        r = GroupResolver({}, grps).resolve("A")
        self.assertTrue(r.unresolved)

    def test_group_RONG_that_su_thi_KHONG_bi_danh_dau(self):
        """Phan biet co y: group rong THAT SU cover 0 dia chi tren thiet bi, nen
        0 o day la DUNG - khong phai "khong biet". Danh dau no se sinh canh bao
        nhieu ma khong co rui ro gi."""
        r = GroupResolver({}, {"G": AddressGroup("G", members=[])}).resolve("G")
        self.assertFalse(r.unresolved)
        self.assertFalse(_co_gia_tri_dia_chi(r))


class TestHopDongServiceResolver(unittest.TestCase):
    def test_service_co_dai_port(self):
        objs = {"S": ServiceObject("S", "tcp", "443", ranges=[(443, 443)])}
        r = ServiceResolver(objs, {}).resolve_name("S")
        self.assertTrue(_co_gia_tri_port(r))
        self.assertFalse(r.unresolved)

    def test_service_khong_co_dai_port(self):
        objs = {"S": ServiceObject("S", "unknown", "", ranges=[])}
        r = ServiceResolver(objs, {}).resolve_name("S")
        self.assertTrue(r.unresolved, "0 port im lang chinh la lo hong B3")

    def test_service_khong_ton_tai(self):
        self.assertTrue(ServiceResolver({}, {}).resolve_name("KHONG-CO").unresolved)

    def test_circular_reference_service(self):
        grps = {"A": ServiceGroup("A", members=["B"]), "B": ServiceGroup("B", members=["A"])}
        self.assertTrue(ServiceResolver({}, grps).resolve_name("A").unresolved)

    def test_hop_dong_qua_resolve_rule_service(self):
        """Duong ma build_rule_infos() THAT SU di qua - day la cho tung lam ban va
        B3 vo nghia vi `unresolved` bi mat sach khi gop len."""
        r = ServiceResolver({}, {}).resolve_rule_service(["KHONG-CO"], ["any"])
        self.assertTrue(r.unresolved,
                        "resolve_rule_service() phai mang theo unresolved - thieu "
                        "dong nay thi resolve_name() co danh dau cung vo nghia")

    def test_any_khong_bi_danh_dau(self):
        for nm in ("any",):
            r = ServiceResolver({}, {}).resolve_name(nm)
            self.assertTrue(r.is_any)
            self.assertFalse(r.unresolved)


if __name__ == "__main__":
    unittest.main(verbosity=2)
