# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_unresolved_scope_gate.py).

Luat nghiep vu cua 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%,
chi doi ten package. Neu sua 1 ben ma quen ben kia thi 2 ban se troi khoi nhau -
do la dung cai ma quy tac dong bo trong PHAN 0 muon ngan.
"""
"""
LO HONG "VALUE THAT" (10/2026 - CHECK RULE): mot object KHONG resolve duoc ra IP
dong gop 0 DIA CHI vao ResolvedAddr, nhung `_is_exactly_scoped()` chi so sanh
`union_address_count() == tong IP cua request` va KHONG he xet `ResolvedAddr.unresolved`
-> field cua rule bi coi la "khop CHINH XAC 1:1 voi request" trong khi THUC TE
tren firewall no con cover them mot tap KHONG XAC DINH.

Hau qua (huong nguy hiem): tool de xuat "+ ADD SOURCE" vao rule do. Admin them
source moi -> source do khong chi voi tói dung 1 dest duoc yeu cau, ma voi tói
ca tap ma object kia resolve ra o runtime. Day la dung kieu am tham cap quyen
vuot pham vi ma `_is_exactly_scoped()` duoc sinh ra de ngan.

4 nguon "0 dia chi im lang":
  1. object `<fqdn>`          -> resolver CO canh bao, nhung van 0 dia chi
  2. object/group KHONG tim thay -> CO canh bao (vd object nam o vsys khac, EDL,
     region object ma parser khong hieu), van 0 dia chi
  3. object `kind='unknown'`  -> CO canh bao, van 0 dia chi
  4. **Dynamic Address Group** (`<dynamic><filter>`) -> `parse_address_groups()`
     chi doc `<static>` nen DAG ra members=[] -> 0 dia chi, **KHONG MOT CANH BAO
     NAO**. Nguy hiem nhat trong 4 cai: thanh vien DAG duoc gan theo tag luc
     runtime (registered-ip), co the la hang tram host.

Phan biet BAT BUOC (quyet dinh thiet ke, xem PHAN II.2.1):
  - TOP1 ("da duoc phep, khong can lam gi") KHONG bi chan: coverage da duoc
    chung minh bang chinh cac range resolve duoc, mot member FQDN/DAG THEM VAO
    khong lam traffic do thanh khong duoc phep. Ket luan "khong can lam gi" van
    dung va an toan.
  - TOP1.1/TOP2/TOP3 ("AN TOAN de bo sung phan con thieu vao rule nay") BI CHAN:
    o day ket luan dua tren "ben kia khop chinh xac pham vi cua anh", ma dieu do
    SAI khi con object khong resolve duoc.

Phan biet thu hai: pham vi "DA BIET rong hon" (vd field 14 dia chi, member khop
4 - da duoc nguoi dung chap nhan qua `_exact_member_scope`) khac han pham vi
"KHONG XAC DINH". Nguoi dung chap nhan cai dau, chua bao gio chap nhan cai sau.
"""

import ipaddress
import unittest
import xml.etree.ElementTree as ET

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule, parse_ip_token,
    parse_address_groups,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow


def _ip(s):
    return int(ipaddress.ip_address(s))


REQ_SRC = "10.9.9.9"        # KHONG nam trong Source cua rule -> phan "con thieu"
REQ_DST = "10.1.1.5"        # nam dung trong Dest cua rule
REQ_PORT = 443


def _request(src=REQ_SRC, dst=REQ_DST, port=REQ_PORT):
    return RequestRow(
        row_number=2,
        source_tokens=[parse_ip_token(src)],
        dest_tokens=[parse_ip_token(dst)],
        port_tokens=[(port, port, "tcp")],
        extra_values=[src, dst, str(port)],
        raw_source=src, raw_dest=dst, raw_port=str(port),
    )


def _svc():
    return ({"TCP_443": ServiceObject("TCP_443", "tcp", "443", ranges=[(443, 443)])}, {})


def _infos(rule, addr_objs, addr_groups):
    svc_objs, svc_groups = _svc()
    return build_rule_infos([rule],
                            GroupResolver(addr_objs, addr_groups),
                            ServiceResolver(svc_objs, svc_groups))


def _rule(dest_name):
    """Rule: Source la 1 host KHAC request (nen request thieu Source -> nhanh TOP2),
    Dest la group dang xet, Service du port."""
    return SecurityRule(
        index=10, name="ALLOW-DC-443",
        source=["SRV-OLD"], destination=[dest_name],
        service=["TCP_443"], application=["any"],
        action="allow", disabled=False,
    )


def _base_objs():
    return {
        "SRV-OLD": AddressObject("SRV-OLD", "host", start=_ip("10.0.0.1"),
                                 end=_ip("10.0.0.1"), display="10.0.0.1"),
        "SRV-A": AddressObject("SRV-A", "host", start=_ip(REQ_DST),
                               end=_ip(REQ_DST), display=REQ_DST),
    }


def _classify(addr_objs, addr_groups, dest_name="GRP-DC"):
    infos = _infos(_rule(dest_name), addr_objs, addr_groups)
    return classify_row(_request(), infos, DeviceIndex())


class TestExactScopeKhongDuocDatKhiCoObjectKhongResolveDuoc(unittest.TestCase):
    """4 nguon "0 dia chi im lang" deu phai chan duoc nhanh "+ ADD"."""

    def _assert_bi_chan(self, res, ten_object):
        self.assertNotIn(res.tier, ("TOP2", "TOP3", "TOP1.1"),
                         f"tier={res.tier}: van de xuat '+ ADD' du Dest cua rule con "
                         f"object '{ten_object}' khong resolve duoc -> pham vi KHONG XAC DINH")
        self.assertEqual(res.tier, "TOP4")
        self.assertEqual(res.nearest_rule_kind, "near_top2",
                         "phai tut xuong near_top2 (van hien rule lam tham khao)")
        self.assertTrue(res.untrusted_scope,
                        "phai bat co untrusted_scope de exporter in ly do")
        self.assertIn(ten_object, res.untrusted_scope_detail or "",
                      "ly do phai NEU TEN object gay ra pham vi khong xac dinh")

    def test_1_member_fqdn(self):
        objs = _base_objs()
        objs["SRV-BACKUP-FQDN"] = AddressObject("SRV-BACKUP-FQDN", "fqdn",
                                                display="backup.corp.local")
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A", "SRV-BACKUP-FQDN"])}
        self._assert_bi_chan(_classify(objs, grps), "SRV-BACKUP-FQDN")

    def test_2_object_khong_tim_thay(self):
        """Ten object co trong rule nhung KHONG co trong config da parse - vd object
        nam o vsys khac, EDL, region object. Tren firewall no VAN cover cai gi do."""
        objs = _base_objs()
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A", "EDL-THREAT-FEED"])}
        self._assert_bi_chan(_classify(objs, grps), "EDL-THREAT-FEED")

    def test_3_object_kind_unknown(self):
        objs = _base_objs()
        objs["ADDR-WILDCARD"] = AddressObject("ADDR-WILDCARD", "unknown",
                                              display="10.1.1.0/0.0.0.255")
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A", "ADDR-WILDCARD"])}
        self._assert_bi_chan(_classify(objs, grps), "ADDR-WILDCARD")

    def test_4_dynamic_address_group_phai_duoc_nhan_dien_tu_XML(self):
        """DAG: nguy hiem nhat vi truoc fix KHONG co mot canh bao nao.

        Di qua dung parse_address_groups() (khong dung tay AddressGroup) vi chinh
        cho parse la noi bo sot `<dynamic>`."""
        xml = """<root><address-group>
          <entry name="GRP-DC"><static>
            <member>SRV-A</member><member>DAG-QUARANTINE</member>
          </static></entry>
          <entry name="DAG-QUARANTINE">
            <dynamic><filter>'tag-quarantine'</filter></dynamic>
          </entry>
        </address-group></root>"""
        grps = parse_address_groups(ET.fromstring(xml))
        self.assertIn("DAG-QUARANTINE", grps)
        self.assertTrue(grps["DAG-QUARANTINE"].dynamic,
                        "parse_address_groups() phai danh dau group <dynamic> - "
                        "neu khong no ra members=[] = 0 dia chi, im lang tuyet doi")
        self._assert_bi_chan(_classify(_base_objs(), grps), "DAG-QUARANTINE")


class TestKhongPhaBanCuDung(unittest.TestCase):
    """Doi chung: cac nhanh DUNG truoc gio phai khong doi."""

    def test_group_sach_khop_1_1_van_la_TOP2(self):
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A"])}
        res = _classify(_base_objs(), grps)
        self.assertEqual(res.tier, "TOP2", "group sach khop 1:1 phai van la TOP2 '+ ADD SOURCE'")
        self.assertFalse(res.untrusted_scope)

    def test_TOP1_khong_bi_chan_boi_member_fqdn(self):
        """TOP1 = 'da duoc phep, khong can lam gi'. Mot member FQDN them vao KHONG
        lam traffic nay thanh khong duoc phep -> ket luan cu van dung, KHONG demote.
        (Quyet dinh thiet ke, xem docstring dau file.)"""
        objs = _base_objs()
        objs["SRV-REQ-SRC"] = AddressObject("SRV-REQ-SRC", "host", start=_ip(REQ_SRC),
                                            end=_ip(REQ_SRC), display=REQ_SRC)
        objs["SRV-BACKUP-FQDN"] = AddressObject("SRV-BACKUP-FQDN", "fqdn",
                                                display="backup.corp.local")
        grps = {
            "GRP-SRC": AddressGroup("GRP-SRC", members=["SRV-REQ-SRC"]),
            "GRP-DC": AddressGroup("GRP-DC", members=["SRV-A", "SRV-BACKUP-FQDN"]),
        }
        rule = SecurityRule(index=10, name="ALLOW-FULL", source=["GRP-SRC"],
                            destination=["GRP-DC"], service=["TCP_443"],
                            application=["any"], action="allow", disabled=False)
        res = classify_row(_request(), _infos(rule, objs, grps), DeviceIndex())
        self.assertEqual(res.tier, "TOP1")


class TestExportPhaiInRaLyDo(unittest.TestCase):
    """Ban va vo hinh neu ly do khong den duoc nguoi doc file Excel.

    Da bi dung 1 lan: chen dong canh bao vao 1 nhanh cua build_name_rule_cell thi
    nhanh 'near_match' - DUNG nhanh ma cong chan demote xuong - khong he in gi.
    Nay build_name_rule_cell boc 1 lan ben ngoai nen khong the bo sot nhanh."""

    def _cell_text(self, res):
        from check_rule_pan import exporter
        cell, _lines = exporter.build_name_rule_cell(res)
        return "".join(getattr(b, "text", "") or "" for b in cell)

    def test_near_match_in_ro_ten_object(self):
        objs = _base_objs()
        objs["SRV-BACKUP-FQDN"] = AddressObject("SRV-BACKUP-FQDN", "fqdn",
                                                display="backup.corp.local")
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A", "SRV-BACKUP-FQDN"])}
        res = _classify(objs, grps)
        from check_rule_pan import exporter
        self.assertEqual(exporter._compute_action_level(res), "near_match")
        text = self._cell_text(res)
        self.assertIn("PHAM VI KHONG DO DUOC", text)
        self.assertIn("SRV-BACKUP-FQDN", text)

    def test_dong_sach_khong_bi_them_dong_rac(self):
        grps = {"GRP-DC": AddressGroup("GRP-DC", members=["SRV-A"])}
        text = self._cell_text(_classify(_base_objs(), grps))
        self.assertNotIn("PHAM VI KHONG DO DUOC", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
