# -*- coding: utf-8 -*-
"""
BAN PORT tu repo PaAIO_StandAlone (tests/test_zone_from_routes.py).

Luat nghiep vu 2 ban GIONG 100% (PHAN 0) nen noi dung test giong 100%, chi doi
ten package. XML trong file nay la dang FIREWALL (khong co tang <config> cua
Template) - co y de kiem rang parse_static_routes() cua ban Panorama xu ly duoc
CA HAI dang duong dan; phan Template duoc kiem o testlab.
"""
"""
B1 (10/2026 - CHECK RULE): cong chan zone gan nhu VO HIEU voi traffic tu ngoai.

Truoc ban va, `zone_lookup` chi duoc dung tu **bang Interface/Zone** (cac subnet
gan TRUC TIEP tren interface). Hau qua tren mang that: moi IP khong nam trong
nhung subnet do - tuc gan nhu moi dia chi internet, moi site khac, moi nguon nam
SAU mot router - deu cho ra `zone_verdict = unknown` -> cong chan **giu tier,
khong chan gi**, chi in thEm 1 dong "CHUA KIEM DUOC ZONE".

Noi cach khac: S2 chi bao ve duoc khi CA HAI dau mut nam trong subnet gan truc
tiep. Firewall nao cung co default route, nen trong thuc te phan lon dong se roi
vao `unknown`.

Cach PAN-OS lam that: zone cua mot dia chi duoc quyet dinh boi **interface egress
theo bang dinh tuyen** (forwarding table), khong phai chi boi subnet gan truc
tiep. Mot engineer map IP -> zone bang tay cung lam dung nhu vay: tra route
longest-prefix -> ra interface -> ra zone.

Ban va: `build_zone_lookup()` nhan them `routes` va NOI them cac entry suy tu
route vao CUNG mot list. Khong doi `resolve_zone_for_ip()` mot dong nao - list da
duoc sort theo prefix_len GIAM DAN nen subnet gan truc tiep (/24) tu dong thang
default route (/0), dung thu tu uu tien that.

HAN CHE phai ghi ro: cach nay sai khi co asymmetric routing hoac
policy-based forwarding (PBF) - luc do duong di that khong theo bang dinh tuyen.
"""

import ipaddress
import unittest
import xml.etree.ElementTree as ET

from check_rule_pan.core import (AddressObject, ServiceObject, SecurityRule,
                             parse_ip_token, parse_interface_subnets, parse_zones,
                             parse_static_routes)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import DeviceIndex, build_zone_lookup, resolve_zone_for_ip
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow


def _ip(s):
    return int(ipaddress.ip_address(s))


# Mot thiet bi rat binh thuong: 2 interface gan truc tiep + 1 DEFAULT ROUTE
# tro ra ethernet1/2 (zone untrust). Dung dang ma moi firewall deu co.
XML = """<config><devices><entry name="localhost.localdomain">
  <network>
    <interface><ethernet>
      <entry name="ethernet1/1"><layer3><ip><entry name="10.10.10.1/24"/></ip></layer3></entry>
      <entry name="ethernet1/2"><layer3><ip><entry name="192.168.50.1/24"/></ip></layer3></entry>
    </ethernet></interface>
    <virtual-router><entry name="default">
      <routing-table><ip><static-route>
        <entry name="default-out">
          <destination>0.0.0.0/0</destination>
          <interface>ethernet1/2</interface>
          <nexthop><ip-address>192.168.50.254</ip-address></nexthop>
        </entry>
        <!-- route co nexthop nhung KHONG khai interface: phai suy interface tu
             chinh nexthop (10.10.10.9 thuoc ethernet1/1) -->
        <entry name="to-branch">
          <destination>10.77.0.0/16</destination>
          <nexthop><ip-address>10.10.10.9</ip-address></nexthop>
        </entry>
        <!-- route khong the suy duoc interface (nexthop khong thuoc subnet nao,
             khong khai interface) -> PHAI BO QUA, khong duoc doan -->
        <entry name="khong-suy-duoc">
          <destination>10.88.0.0/16</destination>
          <nexthop><ip-address>203.0.113.9</ip-address></nexthop>
        </entry>
      </static-route></ip></routing-table>
    </entry></virtual-router>
  </network>
  <vsys><entry name="vsys1">
    <zone>
      <entry name="trust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
      <entry name="untrust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
    </zone>
  </entry></vsys>
</entry></devices></config>"""


def _ctx(with_routes=True):
    root = ET.fromstring(XML)
    ifs = parse_interface_subnets(root)
    zones = parse_zones(root.find("devices/entry/vsys/entry"))
    routes = parse_static_routes(root) if with_routes else None
    return build_zone_lookup(ifs, zones, routes=routes)


class TestParseStaticRoutes(unittest.TestCase):
    def test_doc_duoc_route_co_interface(self):
        routes = parse_static_routes(ET.fromstring(XML))
        d = {r[3]: r for r in routes}          # theo interface
        self.assertIn("ethernet1/2", d, str(routes))

    def test_route_chi_co_nexthop_thi_suy_interface_tu_nexthop(self):
        zl = _ctx()
        # 10.77.x di qua nexthop 10.10.10.9 (thuoc ethernet1/1 = trust)
        self.assertEqual(resolve_zone_for_ip(_ip("10.77.1.1"), zl), "trust")

    def test_route_khong_suy_duoc_interface_thi_BO_QUA(self):
        """Khong duoc doan. 10.88.x chi con khop default route -> untrust,
        chu KHONG duoc gan vao mot zone bua nao."""
        zl = _ctx()
        self.assertEqual(resolve_zone_for_ip(_ip("10.88.1.1"), zl), "untrust")


class TestZoneTuRouteLapDuocKhoangTrong(unittest.TestCase):
    def test_truoc_ban_va_IP_ngoai_subnet_khong_suy_duoc_zone(self):
        """Tai hien dung trieu chung cu: khong co route -> IP internet = unknown."""
        zl = _ctx(with_routes=False)
        self.assertIsNone(resolve_zone_for_ip(_ip("8.8.8.8"), zl),
                          "day la trieu chung cu: cong chan zone im lang")

    def test_sau_ban_va_default_route_cho_ra_zone(self):
        zl = _ctx()
        self.assertEqual(resolve_zone_for_ip(_ip("8.8.8.8"), zl), "untrust")

    def test_subnet_gan_truc_tiep_VAN_THANG_default_route(self):
        """Thu tu uu tien that: /24 truc tiep phai thang /0."""
        zl = _ctx()
        self.assertEqual(resolve_zone_for_ip(_ip("10.10.10.50"), zl), "trust")
        self.assertEqual(resolve_zone_for_ip(_ip("192.168.50.50"), zl), "untrust")

    def test_route_cu_the_thang_default_route(self):
        zl = _ctx()
        self.assertEqual(resolve_zone_for_ip(_ip("10.77.5.5"), zl), "trust")


class TestCongChanZoneNayCoHieuLucThatSu(unittest.TestCase):
    """Phan quan trong nhat: cong chan S2 phai THAT SU chan duoc traffic tu ngoai."""

    def _classify(self, src, with_routes=True):
        objs = {
            "H-SRC": AddressObject("H-SRC", "host", start=_ip(src), end=_ip(src),
                                   display=src),
            "H-DST": AddressObject("H-DST", "host", start=_ip("192.168.50.21"),
                                   end=_ip("192.168.50.21"), display="192.168.50.21"),
        }
        svc = {"SVC-443": ServiceObject("SVC-443", "tcp", "443", ranges=[(443, 443)])}
        # Rule chi cho trust -> untrust
        rule = SecurityRule(index=10, name="ALLOW-TRUST-ONLY", source=["H-SRC"],
                            destination=["H-DST"], service=["SVC-443"],
                            application=["any"], action="allow", disabled=False,
                            from_zones=["trust"], to_zones=["untrust"])
        ris = build_rule_infos([rule], GroupResolver(objs, {}), ServiceResolver(svc, {}))
        row = RequestRow(row_number=2, source_tokens=[parse_ip_token(src)],
                         dest_tokens=[parse_ip_token("192.168.50.21")],
                         port_tokens=[(443, 443, "tcp")], extra_values=[],
                         raw_source=src, raw_dest="192.168.50.21", raw_port="443")
        return classify_row(row, ris, DeviceIndex(),
                            zone_lookup=_ctx(with_routes=with_routes))

    def test_nguon_tu_internet_nay_BI_CHAN_dung(self):
        """Source 8.8.8.8 -> theo default route la zone 'untrust', rule chi cho
        'trust' -> firewall THAT se chan. Truoc ban va: unknown, giu TOP1."""
        res = self._classify("8.8.8.8")
        self.assertEqual(res.zone_verdict, "mismatch")
        self.assertNotIn(res.tier, ("TOP1", "TOP1.1", "TOP2", "TOP3"))

    def test_truoc_ban_va_cung_kich_ban_do_KHONG_bi_chan(self):
        """Doi chung tai hien: khong co route thi van la TOP1 (lo hong cu)."""
        res = self._classify("8.8.8.8", with_routes=False)
        self.assertEqual(res.zone_verdict, "unknown")
        self.assertEqual(res.tier, "TOP1")

    def test_nguon_dung_zone_thi_khong_bi_chan(self):
        res = self._classify("10.10.10.50")
        self.assertEqual(res.zone_verdict, "match")
        self.assertEqual(res.tier, "TOP1")


class TestTuongThichNguoc(unittest.TestCase):
    def test_build_zone_lookup_khong_truyen_routes_van_chay(self):
        root = ET.fromstring(XML)
        zl = build_zone_lookup(parse_interface_subnets(root),
                               parse_zones(root.find("devices/entry/vsys/entry")))
        self.assertTrue(zl)
        self.assertEqual(resolve_zone_for_ip(_ip("10.10.10.50"), zl), "trust")

    def test_config_khong_co_virtual_router_thi_tra_rong(self):
        self.assertEqual(parse_static_routes(ET.fromstring(
            "<config><devices><entry><network/></entry></devices></config>")), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
