# -*- coding: utf-8 -*-
"""
Luoi chan cho LOI THAT tren thiet bi: "object co tren Panorama ma tool khong
tim thay".

NGUYEN NHAN
===========
Config Panorama co device-group o HAI noi:

    /config/devices/entry/device-group/entry            <- co object + rulebase THAT
    /config/readonly/devices/.../device-group/entry     <- ban sao chi-doc,
                                                           thuong CHI co <parent-dg>

check_ip_pan va check_audit_pan truoc day lay `findall(".//device-group/entry")`
roi `setdefault` - tuc la lay cai nao GAP TRUOC trong tai lieu. Tren thiet bi
that <readonly> hay nam TRUOC <devices>, nen tool vo phai ban RONG:

    chuoi DG = ['shared', 'DG-HN']        (mat DG cha)
    object   = ['H-SHARED']               (mat ca object cua chinh DG dang chon!)

Testlab/fixture cu de <readonly> o CUOI file nen moi test deu xanh - dung kieu
loi "chay tot tren mock, chet tren thiet bi".

Fixture duoi day dat <readonly> LEN TRUOC, dung nhu thiet bi that.
"""

import os
import sys
import unittest
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# <readonly> nam TRUOC <devices> - day la diem khac biet lam lo loi.
XML_READONLY_TRUOC = """<config>
  <readonly><devices><entry name="localhost.localdomain"><device-group>
      <entry name="DG-ALL"/>
      <entry name="DG-DC"><parent-dg>DG-ALL</parent-dg></entry>
      <entry name="DG-HN"><parent-dg>DG-DC</parent-dg></entry>
  </device-group></entry></devices></readonly>
  <shared>
    <address><entry name="H-SHARED"><ip-netmask>10.0.0.1/32</ip-netmask></entry></address>
  </shared>
  <devices><entry name="localhost.localdomain"><device-group>
    <entry name="DG-ALL">
      <address><entry name="H-DG-ALL"><ip-netmask>10.1.1.5/32</ip-netmask></entry></address>
    </entry>
    <entry name="DG-DC">
      <address><entry name="H-DG-DC"><ip-netmask>10.2.2.2/32</ip-netmask></entry></address>
    </entry>
    <entry name="DG-HN">
      <address><entry name="H-DG-HN"><ip-netmask>10.3.3.3/32</ip-netmask></entry></address>
      <address-group><entry name="G-HN"><static><member>H-DG-ALL</member></static></entry></address-group>
    </entry>
  </device-group></entry></devices>
</config>"""

# Ban dao thu tu - de chac chan ket qua KHONG phu thuoc thu tu tai lieu.
XML_READONLY_SAU = XML_READONLY_TRUOC.replace(
    "<readonly>", "<!--RO-->").replace("</readonly>", "<!--/RO-->")
_ro = XML_READONLY_TRUOC[XML_READONLY_TRUOC.index("<readonly>"):
                         XML_READONLY_TRUOC.index("</readonly>") + len("</readonly>")]
XML_READONLY_SAU = (XML_READONLY_TRUOC.replace(_ro, "")
                    .replace("</config>", _ro + "\n</config>"))

CHUOI_DUNG = ["shared", "DG-ALL", "DG-DC", "DG-HN"]


class TestChuoiDeviceGroup(unittest.TestCase):
    """Ca BA package phai ra CUNG mot chuoi - chung doc cung mot config."""

    def _roots(self):
        return (("readonly TRUOC", ET.fromstring(XML_READONLY_TRUOC)),
                ("readonly SAU", ET.fromstring(XML_READONLY_SAU)))

    def test_check_ip_di_het_cay_DG(self):
        from check_ip_pan.pan_api import resolve_devicegroup_chain

        for nhan, root in self._roots():
            names, _els = resolve_devicegroup_chain(root, "DG-HN")
            self.assertEqual(names, CHUOI_DUNG, f"({nhan}) sai chuoi DG")

    def test_check_audit_di_het_cay_DG(self):
        from check_audit_pan.pan_api import resolve_devicegroup_chain

        for nhan, root in self._roots():
            self.assertEqual(resolve_devicegroup_chain(root, "DG-HN"), CHUOI_DUNG,
                             f"({nhan}) sai chuoi DG")

    def test_check_rule_di_het_cay_DG(self):
        from check_rule_pan.core import resolve_devicegroup_chain

        for nhan, root in self._roots():
            self.assertEqual(resolve_devicegroup_chain(root, "DG-HN")[0], CHUOI_DUNG,
                             f"({nhan}) sai chuoi DG")


class TestObjectKhongDuocMAT(unittest.TestCase):
    """Day moi la thu nguoi dung thay: object go vao ma tool bao khong co."""

    def _objs(self, xml):
        from check_ip_pan.pan_api import merge_layered_objects

        return merge_layered_objects(ET.fromstring(xml), "DG-HN")["address_objects"]

    def test_lay_duoc_object_cua_MOI_TANG(self):
        for nhan, xml in (("readonly TRUOC", XML_READONLY_TRUOC),
                          ("readonly SAU", XML_READONLY_SAU)):
            objs = self._objs(xml)
            for ten in ("H-SHARED", "H-DG-ALL", "H-DG-DC", "H-DG-HN"):
                self.assertIn(ten, objs, f"({nhan}) mat object {ten}")

    def test_KHONG_duoc_mat_object_cua_chinh_DG_dang_chon(self):
        """Ca te nhat cua ban loi cu: vo phai ban readonly RONG nen ngay ca
        object nam so so trong DG dang chon cung bien mat."""
        self.assertIn("H-DG-HN", self._objs(XML_READONLY_TRUOC))

    def test_group_cua_DG_con_van_resolve_duoc_member_o_DG_cha(self):
        """Group o DG con tro toi object o DG cha - mat DG cha la group rong."""
        from check_ip_pan.pan_api import merge_layered_objects
        from check_ip_pan.resolver_engine import GroupResolver

        merged = merge_layered_objects(ET.fromstring(XML_READONLY_TRUOC), "DG-HN")
        resolver = GroupResolver(merged["address_objects"],
                                 merged["address_groups"], {})
        self.assertIn("10.1.1.5", resolver.resolve("G-HN").exact_ips)

    def test_tra_IP_o_DG_cha_phai_tim_ra_object(self):
        """Dung duong vao THAT cua tinh nang Check Object."""
        from check_ip_pan.pan_api import merge_layered_objects
        from check_ip_pan.resolver_engine import GroupResolver
        from check_ip_pan.where_used import where_used_ip

        merged = merge_layered_objects(ET.fromstring(XML_READONLY_TRUOC), "DG-HN")
        resolver = GroupResolver(merged["address_objects"],
                                 merged["address_groups"], {})
        rep = where_used_ip("10.1.1.5", merged["address_objects"],
                            merged["address_groups"], [], resolver)
        self.assertIn("H-DG-ALL", [o.name for o in rep.objects])


if __name__ == "__main__":
    unittest.main(verbosity=2)
