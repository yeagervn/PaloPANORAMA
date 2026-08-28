# -*- coding: utf-8 -*-
"""
Test pan_api.py (Mục 9): parse running-config, delete_rule_candidate (candidate
config, TUYET DOI KHONG commit - D6), fetch_rule_hit_count best-effort (loi -> {}
khong raise - D10). Dung FakeClient override _request - KHONG goi mang that.
"""

import unittest
import xml.etree.ElementTree as ET
from datetime import datetime

from check_audit import pan_api
from check_audit.pan_api import PanApiClient
from check_audit.core import PanApiError

RUNNING_CONFIG = b"""<response status="success">
<result><config>
  <devices><entry name="localhost.localdomain">
    <vsys><entry name="vsys1">
      <rulebase><security><rules>
        <entry name="r-allow-any" uuid="u-master">
          <from><member>any</member></from>
          <to><member>any</member></to>
          <source><member>any</member></source>
          <destination><member>any</member></destination>
          <service><member>any</member></service>
          <application><member>any</member></application>
          <action>allow</action>
        </entry>
        <entry name="r-disabled" uuid="u-dis">
          <disabled>yes</disabled>
          <from><member>z-in</member></from>
          <to><member>z-out</member></to>
          <source><member>10.0.0.5</member></source>
          <destination><member>10.0.0.6</member></destination>
          <service><member>TCP_1521</member></service>
          <application><member>app-1</member></application>
          <action>deny</action>
        </entry>
      </rules></security></rulebase>
      <address>
        <entry name="WEB"><ip-netmask>10.0.0.5/32</ip-netmask></entry>
        <entry name="RNG"><ip-range>10.0.0.1-10.0.0.10</ip-range></entry>
        <entry name="NET"><ip-netmask>192.168.0.0/16</ip-netmask></entry>
        <entry name="FQ"><fqdn>db.example.com</fqdn></entry>
      </address>
      <address-group>
        <entry name="G1"><static><member>WEB</member><member>RNG</member></static></entry>
      </address-group>
      <service>
        <entry name="TCP_1521"><protocol><tcp><port>1521</port></tcp></protocol></entry>
        <entry name="UDP_689"><protocol><udp><port>689</port></udp></protocol></entry>
      </service>
      <service-group>
        <entry name="SG1"><members><member>TCP_1521</member><member>UDP_689</member></members></entry>
      </service-group>
    </entry></vsys>
  </entry></devices>
</config></result></response>"""

HIT_COUNT_XML = b"""<response status="success"><result><rules>
  <entry name="rA"><hit-count>5</hit-count><last-hit-timestamp>1780000000</last-hit-timestamp><rule-creation-timestamp>1700000000</rule-creation-timestamp></entry>
  <entry name="rB"><hit-count>0</hit-count></entry>
  <entry name="rC"></entry>
</rules></result></response>"""


class FakeClient(PanApiClient):
    """Gan _request lai de cat params + tra fake response (khong goi requests)."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.calls: list = []
        self.responses = iter([])

    def set_responses(self, xml_bytes_list):
        self.responses = iter(xml_bytes_list)

    def _request(self, params: dict) -> ET.Element:
        self.calls.append(dict(params))
        payload = next(self.responses)
        if isinstance(payload, Exception):
            raise payload
        root = ET.fromstring(payload)
        status = root.get("status")
        if status != "success":
            raise PanApiError("boom", f"API Error: boom")
        return root


class TestDeleteCandidateNoCommit(unittest.TestCase):
    def test_delete_params_and_no_commit(self):
        c = FakeClient("1.2.3.4", "apikey")
        c.set_responses([b'<response status="success"/>'])
        ok = c.delete_rule_candidate("vsys1", "r-allow-any")
        self.assertTrue(ok)
        self.assertEqual(len(c.calls), 1)
        p = c.calls[0]
        self.assertEqual(p["type"], "config")
        self.assertEqual(p["action"], "delete")
        self.assertIn("@name='vsys1'", p["xpath"])
        self.assertIn("@name='r-allow-any'", p["xpath"])
        # D6: khong bao gio co type=commit / action=commit trong bat ky request nao
        for call in c.calls:
            self.assertNotIn("commit", call.get("type", ""))
            self.assertNotIn("commit", call.get("action", ""))


class TestRunConfigParse(unittest.TestCase):
    def setUp(self):
        self.config = ET.fromstring(RUNNING_CONFIG).find(".//config")
        self.vsys = pan_api.get_vsys_element(self.config, "vsys1")

    def test_vsys_list(self):
        self.assertEqual(pan_api.get_vsys_list(self.config), ["vsys1"])

    def test_rules_order_and_fields(self):
        rules = pan_api.parse_security_rules(self.vsys)
        self.assertEqual([r.name for r in rules], ["r-allow-any", "r-disabled"])
        self.assertEqual(rules[0].index, 0)
        self.assertEqual(rules[1].index, 1)
        self.assertFalse(rules[0].disabled)
        self.assertTrue(rules[1].disabled)
        self.assertEqual(rules[0].action, "allow")
        self.assertEqual(rules[1].source, ["10.0.0.5"])
        self.assertEqual(rules[1].service, ["TCP_1521"])
        self.assertEqual(rules[0].uuid, "u-master")

    def test_address_objects(self):
        objs = pan_api.parse_address_objects(self.vsys)
        self.assertEqual(objs["WEB"].kind, "host")
        self.assertEqual(objs["RNG"].kind, "range")
        self.assertEqual(objs["NET"].kind, "wide")
        self.assertEqual(objs["FQ"].kind, "fqdn")

    def test_service_objects(self):
        svcs = pan_api.parse_service_objects(self.vsys)
        self.assertEqual(svcs["TCP_1521"].protocol, "tcp")
        self.assertEqual(svcs["TCP_1521"].port_raw, "1521")
        self.assertEqual(svcs["UDP_689"].protocol, "udp")

    def test_groups(self):
        grps = pan_api.parse_address_groups(self.vsys)
        self.assertEqual(grps["G1"].members, ["WEB", "RNG"])
        sgrps = pan_api.parse_service_groups(self.vsys)
        self.assertEqual(sgrps["SG1"].members, ["TCP_1521", "UDP_689"])

    def test_vsys_objects_shared_override(self):
        # vsys de len tren (PAN-OS that se ghi de shared)
        all_objs = pan_api.parse_vsys_objects(self.config, "vsys1")
        self.assertIn("address_objects", all_objs)
        self.assertIn("WEB", all_objs["address_objects"])
        self.assertIn("TCP_1521", all_objs["service_objects"])
        self.assertIn("SG1", all_objs["service_groups"])


class TestHitCount(unittest.TestCase):
    def test_parse_hit_count(self):
        c = FakeClient("1.2.3.4", "apikey")
        c.set_responses([HIT_COUNT_XML])
        stats = c.fetch_rule_hit_count("vsys1")
        self.assertEqual(stats["rA"].hit_count, 5)
        self.assertTrue(isinstance(stats["rA"].last_hit_timestamp, datetime))
        self.assertEqual(stats["rA"].last_hit_timestamp.month, 5)  # 1780000000 ~ 2026-05
        self.assertEqual(stats["rB"].hit_count, None)   # 0 hit -> None (D10/Mục 4.4)
        self.assertIn("rC", stats)
        self.assertEqual(stats["rC"].hit_count, None)

    def test_raise_returns_empty(self):
        c = FakeClient("1.2.3.4", "apikey")
        c.set_responses([RuntimeError("API down")])
        logs = []
        stats = c.fetch_rule_hit_count("vsys1", log_func=logs.append)
        self.assertEqual(stats, {})
        self.assertTrue(any("CANH BAO" in m for m in logs))

    def test_typeop_and_cmd(self):
        c = FakeClient("1.2.3.4", "apikey")
        c.set_responses([HIT_COUNT_XML])
        c.fetch_rule_hit_count("vsys1")
        p = c.calls[0]
        self.assertEqual(p["type"], "op")
        self.assertIn("rule-hit-count", p["cmd"])


if __name__ == "__main__":
    unittest.main()