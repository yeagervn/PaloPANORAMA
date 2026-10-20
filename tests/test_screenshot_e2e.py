# -*- coding: utf-8 -*-
"""Acceptance test dung 3 anh PA-5450 (Objects > Addresses > Global Find) + output Excel that su.
Chay end-to-end: classify_row -> report -> exporter (LOCAL va LIVE_MATCH voi API gia)."""
import ipaddress
import unittest
from unittest import mock

from check_rule_pan.core import (AddressObject, AddressGroup, ServiceObject, SecurityRule, parse_ip_token)
from check_rule_pan.resolver import GroupResolver, ServiceResolver
from check_rule_pan.index import build_device_index
from check_rule_pan import matcher, exporter
from check_rule_pan.matcher import build_rule_infos, classify_row
from check_rule_pan.request import RequestRow

GREEN_IN_RULE, LIGHT_ORANGE, EXIST_GREEN, RED = "006100", "ED7D31", "00A651", "9C0006"


def _ip(s):
    return int(ipaddress.ip_address(s))


def _host(n, a):
    return AddressObject(n, 'host', _ip(a), _ip(a), a)


def _rng(n, a, b):
    return AddressObject(n, 'range', _ip(a), _ip(b), "%s-%s" % (a, b))


def _scenario():
    objs = {}
    for o in [_rng('DR_Bigdata_10.43.128.100-104', '10.43.128.100', '10.43.128.104'),
              _rng('Range_10.43.128.100-104', '10.43.128.100', '10.43.128.104'),       # trung value (anh 1)
              _host('dr-bigdata-util_10.43.128.104', '10.43.128.104'),
              _rng('bigdata-worker_10.43.128.108-112', '10.43.128.108', '10.43.128.112'),  # anh 2
              _host('Host_10.43.128.108', '10.43.128.108'),
              _rng('Range_10.43.128.108-111', '10.43.128.108', '10.43.128.111'),
              _host('Host_10.43.128.183', '10.43.128.183'), _host('Host_10.43.128.184', '10.43.128.184'),  # anh 3
              _rng('Range_10.33.128.140-174', '10.33.128.140', '10.33.128.174'),
              _rng('Range_10.33.128.216-225', '10.33.128.216', '10.33.128.225'),
              _rng('Range_10.43.128.140-158', '10.43.128.140', '10.43.128.158'),
              _host('GW68a', '10.7.66.68'), _host('GW68b', '10.3.66.68')]:
        objs[o.name] = o
    groups = {
        'DataLake_GR_SRV': AddressGroup('DataLake_GR_SRV', ['Host_10.43.128.183', 'Host_10.43.128.184',
                                                            'Range_10.33.128.140-174', 'Range_10.33.128.216-225',
                                                            'Range_10.43.128.140-158']),
        'VPG-GR-GW-68': AddressGroup('VPG-GR-GW-68', ['GW68a', 'GW68b'])}
    for g, ips in {'Stagging-GR-SRV': ['10.0.84.116'], 'EDW-DS': ['10.0.88.13', '10.4.88.13'],
                   'ETL-Dataservice-Infor': ['10.0.88.20', '10.4.88.20'],
                   'ETL-Tool-GR-SRV': ['10.0.88.113', '10.4.88.113', '10.4.88.115'],
                   'EDW-DS_117-118_GR': ['10.0.88.117', '10.4.88.117', '10.4.88.118']}.items():
        ms = []
        for a in ips:
            n = 'H_%s' % a
            objs.setdefault(n, _host(n, a))
            ms.append(n)
        groups[g] = AddressGroup(g, ms)
    svc = {'TCP_2121': ServiceObject('TCP_2121', 'tcp', '2121', ranges=[(2121, 2121)])}
    rule = SecurityRule(index=1, name='Existing-Rule', source=['DataLake_GR_SRV'], destination=['VPG-GR-GW-68'],
                        service=['TCP_2121'], application=['any'], action='allow', disabled=False)
    gr, sr = GroupResolver(objs, groups), ServiceResolver(svc, {})
    cfg = {'address_objects': objs, 'address_groups': groups, 'service_objects': svc,
           'service_groups': {}, 'rules': [rule]}
    idx = build_device_index(cfg, gr, sr)
    infos = build_rule_infos([rule], gr, sr)
    src = ['10.43.128.100-10.43.128.104', '10.43.128.108-10.43.128.112', '10.43.128.140-10.43.128.158',
           '10.43.128.183-10.43.128.184', '10.33.128.140-10.33.128.174', '10.33.128.216-10.33.128.225',
           '10.0.84.116', '10.0.88.13', '10.4.88.13', '10.0.88.20', '10.4.88.20', '10.0.88.113', '10.4.88.113',
           '10.4.88.115', '10.0.88.117', '10.4.88.117', '10.4.88.118']
    dst = ['10.7.66.68', '10.3.66.68']
    row = RequestRow(row_number=2, source_tokens=[parse_ip_token(s) for s in src],
                     dest_tokens=[parse_ip_token(s) for s in dst], port_tokens=[(2121, 2121, 'tcp')],
                     extra_values=[','.join(src), ','.join(dst), '2121'], raw_source=','.join(src),
                     raw_dest=','.join(dst), raw_port='2121')
    return row, infos, idx


def _text(blocks):
    return ''.join(b.text for b in blocks)


def _name_rule_text(res):
    cell = exporter.build_name_rule_cell(res)
    return _text(cell[0] if isinstance(cell, tuple) else cell)


def _color_of(blocks, needle):
    for b in blocks:
        if needle in b.text:
            return b.font.color.rgb[-6:]
    raise AssertionError("khong thay %r trong cell" % needle)


EXPECT_ADD = ("ADD SOURCE: 10.0.84.116, 10.0.88.13, 10.0.88.20, 10.0.88.113, 10.0.88.117, 10.4.88.13, "
              "10.4.88.20, 10.4.88.113, 10.4.88.115, 10.4.88.117, 10.4.88.118, "
              "10.43.128.100-10.43.128.104, 10.43.128.108-10.43.128.112")


class _Mixin:
    def _check(self, res):
        by = {m.display: m for m in res.source_report}
        # Khong co bat ky item nao la 'new' / 'TAO MOI': toan bo object trong anh deu ton tai tren thiet bi.
        self.assertEqual([m.display for m in res.source_report if m.status == 'new'], [])
        for d in ('10.43.128.100-10.43.128.104', '10.43.128.108-10.43.128.112'):
            self.assertEqual((by[d].status, by[d].existing_kind), ('exists', 'range'))
        self.assertIn(by['10.43.128.100-10.43.128.104'].existing_name,
                      ('DR_Bigdata_10.43.128.100-104', 'Range_10.43.128.100-104'))
        self.assertEqual(by['10.43.128.108-10.43.128.112'].existing_name, 'bigdata-worker_10.43.128.108-112')
        for d in ('10.43.128.183-10.43.128.184', '10.43.128.140-10.43.128.158',
                  '10.33.128.140-10.33.128.174', '10.33.128.216-10.33.128.225'):
            self.assertEqual((by[d].status, by[d].existing_name), ('in_rule', 'DataLake_GR_SRV'), d)
        txt = _name_rule_text(res)
        self.assertIn(EXPECT_ADD, txt)
        self.assertNotIn('183-10.43.128.184', txt.split('ADD SOURCE:')[1])  # 183-184 da in_rule -> khong ADD
        blocks = exporter._build_field_lines(res.source_report)
        self.assertNotIn('TAO MOI', _text(blocks))
        self.assertEqual(_color_of(blocks, '\u2022 DataLake_GR_SRV'), GREEN_IN_RULE)       # in_rule giu nguyen
        self.assertEqual(_color_of(blocks, '\u2022 Stagging-GR-SRV'), LIGHT_ORANGE)        # group cover
        self.assertEqual(_color_of(blocks, '\u2022 bigdata-worker_10.43.128.108-112'), EXIST_GREEN)
        full = _text(blocks)
        self.assertIn('bigdata-worker_10.43.128.108-112 (cover: 10.43.128.108-10.43.128.112) - range exist, can ADD vao rule', full.replace('\n', ' ').replace('  ', ' '))


class TestScreenshotE2E(_Mixin, unittest.TestCase):
    def test_local_path(self):
        row, infos, idx = _scenario()
        res = classify_row(row, infos, idx)
        self.assertEqual(res.tier, 'TOP2')
        self.assertEqual(exporter._compute_action_level(res), 'add')
        self._check(res)

    def test_live_match_path(self):
        row, infos, idx = _scenario()
        fake = lambda *a, **k: {"action": "allow", "rule_name": "Existing-Rule"}
        with mock.patch.object(matcher, "fetch_security_policy_match", side_effect=fake):
            # BAN PANORAMA (0.5): Live Match BAT BUOC target=<serial firewall>.
            res = classify_row(row, infos, idx, mgmt_ip="1.2.3.4", api_key="KEY",
                               target_serial="001122334455")
        self.assertEqual(res.tier, 'LIVE_MATCH')
        self.assertEqual(exporter._compute_action_level(res), 'add')
        self._check(res)

    def test_live_match_bi_bo_qua_khi_thieu_target(self):
        """BAN PANORAMA (0.5): co mgmt_ip + api_key nhung THIEU Target Firewall ->
        tier LIVE_MATCH tu bo qua IM LANG (khong goi API), roi thang xuong LOCAL."""
        row, infos, idx = _scenario()
        called = []
        fake = lambda *a, **k: called.append(1) or {"action": "allow", "rule_name": "X"}
        with mock.patch.object(matcher, "fetch_security_policy_match", side_effect=fake):
            res = classify_row(row, infos, idx, mgmt_ip="1.2.3.4", api_key="KEY")
        self.assertEqual(called, [])
        self.assertEqual(res.tier, 'TOP2')
        self.assertIsNone(res.live_match_skip_reason)


if __name__ == '__main__':
    unittest.main()
