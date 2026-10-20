# -*- coding: utf-8 -*-
"""
Test cho FIX 10/2026 (CHECK RULE + CHECK IP):
"Input dang IP RANGE da ton tai tren device nhung tool khong doc duoc / van bao can ADD".

4 nhom nguyen nhan goc duoc phu o day:
  A. PARSE: parse_ip_token() chi hieu dung 1 dinh dang "A.B.C.D-A.B.C.D" voi dau tru
     ASCII -> moi bien the thuc te (rut gon octet cuoi, en/em dash do Excel autocorrect,
     '~', '..', 'to', kem '/32', non-breaking space) bi tra ve 'invalid' va bi
     classify_row() LOAI BO AM THAM.
  B. COVERAGE THEO HOP MEMBER: 1 dai input duoc rule cover DU nho HOP nhieu member
     (nhieu host lien ke / 2 range object ke nhau) van bi coi la chua cover ->
     tier roi xuong TOP2/TOP3 va bao "+ ADD SOURCE/DEST", bao cao thi "TAO MOI".
  C. MEMBER BOUNDS TRUNG KHIT: input '10.1.1.0/24' va rule dung dung object
     Net_10.1.1.0/24 (kieu ip-netmask) van bao can ADD.
  D. TOP2/TOP3 + ben con lai cover du qua SUBNET RONG: khong con gi de ADD nhung van
     hien mau cam "+ ADD SOURCE" + "TAO MOI" (nay -> 'wide_full_match').
Chay: python -m unittest discover -s tests (khong phu thuoc tkinter).
"""

import ipaddress
import unittest

from check_rule_pan.core import (
    AddressObject, AddressGroup, ServiceObject, SecurityRule,
    parse_ip_token, split_ip_tokens,
)
from check_rule_pan.resolver import GroupResolver, ServiceResolver, ResolvedAddr
from check_rule_pan.index import build_device_index
from check_rule_pan.matcher import build_rule_infos, classify_row, build_field_report
from check_rule_pan.request import build_manual_request
from check_rule_pan.exporter import _compute_action_level

from check_ip_pan.core import parse_ip_list_input


def _ip(s):
    return int(ipaddress.ip_address(s))


def _rng(n, a, b):
    return AddressObject(n, 'range', _ip(a), _ip(b), "%s-%s" % (a, b))


def _host(n, a):
    return AddressObject(n, 'host', _ip(a), _ip(a), a)


def _wide(n, net):
    x = ipaddress.ip_network(net, strict=False)
    return AddressObject(n, 'wide', int(x.network_address), int(x.broadcast_address), net)


_SVC = {'tcp443': ServiceObject('tcp443', 'tcp', '443', [(443, 443)])}


def _rule(index, name, src, dst):
    return SecurityRule(index=index, name=name, source=src, destination=dst,
                        service=['tcp443'], application=['any'], action='allow',
                        disabled=False)


def _classify(objs, grps, rules, src_in, dst_in='10.2.2.5', port='443'):
    objs = dict(objs)
    objs.setdefault('DSTH', _host('DSTH', '10.2.2.5'))
    cfg = {'address_objects': objs, 'address_groups': grps,
           'service_objects': _SVC, 'service_groups': {}, 'rules': rules}
    gr = GroupResolver(objs, grps)
    sr = ServiceResolver(_SVC, {})
    idx = build_device_index(cfg, gr, sr)
    ris = build_rule_infos(rules, gr, sr)
    row = build_manual_request([[src_in, dst_in, port]]).rows[0]
    return classify_row(row, ris, idx)


# ---------------------------------------------------------------------------
# A. PARSE - moi dinh dang range thuc te deu phai doc duoc
# ---------------------------------------------------------------------------

class TestRangeTokenParsing(unittest.TestCase):
    EXPECT = (_ip('10.1.1.100'), _ip('10.1.1.110'))

    def test_all_real_world_range_formats(self):
        for tok in [
            "10.1.1.100-10.1.1.110",          # chuan (da chay tu truoc)
            "10.1.1.100 - 10.1.1.110",        # co khoang trang (da chay tu truoc)
            "10.1.1.100-110",                 # RUT GON octet cuoi
            "10.1.1.100 - 110",
            "10.1.1.100–10.1.1.110",     # en dash
            "10.1.1.100—10.1.1.110",     # em dash
            "10.1.1.100−10.1.1.110",     # minus sign
            "10.1.1.100~10.1.1.110",
            "10.1.1.100..10.1.1.110",
            "10.1.1.100 to 10.1.1.110",
            "10.1.1.100 TO 10.1.1.110",
            "10.1.1.100/32-10.1.1.110/32",
            "10.1.1.100 - 10.1.1.110",   # non-breaking space
            " '10.1.1.100-10.1.1.110 ",            # dau nhay Excel + khoang trang
            "10.1.1.110-10.1.1.100",               # dao nguoc -> tu chuan hoa
        ]:
            t = parse_ip_token(tok)
            self.assertEqual(t['kind'], 'range', "token %r" % tok)
            self.assertEqual((t['start'], t['end']), self.EXPECT, "token %r" % tok)

    def test_formats_da_chay_khong_doi(self):
        self.assertEqual(parse_ip_token('10.1.1.5')['kind'], 'host')
        self.assertEqual(parse_ip_token('10.1.1.0/24')['kind'], 'cidr')
        self.assertEqual(parse_ip_token('10.1.1.0/255.255.255.0')['kind'], 'cidr')
        for bad in ['abc', '', '   ', '10.1.1.300-10.1.1.310', 'Host_10.1.1.1']:
            self.assertEqual(parse_ip_token(bad)['kind'], 'invalid', "token %r" % bad)

    def test_split_ip_tokens_tach_theo_khoang_trang_an_toan(self):
        # Tach khi MOI manh deu hop le...
        self.assertEqual(split_ip_tokens('10.1.1.1 10.2.2.2'),
                         ['10.1.1.1', '10.2.2.2'])
        # ...nhung TUYET DOI khong pha vo 1 range co khoang trang
        self.assertEqual(split_ip_tokens('10.1.1.100 - 10.1.1.110'),
                         ['10.1.1.100 - 10.1.1.110'])
        # Con manh khong hop le -> giu nguyen token goc de bao cao "khong doc duoc"
        self.assertEqual(split_ip_tokens('10.1.1.1 abc'), ['10.1.1.1 abc'])
        # Dau phay/; /xuong dong giu nguyen hanh vi cu
        self.assertEqual(split_ip_tokens('10.1.1.1, 10.2.2.2;10.3.3.3'),
                         ['10.1.1.1', '10.2.2.2', '10.3.3.3'])

    def test_token_khong_doc_duoc_duoc_bao_cao_chu_khong_bi_loai_am_tham(self):
        objs = {'R': _rng('R', '10.1.1.100', '10.1.1.110')}
        rules = [_rule(1, 'R-ok', ['R'], ['DSTH'])]
        res = _classify(objs, {}, rules, '10.1.1.100-10.1.1.110, 10.1.1.100-ABC')
        self.assertEqual(res.unparsed_source, ['10.1.1.100-ABC'])
        # Con token khong doc duoc -> KHONG duoc to xanh "FULL MATCH"
        self.assertEqual(_compute_action_level(res), 'add')

    def test_ca_dong_khong_doc_duoc_thi_note_neu_ro_token(self):
        res = _classify({}, {}, [_rule(1, 'R', ['any'], ['any'])], '10.1.1.100-ABC')
        self.assertEqual(res.tier, 'INVALID')
        self.assertIn('10.1.1.100-ABC', res.note)


# ---------------------------------------------------------------------------
# B. COVERAGE THEO HOP MEMBER CUA CUNG 1 FIELD
# ---------------------------------------------------------------------------

class TestRangeCoveredByUnionOfMembers(unittest.TestCase):
    def test_hai_range_object_ke_nhau_trong_rule(self):
        objs = {'R_A': _rng('R_A', '10.1.2.100', '10.1.2.104'),
                'R_B': _rng('R_B', '10.1.2.105', '10.1.2.110')}
        rules = [_rule(1, 'R-union', ['R_A', 'R_B'], ['DSTH'])]
        res = _classify(objs, {}, rules, '10.1.2.100-10.1.2.110')
        self.assertEqual(res.tier, 'TOP1')
        self.assertEqual(_compute_action_level(res), 'none')
        self.assertEqual(res.source_report[0].status, 'in_rule')
        # Dai dien phai neu CA 2 object gop phan (de admin doi chieu)
        self.assertIn('R_A', res.source_report[0].existing_name)
        self.assertIn('R_B', res.source_report[0].existing_name)

    def test_group_nhieu_host_lien_ke_phu_kin_range(self):
        hs = {('H%d' % i): _host('H%d' % i, '10.1.1.%d' % i) for i in range(100, 111)}
        grps = {'G': AddressGroup('G', list(hs))}
        rules = [_rule(1, 'R-grp', ['G'], ['DSTH'])]
        res = _classify(hs, grps, rules, '10.1.1.100-10.1.1.110')
        self.assertEqual(res.tier, 'TOP1')
        self.assertEqual(_compute_action_level(res), 'none')
        self.assertEqual(res.source_report[0].status, 'in_rule')
        self.assertEqual(res.source_report[0].existing_name, 'G')

    def test_range_thuc_su_chua_co_van_phai_bao_tao_moi(self):
        """Khong duoc "noi tay" den muc bao da co trong khi that su chua co gi."""
        objs = {'S': _host('S', '10.9.9.9')}
        rules = [_rule(1, 'R-other', ['S'], ['DSTH'])]
        res = _classify(objs, {}, rules, '10.1.9.1-10.1.9.9')
        self.assertEqual(res.source_report[0].status, 'new')
        self.assertEqual(_compute_action_level(res), 'add')


# ---------------------------------------------------------------------------
# C. MEMBER CO BOUNDS TRUNG KHIT 1:1 VOI INPUT
# ---------------------------------------------------------------------------

class TestExactBoundsMember(unittest.TestCase):
    def test_subnet_object_trung_khit_input(self):
        objs = {'N': _wide('N', '10.1.1.0/24')}
        rules = [_rule(1, 'R-net', ['N'], ['DSTH'])]
        for src_in in ('10.1.1.0/24', '10.1.1.0-10.1.1.255'):
            res = _classify(objs, {}, rules, src_in)
            self.assertEqual(res.tier, 'TOP1', src_in)
            self.assertEqual(_compute_action_level(res), 'none', src_in)
            self.assertEqual(res.source_report[0].status, 'in_rule', src_in)

    def test_exact_only_khong_bi_noi_long_cho_ip_don(self):
        """IP DON nam trong 1 subnet rong VAN khong duoc coi la in_rule o LOCAL -
        nguyen tac exact-only cua thiet ke goc phai giu nguyen tuyet doi."""
        r = ResolvedAddr()
        r.wide_ranges = [(_ip('10.0.0.0'), _ip('10.255.255.255'))]
        self.assertFalse(r.covers_input_exact(_ip('10.1.2.3'), _ip('10.1.2.3')))
        self.assertFalse(r.covers_input_exact(_ip('10.0.0.0'), _ip('10.0.0.9')))
        # ...nhung trung khit bounds thi duoc (khong the cap quyen rong hon input)
        self.assertTrue(r.covers_input_exact(_ip('10.0.0.0'), _ip('10.255.255.255')))

    def test_covers_input_exact_bang_covers_range_exact_voi_ip_don(self):
        """Bang chung 'thay doi chi tac dong token dang range': voi IP don, ham moi
        phai cho ket qua Y HET ham cu tren moi to hop member."""
        r = ResolvedAddr()
        r.exact_singles = {_ip('10.0.0.1'), _ip('10.0.0.2')}
        r.exact_ranges = [(_ip('10.0.0.10'), _ip('10.0.0.20'))]
        r.wide_ranges = [(_ip('10.1.0.0'), _ip('10.1.255.255'))]
        for last in range(0, 40):
            ip = _ip('10.0.0.%d' % last)
            self.assertEqual(r.covers_input_exact(ip, ip), r.covers_range_exact(ip, ip))
        ip = _ip('10.1.2.3')
        self.assertEqual(r.covers_input_exact(ip, ip), r.covers_range_exact(ip, ip))


# ---------------------------------------------------------------------------
# D. TOP2/TOP3 + ben con lai da cover du qua SUBNET RONG -> wide_full_match
# ---------------------------------------------------------------------------

class TestTop2WideFullyCovered(unittest.TestCase):
    def test_range_trong_subnet_rong_cua_rule_khong_con_bao_add(self):
        objs = {'N': _wide('N', '10.1.3.0/24')}
        rules = [_rule(1, 'R-wide', ['N'], ['DSTH'])]
        res = _classify(objs, {}, rules, '10.1.3.10-10.1.3.20')
        self.assertEqual(res.tier, 'TOP2')
        self.assertTrue(res.wide_fully_covered)
        # Khong con mau cam "+ ADD SOURCE"/"TAO MOI" - chuyen sang "DA DUOC CHO PHEP"
        self.assertEqual(_compute_action_level(res), 'wide_full_match')
        self.assertEqual(res.source_report[0].status, 'in_rule')
        self.assertEqual(res.source_report[0].existing_name, 'N')

    def test_top2_that_su_con_thieu_van_giu_nguyen_add(self):
        objs = {'S': _host('S', '10.9.9.9'), 'R': _rng('R', '10.1.1.100', '10.1.1.110')}
        rules = [_rule(1, 'R-other', ['S'], ['DSTH'])]
        res = _classify(objs, {}, rules, '10.1.1.100-10.1.1.110')
        self.assertEqual(res.tier, 'TOP2')
        self.assertFalse(res.wide_fully_covered)
        self.assertEqual(_compute_action_level(res), 'add')
        self.assertEqual(res.source_report[0].status, 'exists')
        self.assertEqual(res.source_report[0].existing_name, 'R')

    def test_build_field_report_van_giu_exact_only(self):
        """Buoc hau xu ly _mark_side_fully_covered() chi chay o classify_row - ban
        than build_field_report() KHONG duoc noi long exact-only (bao ve test
        test_wide_only_group_not_in_rule_local da co)."""
        objs = {'N': _wide('N', '10.0.0.0/8')}
        grps = {'G_WIDE': AddressGroup('G_WIDE', members=['N'])}
        gr = GroupResolver(objs, grps)
        cfg = {'address_objects': objs, 'address_groups': grps,
               'service_objects': {}, 'service_groups': {}, 'rules': []}
        idx = build_device_index(cfg, gr, ServiceResolver({}, {}))
        rules = [_rule(1, 'R', ['G_WIDE'], ['DSTH'])]
        ris = build_rule_infos(rules, gr, ServiceResolver({}, {}))
        t = parse_ip_token('10.0.0.0-10.0.0.9')
        rep = build_field_report([(t['start'], t['end'], t)],
                                 ris[0].source_members, idx, wide=True)
        self.assertNotEqual(rep[0].status, 'in_rule')


# ---------------------------------------------------------------------------
# CHECK IP (tab #2) - o "Danh sach IP can tim"
# ---------------------------------------------------------------------------

class TestCheckIpRangeInput(unittest.TestCase):
    def test_range_co_khoang_trang_khong_con_mat_ip_o_giua(self):
        valid, invalid = parse_ip_list_input('10.100.10.102 - 10.100.10.105')
        self.assertEqual(valid, ['10.100.10.102', '10.100.10.103',
                                 '10.100.10.104', '10.100.10.105'])
        self.assertEqual(invalid, [])

    def test_cac_dinh_dang_range_khac(self):
        for text in ('10.100.10.102-10.100.10.105',
                     '10.100.10.102–10.100.10.105',
                     '10.100.10.102-105',
                     '10.100.10.102 to 10.100.10.105',
                     '10.100.10.102..10.100.10.105'):
            valid, invalid = parse_ip_list_input(text)
            self.assertEqual(len(valid), 4, text)
            self.assertEqual(invalid, [], text)

    def test_khong_gom_2_ip_o_2_dong_khac_nhau(self):
        valid, invalid = parse_ip_list_input('10.1.1.1\n10.1.1.2')
        self.assertEqual(valid, ['10.1.1.1', '10.1.1.2'])
        self.assertEqual(invalid, [])

    def test_ip_don_va_token_rac_giu_nguyen_hanh_vi(self):
        valid, invalid = parse_ip_list_input('10.1.1.1, abc, 10.1.1.1')
        self.assertEqual(valid, ['10.1.1.1'])   # tu loai trung
        self.assertEqual(invalid, ['abc'])


if __name__ == '__main__':
    unittest.main()
