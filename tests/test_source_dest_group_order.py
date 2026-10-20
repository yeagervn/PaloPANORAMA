# -*- coding: utf-8 -*-
"""Test gom nhom/sap xep Source-Dest khi input lon xon (FIX 09/2026).
Case A/B lay tu prompt, dung DeviceIndex/ResolvedAddr gia lap."""
import ipaddress
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from check_rule_pan.exporter import _build_field_lines, _format_add_line
from check_rule_pan.index import DeviceIndex
from check_rule_pan.matcher import (RowResult, build_field_report,
                                build_live_match_field_report)
from check_rule_pan.request import RequestRow
from check_rule_pan.resolver import ResolvedAddr


def _ip(s):
    return int(ipaddress.IPv4Address(s))


def _ra(ip_strs):
    r = ResolvedAddr()
    for s in ip_strs:
        r.exact_singles.add(_ip(s))
    return r


def _ranges(strs):
    return [(_ip(s), _ip(s), {'display': s}) for s in strs]


def _text(blocks):
    return "".join(b.text for b in blocks)


def _fake_res(src_report, dst_report=None):
    row = RequestRow(row_number=1, source_tokens=[], dest_tokens=[],
                     port_tokens=[], extra_values=[],
                     raw_source='', raw_dest='', raw_port='')
    return RowResult(row=row, tier='TOP4', rule=None,
                     source_report=src_report,
                     dest_report=dst_report or [])


def _build_idx(mapping):
    idx = DeviceIndex()
    for g, lst in mapping.items():
        idx.group_resolved[g] = _ra(lst)
        idx.group_member_count[g] = len(lst)
    return idx


CASE_B = {
    'CoreLao-WAS-LaxeXang': ['10.0.121.174', '10.0.121.175', '10.0.121.176',
                             '10.4.121.174', '10.4.121.175', '10.4.121.176'],
    'K8S-Lao-Xpress': ['10.0.121.101', '10.0.121.102',
                       '10.4.121.101', '10.4.121.102'],
    'TP-Form-GR': ['10.0.121.130', '10.4.121.130'],
}
ORDER_B = ['10.4.121.102', '10.0.121.130', '10.0.121.101', '10.4.121.176',
           '10.4.121.175', '10.4.121.174', '10.0.121.176', '10.0.121.175',
           '10.0.121.174', '10.0.121.102', '10.4.121.101', '10.4.121.130']


def test_case_b_grouped_and_sorted():
    idx = _build_idx(CASE_B)
    rep = build_field_report(_ranges(ORDER_B), [], idx, wide=True)
    assert len(rep) == 12 and all(m.status == 'exists' for m in rep)
    txt = _text(_build_field_lines(rep))
    for g, lst in CASE_B.items():
        expect = "cover: " + ", ".join(sorted(lst, key=_ip))
        assert g in txt, txt
        assert expect in txt, txt
    # bullet group sap theo IP nho nhat: K8S (.101) < TP (.130) < Core (.174)
    assert txt.index('K8S-Lao-Xpress') < txt.index('TP-Form-GR') < txt.index('CoreLao-WAS-LaxeXang')


def test_case_b_permutation_stable():
    idx = _build_idx(CASE_B)
    base = sorted((m.display, m.status, m.existing_name)
                  for m in build_field_report(_ranges(ORDER_B), [], idx, wide=True))
    base_txt = _text(_build_field_lines(
        build_field_report(_ranges(ORDER_B), [], idx, wide=True)))
    for seed in range(5):
        sh = ORDER_B[:]
        random.Random(seed).shuffle(sh)
        rep = build_field_report(_ranges(sh), [], idx, wide=True)
        assert sorted((m.display, m.status, m.existing_name) for m in rep) == base
        assert _text(_build_field_lines(rep)) == base_txt


def test_case_a_mixed_with_new():
    ips = ['10.3.16.108', '10.3.66.132', '10.4.124.109', '10.4.124.110',
           '10.4.124.111', '10.7.16.108', '10.7.66.132']
    idx = DeviceIndex()
    for i, s in enumerate(ips):
        if s == '10.4.124.110':
            continue
        idx.group_resolved[f'G{i}'] = _ra([s])
        idx.group_member_count[f'G{i}'] = 1
    rep = build_field_report(_ranges(ips), [], idx, wide=True)
    by_ip = {m.display: m for m in rep}
    assert by_ip['10.4.124.110'].status == 'new'
    assert all(by_ip[s].status == 'exists' for s in ips if s != '10.4.124.110')
    txt = _text(_build_field_lines(rep))
    # moi group exists van kem chi tiet IP, IP new van hien TAO MOI
    assert '10.4.124.110' in txt and 'TAO MOI' in txt
    # hoan vi van on dinh
    base = sorted((m.display, m.status, m.existing_name) for m in rep)
    for seed in range(3):
        sh = ips[:]
        random.Random(100 + seed).shuffle(sh)
        rep2 = build_field_report(_ranges(sh), [], idx, wide=True)
        assert sorted((m.display, m.status, m.existing_name) for m in rep2) == base


def test_mixed_in_rule_still_shows_ips():
    r = _ra(['10.0.0.1', '10.0.0.2'])
    idx = DeviceIndex()
    idx.group_resolved['GRP-IN'] = r
    idx.group_member_count['GRP-IN'] = 1
    rep = build_field_report(
        _ranges(['10.0.0.2', '10.0.0.1', '10.0.0.99']),
        [('GRP-IN', 'group', r)], idx, wide=True)
    txt = _text(_build_field_lines(rep))
    assert 'GRP-IN' in txt and '10.0.0.1' in txt and '10.0.0.2' in txt
    assert 'TAO MOI' in txt


def test_cover_full_kept():
    r = _ra(['10.0.0.1', '10.0.0.2'])
    idx = DeviceIndex()
    idx.group_resolved['GRP-IN'] = r
    idx.group_member_count['GRP-IN'] = 1
    rep = build_field_report(_ranges(['10.0.0.2', '10.0.0.1']),
                             [('GRP-IN', 'group', r)], idx, wide=True)
    txt = _text(_build_field_lines(rep))
    assert 'cover full IP(s)' in txt


def test_display_sorts_explicitly_despite_unsorted_input():
    # Dua thang 1 report CHUA sort vao exporter -> van phai in ra da sort.
    from check_rule_pan.matcher import MissingItem
    items = [MissingItem(_ip('10.0.0.3'), '10.0.0.3', 'exists', 'G', 'group',
                         group_coverage_pct=50),
             MissingItem(_ip('10.0.0.1'), '10.0.0.1', 'exists', 'G', 'group',
                         group_coverage_pct=50),
             MissingItem(_ip('10.0.0.2'), '10.0.0.2', 'exists', 'G', 'group',
                         group_coverage_pct=50)]
    txt = _text(_build_field_lines(items))
    assert txt.index('10.0.0.1') < txt.index('10.0.0.2') < txt.index('10.0.0.3')
    rr = _fake_res(list(reversed(items)))
    line = _format_add_line('ADD SOURCE', rr)
    assert line == 'ADD SOURCE: 10.0.0.1, 10.0.0.2, 10.0.0.3', line


def test_live_match_path_grouped_sorted():
    idx = _build_idx(CASE_B)
    rep = build_live_match_field_report(_ranges(ORDER_B), [], idx)
    txt = _text(_build_field_lines(rep))
    for g, lst in CASE_B.items():
        assert g in txt
    # ADD line sort tang dan
    rr = _fake_res(rep)
    line = _format_add_line('ADD SOURCE', rr)
    ips = [p.strip() for p in line.split(': ', 1)[1].split(',')]
    assert ips == sorted(ips, key=_ip), line


# --- Quy tac cot loi muc 2b: gom cum theo MEMBERSHIP that, khong theo octet ---

def test_2b_same_subnet_cluster_single_group_wins():
    """Cum 3 IP lien tuc cung /24, co 1 group cover tron 3 IP -> ca 3 ve
    DUNG 1 group duy nhat (khong tach vun), ke ca khi input lon xon."""
    ips = ['10.4.121.176', '10.4.121.174', '10.4.121.175']  # co tinh lon xon
    idx = _build_idx({'SUBNET-GR': ['10.4.121.174', '10.4.121.175', '10.4.121.176']})
    rep = build_field_report(_ranges(ips), [], idx, wide=True)
    assert len(rep) == 3
    assert {m.existing_name for m in rep} == {'SUBNET-GR'}
    assert all(m.status == 'exists' for m in rep)
    txt = _text(_build_field_lines(rep))
    assert 'cover full IP(s)' in txt  # group cover tron 100% input
    # hoan vi van on dinh
    base = sorted((m.display, m.status, m.existing_name) for m in rep)
    sh = ips[:]
    random.Random(7).shuffle(sh)
    rep2 = build_field_report(_ranges(sh), [], idx, wide=True)
    assert sorted((m.display, m.status, m.existing_name) for m in rep2) == base


def test_2b_membership_wins_over_shape_no_octet_merge():
    """Cum 3 IP lien tuc cung /24 NHUNG thiet bi chia lam 2 group khac nhau ->
    ket qua PHAI tach theo membership that, KHONG duoc gom thanh 1 cum theo
    hinh dang octet/range (chong chi dinh muc 2b: cam tien xu ly cluster)."""
    ips = ['10.4.121.176', '10.4.121.174', '10.4.121.175']
    idx = _build_idx({'GR-A': ['10.4.121.174', '10.4.121.175'],
                      'GR-B': ['10.4.121.176']})
    rep = build_field_report(_ranges(ips), [], idx, wide=True)
    by_ip = {m.display: m.existing_name for m in rep}
    assert by_ip['10.4.121.174'] == 'GR-A'
    assert by_ip['10.4.121.175'] == 'GR-A'
    assert by_ip['10.4.121.176'] == 'GR-B'
    txt = _text(_build_field_lines(rep))
    assert 'GR-A' in txt and 'GR-B' in txt


def test_2b_cross_subnet_group_not_split_by_octet():
    """Group cover 6 IP xuyen 2 subnet /24 khac nhau (cum CoreLao Case B) ->
    van gom thanh 1 bullet duy nhat, khong bi che theo octet."""
    idx = _build_idx(CASE_B)
    sub = CASE_B['CoreLao-WAS-LaxeXang']
    rep = build_field_report(_ranges(list(reversed(sub))), [], idx, wide=True)
    assert {m.existing_name for m in rep} == {'CoreLao-WAS-LaxeXang'}
    assert sorted(m.display for m in rep) == sorted(sub, key=_ip)
    txt = _text(_build_field_lines(rep))
    # group cover tron 100% input rieng nay -> giu rut gon theo spec muc 5.2
    assert 'cover full IP(s)' in txt, txt


def test_2b_dest_side_cluster():
    """Quy tac 2b ap dung cho CA Source LAN Dest (build_field_report khong
    phan biet side) - cum Dest cung /24 ve dung 1 group."""
    ips = ['10.0.5.3', '10.0.5.1', '10.0.5.2']
    idx = _build_idx({'DEST-GR': ['10.0.5.1', '10.0.5.2', '10.0.5.3']})
    rep = build_field_report(_ranges(ips), [], idx, wide=True)
    assert {m.existing_name for m in rep} == {'DEST-GR'}
    rr = _fake_res([], rep)
    line = _format_add_line('ADD DEST', rr)
    assert line == 'ADD DEST: 10.0.5.1, 10.0.5.2, 10.0.5.3', line
