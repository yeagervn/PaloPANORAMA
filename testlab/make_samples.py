#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_samples.py - Sinh cac file INPUT MAU cho testlab (chay 1 lan, hoac chay lai
bat ky luc nao - ket qua luon giong nhau).

Sinh ra trong testlab/samples/:
  request_check_rule.xlsx  - file Request cho tab CHECK RULE (moi dong 1 tier khac nhau)
  request_check_rule.csv   - ban CSV cua cung noi dung (de test nhanh doc CSV)
  ip_list.txt              - danh sach IP/range de PASTE vao tab CHECK IP (muc 2)
  traffic_log.xlsx         - File Log doi chieu cho tab CHECK IP (muc 3)
"""

import os
import openpyxl

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "samples")

# (Source, Dest, Port, Ghi chu - ky vong)
REQUEST_ROWS = [
    ("10.10.10.11", "192.168.50.21", "1433",
     "TOP1 - FULL MATCH (H01, DG-HN-PRE) - object HOST-DB-01 THUA KE tu DG-DC"),
    ("10.10.10.11,10.10.10.12,10.10.10.13", "192.168.50.80", "8080",
     "TOP1.1 - Source+Dest khop khit, THIEU port -> + ADD PORT (H02)"),
    ("10.10.10.99", "192.168.50.80", "443",
     "TOP2 - Dest khop khit + port du, Source thieu -> + ADD SOURCE"),
    ("10.10.10.100-10.10.10.110", "192.168.50.99", "1521",
     "TOP3 - Source (RANGE-WORKER cua DG-DC) khop khit, Dest thieu -> + ADD DEST"),
    ("10.10.10.100-10.10.10.110", "192.168.50.21", "1521",
     "TOP1 qua ip-range object THUA KE tu DG cha (D01, DG-DC-PRE)"),
    ("10.10.10.100-110", "192.168.50.21", "1521",
     "NHU TREN nhung viet RUT GON octet cuoi - phai doc duoc"),
    ("10.10.10.100 \u2013 10.10.10.110", "192.168.50.21", "1521",
     "NHU TREN nhung dung EN-DASH (Excel tu doi) - phai doc duoc"),
    ("10.10.10.200-10.10.10.210", "192.168.50.22", "1521",
     "TOP1 - range phu kin boi HOP 2 object (RANGE-A + RANGE-B)"),
    ("10.1.2.3", "172.20.0.50", "9092",
     "wide_full_match - cover qua subnet rong cua DG-ALL -> 'DA DUOC CHO PHEP'"),
    ("172.20.0.77", "192.168.50.21", "514",
     "THIEU ZONE - can Target Firewall de lay Template (0.6); khong co Target thi tat"),
    ("10.66.66.50", "192.168.50.21", "1433",
     "SHADOW - khop H03 (DG-HN-PRE) nhung bi S00 (Shared-PRE deny) chan truoc"),
    ("10.10.10.1", "10.10.10.250", "443",
     "SAME_SUBNET - cung /24, khong qua firewall"),
    ("10.10.10.77", "192.168.50.21", "1433",
     "CANDIDATE CONFIG - rule H99 dang cho commit vao Panorama (xanh ngoc)"),
    ("10.99.99.99", "192.168.50.99", "7777",
     "TOP4 - chua co gi -> can tao Rule moi (do)"),
    ("10.10.10.11, KHONG-PHAI-IP", "192.168.50.21", "1433",
     "TOKEN RAC - phai hien 'KHONG DOC DUOC', khong duoc nuot im lang"),
    # P2: nam trong dai bi S00-BLOCK-BADNET (Shared-PRE) deny VA khong co rule
    # allow nao khop -> ket luan phai la "KHONG THE cap phep tu Device Group nay",
    # vi thu tu lap rap 0.3 khong cho rule nao cua DG dung truoc Shared-PRE.
    ("10.66.66.88", "192.168.99.99", "6666",
     "P2 - deny o SHARED-PRE: khong the cap phep tu DG, phai sua Shared-PRE"),
    # B1: nguon tu internet, rule doi zone trust -> phai chan duoc
    ("203.0.113.77", "192.168.50.91", "443",
     "B1 - nguon internet: default route cho ra untrust, rule doi trust -> PHAI chan"),
    # B3: rule deny chan cap nay co service la group KHONG resolve duoc
    ("10.10.88.11", "192.168.88.21", "9443",
     "B3 - deny co service khong resolve duoc: PHAI van canh bao bi chan truoc"),
    # B4: deny o SHARED-POST -> ket luan NGUOC DAU voi P2: them rule vao DG la
    # giai phap hop le, KHONG can sua Shared
    ("10.10.44.11", "192.168.44.21", "7443",
     "B4 - deny o SHARED-POST: them rule vao DG la giai quyet duoc"),
]

# LUU Y: o "Danh sach IP can tim" chi nhan IP/range - KHONG co dong ghi chu,
# vi moi token khong phai IP se bi bao la dong khong hop le (dung nhu thiet ke).
IP_LIST = """10.10.10.11
10.10.10.12
192.168.50.21
10.10.10.100-10.10.10.104
10.10.10.200 - 10.10.10.202
192.168.50.80
"""

# File Log doi chieu: (Source IP, Dest IP, Port)
LOG_ROWS = [
    ("10.10.10.11", "192.168.50.21", "1433"),
    ("10.10.10.12", "192.168.50.21", "1433"),
    ("10.10.10.11", "192.168.50.80", "443"),
    ("10.10.10.101", "192.168.50.22", "1521"),
    ("192.168.50.21", "8.8.8.8", "53"),
]


def main():
    os.makedirs(OUT, exist_ok=True)

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Request"
    ws.append(["Source IP", "Dest IP", "Port", "Ghi chu (ky vong)"])
    for r in REQUEST_ROWS:
        ws.append(list(r))
    for col, w in zip("ABCD", (34, 18, 10, 62)):
        ws.column_dimensions[col].width = w
    p1 = os.path.join(OUT, "request_check_rule.xlsx")
    wb.save(p1)

    import csv
    p2 = os.path.join(OUT, "request_check_rule.csv")
    with open(p2, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Source IP", "Dest IP", "Port", "Ghi chu (ky vong)"])
        w.writerows(REQUEST_ROWS)

    p3 = os.path.join(OUT, "ip_list.txt")
    with open(p3, "w", encoding="utf-8") as f:
        f.write(IP_LIST)

    wb2 = openpyxl.Workbook()
    ws2 = wb2.active
    ws2.title = "Log"
    ws2.append(["Source IP", "Dest IP", "Port"])
    for r in LOG_ROWS:
        ws2.append(list(r))
    p4 = os.path.join(OUT, "traffic_log.xlsx")
    wb2.save(p4)

    for p in (p1, p2, p3, p4):
        print(f"  OK  {p}")


if __name__ == "__main__":
    main()
