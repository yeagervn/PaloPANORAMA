# -*- coding: utf-8 -*-
"""
check_ip_pan - Tool "CHECK IP" bản PANORAMA: tra cuu Security Rule / NAT Rule
tren PAN-OS có liên quan tới 1 danh sách IP cụ thể (EXACT-HOST ONLY), doi chieu
File Log, xuat Excel/CSV rich-text.

Khac biet so voi bản Firewall đơn (check_ip/):
  - Ket noi toi Panorama IP thay vi Firewall; dropdown "Device Group" (0.8) thay
    cho "VSYS"; o "Target Firewall (Serial)" tuy chon (0.5/0.7).
  - Pham vi tim kiem = Shared + Device Group dang chon (ca pre lan post-rulebase),
    lap rap theo 6 buoc 0.3 thay vi 1 vsys.
  - Object nap theo 0.2 (Shared truoc, DG xa->gan, DG gan hon DE khi trung ten).
  - Output Security Rule them cot "Vi tri Rule", NAT export them cot "Nguon Rule".

Package nay HOAN TOAN DOC LAP voi check_rule_pan/ (khong import lan nhau, khong
dung chung bien toan cuc/OUTPUT_DIR/log). Khi sua tinh nang cua check_ip_pan,
CHI can sua file trong thu muc nay - khong anh huong cac tool khac.
"""
