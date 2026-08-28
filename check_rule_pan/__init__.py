# -*- coding: utf-8 -*-
"""
check_rule_pan - Tool "CHECK RULE" cho PANORAMA (ban chuyen doi tu check_rule firewall
standalone). Giu nguyen 100% luat nghiep vu cua ban goc (thu tu tier, exact-scope,
3 quy tac loai rule qua rong, TOP4 3 tang, shadow-check, candidate overlay, format
Excel/rich-text) - chi thay doi lop ha tang lay du lieu theo PHAN 0 cua panoramaAIO.md:
  - Ket noi toi Panorama IP (khong phai Management IP firewall)
  - Device Group (thay VSYS) voi chuoi thua ke Shared -> DG cha -> DG con (0.2)
  - Rulebase lap rap theo dung 6 buoc PAN-OS danh gia (Shared-PRE -> DG-PRE -> DG-POST
    -> Shared-POST) (0.3)
  - Live Match bat buoc target=<serial firewall>, tu vo hieu im lang neu thieu (0.5)
  - Zone awareness lay tu Template cua Target Firewall, tu vo hieu neu thieu (0.6)

Package nay HOAN TOAN DOC LAP voi check_rule/ / check_ip/ / check_audit/ / *_pan/ -
khong import lan nhau, output/log rieng.
"""
