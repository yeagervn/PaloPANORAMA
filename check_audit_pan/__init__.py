# -*- coding: utf-8 -*-
"""
check_audit_pan - Tool "CHECK AUDIT" ban PANORAMA: ra soat "ve sinh chinh sach"
(policy hygiene) tren rulebase Security cua Shared + Device Group da chon (pre +
post, lap rap theo 6 buoc 0.3), voi 3 tinh nang DOC LAP: Shadow Rules, Disabled
Rules, Overly Permissive Rules. Dinh nghia day du: panoramaAIO.md PHAN IV.

Khac biet so voi ban Firewall goc (check_audit/):
  - Ket noi Panorama IP + Device Group (thay VSYS).
  - Object override theo chuoi thua ke 0.2 (Shared la lop goc, DG gan hon de len).
  - Rulebase lap rap theo 6 buoc 0.3, index gan lai tang dan.
  - Export 15 cot them "Vi tri Rule" (Shared-PRE/<DG>-PRE/<DG>-POST/Shared-POST).
  - Import roi de xoa rule tren Candidate Config cua Panorama (khong commit/khong push).

Package nay HOAN TOAN DOC LAP voi check_rule/check_ip/check_ip_pan/check_rule_pan
(khong import lan nhau, OUTPUT_DIR = .../output/check_audit_pan/).
"""

APP_NAME = "CheckAuditPan"
