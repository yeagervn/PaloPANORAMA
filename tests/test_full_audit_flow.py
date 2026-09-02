# -*- coding: utf-8 -*-
"""
Test end-to-end flow audit_pan: detectors -> export -> import -> action classification
Kết quả lưu vào tests/output_for_review
"""
import os, sys, shutil, tempfile, datetime
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from check_audit_pan.core import Finding, RuleSnapshot, ServiceObject
from check_audit_pan.detectors import find_shadow_rules, find_disabled_rules, find_overly_permissive_rules
from check_audit_pan.excel_io import export_findings, parse_import_file, HEADERS
from check_audit_pan.pan_api import PanApiClient
from check_audit_pan.resolver import GroupResolver, ServiceResolver, ResolvedAddr, ResolvedService
import ipaddress

def ip_int(ip): return int(ipaddress.ip_address(ip))

out_dir = os.path.join(os.path.dirname(__file__), "output_for_review")
os.makedirs(out_dir, exist_ok=True)
# clean old
for f in os.listdir(out_dir):
    try: os.remove(os.path.join(out_dir, f))
    except: pass

log_path = os.path.join(os.path.dirname(__file__), "test_full_flow_result.txt")
log_lines=[]
import io
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except Exception:
    pass

def log(msg):
    try:
        print(msg)
    except Exception:
        print(msg.encode('ascii','ignore').decode())
    log_lines.append(msg)

log("=== FULL AUDIT FLOW TEST ===")
log(f"HEADERS={HEADERS} len={len(HEADERS)}")

# 1. Build mock rules: R1 broad, R2 shadow hit0, R3 disabled, R4 overly any
from check_audit_pan.core import AddressObject, AddressGroup, ServiceObject, ServiceGroup
# need resolver for shadow check
# Create synthetic rules with resolved via detectors mock

# Rule creation
rules=[]
# R1 broad allow any (will shadow R2)
r1 = RuleSnapshot(index=0, name="R1-BROAD-ALLOW", uuid="u1", from_zones=["any"], to_zones=["any"], source=["any"], destination=["any"], service=["any"], action="allow", disabled=False, vi_tri="Shared-PRE", rulebase="pre")
r1.resolved_source = ResolvedAddr(is_any=True)
r1.resolved_destination = ResolvedAddr(is_any=True)
r1.resolved_service = ResolvedService(is_any=True)
rules.append(r1)
# R2 shadow host hit 0
r2 = RuleSnapshot(index=1, name="R2-SHADOW-HIT0", uuid="u2", from_zones=["any"], to_zones=["any"], source=["10.0.0.5"], destination=["10.0.0.6"], service=["TCP_1521"], action="allow", disabled=False, vi_tri="DG1-PRE", rulebase="pre")
r2.resolved_source = ResolvedAddr(ranges=[(ip_int("10.0.0.5"), ip_int("10.0.0.5"))])
r2.resolved_destination = ResolvedAddr(ranges=[(ip_int("10.0.0.6"), ip_int("10.0.0.6"))])
r2.resolved_service = ResolvedService(ports=[("tcp",1521,1521)])
rules.append(r2)
# R3 disabled
r3 = RuleSnapshot(index=2, name="R3-DISABLED", uuid="u3", from_zones=["any"], to_zones=["any"], source=["10.1.0.1"], destination=["10.1.0.2"], service=["TCP_80"], action="deny", disabled=True, vi_tri="DG1-PRE", rulebase="pre")
r3.resolved_source = ResolvedAddr(ranges=[(ip_int("10.1.0.1"), ip_int("10.1.0.1"))])
r3.resolved_destination = ResolvedAddr(ranges=[(ip_int("10.1.0.2"), ip_int("10.1.0.2"))])
r3.resolved_service = ResolvedService(ports=[("tcp",80,80)])
rules.append(r3)
# R4 overly any-any-any
r4 = RuleSnapshot(index=3, name="R4-OVERLY-ANY", uuid="u4", from_zones=["any"], to_zones=["any"], source=["any"], destination=["any"], service=["any"], action="allow", disabled=False, vi_tri="DG1-PRE", rulebase="pre")
r4.resolved_source = ResolvedAddr(is_any=True)
r4.resolved_destination = ResolvedAddr(is_any=True)
r4.resolved_service = ResolvedService(is_any=True)
rules.append(r4)

# detectors - SỬA 2026-09-02: hit_stats khoá (name, vi_tri)
shadow_hits = {
    ("R2-SHADOW-HIT0", "DG1-PRE"): __import__('check_audit_pan.core', fromlist=['RuleHitStat']).RuleHitStat(0, None, datetime.datetime.now() - datetime.timedelta(days=45))
}
shadow_findings = find_shadow_rules(rules, None, None, shadow_hits, datetime.datetime.now())
disabled_findings = find_disabled_rules(rules)
overly_findings = find_overly_permissive_rules(rules)
log(f"Shadow findings: {len(shadow_findings)} {[f.rule_name for f in shadow_findings]}")
log(f"Disabled findings: {len(disabled_findings)} {[f.rule_name for f in disabled_findings]}")
log(f"Overly findings: {len(overly_findings)} {[f.rule_name for f in overly_findings]}")

# Need to assign vi_tri from rule index
for f in shadow_findings+disabled_findings+overly_findings:
    if 0 <= f.rule_index < len(rules):
        f.vi_tri = rules[f.rule_index].vi_tri

# Build service_info for export
svc_objs = {"TCP_1521": ServiceObject("TCP_1521","tcp","1521"), "TCP_80": ServiceObject("TCP_80","tcp","80")}
from check_audit_pan.core import build_service_info
svc_info = build_service_info(svc_objs, {})

all_findings = shadow_findings + disabled_findings + overly_findings
log(f"Total findings: {len(all_findings)}")

# Export
export_path = export_findings(all_findings, out_dir, fmt="xlsx", service_info=svc_info, types=["shadow","disabled","overly_permissive"])
log(f"Exported: {export_path}")
# also csv
csv_path = export_findings(all_findings, out_dir, fmt="csv", service_info=svc_info, types=["shadow","disabled","overly_permissive"])
log(f"Exported CSV: {csv_path}")

# Parse back
rows = parse_import_file(export_path, log_func=log)
log(f"Parse rows count: {len(rows)}")
for r in rows:
    log(f"  row: {r}")

# Simulate GUI classification
candidates=[]
skipped=0
for row in rows:
    name, loai, vi_tri, hit_raw = row
    if loai=="Overly Permissive Rules":
        skipped+=1
        log(f"  -> Skip Overly {name}")
        continue
    if loai not in ("Shadow Rules","Disabled Rules"):
        continue
    action = "delete" if loai=="Disabled Rules" else "disable"
    candidates.append((name, loai, vi_tri, hit_raw, action))
    log(f"  -> Candidate {name} [{loai}] hit={hit_raw} => {action}")

log(f"Candidates: {len(candidates)} skipped overly={skipped}")
# Assert expectations
assert any(c[0]=="R2-SHADOW-HIT0" and c[4]=="disable" for c in candidates), "R2 should be disable"
assert any(c[0]=="R3-DISABLED" and c[4]=="delete" for c in candidates), "R3 should be delete"
assert skipped==len([f for f in overly_findings]), "overly should be skipped"
log("GUI logic OK: shadow->disable, disabled->delete, overly skipped")

# Test pan_api fake disable/delete
import xml.etree.ElementTree as ET
class Fake(PanApiClient):
    def __init__(self):
        super().__init__("1.1.1.1","key")
        self.calls=[]
    def _request(self, params):
        self.calls.append(dict(params))
        return ET.fromstring(b'<response status="success"/>')
fake=Fake()
for name, loai, vi_tri, hit_raw, action in candidates:
    dg, rb = ("DG1","pre") if "DG1" in vi_tri else ("","shared-pre")
    if action=="disable":
        fake.disable_rule_candidate(dg, rb, name)
        log(f"  FAKE disable {name} -> {fake.calls[-1]['xpath']}")
    else:
        fake.delete_rule_candidate(dg, rb, name)
        log(f"  FAKE delete {name} -> {fake.calls[-1]['xpath']}")
log(f"API calls: {len(fake.calls)} actions: {[c['action'] for c in fake.calls]}")
assert fake.calls[0]["action"]=="set", "first should be disable set"
assert "delete" in [c["action"] for c in fake.calls], "should have at least one delete"
assert "set" in [c["action"] for c in fake.calls], "should have at least one set"
log("API disable/delete OK")

# Check no commit
for call in fake.calls:
    assert "commit" not in call.get("type","")
    assert "commit" not in call.get("action","")
log("No commit verified")

# Save log to file
with open(log_path,"w",encoding="utf-8") as fh:
    fh.write("\n".join(log_lines))
log(f"Log saved to {log_path}")
log(f"Excel outputs in {out_dir}: {os.listdir(out_dir)}")
log("=== TEST PASSED ===")
