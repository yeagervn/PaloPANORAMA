#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
mock_panorama_api.py - PANORAMA GIA LAP cho testlab.

Dung de chay THU TOAN BO tinh nang cua ban PANORAMA (ca 3 tab, ca GUI that) ma
KHONG can Panorama that. Server noi dung XML API ma tool dang goi, KEM cac lenh
rieng cua Panorama (devicegroups / devices / target=<serial>):

  type=config action=show                 -> running-config (fixtures/running_config.xml)
  type=config action=get  xpath=/config   -> candidate-config (fixtures/candidate_config.xml)
  type=config action=get  xpath=<cu the>  -> cat dung nhanh do ra tra ve
  type=config action=delete|edit|set      -> GHI NHAT KY, khong sua file, tra success
  type=op  <show><system><info>           -> hostname
  type=op  test security-policy-match     -> MO PHONG danh gia rulebase that
  type=op  <show><rule-hit-count>         -> hit-count gia lap (co rule 0 hit)
  type=op  <show><object><registered-ip>  -> tag cho Dynamic Address Group
  type=op  <show><devicegroups/>          -> danh sach Device Group
  type=op  <show><devices><all/>          -> danh sach firewall + serial
  (moi lenh op chay tren dataplane - policy-match, rule-hit-count - server KIEM
   TRA co tham so `target=<serial>` hay khong: thieu -> tra LOI dung nhu Panorama
   that, de kiem chung luat 0.5/0.7 "bat buoc Target Firewall")

NGUYEN TAC: server CHI DOC file fixture. Moi lenh ghi (delete/edit/set) chi duoc
ghi vao nhat ky `testlab/.journal.log` + tra ve success - KHONG BAO GIO sua
fixture, de chay lai bao nhieu lan cung ra ket qua giong nhau.

CHAY:
    python testlab/mock_panorama_api.py
roi nhap vao GUI:  Panorama IP = 127.0.0.1:8443  |  API Key = bat ky
                   Device Group = DG-HN          |  Target = 001122334455

Tham so: --port 8443  --host 127.0.0.1  --config <file>  --candidate <file>
"""

import argparse
import datetime
import ipaddress
import os
import re
import ssl
import sys
import threading
import urllib.parse
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_RUNNING = os.path.join(HERE, "fixtures", "running_config.xml")
DEFAULT_CANDIDATE = os.path.join(HERE, "fixtures", "candidate_config.xml")
CERT_DIR = os.path.join(HERE, ".certs")
JOURNAL = os.path.join(HERE, ".journal.log")

STATE = {"running": None, "candidate": None, "quiet": False}


def log(msg):
    if not STATE["quiet"]:
        print(f"  [mock] {msg}", flush=True)


def journal(msg):
    with open(JOURNAL, "a", encoding="utf-8") as f:
        f.write(f"{datetime.datetime.now():%Y-%m-%d %H:%M:%S}  {msg}\n")


# ---------------------------------------------------------------- TLS
def ensure_cert():
    """Sinh cert self-signed cho localhost (1 lan, vao testlab/.certs/ - da gitignore).
    Tool luon goi https:// va dung verify=False nen cert tu ky la du."""
    os.makedirs(CERT_DIR, exist_ok=True)
    crt = os.path.join(CERT_DIR, "mock.crt")
    key = os.path.join(CERT_DIR, "mock.key")
    if os.path.exists(crt) and os.path.exists(key):
        return crt, key
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
    except ImportError:
        sys.exit("Thieu thu vien 'cryptography' de sinh cert. Cai: pip install cryptography\n"
                 "(hoac dung --no-tls de chay HTTP, nhung tool luon goi https:// nen se KHONG ket noi duoc)")
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mock-panos-testlab")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name).public_key(k.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(k, hashes.SHA256()))
    with open(key, "wb") as f:
        f.write(k.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()))
    with open(crt, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    log(f"da sinh cert self-signed moi: {crt}")
    return crt, key


# ---------------------------------------------------------------- helpers
def ok(payload_xml: str) -> bytes:
    return f"<response status=\"success\" code=\"19\"><result>{payload_xml}</result></response>".encode()


def err(msg: str) -> bytes:
    return (f"<response status=\"error\" code=\"12\"><msg><line>{msg}</line></msg>"
            f"</response>").encode()


_XPATH_STEP = re.compile(r"([A-Za-z0-9_.-]+)(?:\[@name=(?:'([^']*)'|\"([^\"]*)\")\])?")


def resolve_xpath(root: ET.Element, xpath: str):
    """Doc 1 nhanh theo xpath kieu PAN-OS (`/config/devices/entry[@name='x']/...`).
    Ho tro dung 2 thu tool can: ten the + vi tu [@name='...']."""
    parts = [p for p in xpath.strip().strip("/").split("/") if p]
    if not parts:
        return None
    if parts[0] == root.tag:
        parts = parts[1:]
    cur = [root]
    for part in parts:
        m = _XPATH_STEP.fullmatch(part)
        if not m:
            return None
        tag, n1, n2 = m.group(1), m.group(2), m.group(3)
        want = n1 if n1 is not None else n2
        nxt = []
        for el in cur:
            for child in el.findall(tag):
                if want is None or child.get("name") == want:
                    nxt.append(child)
        if not nxt:
            return None
        cur = nxt
    return cur[0]



# ------------------------------------------------- Panorama: pham vi & thu tu
def _object_scopes(cfg_root):
    """Moi container co the chua object: <shared> + MOI <device-group><entry>.
    Mock khong mo phong thua ke theo tung DG (tool tu lam viec do) - o day chi
    can du object de resolve khi mo phong policy-match."""
    out = [cfg_root.find("shared")]
    for dg in cfg_root.iter("device-group"):
        out.extend(dg.findall("entry"))
    return [x for x in out if x is not None]


def _ordered_rules(cfg_root):
    """Lap rap rulebase theo DUNG thu tu PAN-OS danh gia tren Panorama:
       Shared-PRE -> DG-PRE (to tien -> con) -> DG-POST (con -> to tien) -> Shared-POST
    De mo phong policy-match tra ve dung rule ma firewall that se chon."""
    shared = cfg_root.find("shared")
    dgs = []
    for dg in cfg_root.iter("device-group"):
        for e in dg.findall("entry"):
            if e.find("pre-rulebase") is not None or e.find("post-rulebase") is not None:
                dgs.append(e)
    def rules_of(container, rb):
        if container is None:
            return []
        el = container.find(f"{rb}-rulebase/security/rules")
        return list(el.findall("entry")) if el is not None else []
    out = rules_of(shared, "pre")
    for e in dgs:
        out += rules_of(e, "pre")
    for e in reversed(dgs):
        out += rules_of(e, "post")
    out += rules_of(shared, "post")
    return out


# ------------------------------------------------- mo phong Test Policy Match
def _addr_set(cfg_root, names):
    """Resolve 1 danh sach member -> list (start,end). Du dung cho mo phong."""
    objs, groups = {}, {}
    for scope in _object_scopes(cfg_root):
        if scope is None:
            continue
        for e in scope.findall("address/entry"):
            objs[e.get("name")] = e
        for e in scope.findall("address-group/entry"):
            groups[e.get("name")] = e

    out, seen = [], set()

    def walk(nm, depth=0):
        if depth > 10 or nm in seen:
            return
        seen.add(nm)
        if nm == "any":
            out.append((0, 0xFFFFFFFF))
            return
        if nm in groups:
            st = groups[nm].find("static")
            for m in (st.findall("member") if st is not None else []):
                if m.text:
                    walk(m.text.strip(), depth + 1)
            return
        e = objs.get(nm)
        if e is not None:
            nm_el, rg_el = e.find("ip-netmask"), e.find("ip-range")
            try:
                if nm_el is not None and nm_el.text:
                    n = ipaddress.ip_network(nm_el.text.strip(), strict=False)
                    out.append((int(n.network_address), int(n.broadcast_address)))
                elif rg_el is not None and rg_el.text:
                    a, b = rg_el.text.split("-", 1)
                    out.append((int(ipaddress.ip_address(a.strip())),
                                int(ipaddress.ip_address(b.strip()))))
            except Exception:
                pass
            return
        try:  # IP/CIDR go thang trong rule
            n = ipaddress.ip_network(nm, strict=False)
            out.append((int(n.network_address), int(n.broadcast_address)))
        except Exception:
            pass

    for nm in names:
        seen.clear()
        walk(nm)
    return out


def _svc_ports(cfg_root, names):
    objs, groups = {}, {}
    for scope in _object_scopes(cfg_root):
        if scope is None:
            continue
        for e in scope.findall("service/entry"):
            objs[e.get("name")] = e
        for e in scope.findall("service-group/entry"):
            groups[e.get("name")] = e
    out = []

    def walk(nm, depth=0):
        if depth > 10:
            return
        if nm == "any":
            out.append((None, 0, 65535))
            return
        if nm in groups:
            for m in groups[nm].findall("members/member"):
                if m.text:
                    walk(m.text.strip(), depth + 1)
            return
        e = objs.get(nm)
        if e is None:
            return
        for proto in ("tcp", "udp"):
            pel = e.find(f"protocol/{proto}/port")
            if pel is None or not pel.text:
                continue
            for chunk in pel.text.split(","):
                chunk = chunk.strip()
                if "-" in chunk:
                    a, b = chunk.split("-", 1)
                    out.append((proto, int(a), int(b)))
                elif chunk.isdigit():
                    out.append((proto, int(chunk), int(chunk)))

    for nm in names:
        walk(nm)
    return out


def _zone_of(cfg_root, ip_int):
    """Longest-prefix: IP nay thuoc zone nao (theo interface trong config)."""
    best = (None, -1)
    iface_zone = {}
    for z in cfg_root.iter("zone"):
        for ze in z.findall("entry"):
            for m in ze.findall("network/layer3/member"):
                if m.text:
                    iface_zone[m.text.strip()] = ze.get("name")
    for eth in cfg_root.findall(".//network/interface/ethernet/entry"):
        zone = iface_zone.get(eth.get("name"))
        if not zone:
            continue
        for ipe in eth.findall("layer3/ip/entry"):
            try:
                n = ipaddress.ip_network(ipe.get("name"), strict=False)
            except Exception:
                continue
            if int(n.network_address) <= ip_int <= int(n.broadcast_address) and n.prefixlen > best[1]:
                best = (zone, n.prefixlen)
    return best[0]


def simulate_policy_match(cfg_root, src, dst, port, proto_num):
    """Mo phong `test security-policy-match`: duyet rule theo DUNG thu tu XML, bo
    rule disabled, tra ve rule DAU TIEN khop ca zone/source/dest/service."""
    try:
        s_i = int(ipaddress.ip_address(src))
        d_i = int(ipaddress.ip_address(dst))
    except Exception:
        return None
    proto = {6: "tcp", 17: "udp", 1: "icmp"}.get(int(proto_num or 6), "tcp")
    s_zone, d_zone = _zone_of(cfg_root, s_i), _zone_of(cfg_root, d_i)

    def members(entry, tag):
        return [m.text.strip() for m in entry.findall(f"{tag}/member") if m.text]

    for e in _ordered_rules(cfg_root):
        dis = e.find("disabled")
        if dis is not None and (dis.text or "").strip().lower() == "yes":
            continue
        frm, to = members(e, "from") or ["any"], members(e, "to") or ["any"]
        if "any" not in frm and (s_zone is None or s_zone not in frm):
            continue
        if "any" not in to and (d_zone is None or d_zone not in to):
            continue
        if not any(a <= s_i <= b for a, b in _addr_set(cfg_root, members(e, "source") or ["any"])):
            continue
        if not any(a <= d_i <= b for a, b in _addr_set(cfg_root, members(e, "destination") or ["any"])):
            continue
        svc = members(e, "service") or ["any"]
        if not any((p is None or p == proto) and a <= int(port) <= b
                   for p, a, b in _svc_ports(cfg_root, svc)):
            continue
        act = e.findtext("action", "allow").strip()
        return e.get("name"), act
    return None


# ------------------------------------------------------- hit-count gia lap
def _hit_stat(name, i):
    """Sinh so lieu hit cho 1 rule, theo MARKER TUONG MINH trong ten rule:
       - ten KET THUC bang '-NOHIT' -> 0 hit, tao 200 ngay truoc
         => nhanh UNUSED bat duoc, va Import se DISABLE (shadow hit=0)
       - con lai -> co hit gan day
    Dung marker thay vi doan theo tu khoa ('SHADOW'/'OLD'...) de ten rule trong
    fixture khong vo tinh dinh nham - loi nay da tung lam sai 1 ca kiem thu."""
    now = int(datetime.datetime.now().timestamp())
    if (name or "").upper().endswith("-NOHIT"):
        return 0, 0, now - 200 * 86400
    return 100 + i, now - 2 * 86400, now - 300 * 86400


def _rules_el(container, rb):
    if container is None:
        return None
    return container.find(f"{rb}-rulebase/security/rules")


def hit_count_payload(cfg_root, cmd):
    """Tra ve response rule-hit-count PHAN CHIEU DUNG PHAM VI MA REQUEST HOI,
    giong cach PAN-OS tra loi lenh op (lồng lại đúng cây device-group/shared +
    pre|post-rulebase/entry[@name='security']/rules), de product phai tu suy
    vi_tri (Shared-PRE / <DG>-PRE / <DG>-POST / Shared-POST) tu chinh response
    - day la yeu cau D9 (2 rule trung ten o 2 DG khac nhau phai phan biet duoc).

    Request product gui (4 lenh, chi phi co dinh):
      <show><rule-hit-count><device-group><entry name='*'><pre|post-rulebase>...
      <show><rule-hit-count><shared><pre|post-rulebase>...
    'name=*' -> tra ve TAT CA device-group.
    """
    c = (cmd or "").replace(" ", "")
    rb = "post" if "<post-rulebase>" in c else "pre"
    want_shared = "<shared>" in c
    idx = 0

    def rules_xml(container):
        nonlocal idx
        rules = _rules_el(container, rb)
        if rules is None:
            return ""
        rows = []
        for e in rules.findall("entry"):
            nm = e.get("name") or ""
            hc, last, created = _hit_stat(nm, idx)
            idx += 1
            rows.append(
                f'<entry name="{nm}"><latest>yes</latest>'
                f"<hit-count>{hc}</hit-count>"
                f"<last-hit-timestamp>{last}</last-hit-timestamp>"
                f"<rule-creation-timestamp>{created}</rule-creation-timestamp></entry>")
        if not rows:
            return ""
        return (f"<{rb}-rulebase><entry name=\"security\"><rules>"
                + "".join(rows) + f"</rules></entry></{rb}-rulebase>")

    if want_shared:
        body = rules_xml(cfg_root.find("shared"))
        return "<rule-hit-count><shared>" + body + "</shared></rule-hit-count>"

    dg_rows = []
    for dg in cfg_root.iter("device-group"):
        for e in dg.findall("entry"):
            if e.find("pre-rulebase") is None and e.find("post-rulebase") is None:
                continue  # bo qua ban sao trong <readonly> / entry khong co rulebase
            body = rules_xml(e)
            if body:
                dg_rows.append(f'<entry name="{e.get("name")}">' + body + "</entry>")
    return ("<rule-hit-count><device-group>" + "".join(dg_rows)
            + "</device-group></rule-hit-count>")


REGISTERED_IP = """<registered-ip>
  <entry ip="10.10.10.150"><tag><member>tag-prod</member></tag></entry>
  <entry ip="10.10.10.151"><tag><member>tag-prod</member><member>tag-web</member></tag></entry>
</registered-ip>"""


# ---------------------------------------------------------------- handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, body: bytes, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/xml; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        self._handle(urllib.parse.parse_qs(parsed.query), parsed.path)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode("utf-8", "replace")
        parsed = urllib.parse.urlparse(self.path)
        q = urllib.parse.parse_qs(parsed.query)
        q.update(urllib.parse.parse_qs(raw))
        self._handle(q, parsed.path)

    def _handle(self, q, path):
        if not path.rstrip("/").endswith("/api"):
            return self._send(err("Khong phai endpoint /api/"), 404)
        g = lambda k, d="": (q.get(k) or [d])[0]
        if not g("key"):
            return self._send(err("Thieu API key"), 403)
        typ, action = g("type"), g("action")

        if typ == "config":
            return self._config(action, g("xpath"), g("element"))
        if typ == "op":
            return self._op(g("cmd"), g("target"))
        return self._send(err(f"type='{typ}' khong ho tro"))

    def _config(self, action, xpath, element):
        if action == "show":
            log("config action=show -> running-config")
            return self._send(ok(ET.tostring(STATE["running"], encoding="unicode")))
        if action == "get":
            if not xpath or xpath.strip("/") in ("config", ""):
                log("config action=get /config -> candidate-config")
                return self._send(ok(ET.tostring(STATE["candidate"], encoding="unicode")))
            el = resolve_xpath(STATE["candidate"], xpath)
            log(f"config action=get xpath={xpath} -> {'OK' if el is not None else 'khong thay'}")
            if el is None:
                return self._send(err(f"No such node: {xpath}"))
            return self._send(ok(ET.tostring(el, encoding="unicode")))
        if action in ("delete", "edit", "set"):
            # KHONG sua fixture - chi ghi nhat ky (dung tinh than D6: khong commit)
            journal(f"action={action} xpath={xpath} element={element}")
            log(f"config action={action} -> GHI NHAT KY (khong sua fixture): {xpath}")
            return self._send(ok("<msg>command succeeded</msg>"))
        if action == "commit":
            log("!!! co lenh COMMIT - tool KHONG duoc phep goi (D6) !!!")
            journal("CANH BAO: co lenh commit!")
            return self._send(err("Testlab tu choi: tool khong duoc phep commit (D6)"))
        return self._send(err(f"action='{action}' khong ho tro"))

    def _op(self, cmd, target=""):
        c = (cmd or "").replace(" ", "")
        if "<system><info>" in c:
            log("op: show system info")
            return self._send(ok("<system><hostname>MOCK-FW-TESTLAB</hostname>"
                                  "<model>PA-VM</model><sw-version>11.1.0</sw-version>"
                                  "<serial>007000000001</serial></system>"))
        if "registered-ip" in c:
            log("op: show registered-ip (Dynamic Address Group)")
            return self._send(ok(REGISTERED_IP))
        if "<devicegroups" in c:
            names = [e.get("name") for dg in STATE["running"].iter("device-group")
                     for e in dg.findall("entry") if e.get("name")]
            seen, uniq = set(), []
            for n in names:
                if n not in seen:
                    seen.add(n); uniq.append(n)
            log(f"op: show devicegroups -> {uniq}")
            return self._send(ok("<devicegroups>" + "".join(
                f"<entry name=\"{n}\"/>" for n in uniq) + "</devicegroups>"))
        if "<devices>" in c and "registered-ip" not in c:
            log("op: show devices all")
            return self._send(ok(
                "<devices>"
                "<entry name='001122334455'><serial>001122334455</serial>"
                "<hostname>FW-HN-01</hostname><connected>yes</connected></entry>"
                "<entry name='009988776655'><serial>009988776655</serial>"
                "<hostname>FW-HN-02</hostname><connected>yes</connected></entry>"
                "</devices>"))
        if "rule-hit-count" in c:
            # 0.7: du lieu runtime cua TUNG firewall -> Panorama BAT BUOC co target
            if not target:
                log("op: rule-hit-count THIEU target -> tra loi (dung nhu Panorama that)")
                return self._send(err("target is required for this operational command"))
            log(f"op: show rule-hit-count (target={target})")
            return self._send(ok(hit_count_payload(STATE["running"], cmd)))
        if "security-policy-match" in c:
            # 0.5: chay tren dataplane firewall -> Panorama BAT BUOC co target
            if not target:
                log("op: policy-match THIEU target -> tra loi (dung nhu Panorama that)")
                return self._send(err("target is required for this operational command"))
            m = dict(re.findall(r"<(source|destination|destination-port|protocol)>([^<]+)</\1>", cmd or ""))
            res = simulate_policy_match(STATE["running"], m.get("source", ""),
                                         m.get("destination", ""),
                                         m.get("destination-port", "0"),
                                         m.get("protocol", "6"))
            label = (f"{m.get('source')}->{m.get('destination')}:{m.get('destination-port')}")
            if res is None:
                log(f"op: policy-match[{target}] {label} -> KHONG khop rule nao")
                return self._send(ok("<rules/>"))
            name, act = res
            log(f"op: policy-match[{target}] {label} -> {name} ({act})")
            return self._send(ok(f"<rules><entry name=\"{name}\"><action>{act}</action>"
                                  f"</entry></rules>"))
        log(f"op: lenh chua mo phong -> tra rong ({(cmd or '')[:60]})")
        return self._send(ok("<msg>command succeeded</msg>"))


def main():
    ap = argparse.ArgumentParser(description="Panorama gia lap cho testlab")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8443)
    ap.add_argument("--config", default=DEFAULT_RUNNING)
    ap.add_argument("--candidate", default=DEFAULT_CANDIDATE)
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    STATE["quiet"] = args.quiet
    STATE["running"] = ET.parse(args.config).getroot()
    STATE["candidate"] = ET.parse(args.candidate).getroot()

    crt, key = ensure_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)

    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    n_rules = len(STATE["running"].findall(".//security/rules/entry"))
    n_nat = len(STATE["running"].findall(".//nat/rules/entry"))
    n_dg = len(STATE["running"].findall(".//device-group/entry"))
    print("=" * 72)
    print("  PANORAMA GIA LAP (testlab) - da san sang")
    print("=" * 72)
    print(f"  Dia chi  : https://{args.host}:{args.port}/api/")
    print(f"  Config   : {n_dg} Device Group, {n_rules} security rule, {n_nat} NAT rule")
    print(f"  Nhat ky  : {JOURNAL}  (ghi lai moi lenh delete/edit/set)")
    print()
    print("  NHAP VAO GUI CUA TOOL:")
    print(f"     Panorama IP   : {args.host}:{args.port}")
    print( "     API Key       : bat ky chuoi nao (vd: testlab)")
    print( "     Device Group  : DG-HN  (hoac DG-DC / DG-ALL de thay doi pham vi)")
    print( "     Target FW     : 001122334455  (de trong = tat Live Match + Zone)")
    print( "     SSL Certificate: KHONG tick (cert tu ky)")
    print()
    print("  Ctrl+C de dung.")
    print("=" * 72)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n  [mock] da dung.")


if __name__ == "__main__":
    main()
