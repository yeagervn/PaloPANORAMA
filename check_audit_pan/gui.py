# -*- coding: utf-8 -*-
"""
gui.py - Giao dien Tkinter cua CHECK AUDIT (ban PANORAMA): class App(ttk.Frame)
de nhung duoc vao ttk.Notebook cua Suite (khong tu dat title/geometry). KHONG
chua logic nghiep vu - moi xu ly nam o core/pan_api/resolver/detectors/excel_io.

Luong Import->popup Yes/No->delete candidate theo dung D5/D6/D9 (Mục 5), voi
DID RULEBASE PANORAMA: xpath delete duoc duy theo cot "Vi tri Rule" (0.8),
canh bao cuoi kem 2 tang commit (0.4). shutdown() chi set cancel_event, KHONG
tu destroy() cua so.
"""

import os
import queue
import subprocess
import threading
from datetime import datetime
from typing import Dict, List, Optional, Tuple

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from .core import (
    OUTPUT_DIR, LOG_PATH, setup_logger, PanApiError,
    Finding, RuleSnapshot,
    CHECK_TYPE_LABELS, SHADOW_UNUSED, UNUSED_RULE_THRESHOLD_DAYS,
    format_service_entries,
)
from .pan_api import (
    PanApiClient, get_devicegroup_list, parse_devicegroup_objects,
    assemble_security_rules, delete_rule_candidate, disable_rule_candidate,
    fetch_rule_hit_count, fetch_rule_hit_count_multi, fetch_current_rule_states,
    devicegroup_device_serials,
)
from .resolver import GroupResolver, ServiceResolver
from .detectors import (
    find_shadow_rules, find_disabled_rules, find_overly_permissive_rules,
)
from .excel_io import export_findings, parse_import_file

TREE_COLUMNS = ("loai", "rule", "vi_tri", "src", "dst", "port", "action",
                "disabled", "shadow_reason", "no_hit", "detail")
TREE_HEADERS = ("Loại", "Rule Name", "Vi tri Rule", "Source", "Dest", "Port",
                "Action", "Disabled", "Shadow Reason", "No Hits Duration", "Detail")


def _vi_tri_to_xpath_params(vi_tri: str) -> Tuple[str, str]:
    """Bien 'Vi tri Rule' -> (devicegroup, rulebase) dung cho delete_rule_candidate.
    'Shared-PRE'/'Shared-POST' -> ('', 'shared-pre'/'shared-post').
    '<DG>-PRE'/'<DG>-POST' -> ('<DG>', 'pre'/'post')."""
    vi_tri = (vi_tri or "").strip()
    if vi_tri in ("Shared-PRE", "Shared-POST"):
        return "", "shared-pre" if vi_tri.endswith("PRE") else "shared-post"
    if "-" in vi_tri:
        base, suffix = vi_tri.rsplit("-", 1)
        suffix = suffix.upper()
        if suffix in ("PRE", "POST"):
            return base, suffix.lower()
    return "", ""


class App(ttk.Frame):
    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.root = self  # alias noi bo, giu cho self.root.xxx() hoat dong dung

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.logger = setup_logger(LOG_PATH)

        self.msg_queue: "queue.Queue" = queue.Queue()
        self.cancel_event = threading.Event()
        # Cua so dang dong -> dung vong _poll_queue (xem shutdown()).
        self._closing = False
        self._poll_after_id = None

        self.api_client: Optional[PanApiClient] = None
        self.config_root = None
        self._mgmt_ip = ""
        self._api_key = ""
        self._verify_ssl = False
        self._dg_name = ""
        self._target_serial = ""

        # Trang thai lam viec cua CLIP "luat co Import" (D5):
        self.rules: List[RuleSnapshot] = []
        self.rule_by_key: Dict[Tuple[str, str], RuleSnapshot] = {}  # (name, vi_tri)
        self.service_info = None
        self.findings: List[Finding] = []
        self._import_eligible = False

        self._build_ui()
        self._poll_after_id = self.root.after(100, self._poll_queue)
        self._log(f"San sang. Thu muc output: {OUTPUT_DIR}")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        # Khung 1 - Ket noi Panorama
        frm_conn = ttk.LabelFrame(self.root, text="1. Kết nối Panorama")
        frm_conn.pack(fill="x", **pad)
        ttk.Label(frm_conn, text="Panorama IP:").grid(row=0, column=0, sticky="w", **pad)
        self.ent_host = ttk.Entry(frm_conn, width=28)
        self.ent_host.grid(row=0, column=1, sticky="w", **pad)
        ttk.Label(frm_conn, text="API Key:").grid(row=0, column=2, sticky="w", **pad)
        self.ent_apikey = ttk.Entry(frm_conn, width=42, show="*")
        self.ent_apikey.grid(row=0, column=3, sticky="w", **pad)
        self.var_show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_conn, text="Hiện", variable=self.var_show_key,
                        command=self._toggle_key_visibility).grid(row=0, column=4, sticky="w")
        self.var_verify_ssl = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_conn, text="Kiểm tra SSL Certificate",
                        variable=self.var_verify_ssl).grid(row=1, column=0, columnspan=2, sticky="w", **pad)
        ttk.Label(frm_conn, text="Device Group:").grid(row=1, column=2, sticky="e", **pad)
        self.cmb_dg = ttk.Combobox(frm_conn, width=18, state="readonly")
        self.cmb_dg.grid(row=1, column=3, sticky="w", **pad)
        ttk.Label(frm_conn, text="Target Firewall (Serial):").grid(row=2, column=0, sticky="w", **pad)
        self.ent_serial = ttk.Entry(frm_conn, width=28)
        self.ent_serial.grid(row=2, column=1, sticky="w", **pad)
        ttk.Label(frm_conn,
                  text="(không bắt buộc - cần cho Rule Hit Count & độ chính xác so zone ở Shadow-check)",
                  foreground="#888888").grid(row=2, column=2, columnspan=3, sticky="w", **pad)
        self.btn_connect = ttk.Button(frm_conn, text="Connect", command=self._on_connect)
        self.btn_connect.grid(row=0, column=5, rowspan=3, sticky="ns", **pad)

        # Khung 2 - Chon tinh nang ra soat (D1: 3 checkbox doc lap, tick san ca 3)
        frm_feat = ttk.LabelFrame(self.root, text="2. Chọn tính năng rà soát")
        frm_feat.pack(fill="x", **pad)
        self.var_shadow = tk.BooleanVar(value=True)
        self.var_disabled = tk.BooleanVar(value=True)
        self.var_overly = tk.BooleanVar(value=True)
        ttk.Checkbutton(frm_feat, text="Shadow Rules", variable=self.var_shadow,
                        command=self._update_button_states).pack(side="left", padx=8, pady=4)
        ttk.Checkbutton(frm_feat, text="Disabled Rules", variable=self.var_disabled,
                        command=self._update_button_states).pack(side="left", padx=8, pady=4)
        ttk.Checkbutton(frm_feat, text="Overly Permissive Rules (Any)", variable=self.var_overly,
                        command=self._update_button_states).pack(side="left", padx=8, pady=4)

        # Nguong UNUSED cau hinh duoc (dong bo voi ban Firewall standalone) - nhanh
        # UNUSED cua Shadow Rules chi tinh khi co Target Firewall (0.7).
        ttk.Label(frm_feat, text="Ngưỡng Unused (ngày):").pack(side="left", padx=(16, 2))
        self.var_unused_threshold = tk.StringVar(value=str(UNUSED_RULE_THRESHOLD_DAYS))
        self.ent_unused_threshold = ttk.Spinbox(frm_feat, from_=1, to=3650, width=6,
                                                 textvariable=self.var_unused_threshold)
        self.ent_unused_threshold.pack(side="left", padx=2, pady=4)

        # Khung 3 - Hanh dong
        frm_actions = ttk.LabelFrame(self.root, text="3. Hành động")
        frm_actions.pack(fill="x", **pad)
        self.btn_check = ttk.Button(frm_actions, text="Check", command=self._on_check, state="disabled")
        self.btn_check.pack(side="left", padx=6, pady=4)
        self.btn_export = ttk.Button(frm_actions, text="Export", command=self._on_export, state="disabled")
        self.btn_export.pack(side="left", padx=6, pady=4)
        ttk.Label(frm_actions, text="Định dạng:").pack(side="left", padx=(4, 0))
        self.cmb_format = ttk.Combobox(frm_actions, width=6, state="readonly", values=["xlsx", "csv"])
        self.cmb_format.set("xlsx")
        self.cmb_format.pack(side="left", padx=4, pady=4)
        self.btn_import = ttk.Button(frm_actions, text="Import", command=self._on_import, state="disabled")
        self.btn_import.pack(side="left", padx=6, pady=4)
        self.btn_open_output = ttk.Button(frm_actions, text="Mở thư mục Output",
                                          command=self._on_open_output)
        self.btn_open_output.pack(side="left", padx=6, pady=4)
        ttk.Label(frm_actions,
                  text="(Import: Shadow (hit=0) → Disable | Disabled → Delete | Overly chỉ Export)",
                  foreground="#888888").pack(side="left", padx=10)

        # Khung 4 - Bang ket qua
        frm_result = ttk.LabelFrame(self.root, text="4. Kết quả")
        frm_result.pack(fill="both", expand=True, **pad)
        self.tree = ttk.Treeview(frm_result, columns=TREE_COLUMNS, show="headings")
        for col, header in zip(TREE_COLUMNS, TREE_HEADERS):
            self.tree.heading(col, text=header)
            width = 60 if col in ("action", "disabled") else (
                150 if col == "vi_tri" else (200 if col in ("detail",) else 140))
            self.tree.column(col, width=width, anchor="w")
        vsb = ttk.Scrollbar(frm_result, orient="vertical", command=self.tree.yview)
        hsb = ttk.Scrollbar(frm_result, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frm_result.rowconfigure(0, weight=1)
        frm_result.columnconfigure(0, weight=1)

        # Khung 5 - Log
        frm_log = ttk.LabelFrame(self.root, text="5. Log")
        frm_log.pack(fill="both", expand=False, **pad)
        self.txt_log = scrolledtext.ScrolledText(frm_log, height=10, state="disabled", font=("Consolas", 9))
        self.txt_log.pack(fill="x", **pad)

        self._update_button_states()

        # Enter xac nhan: o nhap IP/API Key -> Connect; chon DG -> Check.
        self._bind_enter(self.ent_host, self.btn_connect)
        self._bind_enter(self.ent_apikey, self.btn_connect)
        self._bind_enter(self.ent_serial, self.btn_connect)
        self._bind_enter(self.cmb_dg, self.btn_check)

    def _toggle_key_visibility(self):
        self.ent_apikey.config(show="" if self.var_show_key.get() else "*")

    # Enter trong o nhap dang co focus -> kich hoat nut di theo sau (ngoài bam truc tiep).
    def _bind_enter(self, widget, button):
        widget.bind("<Return>", lambda e: self._trigger_button(button))

    def _trigger_button(self, button):
        try:
            if str(button["state"]) == "normal":
                button.invoke()
        except Exception:
            pass

    # -------------------------------------------------------------- queue
    def _log(self, msg: str):
        self.msg_queue.put(("log", msg))

    def _poll_queue(self):
        try:
            while True:
                kind, payload = self.msg_queue.get_nowait()
                if kind == "log":
                    self.logger.info(payload)
                    self.txt_log.configure(state="normal")
                    self.txt_log.insert("end", payload + "\n")
                    self.txt_log.see("end")
                    self.txt_log.configure(state="disabled")
                elif kind == "error":
                    messagebox.showerror("Lỗi", payload)
                elif kind == "done_connect":
                    self._finish_connect(payload)
                elif kind == "done_check":
                    self._finish_check()
                elif kind == "done_delete":
                    self._finish_delete(payload)
                elif kind == "enable_ui":
                    self._set_busy(False)
        except queue.Empty:
            pass
        if self._closing:
            self._poll_after_id = None
            return
        self._poll_after_id = self.root.after(100, self._poll_queue)

    def _set_busy(self, busy: bool):
        self.btn_connect.config(state="disabled" if busy else "normal")
        self._update_button_states()

    def _selected_types(self) -> List[str]:
        types = []
        if self.var_shadow.get():
            types.append("shadow")
        if self.var_disabled.get():
            types.append("disabled")
        if self.var_overly.get():
            types.append("overly_permissive")
        return types

    def _update_button_states(self):
        connected = self.config_root is not None
        any_feature = bool(self._selected_types())
        self.btn_check.config(state="normal" if (connected and any_feature and
                                                 str(self.btn_connect["state"]) != "disabled") else "disabled")
        self.btn_export.config(state="normal" if (self.findings and
                                                  str(self.btn_connect["state"]) != "disabled") else "disabled")
        self.btn_import.config(state="normal" if (self._import_eligible and
                                                  str(self.btn_connect["state"]) != "disabled") else "disabled")

    # ------------------------------------------------------------- connect
    def _on_connect(self):
        host = self.ent_host.get().strip()
        api_key = self.ent_apikey.get().strip()
        if not host or not api_key:
            messagebox.showwarning("Thiếu thông tin", "Vui lòng nhập Panorama IP và API Key.")
            return
        self._set_busy(True)
        self.cancel_event.clear()
        threading.Thread(target=self._connect_worker,
                         args=(host, api_key, self.var_verify_ssl.get()), daemon=True).start()

    def _connect_worker(self, host, api_key, verify_ssl):
        try:
            client = PanApiClient(host, api_key, verify_ssl=verify_ssl)
            self._log("Đang kết nối tới Panorama...")
            hostname = client.test_connection()
            self._log(f"Connect OK (hostname: {hostname})")
            self._log("Đang tải FULL running-config Panorama (có thể mất vài giây)...")
            config_root = client.fetch_running_config()
            dg_list = get_devicegroup_list(config_root) or ["shared"]
            self._log(f"Danh sách Device Group: {', '.join(dg_list)}")
            self.api_client = client
            self.config_root = config_root
            self._mgmt_ip = host
            self._api_key = api_key
            self._verify_ssl = verify_ssl
            self.msg_queue.put(("done_connect", dg_list))
        except PanApiError as e:
            self._log(f"Connect FAILED: {e.user_message}")
            self.logger.exception("Connect error")
            self.msg_queue.put(("error", e.user_message))
        except Exception:
            self._log("Connect FAILED: lỗi không xác định (xem log.txt)")
            self.logger.exception("Unexpected connect error")
            self.msg_queue.put(("error", "Đã xảy ra lỗi không xác định khi Connect. Xem log.txt để biết chi tiết."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _finish_connect(self, dg_list):
        self.cmb_dg["values"] = dg_list
        self.cmb_dg.current(0)
        self._log("Connect thành công. Chọn Device Group rồi bấm Check.")
        self._update_button_states()

    # ---------------------------------------------------------------- check
    def _on_check(self):
        if self.config_root is None:
            messagebox.showwarning("Chưa kết nối", "Vui lòng Connect trước khi Check.")
            return
        dg = self.cmb_dg.get()
        if not dg:
            messagebox.showwarning("Thiếu Device Group", "Vui lòng chọn Device Group.")
            return
        types = self._selected_types()
        if not types:
            messagebox.showwarning("Chưa chọn tính năng", "Vui lòng tick ít nhất 1 tính năng rà soát.")
            return
        try:
            unused_threshold = int(self.var_unused_threshold.get().strip())
            if unused_threshold <= 0:
                raise ValueError
        except (ValueError, TypeError):
            messagebox.showwarning("Ngưỡng không hợp lệ",
                                   "Ngưỡng Unused (ngày) phải là số nguyên dương.")
            return
        if self.cancel_event.is_set():
            self.cancel_event.clear()
        self._set_busy(True)
        self._dg_name = dg
        self._target_serial = self.ent_serial.get().strip()
        self._log(f"Bắt đầu Check Device Group={dg}, tính năng: {', '.join(types)}")
        threading.Thread(target=self._check_worker,
                         args=(dg, self._target_serial, types, self._mgmt_ip, self._api_key,
                               self._verify_ssl, unused_threshold),
                         daemon=True).start()

    def _hitcount_serials(self, dg_name, target_serial):
        """P1 (10/2026): PHAM VI firewall phai doc hit-count = MOI firewall cua
        Device Group dang chon, HOP voi Target Firewall neu co.

        Vi sao khong chi dung Target: hit-count la so lieu cua tung firewall, nhung
        1 rule trong DG duoc push xuong MOI firewall cua DG. Doc 1 con roi ket luan
        UNUSED = de xuat XOA rule co the dang chay tren cac con khac.

        HAN CHE PHAI NOI RO: rule o Shared-PRE/Shared-POST ap cho MOI firewall
        Panorama quan ly, khong chi cac con trong DG nay - nen voi rule Shared,
        pham vi bang chung o day VAN con hep hon pham vi that. Vi vay ket luan
        luon kem cau "da kiem N firewall: ..." (RuleHitStat.evidence_scope) thay vi
        mot chu "UNUSED" tran.

        Dung devicegroup_device_serials() CUA CHINH check_audit_pan (khong import
        cheo tu check_rule_pan - 3 package doc lap 100%, co test khoa)."""
        serials = []
        try:
            serials = list(devicegroup_device_serials(self.config_root, dg_name) or [])
        except Exception as e:
            self._log(f"CANH BAO: khong liet ke duoc firewall cua Device Group "
                      f"{dg_name} ({e}) - se chi dua tren Target Firewall neu co.")
        if target_serial and target_serial not in serials:
            serials.append(target_serial)
        return serials

    def _check_worker(self, dg_name, target_serial, types, mgmt_ip, api_key, verify_ssl,
                       unused_threshold_days=UNUSED_RULE_THRESHOLD_DAYS):
        try:
            objs = parse_devicegroup_objects(self.config_root, dg_name)
            rules = assemble_security_rules(self.config_root, dg_name)
            self._log(f"Đọc {len(rules)} Security Rule (Device Group={dg_name}, theo 6 bước 0.3)")

            resolver = GroupResolver(objs["address_objects"], objs["address_groups"], log_func=self._log)
            svc_resolver = ServiceResolver(objs["service_objects"], objs["service_groups"], log_func=self._log)
            service_info = _build_service_info_from(objs["service_objects"], objs["service_groups"])

            hit_stats = {}
            if "shadow" in types:
                # P1 (10/2026): doc hit-count tren MOI firewall cua Device Group,
                # khong chi rieng Target. Xem _hitcount_serials().
                _serials = self._hitcount_serials(dg_name, target_serial)
                if _serials:
                    self._log(f"Đọc Policy Optimizer (rule-hit-count) trên "
                              f"{len(_serials)} firewall của Device Group {dg_name}: "
                              f"{', '.join(_serials)}")
                    if len(_serials) == 1:
                        self._log("LƯU Ý: chỉ có 1 firewall trong phạm vi → kết luận "
                                  "UNUSED chỉ có giá trị cho đúng firewall đó.")
                    hit_stats = fetch_rule_hit_count_multi(mgmt_ip, api_key, _serials,
                                                           verify_ssl=verify_ssl,
                                                           log_func=self._log)
                    _thieu = sum(1 for st in hit_stats.values()
                                 if not getattr(st, "hits_known", True))
                    self._log(f"Hit-count OK ({len(hit_stats)} rule có dữ liệu thống kê)"
                              if hit_stats else "Hit-count trả về rỗng → nhánh UNUSED sẽ bỏ qua")
                    if _thieu:
                        self._log(f"CANH BAO: {_thieu} rule THIẾU bằng chứng hit-count ở "
                                  f"ít nhất 1 firewall → KHÔNG kết luận UNUSED cho các "
                                  f"rule đó (không biết KHÁC bằng 0).")
                    # 0.6: kiem tra Template Zone neu co target (best-effort)
                    try:
                        from .pan_api import resolve_template_for_serial
                        tmpl = resolve_template_for_serial(self.config_root, target_serial)
                        if tmpl is None:
                            self._log("CANH BAO: không tìm thấy Template cho Target → so sánh Zone trong shadow-check sẽ fallback 'luôn coi tương thích' (0.6), có thể báo shadow sai - độ chính xác giảm.")
                    except Exception:
                        pass
                else:
                    self._log("CANH BAO: không xác định được firewall nào (Device Group "
                              "không có thiết bị và chưa nhập Target Firewall) → nhánh "
                              "UNUSED (Shadow) bị bỏ qua.")
                    self._log("CANH BAO: chưa chọn Target Firewall (Serial) → so sánh Zone trong 5-điều-kiện-superset sẽ fallback 'luôn coi tương thích' (0.6), có thể báo shadow sai ở trường hợp Zone khác nhau (IV.2.3/IV.7.5).")

            findings: List[Finding] = []
            if "disabled" in types:
                findings += find_disabled_rules(rules)
                self._log(f"Disabled Rules: {len([f for f in findings if f.check_type == 'disabled'])} finding")
            if "overly_permissive" in types:
                findings += find_overly_permissive_rules(rules)
                self._log(f"Overly Permissive: {len([f for f in findings if f.check_type == 'overly_permissive'])} finding")
            if "shadow" in types:
                self._log(f"Đang audit Shadow Rules với ngưỡng Unused = {unused_threshold_days} ngày...")
                shadow_findings = find_shadow_rules(rules, resolver, svc_resolver, hit_stats,
                                                     datetime.now(),
                                                     threshold_days=unused_threshold_days)
                findings += shadow_findings
                self._log(f"Shadow Rules: {len(shadow_findings)} finding")

            # Gan 'vi_tri' cho tung Finding tu RuleSnapshot (theo index da lap rap 0.3).
            for f in findings:
                if 0 <= f.rule_index < len(rules):
                    f.vi_tri = rules[f.rule_index].vi_tri

            self.rules = rules
            self.rule_by_key = {}
            for r in rules:
                self.rule_by_key[(r.name, r.vi_tri)] = r
            self.service_info = service_info
            self.findings = findings
            self._log(f"Check xong. Tổng {len(findings)} finding.")
            self.msg_queue.put(("done_check", None))
        except PanApiError as e:
            self._log(f"Check FAILED: {e.user_message}")
            self.logger.exception("Check error")
            self.msg_queue.put(("error", e.user_message))
        except Exception:
            self._log("Check FAILED: lỗi không xác định (xem log.txt)")
            self.logger.exception("Unexpected check error")
            self.msg_queue.put(("error", "Đã xảy ra lỗi không xác định khi Check. Xem log.txt để biết chi tiết."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _finish_check(self):
        self._render_table()
        self._update_button_states()

    def _no_hit_cell(self, f: Finding) -> str:
        if f.check_type == "shadow" and SHADOW_UNUSED in f.shadow_reasons and f.no_hit_days is not None:
            return f"{f.no_hit_days} ngày"
        return ""

    def _render_table(self):
        self.tree.delete(*self.tree.get_children())
        for f in self.findings:
            self.tree.insert("", "end", values=(
                CHECK_TYPE_LABELS.get(f.check_type, f.check_type),
                f.rule_name,
                f.vi_tri,
                ", ".join(f.source),
                ", ".join(f.destination),
                format_service_entries(f.service, self.service_info),
                f.action,
                "Yes" if f.disabled else "No",
                ", ".join(f.shadow_reasons) if f.check_type == "shadow" else "",
                self._no_hit_cell(f),
                f.detail,
            ))

    # ---------------------------------------------------------------- export
    def _open_in_explorer(self, path: str, select: Optional[str] = None):
        """Mo 1 thu muc trong Explorer (chon san file neu co `select`). Neu mo
        that bai -> chi ghi canh bao vao log, khong lam crash GUI."""
        try:
            if os.name == "nt":
                if select:
                    subprocess.Popen(["explorer", "/select,", select])
                else:
                    subprocess.Popen(["explorer", path])
            else:
                os.startfile(path)
            self._log(f"Đã mở thư mục Output trong Explorer: {path}")
        except Exception as e:
            self._log(f"CANH BAO: không mở được thư mục Output ({e}). Đường dẫn: {path}")

    def _on_open_output(self):
        if not os.path.isdir(OUTPUT_DIR):
            os.makedirs(OUTPUT_DIR, exist_ok=True)
        self._open_in_explorer(OUTPUT_DIR)

    def _on_export(self):
        if not self.findings:
            messagebox.showwarning("Chưa có kết quả", "Không có Finding nào để Export.")
            return
        fmt = self.cmb_format.get() or "xlsx"
        types = sorted({f.check_type for f in self.findings})
        try:
            path = export_findings(self.findings, OUTPUT_DIR, fmt,
                                   service_info=self.service_info, types=types, log_func=self._log)
        except Exception as e:
            self.logger.exception("Export error")
            messagebox.showerror("Lỗi Export", str(e))
            return
        self._import_eligible = any(t in ("shadow", "disabled") for t in types)
        self._log(f"EXPORT: {path}")
        self._open_in_explorer(OUTPUT_DIR, select=path)
        messagebox.showinfo("Hoàn tất", f"Đã xuất kết quả:\n{path}")
        self._update_button_states()

    # ---------------------------------------------------------------- import
    # Quy tac moi (IV.4 cap nhat):
    #   - Shadow Rules co hit_count == 0 (UNUSED, chua tung co hit hoac 0 hit trong 30 ngay)
    #     -> khi Import CHI co option DISABLE (khong xoa thang) - an toan, cho phep rollback.
    #   - Disabled Rules -> khi Import co option DELETE (xoa thang candidate).
    #   - Overly Permissive Rules -> CHI EXPORT, khong cho Import thao tac gi (D5 moi).
    def _on_import(self):
        if not self._import_eligible:
            messagebox.showwarning("Import chưa sẵn sàng",
                                   "Import chỉ khả dụng sau khi Export thành công file có chứa "
                                   "Shadow Rules hoặc Disabled Rules (D5). "
                                   "Overly Permissive chỉ Export, không Import.")
            return
        path = filedialog.askopenfilename(
            title="Chọn file .xlsx đã export (Shadow→Disable, Disabled→Delete)",
            filetypes=[("Excel files", "*.xlsx")],
        )
        if not path:
            return
        try:
            rows = parse_import_file(path, log_func=self._log)
        except Exception as e:
            messagebox.showerror("Lỗi đọc file Import", str(e))
            return

        # Phan loai theo quy tac moi:
        #   Shadow (hit==0) -> disable ; Disabled -> delete ; Overly -> skip (export only)
        candidates = []      # (rule_name, loai, vi_tri, devicegroup, rulebase, action)
        not_found = []       # (rule_name, loai)
        duplicates = []      # (rule_name, loai, vi_tri)
        skipped_overly = 0
        for row in rows:
            # parse_import_file tra 4-tuple (name, loai, vi_tri, hit_raw) - giu tuong thich cu 3-tuple
            if len(row) == 4:
                name, loai, vi_tri, hit_raw = row
            else:
                name, loai, vi_tri = row[:3]
                hit_raw = ""
            # Overly Permissive chi Export - bo qua hoan toan khi Import
            if loai == "Overly Permissive Rules":
                skipped_overly += 1
                self._log(f"CANH BAO: bỏ qua Overly Permissive '{name}' - loại này CHI EXPORT, không Import thao tác (quy tắc mới).")
                continue
            if loai not in ("Shadow Rules", "Disabled Rules"):
                self._log(f"CANH BAO: bỏ qua dòng 'not importable' Loại='{loai}' cho rule '{name}' (D5).")
                continue

            # Xac dinh action theo loai + hit_count
            if loai == "Disabled Rules":
                action = "delete"
            else:  # Shadow Rules
                # Shadow ->.disable . Neu hit_count !=0 van disable (an toan), nhung log nhan manh
                # truong hop "hits count =0" la truong hop dien hinh duoc quy tac mo ta.
                # Kiem tra ca Finding trong memory (chinh xac) va hit_raw tu file (fallback).
                finding = next((f for f in self.findings if f.rule_name == name and f.vi_tri == vi_tri), None)
                hit_is_zero = False
                if finding is not None and finding.hit_count is not None:
                    hit_is_zero = (finding.hit_count == 0)
                elif hit_raw != "":
                    try:
                        hit_is_zero = (int(float(hit_raw)) == 0)
                    except Exception:
                        hit_is_zero = (hit_raw.strip() == "0")
                else:
                    # Khong co hit data -> coi nhu la 0-hit (UNREACHABLE) van cho disable
                    hit_is_zero = True
                action = "disable"
                if not hit_is_zero:
                    self._log(f"  Shadow '{name}' hit_count={hit_raw or (finding.hit_count if finding else 'N/A')} !=0 -> van cho phep Disable (khong Delete) theo quy tắc shadow->disable.")

            match = self.rule_by_key.get((name, vi_tri))
            if match is None:
                not_found.append((name, loai))
            else:
                # SỬA 2026-09-02 audit: trước đây chặn mọi trùng tên (kiểm tra len([k for k in rule_by_key if k[0]==name])>1)
                # dù đã có vi_tri để phân biệt — quá tay, dù an toàn nhưng làm giảm tự động hoá.
                # Nay đã có vi_tri chính xác nên không cần chặn theo tên thuần nữa; chỉ cần match chính xác (name, vi_tri) là đủ.
                # Giữ lại log cảnh báo nếu trùng tên ở DG khác để audit, nhưng không chặn.
                dup_count = len([k for k in self.rule_by_key if k[0] == name])
                if dup_count > 1:
                    self._log(f"Lưu ý: rule '{name}' trùng tên ở {dup_count} vị trí khác nhau, nhưng candidate có vi_tri='{vi_tri}' nên vẫn xử lý chính xác theo vi_tri (D9 đã sửa).")
                dg, rb = _vi_tri_to_xpath_params(vi_tri)
                if not rb:
                    self._log(f"CANH BAO: 'Vi tri Rule' không hợp lệ '{vi_tri}' cho rule '{name}' - bỏ qua.")
                    continue
                candidates.append((name, loai, vi_tri, dg, rb, action))

        if skipped_overly:
            self._log(f"Đã bỏ qua {skipped_overly} dòng Overly Permissive (chỉ Export).")
        if not candidates:
            msg = "File import không có rule nào khớp chính xác với config hiện tại để thao tác."
            if not_found:
                msg += "\n\nCác rule không còn tồn tại (hoặc đổi tên):\n- " + "\n- ".join(n for n, _ in not_found[:20])
            if duplicates:
                msg += f"\n\n{len(duplicates)} rule trùng tên đã bỏ qua (theo D9 - an toàn)."
            if skipped_overly:
                msg += f"\n\n{skipped_overly} rule Overly Permissive đã bỏ qua (chỉ Export)."
            messagebox.showinfo("Không có rule để thao tác", msg)
            return

        self._show_confirm_dialog(candidates, not_found)

    def _show_confirm_dialog(self, candidates, not_found):
        # candidates: List[(name, loai, vi_tri, dg, rb, action)]
        dlg = tk.Toplevel(self.root)
        has_disable = any(c[5] == "disable" for c in candidates)
        has_delete = any(c[5] == "delete" for c in candidates)
        if has_disable and has_delete:
            title = "Xác nhận Disable / Delete:"
        elif has_disable:
            title = "Xác nhận Disable (Shadow hit=0):"
        else:
            title = "Xác nhận Delete (Disabled):"
        dlg.title(title)
        dlg.transient(self.root)
        dlg.geometry("720x480")
        try:
            dlg.grab_set()
        except Exception:
            pass

        container = ttk.Frame(dlg)
        container.pack(fill="both", expand=True, padx=8, pady=8)
        canvas = tk.Canvas(container)
        scroll = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

        hdr = "Chọn Yes để thực hiện trên Candidate Config (mặc định No):"
        if has_disable and not has_delete:
            hdr += "  [Shadow hit=0 → Disable]"
        elif has_delete and not has_disable:
            hdr += "  [Disabled → Delete]"
        else:
            hdr += "  [Shadow→Disable | Disabled→Delete]"
        ttk.Label(inner, text=hdr,
                  foreground="#333333").grid(row=0, column=0, columnspan=6, sticky="w", pady=(0, 6))
        ttk.Label(inner, text="Rule", foreground="#666666").grid(row=1, column=0, sticky="w", padx=4)
        ttk.Label(inner, text="Vi tri", foreground="#666666").grid(row=1, column=1, sticky="w", padx=4)
        ttk.Label(inner, text="Hành động", foreground="#0066CC").grid(row=1, column=2, sticky="w", padx=4)

        # Radio mặc định MỖI dòng là No (an toàn - không tự tick Yes) - D5.
        vars_: List[tk.StringVar] = []
        row_idx = 2
        for idx, (name, _loai, vi_tri, _dg, _rb, action) in enumerate(candidates):
            var = tk.StringVar(value="No")
            vars_.append(var)
            ttk.Label(inner, text=name).grid(row=row_idx, column=0, sticky="w", padx=4, pady=2)
            ttk.Label(inner, text=vi_tri, foreground="#444444").grid(row=row_idx, column=1, sticky="w", padx=4)
            act_label = "Disable" if action == "disable" else "Delete"
            act_color = "#CC6600" if action == "disable" else "#CC0000"
            ttk.Label(inner, text=act_label, foreground=act_color, font=("TkDefaultFont", 9, "bold")).grid(row=row_idx, column=2, sticky="w", padx=4)
            ttk.Radiobutton(inner, text="Yes", variable=var, value="Yes").grid(row=row_idx, column=3, padx=4)
            ttk.Radiobutton(inner, text="No", variable=var, value="No").grid(row=row_idx, column=4, padx=4)
            row_idx += 1

        if not_found:
            ttk.Separator(inner, orient="horizontal").grid(row=row_idx, column=0, columnspan=6,
                                                           sticky="ew", pady=6)
            row_idx += 1
            ttk.Label(inner, text="Các rule không thể thao tác (không còn tồn tại trong config hiện tại):",
                      foreground="#888888").grid(row=row_idx, column=0, columnspan=6, sticky="w")
            row_idx += 1
            for name, _loai in not_found:
                var = tk.StringVar(value="No")
                ttk.Label(inner, text=name, foreground="#AAAAAA").grid(row=row_idx, column=0,
                                                                       sticky="w", padx=4, pady=1)
                ttk.Radiobutton(inner, text="Yes", variable=var, value="Yes",
                                state="disabled").grid(row=row_idx, column=3, padx=4)
                ttk.Radiobutton(inner, text="No", variable=var, value="No").grid(row=row_idx, column=4, padx=4)
                ttk.Label(inner, text="Không còn tồn tại trong cấu hình hiện tại — có thể đã đổi tên/xoá từ trước",
                          foreground="#AAAAAA").grid(row=row_idx, column=1, columnspan=2, sticky="w")
                vars_.append(var)
                row_idx += 1

        btn_row = ttk.Frame(dlg)
        btn_row.pack(fill="x", pady=6)

        def on_confirm():
            yes = [c for c, _v in zip(candidates, vars_[:len(candidates)]) if _v.get() == "Yes"]
            dlg.destroy()
            if not yes:
                self._log("Bạn đã chọn No cho tất cả → không thao tác rule nào.")
                return
            names = [f"{c[0]}({c[5]})" for c in yes]
            self._log(f"Xác nhận thao tác {len(names)} rule trên Candidate Config: {', '.join(names)}")
            self._set_busy(True)
            threading.Thread(target=self._delete_worker,
                             args=(yes, self._mgmt_ip, self._api_key, self._verify_ssl, self._target_serial),
                             daemon=True).start()

        ttk.Button(btn_row, text="Xác nhận", command=on_confirm).pack(side="left", padx=8)
        ttk.Button(btn_row, text="Huỷ", command=dlg.destroy).pack(side="left", padx=8)

        # Enter = Xác nhận, Escape = Huỷ (ngoài việc bấm trực tiếp).
        dlg.bind("<Return>", lambda e: on_confirm())
        dlg.bind("<Escape>", lambda e: dlg.destroy())

    def _delete_worker(self, candidates, mgmt_ip, api_key, verify_ssl, target_serial=""):
        """
        R1-R4: Xác minh batch trước khi Disable/Delete - chi phí cố định 4-5 API call/batch.
        candidates: List[(name, loai, vi_tri, devicegroup, rulebase, action)] action=disable|delete
        target_serial: str từ ô Target Firewall (Serial), có thể rỗng (degrade im lặng 0.7)
        """
        # R2: Batch xác minh (chỉ 1 lần cho cả batch)
        fresh_hit_stats = {}
        fresh_states = None
        # R2.a: fresh hit stats nếu có target
        if target_serial:
            try:
                self._log(f"Xác minh batch: đọc lại hit-count cho Target={target_serial}...")
                # P1: xac minh lai PHAI dung dung pham vi nhu luc Check, neu khong
                # thi buoc xac minh se "xac nhan" bang so lieu hep hon chinh cai
                # da dung de ket luan - vo nghia.
                _ser_v = self._hitcount_serials(getattr(self, '_dg_name', '') or '', target_serial)
                fresh_hit_stats = fetch_rule_hit_count_multi(mgmt_ip, api_key, _ser_v, verify_ssl=verify_ssl, log_func=self._log)
                self._log(f"  -> fresh_hit_stats: {len(fresh_hit_stats)} entry (khoá (name,vi_tri))")
            except Exception as e:
                self._log(f"CANH BAO: fetch_rule_hit_count lỗi best-effort: {e} -> bỏ xác minh hit-count")
                fresh_hit_stats = {}
        else:
            self._log("Xác minh batch: không có Target Serial -> bỏ qua kiểm tra hit-count (degrade im lặng 0.7)")
            fresh_hit_stats = {}
        # R2.b: fresh rule states 4 lệnh wildcard
        try:
            self._log("Xác minh batch: đọc lại Candidate Config 4 wildcard (Shared-PRE/POST + DG PRE/POST)...")
            fresh_states = fetch_current_rule_states(mgmt_ip, api_key, verify_ssl=verify_ssl, log_func=self._log)
            if fresh_states is None:
                self._log("  -> fresh_states: None (lỗi 1 trong 4 lệnh) -> bỏ xác minh, dùng dữ liệu Check cũ")
            else:
                self._log(f"  -> fresh_states: {len(fresh_states)} rule (khoá (name,vi_tri))")
        except Exception as e:
            self._log(f"CANH BAO: fetch_current_rule_states lỗi best-effort: {e} -> bỏ xác minh")
            fresh_states = None

        ok_disable, ok_delete = 0, 0
        filtered_verify = 0  # Z: bị loại khi xác minh lại
        skipped_already = 0  # W: đã ở trạng thái mong muốn sẵn
        fail = []  # V: lỗi API thật

        for name, _loai, vi_tri, dg, rb, action in candidates:
            if self.cancel_event.is_set():
                self._log("Đã huỷ theo yêu cầu (shutdown).")
                break

            # R3: Tra cứu tại chỗ bằng (name, vi_tri), không gọi API trong loop
            state = None
            if fresh_states is not None:
                state = fresh_states.get((name, vi_tri))
                if state is None:
                    self._log(f"  -> Bỏ qua '{name}' ({vi_tri}): Rule không còn tồn tại đúng vị trí tại thời điểm thực thi")
                    filtered_verify += 1
                    continue

            # Lấy orig data để so sánh S/D/S (từ rule_by_key lúc Check)
            orig = self.rule_by_key.get((name, vi_tri)) if hasattr(self, 'rule_by_key') else None

            # 2) Disabled->delete nhưng đã enable lại
            if action == "delete" and state is not None and state.get("disabled") is False:
                self._log(f"  -> Bỏ qua '{name}' ({vi_tri}): Rule đã được enable lại, không còn là Disabled Rule")
                filtered_verify += 1
                continue

            # 3) Shadow->disable nhưng đã disabled sẵn -> bỏ qua an toàn, không fail, không gọi lại API
            if action == "disable" and state is not None and state.get("disabled") is True:
                self._log(f"  -> Bỏ qua '{name}' ({vi_tri}): đã disabled sẵn, bỏ qua gọi API thừa")
                skipped_already += 1
                continue

            # 4) Shadow->disable nhưng S/D/S đã bị sửa (SỬA 2026-09-02 audit: so sánh set thay vì list để tránh sai do thứ tự <member> khác)
            if action == "disable" and state is not None and orig is not None:
                if (set(state.get("source") or []) != set(orig.source) or
                    set(state.get("destination") or []) != set(orig.destination) or
                    set(state.get("service") or []) != set(orig.service)):
                    self._log(f"  -> Bỏ qua '{name}' ({vi_tri}): Rule đã bị chỉnh sửa Source/Destination/Service từ lúc Check - cần Check lại")
                    filtered_verify += 1
                    continue

            # 5) Shadow->disable + có target + có fresh_hit_stats + hit_count is not None (0-hit luôn None theo D10)
            if action == "disable" and target_serial and fresh_hit_stats:
                stat = fresh_hit_stats.get((name, vi_tri))
                if stat is not None and stat.hit_count is not None:
                    self._log(f"  -> Bỏ qua '{name}' ({vi_tri}): Hit Count đã thay đổi kể từ lúc Check (hit={stat.hit_count}) - bỏ qua để an toàn")
                    filtered_verify += 1
                    continue

            # Ngược lại -> tiếp tục gọi API như cũ
            try:
                if action == "disable":
                    disable_rule_candidate(mgmt_ip, api_key, dg, rb, name, verify_ssl=verify_ssl)
                    ok_disable += 1
                    self._log(f"  -> Disable candidate OK: '{name}' ({rb}/{dg})")
                else:
                    delete_rule_candidate(mgmt_ip, api_key, dg, rb, name, verify_ssl=verify_ssl)
                    ok_delete += 1
                    self._log(f"  -> Xoá candidate OK: '{name}' ({rb}/{dg})")
            except PanApiError as e:
                fail.append((name, f"{action} {rb}/{dg}: {e.user_message}"))
                self._log(f"  -> {action.upper()} candidate LỖI '{name}' ({rb}/{dg}): {e.user_message} (tiếp tục rule khác - Continue)")
            except Exception as e:
                fail.append((name, f"{action} {rb}/{dg}: {e}"))
                self._log(f"  -> {action.upper()} candidate LỖI KHÔNG XÁC ĐỊNH '{name}' ({rb}/{dg}): {e}")

        self.msg_queue.put(("done_delete", (ok_disable, ok_delete, filtered_verify, skipped_already, fail)))

    def _finish_delete(self, payload):
        ok_disable, ok_delete, filtered_verify, skipped_already, fail = payload
        total_ok = ok_disable + ok_delete
        msg = (f"Disable thành công (Candidate Config): {ok_disable} rule.\n"
               f"Xoá thành công (Candidate Config): {ok_delete} rule.\n"
               f"Bị loại khi xác minh lại (config đã đổi từ lúc Check): {filtered_verify} rule.\n"
               f"Bỏ qua vì đã ở trạng thái mong muốn sẵn: {skipped_already} rule.\n"
               f"Tổng thành công: {total_ok} rule. Lỗi API: {len(fail)} rule.")
        for name, err in fail[:10]:
            msg += f"\n  - {name}: {err}"
        if len(fail) > 10:
            msg += f"\n  ... (xem log.txt để biết {len(fail) - 10} lỗi còn lại)"
        msg += ("\n\nCác thay đổi trên CHỈ nằm ở Candidate Config của Panorama (chưa commit). "
                "Vui lòng vào Panorama review rồi Commit theo 2 tầng: "
                "Commit to Panorama → Commit and Push, để áp dụng xuống Firewall (0.4).")
        messagebox.showinfo("Kết quả thao tác", msg)
        self._set_busy(False)

    # -------------------------------------------------------------- misc
    def shutdown(self):
        """Goi khi CUA SO CHINH cua Suite dang dong lai - CHI huy cac tac vu
        dang chay (set cancel_event), KHONG tu destroy() gi ca."""
        self._closing = True
        self.cancel_event.set()
        if self._poll_after_id is not None:
            try:
                self.root.after_cancel(self._poll_after_id)
            except Exception:
                pass
            self._poll_after_id = None


def _build_service_info_from(service_objects, service_groups):
    from .core import build_service_info
    return build_service_info(service_objects, service_groups)


if __name__ == "__main__":
    _root = tk.Tk()
    _root.title("Check Audit (Panorama)")
    _root.geometry("1100x820")
    _root.minsize(940, 680)
    try:
        _style = ttk.Style()
        if "clam" in _style.theme_names():
            _style.theme_use("clam")
    except Exception:
        pass
    _app = App(_root)
    _app.pack(fill="both", expand=True)

    def _on_close_standalone():
        _app.shutdown()
        _root.destroy()

    _root.protocol("WM_DELETE_WINDOW", _on_close_standalone)
    _root.mainloop()
