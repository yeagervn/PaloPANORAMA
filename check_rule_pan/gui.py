# -*- coding: utf-8 -*-
import os
import sys
import threading
import subprocess
import queue
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import xml.etree.ElementTree as ET

from .core import fetch_panorama_config_xml, load_pan_config_from_xml_string, configure_live_match_concurrency, \
    fetch_candidate_config_xml, parse_candidate_config, diff_candidate_config, get_panorama_devicegroups, \
    list_devicegroups
from .resolver import GroupResolver, ServiceResolver
from .index import build_device_index, build_zone_lookup
from .request import parse_request_file, build_manual_request
from .matcher import build_rule_infos, classify_row, apply_candidate_overlay
from .exporter import export_results

SAME_SUBNET_PREFIX = 24
DEFAULT_THREADS = 30
MIN_THREADS = 20
MAX_THREADS = 70


class PANOSCheckerGUI(ttk.Frame):
    """Giao dien tool CHECK RULE (BAN PANORAMA) - selenium 1 ttk.Frame de nhung duoc
    vao ttk.Notebook cua Suite.

    Thay doi so vs ban Firewall standalone:
      - 'Management IP' -> 'Panorama IP'
      - dropdown 'VSYS' -> dropdown 'Device Group' (populate sau Connect)
      - them o 'Target Firewall (Serial) - tùy chọn' (0.1) - bat buoc cho Live Match
        (0.5) va Zone awareness tu Template (0.6); thieu -> 2 tinh nang nay tu vo hieu
        im lang.
    """

    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

        self.rule_infos = None
        self.idx = None
        self.candidate_rule_infos = None
        self.candidate_idx = None
        self.zone_lookup = None
        self.dg_used = None
        self.full_config_xml = None
        self._tree_edit_entry = None
        self._log_queue = queue.Queue()
        self.last_output_dir = None
        self.last_output_path = None

        self._build_ui()
        self.after(100, self._drain_log_queue)

    def _build_ui(self):
        config_frame = ttk.LabelFrame(self, text="1. Kết nối Panorama (API)", padding=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        ttk.Label(config_frame, text="Panorama IP:").grid(row=0, column=0, sticky="w", pady=5)
        self.mgmt_ip_var = tk.StringVar()
        mgmt_ip_entry = ttk.Entry(config_frame, textvariable=self.mgmt_ip_var, width=25)
        mgmt_ip_entry.grid(row=0, column=1, sticky="w", padx=5)

        ttk.Label(config_frame, text="API Key:").grid(row=1, column=0, sticky="w")
        self.api_key_var = tk.StringVar()
        api_key_entry = ttk.Entry(config_frame, textvariable=self.api_key_var, width=50, show="*")
        api_key_entry.grid(row=1, column=1, sticky="w", padx=5)

        ttk.Button(config_frame, text="Load Config", command=self._start_load_config).grid(row=1, column=2, padx=5)

        mgmt_ip_entry.bind("<Return>", lambda e: self._start_load_config())
        api_key_entry.bind("<Return>", lambda e: self._start_load_config())

        # Device Group dropdown + Target Firewall (0.1)
        ttk.Label(config_frame, text="Device Group:").grid(row=2, column=0, sticky="w", pady=5)
        self.dg_var = tk.StringVar()
        self.dg_combo = ttk.Combobox(config_frame, textvariable=self.dg_var, width=40, state="readonly")
        self.dg_combo.grid(row=2, column=1, sticky="w", padx=5)

        ttk.Label(config_frame, text="Target Firewall (Serial) - tùy chọn:").grid(row=3, column=0, sticky="w")
        self.target_serial_var = tk.StringVar()
        ttk.Entry(config_frame, textvariable=self.target_serial_var, width=40).grid(row=3, column=1, sticky="w", padx=5)
        ttk.Label(config_frame, text="(Bắt buộc cho Live Match & Zone)", foreground="#666666").grid(
            row=3, column=2, sticky="w", padx=5)

        # 2. Mode Request Frame
        req_frame = ttk.LabelFrame(self, text="2. File Request / Nhập tay cần kiểm tra", padding=10)
        req_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.input_mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(req_frame, text="Chọn file (.xlsx / .csv)", variable=self.input_mode_var,
                        value="file", command=self._toggle_mode).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(req_frame, text="Nhập tay trực tiếp", variable=self.input_mode_var,
                        value="manual", command=self._toggle_mode).grid(row=0, column=1, sticky="w")

        self.file_subframe = ttk.Frame(req_frame)
        self.file_subframe.grid(row=1, column=0, columnspan=3, sticky="we", pady=5)
        ttk.Label(self.file_subframe, text="File Request:").pack(side="left")
        self.req_file_var = tk.StringVar()
        req_file_entry = ttk.Entry(self.file_subframe, textvariable=self.req_file_var, width=50)
        req_file_entry.pack(side="left", padx=5)
        ttk.Button(self.file_subframe, text="Browse...", command=self._browse_req_file).pack(side="left")
        req_file_entry.bind("<Return>", lambda e: self._start_check())

        self.manual_subframe = ttk.Frame(req_frame)
        columns = ("src", "dst", "port")
        self.tree = ttk.Treeview(self.manual_subframe, columns=columns, show="headings", height=8)
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Dest IP")
        self.tree.heading("port", text="Port")
        self.tree.column("src", width=250)
        self.tree.column("dst", width=250)
        self.tree.column("port", width=150)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_tree_double_click)

        btn_box = ttk.Frame(self.manual_subframe)
        btn_box.pack(side="left", fill="y", padx=5)
        ttk.Button(btn_box, text="+ Thêm dòng", command=self._add_manual_row).pack(fill="x", pady=2)
        ttk.Button(btn_box, text="Xóa dòng", command=self._del_manual_row).pack(fill="x", pady=2)
        ttk.Button(btn_box, text="Xóa tất cả", command=self._clear_manual_rows).pack(fill="x", pady=2)
        ttk.Label(btn_box, text="(Nhấp đúp vào ô\nđể nhập/sửa giá trị)",
                  foreground="#666666", justify="left").pack(fill="x", pady=(8, 2))

        self._toggle_mode()

        exec_frame = ttk.Frame(self, padding=10)
        exec_frame.pack(fill="both", expand=True, padx=10, pady=5)

        run_bar = ttk.Frame(exec_frame)
        run_bar.pack(fill="x", anchor="w")

        ttk.Button(run_bar, text="Check", command=self._start_check).pack(side="left")

        ttk.Label(run_bar, text="   Số lượng Thread:").pack(side="left")
        self.thread_var = tk.IntVar(value=DEFAULT_THREADS)
        ttk.Spinbox(run_bar, from_=MIN_THREADS, to=MAX_THREADS, textvariable=self.thread_var,
                    width=5, wrap=False).pack(side="left", padx=(0, 5))
        ttk.Label(run_bar, text=f"({MIN_THREADS}-{MAX_THREADS}, mặc định {DEFAULT_THREADS})",
                  foreground="#666666").pack(side="left")

        self.browse_output_btn = ttk.Button(run_bar, text="Browse Output...",
                                             command=self._browse_output, state="disabled")
        self.browse_output_btn.pack(side="left", padx=(10, 0))

        ttk.Label(exec_frame, text="Nhật ký xử lý:").pack(anchor="w", pady=(5, 0))
        self.log_text = tk.Text(exec_frame, height=10, state="disabled")
        self.log_text.pack(fill="both", expand=True)

    def _log(self, msg: str):
        self._log_queue.put(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

    def _drain_log_queue(self):
        pending = []
        try:
            while True:
                pending.append(self._log_queue.get_nowait())
        except queue.Empty:
            pass
        if pending:
            self.log_text.config(state="normal")
            self.log_text.insert("end", "".join(pending))
            self.log_text.see("end")
            self.log_text.config(state="disabled")
        self.after(100, self._drain_log_queue)

    def _toggle_mode(self):
        if self.input_mode_var.get() == "file":
            self.manual_subframe.grid_remove()
            self.file_subframe.grid(row=1, column=0, columnspan=3, sticky="we", pady=5)
        else:
            self.file_subframe.grid_remove()
            self.manual_subframe.grid(row=1, column=0, columnspan=3, sticky="nsew", pady=5)

    def _browse_req_file(self):
        path = filedialog.askopenfilename(filetypes=[("Excel/CSV Files", "*.xlsx *.csv"), ("All Files", "*.*")])
        if path:
            self.req_file_var.set(path)

    def _open_path(self, path: str):
        if os.name == 'nt':
            os.startfile(path)
        else:
            subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', path])

    def _browse_output(self):
        if not self.last_output_dir or not os.path.exists(self.last_output_dir):
            messagebox.showinfo("Thông báo", "Chưa có file kết quả nào trong phiên làm việc này - "
                                               "vui lòng bấm 'Check' trước.")
            return
        self._open_path(self.last_output_dir)

    # ---- Treeview ----
    def _add_manual_row(self):
        self.tree.insert("", "end", values=("", "", ""))

    def _del_manual_row(self):
        self._commit_tree_edit()
        for item in self.tree.selection():
            self.tree.delete(item)

    def _clear_manual_rows(self):
        self._commit_tree_edit()
        for item in self.tree.get_children():
            self.tree.delete(item)

    def _commit_tree_edit(self):
        if self._tree_edit_entry is not None:
            try:
                self._tree_edit_entry.event_generate("<Return>")
            except tk.TclError:
                pass

    def _on_tree_double_click(self, event):
        self._commit_tree_edit()
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)
        if not row_id or not col_id:
            return
        col_index = int(col_id.replace("#", "")) - 1
        col_name = self.tree["columns"][col_index]
        bbox = self.tree.bbox(row_id, col_id)
        if not bbox:
            return
        x, y, w, h = bbox
        current_value = self.tree.set(row_id, col_name)
        entry = ttk.Entry(self.tree)
        entry.place(x=x, y=y, width=w, height=h)
        entry.insert(0, current_value)
        entry.select_range(0, "end")
        entry.focus()
        self._tree_edit_entry = entry

        def _save(event=None):
            if self._tree_edit_entry is entry:
                self.tree.set(row_id, col_name, entry.get())
                entry.destroy()
                self._tree_edit_entry = None

        def _cancel(event=None):
            if self._tree_edit_entry is entry:
                entry.destroy()
                self._tree_edit_entry = None

        entry.bind("<Return>", _save)
        entry.bind("<KP_Enter>", _save)
        entry.bind("<FocusOut>", _save)
        entry.bind("<Escape>", _cancel)

    # ---- Load config (Panorama) ----
    def _start_load_config(self):
        mgmt_ip = self.mgmt_ip_var.get().strip()
        api_key = self.api_key_var.get().strip()
        if not mgmt_ip or not api_key:
            messagebox.showerror("Lỗi", "Vui lòng nhập đầy đủ Panorama IP và API Key.")
            return

        def _worker():
            self._log(f"Đang đăng nhập và đọc running-config từ Panorama {mgmt_ip} qua API...")
            try:
                xml_text = fetch_panorama_config_xml(mgmt_ip, api_key)
                self.full_config_xml = xml_text
                root = ET.fromstring(xml_text)
                dg_list = list_devicegroups(root)
                if not dg_list:
                    # Fallback: thu lay tu op command
                    try:
                        dg_list = get_panorama_devicegroups(mgmt_ip, api_key)
                    except Exception:
                        dg_list = []
                if not dg_list:
                    raise RuntimeError("Không tìm thấy Device Group nào trong cấu hình Panorama.")

                # Populate dropdown (chay tren main thread)
                self.after(0, lambda: self._populate_dg(dg_list))
                dg_name = self.dg_var.get().strip() or dg_list[0]
                target_serial = self.target_serial_var.get().strip() or None

                cfg = load_pan_config_from_xml_string(xml_text, dg_name, target_serial)

                group_resolver = GroupResolver(cfg['address_objects'], cfg['address_groups'])
                svc_resolver = ServiceResolver(cfg['service_objects'], cfg['service_groups'])
                idx = build_device_index(cfg, group_resolver, svc_resolver)
                rule_infos = build_rule_infos(cfg['rules'], group_resolver, svc_resolver)

                zone_lookup = []
                if target_serial:
                    try:
                        zone_lookup = build_zone_lookup(cfg.get('interface_subnets', []), cfg.get('zones', {}))
                        if zone_lookup:
                            self._log(f"Đã dựng bảng tra cứu Zone từ Template (Target: {target_serial}), "
                                      f"{len(zone_lookup)} subnet.")
                        else:
                            self._log("Không dựng được bảng Zone từ Template của Target "
                                      "(không tìm thấy Template/Interface/Zone) - tính năng thiếu Zone "
                                      "sẽ không hoạt động (không ảnh hưởng tính năng khác).")
                    except Exception as e:
                        self._log(f"Cảnh báo: không dựng được bảng Zone ({e}) - bỏ qua tính năng này.")
                else:
                    self._log("Chưa nhập Target Firewall - tính năng Live Match và Zone bị tắt (im lặng).")

                candidate_rule_infos = []
                candidate_idx = None
                try:
                    cand_xml = fetch_candidate_config_xml(mgmt_ip, api_key)
                    cand_cfg = parse_candidate_config(cand_xml, dg_name, target_serial)
                    diff_cfg = diff_candidate_config(cfg, cand_cfg)
                    cand_group_resolver = GroupResolver(cand_cfg['address_objects'], cand_cfg['address_groups'])
                    cand_svc_resolver = ServiceResolver(cand_cfg['service_objects'], cand_cfg['service_groups'])
                    candidate_idx = build_device_index(diff_cfg, cand_group_resolver, cand_svc_resolver)
                    candidate_rule_infos = build_rule_infos(diff_cfg['rules'], cand_group_resolver, cand_svc_resolver)
                    n_new_rules = len(diff_cfg['rules'])
                    n_new_objs = (len(diff_cfg['address_objects']) + len(diff_cfg['address_groups']) +
                                   len(diff_cfg['service_objects']) + len(diff_cfg['service_groups']))
                    if n_new_rules or n_new_objs:
                        self._log(f"Ghi nhận {n_new_rules} rule và {n_new_objs} object/group THẬT SỰ "
                                   f"mới/thay đổi trong candidate-config (CHƯA commit) - chỉ dùng để "
                                   f"cảnh báo tham khảo, KHÔNG dùng để kết luận traffic đã được phép. "
                                   f"[Panorama 2 tang: Commit to Panorama -> Commit and Push (0.4)]")
                except Exception as e:
                    self._log(f"Cảnh báo: không lấy được candidate-config để đối chiếu thay đổi "
                               f"chưa commit ({e}) - vẫn tiếp tục với running-config như cũ.")

                self.idx = idx
                self.rule_infos = rule_infos
                self.zone_lookup = zone_lookup
                self.candidate_rule_infos = candidate_rule_infos
                self.candidate_idx = candidate_idx
                self.dg_used = dg_name
                self._log(f"Nạp thành công {len(cfg['rules'])} rules (Device Group: {dg_name}).")
                self._log(f"Chuỗi thừa kế Device Group: {' -> '.join(cfg.get('devicegroup_chain', []))}")
                messagebox.showinfo("Thông báo", "Đọc cấu hình từ Panorama thành công!")
            except Exception as e:
                self._log(f"Lỗi nạp config: {e}")
                messagebox.showerror("Lỗi", str(e))

        threading.Thread(target=_worker, daemon=True).start()

    def _populate_dg(self, dg_list):
        self.dg_combo['values'] = dg_list
        if not self.dg_var.get():
            self.dg_var.set(dg_list[0])

    def _start_check(self):
        self._commit_tree_edit()

        if not self.rule_infos:
            messagebox.showwarning("Cảnh báo", "Vui lòng 'Load Config' trước khi kiểm tra.")
            return

        mode = self.input_mode_var.get()
        mgmt_ip = self.mgmt_ip_var.get().strip()
        api_key = self.api_key_var.get().strip()
        target_serial = self.target_serial_var.get().strip() or None
        thread_count = max(MIN_THREADS, min(MAX_THREADS, self.thread_var.get() or DEFAULT_THREADS))
        configure_live_match_concurrency(thread_count)

        headers = []
        rows = []
        if mode == "file":
            req_path = self.req_file_var.get().strip()
            if not req_path or not os.path.exists(req_path):
                messagebox.showerror("Lỗi", "File Request không hợp lệ.")
                return
            parsed = parse_request_file(req_path)
            headers, rows = parsed.headers, parsed.rows
        else:
            raw_tuples = []
            for item in self.tree.get_children():
                vals = self.tree.item(item, "values")
                raw_tuples.append((vals[0], vals[1], vals[2]))
            if not raw_tuples:
                messagebox.showwarning("Cảnh báo", "Bảng nhập tay hiện đang trống.")
                return
            parsed = build_manual_request(raw_tuples)
            headers, rows = parsed.headers, parsed.rows

        def _worker():
            self._log(f"Bắt đầu kiểm tra {len(rows)} kết nối (Thread: {thread_count})...")
            results = [None] * len(rows)
            # 0.5: xac dinh vsys that tren target firewall (best-effort), fallback vsys1
            vsys_for_live = "vsys1"
            if target_serial and self.full_config_xml:
                try:
                    _r = ET.fromstring(self.full_config_xml)
                    for dev in _r.findall("./devices/entry"):
                        if dev.get('name') == target_serial:
                            v = dev.find("vsys/entry")
                            if v is not None and v.get('name'):
                                vsys_for_live = v.get('name')
                                break
                    if vsys_for_live == "vsys1":
                        fe = _r.find(".//vsys/entry")
                        if fe is not None and fe.get('name'):
                            vsys_for_live = fe.get('name')
                except Exception:
                    pass

            def _process(item):
                i, row = item
                res = classify_row(
                    row,
                    self.rule_infos,
                    self.idx,
                    same_subnet_prefix=SAME_SUBNET_PREFIX,
                    mgmt_ip=mgmt_ip,
                    api_key=api_key,
                    vsys=vsys_for_live,
                    max_workers=thread_count,
                    log_func=self._log,
                    zone_lookup=self.zone_lookup,
                    target_serial=target_serial,
                )
                if res.tier != 'LIVE_MATCH':
                    apply_candidate_overlay(res, row, self.candidate_rule_infos, self.candidate_idx)
                return i, res

            workers = min(thread_count, max(1, len(rows)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for i, res in executor.map(_process, enumerate(rows)):
                    results[i] = res

            if mode == "manual":
                self._log("=== KẾT QUẢ KIỂM TRA TRỰC TIẾP (NHẬP TAY) ===")
                summary_lines = []
                for i, res in enumerate(results, 1):
                    rule_nm = res.rule.name if res.rule else "Chưa có"
                    vi_tri = res.rule.vi_tri if res.rule else ""
                    msg = f"Dòng {i}: Status [{res.tier}] | Matched Rule: {rule_nm}"
                    if vi_tri:
                        msg += f" ({vi_tri})"
                    if res.note:
                        msg += f" | {res.note}"
                    self._log(msg)
                    summary_lines.append(msg)
                messagebox.showinfo(
                    "Kết quả Test Policy Match",
                    "Đã hoàn thành kiểm tra trực tiếp:\n\n" + "\n".join(summary_lines)
                )
            else:
                self._log("Đang xuất kết quả ra file Excel...")
                out_dir = os.path.dirname(os.path.abspath(self.req_file_var.get().strip()))
                input_base = os.path.splitext(os.path.basename(self.req_file_var.get().strip()))[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                out_path = os.path.join(out_dir, f"Result_{input_base}_{timestamp}.xlsx")

                export_results(headers, results, out_path)
                self._log(f"Đã xuất file thành công: {out_path}")

                self.last_output_dir = out_dir
                self.last_output_path = out_path
                self.after(0, lambda: self.browse_output_btn.config(state="normal"))

                self._open_path(out_dir)

                messagebox.showinfo(
                    "PAN-OS Request Checker",
                    f"ĐÃ HOÀN THÀNH! Tổng cộng: {len(results)} dòng.\n\n"
                    f"File kết quả:\n{out_path}\n\n"
                    f"Thư mục chứa file đã được mở."
                )

        threading.Thread(target=_worker, daemon=True).start()


if __name__ == "__main__":
    _root = tk.Tk()
    _root.title("PAN-OS Policy & Request Matcher - CHECK RULE (Panorama)")
    _root.geometry("980x760")
    app = PANOSCheckerGUI(_root)
    app.pack(fill="both", expand=True)
    _root.mainloop()
