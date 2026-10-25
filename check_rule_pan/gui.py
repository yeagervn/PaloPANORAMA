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

from .core import (fetch_panorama_config_xml, load_pan_config_from_xml_string,
                    configure_live_match_concurrency, fetch_candidate_config_xml,
                    parse_candidate_config, diff_candidate_config,
                    get_panorama_devicegroups, get_panorama_devices,
                    list_devicegroups, devicegroup_devices)
from .resolver import GroupResolver, ServiceResolver
from .index import build_device_index, build_zone_lookup
from .request import parse_request_file, build_manual_request
from .matcher import build_rule_infos, classify_row, apply_candidate_overlay
from .exporter import export_results

SAME_SUBNET_PREFIX = 24
DEFAULT_THREADS = 30
MIN_THREADS = 20
MAX_THREADS = 70
# Gioi han so to hop Source x Dest x Port toi da cho Live Match (Test Policy Match)
# tren 1 dong request - tran an toan de tranh 1 dong cuc lon lam treo tac vu hoac
# doi qua nhieu request vao firewall that. Cau hinh duoc tu o Spinbox tren GUI
# (mac dinh 300: voi 30 luong song song ~ 10 batch, chap nhan duoc cho tac vu nen).
DEFAULT_MAX_COMBOS = 300
MIN_MAX_COMBOS = 10
MAX_MAX_COMBOS = 2000
# Tong so API call Live Match (Test Policy Match) dong thoi TOI DA tren TOAN BO
# luot chay - DUNG CHUNG cho moi dong qua 1 threading.Semaphore khoi tao 1 lan
# (xem _start_check). Doc lap voi thread_count (so DONG chay song song): neu de
# moi dong tu mo executor rieng voi max_workers=thread_count, dinh diem co the
# len toi thread_count x thread_count request dong thoi vao CUNG 1 firewall
# (vd 30 -> ~900), vuot xa kha nang management plane PAN-OS. Co dinh 30 la du.
# S7 (10/2026): ha 30 -> 10 theo kinh nghiem van hanh.
# `test security-policy-match` chay tren MANAGEMENT PLANE, va mgmt plane la cho yeu
# nhat cua PA-3200/5200. 30 op-command dong thoi du de day mgmt CPU len cao va lam
# CHAM COMMIT/LOGGING CUA NGUOI KHAC - tool audit khong duoc phep gay ra dieu do.
# Them nua: moi call deu vao mgmt log, audit 2000 dong sinh hang chuc nghin dong
# log API, auditor se hoi. 10 van du nhanh (tran nay la tong toan tool, doc lap voi
# so DONG chay song song - xem live_match_semaphore).
# RIENG BAN PANORAMA con nang hon: moi op-command co target= deu duoc PANORAMA
# PROXY xuong firewall, va Panorama thuong la con undersize nhat trong estate -
# nen tran nay quan trong hon ca o ban standalone.
LIVE_MATCH_CONCURRENCY = 10


class PANOSCheckerGUI(ttk.Frame):
    """Giao dien tool CHECK RULE - dang 1 ttk.Frame de nhung duoc vao bat ky
    container nao (vd 1 tab cua ttk.Notebook trong PaloRuleSearchSuite), thay vi
    tu lam chu 1 cua so rieng (tk.Tk). Title/geometry cua CUA SO CHINH (neu chay
    doc lap qua khoi __main__ ben duoi, hoac khi nhung vao Suite) do NOI GOI
    (main.py) chiu trach nhiem - class nay khong con tu dat title/geometry nua."""

    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)

        self.rule_infos = None
        self.idx = None
        self.candidate_rule_infos = None
        self.candidate_idx = None
        self.zone_lookup = None
        # BAN PANORAMA: thay 1 "vsys dang chon" bang Device Group dang chon + (tuy
        # chon) serial firewall dich. `vsys_for_live` la vsys THAT tren firewall dich,
        # chi dung cho Live Match (0.5) - Device Group KHONG thay the duoc vsys.
        self.dg_used = None
        self.dg_list = []
        self.dg_devices = []
        self.vsys_for_live = "vsys1"
        self.full_config_xml = None
        self._tree_edit_entry = None
        self._log_queue = queue.Queue()
        # Hang doi cac viec PHAI chay tren main thread (mo hop thoai, doi trang
        # thai widget...). Worker thread CHI duoc day callable vao day, KHONG
        # duoc dung widget/messagebox truc tiep - Tkinter khong thread-safe.
        self._ui_queue = queue.Queue()
        # Dat khi cua so Suite dang dong (shutdown) - de worker dung som va de
        # vong lap _drain_log_queue tu ket thuc, thay vi goi after() tren widget
        # da bi destroy (gay RuntimeError: main thread is not in main loop).
        self.cancel_event = threading.Event()
        self._closing = False
        self._drain_after_id = None
        # Duong dan thu muc/chua file ket qua CUA LAN CHAY GAN NHAT (mode "file") -
        # dung cho nut "Browse Output" de nguoi dung tu mo lai bang tay bat ky luc nao
        # (khong chi luc vua chay xong tu dong mo 1 lan). None = chua co lan nao xuat
        # file thanh cong trong phien lam viec nay.
        self.last_output_dir = None
        self.last_output_path = None

        self._build_ui()
        self._drain_after_id = self.after(100, self._drain_log_queue)

    def _build_ui(self):
        # 1. Ket noi thiet bi (dang nhap bang API Key, doc thang running-config qua API)
        config_frame = ttk.LabelFrame(self, text="1. Kết nối PANORAMA (API)", padding=10)
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

        # BAN PANORAMA (0.1): dropdown "VSYS" cua ban Firewall doi thanh "Device Group".
        # Danh sach duoc nap sau khi Load Config; doi DG thi phai nap lai (object +
        # rulebase deu phu thuoc chuoi thua ke cua DG do).
        ttk.Label(config_frame, text="Device Group:").grid(row=2, column=0, sticky="w", pady=5)
        self.dg_var = tk.StringVar()
        self.cmb_dg = ttk.Combobox(config_frame, textvariable=self.dg_var, width=30, state="readonly")
        self.cmb_dg.grid(row=2, column=1, sticky="w", padx=5)
        self.cmb_dg.bind("<<ComboboxSelected>>", lambda e: self._on_dg_changed())

        # BAN PANORAMA (0.1 + 0.5/0.6/0.7): Target Firewall - TUY CHON, chi bat buoc
        # cho 3 tinh nang chay tren dataplane 1 firewall cu the (Live Match, Zone
        # awareness, Rule Hit Count). De trong -> 3 tinh nang do tu vo hieu IM LANG.
        # Dung Combobox (khong phai Entry) de chon tu danh sach thiet bi Panorama
        # dang quan ly - go tay 1 ky tu sai serial thi Live Match im lang khong chay,
        # rat kho phat hien.
        ttk.Label(config_frame, text="Target Firewall (Serial) - tùy chọn:").grid(row=3, column=0, sticky="w")
        self.target_serial_var = tk.StringVar()
        self.cmb_target = ttk.Combobox(config_frame, textvariable=self.target_serial_var, width=40)
        self.cmb_target.grid(row=3, column=1, sticky="w", padx=5)
        self.lbl_target_hint = ttk.Label(config_frame, text="(trống = bỏ qua Live Match / Zone)",
                                          foreground="#666666")
        self.lbl_target_hint.grid(row=3, column=2, sticky="w", padx=5)

        # Cho phep nhan Enter tren 2 o Management IP / API Key de chay Load Config
        # ngay, khong bat buoc phai click chuot vao nut - thuan tien khi go xong la
        # bam Enter lien tay.
        mgmt_ip_entry.bind("<Return>", lambda e: self._start_load_config())
        api_key_entry.bind("<Return>", lambda e: self._start_load_config())

        # 2. Mode Request Frame
        req_frame = ttk.LabelFrame(self, text="2. File Request / Nhập tay cần kiểm tra", padding=10)
        req_frame.pack(fill="both", expand=True, padx=10, pady=5)

        self.input_mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(req_frame, text="Chọn file (.xlsx / .csv)", variable=self.input_mode_var,
                        value="file", command=self._toggle_mode).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(req_frame, text="Nhập tay trực tiếp", variable=self.input_mode_var,
                        value="manual", command=self._toggle_mode).grid(row=0, column=1, sticky="w")

        # File Sub-frame
        self.file_subframe = ttk.Frame(req_frame)
        self.file_subframe.grid(row=1, column=0, columnspan=3, sticky="we", pady=5)
        ttk.Label(self.file_subframe, text="File Request:").pack(side="left")
        self.req_file_var = tk.StringVar()
        req_file_entry = ttk.Entry(self.file_subframe, textvariable=self.req_file_var, width=50)
        req_file_entry.pack(side="left", padx=5)
        ttk.Button(self.file_subframe, text="Browse...", command=self._browse_req_file).pack(side="left")

        # Nhan Enter ngay tren o File Request (vd sau khi Browse chon xong file, o nay
        # dang focus) de chay Check luon, khong bat buoc phai click chuot xuong nut
        # ben duoi.
        req_file_entry.bind("<Return>", lambda e: self._start_check())

        # Manual Input Sub-frame (Treeview co the sua truc tiep tung o)
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

        # 3. Execution Control & Log Output
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

        # SUA LOI (09/2026 - minh bach Live Match): nguong max_combos truoc day
        # hardcode 50 trong matcher, khong cach nao chinh tu giao dien - request
        # vai chuc Source x vai Dest (vd 23x5=115 combo) luon bi bo qua Live Match
        # ngay lap tuc. O Spinbox nay (cung pattern voi thread_count) cho phep
        # admin chinh tay, truyen xuong classify_row -> try_live_match.
        ttk.Label(run_bar, text="   Giới hạn tổ hợp Live Match:").pack(side="left")
        self.max_combos_var = tk.IntVar(value=DEFAULT_MAX_COMBOS)
        ttk.Spinbox(run_bar, from_=MIN_MAX_COMBOS, to=MAX_MAX_COMBOS,
                    textvariable=self.max_combos_var,
                    width=6, wrap=False).pack(side="left", padx=(0, 5))
        ttk.Label(run_bar, text=f"({MIN_MAX_COMBOS}-{MAX_MAX_COMBOS}, mặc định {DEFAULT_MAX_COMBOS})",
                  foreground="#666666").pack(side="left")

        # Nut mo lai file/thu muc ket qua CUA LAN CHAY GAN NHAT BANG TAY - bo sung
        # them cho co che tu dong mo thu muc ngay sau khi chay xong (vd nguoi dung lo
        # dong cua so do, hoac muon mo lai sau mot luc). Vo hieu hoa (disabled) cho
        # toi khi co it nhat 1 lan xuat file Excel thanh cong trong phien lam viec nay.
        self.browse_output_btn = ttk.Button(run_bar, text="Browse Output...",
                                             command=self._browse_output, state="disabled")
        self.browse_output_btn.pack(side="left", padx=(10, 0))

        ttk.Label(exec_frame, text="Nhật ký xử lý:").pack(anchor="w", pady=(5, 0))
        self.log_text = tk.Text(exec_frame, height=10, state="disabled")
        self.log_text.pack(fill="both", expand=True)

    def _log(self, msg: str):
        """An toan goi tu bat ky thread nao: chi day vao queue, khong dung truc tiep
        vao Tk widget (Tkinter khong thread-safe). Main thread se rut ra va ghi that
        theo lo trong _drain_log_queue()."""
        self._log_queue.put(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")

    def _ui(self, func):
        """An toan goi tu worker thread: xep 1 viec de MAIN THREAD chay.

        Dung cho moi thao tac cham vao Tk (messagebox, widget.config...).
        Khong lam gi neu cua so dang dong - tranh dung vao widget da destroy.
        """
        if self._closing:
            return
        self._ui_queue.put(func)

    def shutdown(self):
        """Goi khi CUA SO CHINH cua Suite dang dong lai (WM_DELETE_WINDOW).

        Dong vai tro y het shutdown() cua tab CHECK IP / CHECK AUDIT: huy tac
        vu dang chay, KHONG tu destroy() gi ca, va dung luon vong
        _drain_log_queue - neu khong, worker se goi after()/messagebox tren
        widget da bi destroy va nem RuntimeError("main thread is not in main
        loop").
        """
        self._closing = True
        self.cancel_event.set()
        if self._drain_after_id is not None:
            try:
                self.after_cancel(self._drain_after_id)
            except Exception:
                pass
            self._drain_after_id = None

    def _drain_log_queue(self):
        """Chay tren main thread (qua self.after) - rut het cac dong log dang cho trong
        queue va ghi 1 lan vao widget, thay vi tung dong rieng le -> giam so lan thao tac
        widget khi log den don dap tu nhieu worker thread cung luc."""
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

        # Cac viec worker thread nho chay ho tren main thread.
        while True:
            try:
                job = self._ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                job()
            except Exception as exc:
                self._log(f"Lỗi khi cập nhật giao diện: {exc}")

        if self._closing:
            self._drain_after_id = None
            return
        self._drain_after_id = self.after(100, self._drain_log_queue)

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
        """Mo 1 file/thu muc bang ung dung mac dinh cua OS - dung CHUNG cho 2 truong
        hop: (1) tu dong mo thu muc chua file ket qua ngay sau khi xuat xong, va (2)
        nut 'Browse Output' de nguoi dung tu mo lai bang tay bat ky luc nao."""
        if os.name == 'nt':
            os.startfile(path)
        else:
            subprocess.Popen(['open' if sys.platform == 'darwin' else 'xdg-open', path])

    def _browse_output(self):
        """Mo lai THU MUC chua file ket qua CUA LAN CHAY GAN NHAT (mode 'file') bang
        tay - danh cho truong hop nguoi dung da lo dong cua so tu dong mo truoc do,
        hoac muon mo lai sau mot luc lam viec khac. Neu chua co lan nao xuat file
        thanh cong trong phien lam viec nay, nut nay dang o trang thai disabled nen
        khong the bam toi (xem _build_ui/_start_check)."""
        if not self.last_output_dir or not os.path.exists(self.last_output_dir):
            messagebox.showinfo("Thông báo", "Chưa có file kết quả nào trong phiên làm việc này - "
                                               "vui lòng bấm 'Check' trước.")
            return
        self._open_path(self.last_output_dir)

    # ---- Treeview: them dong trong + cho phep sua truc tiep tung o ----

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
        """Neu dang co 1 o duoc edit dang mo, luu gia tri lai truoc khi thao tac khac."""
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
        col_id = self.tree.identify_column(event.x)  # vd: '#1', '#2', '#3'
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

    # ---- Load cau hinh: dang nhap bang API Key, doc thang running-config qua API ----

    @staticmethod
    def _normalize_serial(raw: str) -> str:
        """O Target Firewall la Combobox co the hien 'SERIAL  (hostname)' - lay lai
        dung phan serial truoc dau cach (nguoi dung van go tay thuan serial duoc)."""
        return (raw or '').strip().split()[0] if (raw or '').strip() else ''

    def _detect_vsys_for_target(self, root_el, target_serial) -> str:
        """0.5: `test security-policy-match` can vsys THAT tren chinh firewall dich -
        Device Group KHONG anh xa 1-1 sang vsys. Panorama luu vsys cua tung thiet bi
        o /config/devices/entry[@name=<serial>]/vsys/entry. Khong suy ra duoc -> dung
        'vsys1' (mac dinh pho bien nhat), dung tinh than "khong doan bua nhung van
        chay duoc" cua ban goc."""
        if not target_serial or root_el is None:
            return "vsys1"
        try:
            for dev in root_el.findall("./devices/entry"):
                if dev.get('name') != target_serial:
                    continue
                v = dev.find("vsys/entry")
                if v is not None and v.get('name'):
                    return v.get('name')
            # Panorama khong luu vsys cua thiet bi -> thu doan tu template cua no
            for dev in root_el.iter('devices'):
                for e in dev.findall('entry'):
                    if e.get('name') == target_serial:
                        v = e.find("vsys/entry")
                        if v is not None and v.get('name'):
                            return v.get('name')
        except Exception:
            pass
        return "vsys1"

    def _on_dg_changed(self):
        """Doi Device Group -> PHAI nap lai toan bo (object nap theo chuoi thua ke cua
        DG do, rulebase lap rap theo chinh DG do) - khong the tai su dung cfg cu."""
        if self.full_config_xml:
            self._log(f"Đã đổi Device Group sang '{self.dg_var.get()}' - đang nạp lại cấu hình...")
            self._start_load_config()

    def _start_load_config(self):
        mgmt_ip = self.mgmt_ip_var.get().strip()
        api_key = self.api_key_var.get().strip()
        if not mgmt_ip or not api_key:
            messagebox.showerror("Lỗi", "Vui lòng nhập đầy đủ Panorama IP và API Key.")
            return
        dg_wanted = self.dg_var.get().strip() or None
        target_serial = self._normalize_serial(self.target_serial_var.get()) or None

        def _worker():
            self._log(f"Đang đăng nhập và đọc config từ PANORAMA {mgmt_ip} qua API...")
            try:
                xml_text = fetch_panorama_config_xml(mgmt_ip, api_key)
                self.full_config_xml = xml_text

                # 0.1: danh sach Device Group - uu tien op-command, fallback doc thang
                # tu config (duong tin cay hon, luon co san vi vua tai ca cay config).
                root_el = ET.fromstring(xml_text)
                dg_list = list_devicegroups(root_el)
                try:
                    api_dgs = get_panorama_devicegroups(mgmt_ip, api_key)
                    for nm in api_dgs:
                        if nm not in dg_list:
                            dg_list.append(nm)
                except Exception:
                    pass
                if not dg_list:
                    raise RuntimeError(
                        "Không tìm thấy Device Group nào trong cấu hình Panorama. "
                        "Kiểm tra lại API Key có quyền đọc toàn bộ /config hay không.")
                self.dg_list = dg_list
                dg_name = dg_wanted if dg_wanted in dg_list else dg_list[0]

                # 0.1: danh sach serial de chon Target Firewall (best-effort)
                try:
                    devs = get_panorama_devices(mgmt_ip, api_key)
                    if devs:
                        # widget['values'] = ... la __setitem__ -> configure():
                        # cung la 1 loi goi vao Tcl, phai day ve main thread.
                        target_values = [
                            f"{sn}" + (f"  ({hn})" if hn else "") for sn, hn in devs]
                        self._ui(lambda: self.cmb_target.configure(values=target_values))
                except Exception:
                    pass

                cfg = load_pan_config_from_xml_string(xml_text, dg_name, target_serial)

                group_resolver = GroupResolver(cfg['address_objects'], cfg['address_groups'])
                svc_resolver = ServiceResolver(cfg['service_objects'], cfg['service_groups'])
                idx = build_device_index(cfg, group_resolver, svc_resolver)
                rule_infos = build_rule_infos(cfg['rules'], group_resolver, svc_resolver)

                zone_lookup = []
                try:
                    # B1 (10/2026): truyen ca static route. Thieu route thi cong chan
                    # zone chi hoat dong voi 2 dau mut nam trong subnet gan truc tiep -
                    # tuc gan nhu vo hieu voi traffic tu ngoai.
                    zone_lookup = build_zone_lookup(cfg.get('interface_subnets', []),
                                                     cfg.get('zones', {}),
                                                     routes=cfg.get('static_routes') or None)
                    if zone_lookup:
                        self._log(f"Đã dựng bảng tra cứu Zone từ {len(zone_lookup)} subnet interface trên thiết bị.")
                    else:
                        self._log("Không tìm thấy dữ liệu Interface/Zone phù hợp - tính năng cảnh báo "
                                   "thiếu Zone sẽ không hoạt động cho lần chạy này (không ảnh hưởng các "
                                   "tính năng khác).")
                except Exception as e:
                    self._log(f"Cảnh báo: không dựng được bảng tra cứu Zone ({e}) - bỏ qua tính năng này, "
                               f"vẫn tiếp tục bình thường với các tính năng khác.")

                # Doc CANDIDATE config (rule/object dang cho commit) - HOAN TOAN TACH
                # BIET, tu resolver/idx/rule_infos rieng, KHONG dung chung voi bo running
                # o tren (xem core.parse_candidate_config - ly do tach biet nghiem ngat
                # de tranh 1 group dang duoc rule running dung bi tinh sai la da cover
                # them member moi tren candidate). Neu buoc nay loi vi ly do gi, bo qua
                # va van tiep tuc voi du lieu running-config nhu truoc gio.
                candidate_rule_infos = []
                candidate_idx = None
                try:
                    cand_xml = fetch_candidate_config_xml(mgmt_ip, api_key)
                    cand_cfg = parse_candidate_config(cand_xml, cfg.get('devicegroup_used'))
                    # QUAN TRONG: candidate API tra ve TOAN BO cay cau hinh (khong phai
                    # diff) - phai loc xuong CHI con phan THAT SU moi/thay doi so voi
                    # running, neu khong gan nhu MOI item se bi gan nham la 'candidate'
                    # (vi trung voi rule/object von da co san tu truoc). Van dung
                    # cand_cfg GOC (chua loc) de dung lam RESOLVER context, dam bao rule/
                    # group moi tham chieu toi object cu KHONG doi van resolve dung.
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
                                   f"cảnh báo tham khảo, KHÔNG dùng để kết luận traffic đã được phép.")
                except Exception as e:
                    self._log(f"Cảnh báo: không lấy được candidate-config để đối chiếu thay đổi "
                               f"chưa commit ({e}) - vẫn tiếp tục với running-config như cũ.")

                self.idx = idx
                self.rule_infos = rule_infos
                self.zone_lookup = zone_lookup
                self.candidate_rule_infos = candidate_rule_infos
                self.candidate_idx = candidate_idx
                self.dg_used = cfg.get('devicegroup_used')
                self.dg_devices = cfg.get('devicegroup_devices') or []
                dg_values = list(dg_list)
                self._ui(lambda: self.cmb_dg.configure(values=dg_values))
                # tk.StringVar.set() cung la loi goi vao Tcl - day ve main thread.
                dg_shown = self.dg_used or ''
                self._ui(lambda: self.dg_var.set(dg_shown))

                chain = cfg.get('devicegroup_chain') or []
                self._log("Chuỗi thừa kế Device Group (object nạp theo thứ tự này, "
                          "DG sau đè DG trước): " + " -> ".join(chain))
                self._log(f"Nạp thành công {len(cfg['rules'])} rule đã LẮP RÁP theo đúng thứ tự "
                          f"PAN-OS đánh giá (Shared-PRE -> DG-chain-PRE -> DG-chain-POST -> "
                          f"Shared-POST) cho Device Group '{self.dg_used}'.")

                # 0.5/0.6: kiem tra cheo Target Firewall voi DG dang chon
                self.vsys_for_live = self._detect_vsys_for_target(root_el, target_serial)
                if target_serial:
                    if self.dg_devices and target_serial not in self.dg_devices:
                        self._log(f"CẢNH BÁO: serial '{target_serial}' KHÔNG nằm trong danh sách "
                                  f"thiết bị của Device Group '{self.dg_used}' ({', '.join(self.dg_devices)}). "
                                  f"Live Match vẫn chạy được nhưng rulebase bạn đang đối chiếu có thể "
                                  f"KHÔNG phải rulebase thật của firewall đó.")
                    tpl = cfg.get('template_used') or []
                    if tpl:
                        self._log(f"Zone lấy từ Template: {', '.join(tpl)} (Target {target_serial}).")
                    else:
                        self._log(f"Không tìm thấy Template gắn với serial '{target_serial}' - "
                                  f"tính năng cảnh báo thiếu Zone tự vô hiệu cho lần chạy này.")
                    self._log(f"Live Match sẽ gọi với target={target_serial}, vsys={self.vsys_for_live}.")
                else:
                    self._log("Không nhập Target Firewall - Live Match và cảnh báo Zone TỰ VÔ HIỆU "
                              "(chỉ chạy thuật toán LOCAL trên config Panorama).")
                self._ui(lambda: messagebox.showinfo(
                    "Thông báo", "Đọc cấu hình từ Panorama thành công!"))
            except Exception as e:
                self._log(f"Lỗi nạp config: {e}")
                msg = str(e)
                self._ui(lambda: messagebox.showerror("Lỗi", msg))

        threading.Thread(target=_worker, daemon=True).start()

    def _start_check(self):
        self._commit_tree_edit()

        if not self.rule_infos:
            messagebox.showwarning("Cảnh báo", "Vui lòng 'Load Config' trước khi kiểm tra.")
            return

        mode = self.input_mode_var.get()
        mgmt_ip = self.mgmt_ip_var.get().strip()
        api_key = self.api_key_var.get().strip()
        # Doc duong dan file NGAY TAI DAY (main thread) roi truyen vao worker qua
        # closure. tk.StringVar.get() cung la 1 loi goi vao Tcl - doc tu worker
        # thread nem RuntimeError("main thread is not in main loop") dung luc
        # chuan bi xuat file, tuc mat trang ca luot chay.
        req_file_path = self.req_file_var.get().strip()
        thread_count = max(MIN_THREADS, min(MAX_THREADS, self.thread_var.get() or DEFAULT_THREADS))
        configure_live_match_concurrency(thread_count)
        # BAN PANORAMA (0.5): doc lai serial tai thoi diem bam Check (nguoi dung co the
        # vua doi Target sau khi Load Config - Live Match dung ngay gia tri moi).
        target_serial = self._normalize_serial(self.target_serial_var.get()) or None
        max_combos = max(MIN_MAX_COMBOS, min(MAX_MAX_COMBOS,
                                             self.max_combos_var.get() or DEFAULT_MAX_COMBOS))

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
            self._log(f"Bắt đầu kiểm tra {len(rows)} kết nối (Thread: {thread_count}, "
                      f"Giới hạn tổ hợp Live Match: {max_combos})...")
            results = [None] * len(rows)
            # SUA LOI (09/2026 - hieu nang Live Match): khoi tao 1 LAN DUY NHAT cho
            # ca luot chay, dung chung cho MOI dong - KHONG tao moi moi dong:
            # - live_match_semaphore: tran TONG so API call Live Match dong thoi
            #   (30), ke ca khi nhieu dong chay song song (thread_count co the 70).
            #   Trong try_live_match(), moi lan goi API that deu `with` semaphore
            #   nay truoc - day moi la lop gioi han THUC SU (executor noi bo chi
            #   dieu phoi + early-exit qua as_completed).
            # - combo_cache: dedup combo TRUNG nhau giua cac dong (key
            #   (src_ip, dst_ip, port, proto)) - ket qua 1 combo bat bien trong
            #   1 luot chay nen tai su dung khong anh huong do chinh xac.
            live_match_semaphore = threading.Semaphore(LIVE_MATCH_CONCURRENCY)
            combo_cache: dict = {}

            def _process(item):
                i, row = item
                res = classify_row(
                    row,
                    self.rule_infos,
                    self.idx,
                    same_subnet_prefix=SAME_SUBNET_PREFIX,
                    mgmt_ip=mgmt_ip,
                    api_key=api_key,
                    vsys=self.vsys_for_live,
                    max_workers=thread_count,
                    log_func=self._log,
                    zone_lookup=self.zone_lookup,
                    max_combos=max_combos,
                    live_match_semaphore=live_match_semaphore,
                    combo_cache=combo_cache,
                    # BAN PANORAMA (0.5): khong co serial -> classify_row tu bo qua
                    # tier LIVE_MATCH, im lang, roi thang xuong thuat toan LOCAL.
                    target_serial=target_serial,
                )
                # Canh bao/bo sung THAM KHAO tu CANDIDATE config (rule/object chua
                # commit) - sua truc tiep source_report/dest_report/missing_ports cua
                # res, KHONG doi tier/action chinh dua tren running-config. Bo qua neu
                # da la LIVE_MATCH (da xac nhan chac chan qua thiet bi that).
                if res.tier != 'LIVE_MATCH':
                    apply_candidate_overlay(res, row, self.candidate_rule_infos, self.candidate_idx)
                return i, res

            workers = min(thread_count, max(1, len(rows)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                for i, res in executor.map(_process, enumerate(rows)):
                    results[i] = res
                    # Nguoi dung dong cua so giua chung -> dung ngay, khong xuat
                    # file dang do va khong dung vao widget nua.
                    if self.cancel_event.is_set():
                        self._log("Đã dừng theo yêu cầu (cửa sổ đang đóng).")
                        return

            # XỬ LÝ KẾT QUẢ THEO MODE
            if mode == "manual":
                # NHẬP TAY: Chỉ in trực tiếp ra GUI / Log, KHÔNG sinh file output
                self._log("=== KẾT QUẢ KIỂM TRA TRỰC TIẾP (NHẬP TAY) ===")
                summary_lines = []
                for i, res in enumerate(results, 1):
                    rule_nm = res.rule.name if res.rule else "Chưa có"
                    msg = f"Dòng {i}: Status [{res.tier}] | Matched Rule: {rule_nm}"
                    if res.note:
                        msg += f" | {res.note}"
                    self._log(msg)
                    summary_lines.append(msg)

                body = "Đã hoàn thành kiểm tra trực tiếp:\n\n" + "\n".join(summary_lines)
                self._ui(lambda: messagebox.showinfo("Kết quả Test Policy Match", body))

            else:
                # ĐỌC FILE: Xuất file Excel và TỰ ĐỘNG MỞ THƯ MỤC
                self._log("Đang xuất kết quả ra file Excel...")
                out_dir = os.path.dirname(os.path.abspath(req_file_path))
                input_base = os.path.splitext(os.path.basename(req_file_path))[0]
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                out_path = os.path.join(out_dir, f"Result_{input_base}_{timestamp}.xlsx")

                export_results(headers, results, out_path)
                self._log(f"Đã xuất file thành công: {out_path}")

                # Ghi lai duong dan cho nut "Browse Output" dung sau nay + bat nut do
                # len (dang bi disabled tu dau, xem _build_ui). Thao tac config() tren
                # widget PHAI chay tren main thread (Tkinter khong thread-safe) - dung
                # self.after(0, ...) de day ve main thread thay vi goi truc tiep tu day
                # (dang chay trong worker thread).
                self.last_output_dir = out_dir
                self.last_output_path = out_path
                self._ui(lambda: self.browse_output_btn.config(state="normal"))

                # Tự động mở thư mục chứa file
                self._open_path(out_dir)

                done_msg = (f"ĐÃ HOÀN THÀNH! Tổng cộng: {len(results)} dòng.\n\n"
                            f"File kết quả:\n{out_path}\n\n"
                            f"Thư mục chứa file đã được mở.")
                self._ui(lambda: messagebox.showinfo("PAN-OS Request Checker", done_msg))

        threading.Thread(target=_worker, daemon=True).start()


if __name__ == "__main__":
    # Cho phep chay/test doc lap tool CHECK RULE (khong qua Suite chinh) - tu dung
    # 1 cua so tk.Tk() rieng lam container, giu nguyen hanh vi title/geometry nhu
    # truoc day khi con la tk.Tk truc tiep.
    _root = tk.Tk()
    _root.title("PAN-OS Policy & Request Matcher - CHECK RULE (standalone)")
    _root.geometry("900x720")
    app = PANOSCheckerGUI(_root)
    app.pack(fill="both", expand=True)
    _root.mainloop()
