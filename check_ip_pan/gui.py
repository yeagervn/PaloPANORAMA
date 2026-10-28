# -*- coding: utf-8 -*-
"""
gui.py - Giao dien Tkinter (class App).
"""

import os
import threading
import queue
import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional, Set

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from .core import APP_TITLE, OUTPUT_DIR, LOG_PATH, DEFAULT_WORKERS, setup_logger, PanApiError
from .core import parse_ip_list_input, build_run_plan, describe_run_plan
from .pan_api import PanApiClient, get_devicegroup_list, resolve_devicegroup_chain
from .matching_engine import (parse_log_file, run_search_pipeline,
                              run_nat_export_pipeline, run_where_used_pipeline)
from .excel_export import (export_to_excel, export_nat_to_excel, export_nat_to_csv,
                            export_combined_to_excel, export_where_used_to_excel,
                            export_where_used_to_csv)
from .where_used import format_report
from . import rows as rowbuild

def _font_deu(widget):
    """Trả về (font ĐỀU của hệ thống, bản ĐẬM của nó) — KHÔNG dùng `tkinter.font`.

    LỖI THẬT ĐÃ GẶP (10/2026, bản .exe): `from tkinter import font` ném
    `ImportError: cannot import name 'font' from 'tkinter'` ngay lúc NẠP
    module, nên **chết cả tab CHECK IP** - trong khi hai tab kia vẫn chạy.
    PyInstaller chỉ nhúng những submodule của `tkinter` được liệt kê trong
    `hiddenimports`, và `tkinter.font` không có trong danh sách đó.

    Cách sửa ở đây là **bỏ hẳn phụ thuộc**: hỏi thẳng Tcl qua `widget.tk.call`
    - thứ luôn có sẵn ở bất kỳ widget Tk nào - đúng việc mà `tkinter.font` làm
    bên dưới. Thêm `tkinter.font` vào `hiddenimports` (đã làm) chỉ cứu được
    bản .exe dựng lại; bỏ phụ thuộc thì cứu mọi đường chạy.

    Lỗi đọc font -> lùi về Courier New: mất đúng độ rộng chữ, KHÔNG mất tab.
    """
    try:
        family = str(widget.tk.call("font", "actual", "TkFixedFont", "-family"))
        size = int(widget.tk.call("font", "actual", "TkFixedFont", "-size"))
    except Exception:                                   # noqa: BLE001
        family, size = "Courier New", 10
    return (family, size), (family, size, "bold")


class App(ttk.Frame):
    """Giao dien tool CHECK IP - dang 1 ttk.Frame de nhung duoc vao bat ky
    container nao (vd 1 tab cua ttk.Notebook trong PaloRuleSearchSuite), thay vi
    tu lam chu 1 cua so rieng (tk.Tk). Title/geometry/WM_DELETE_WINDOW cua CUA SO
    CHINH do NOI GOI (main.py) chiu trach nhiem - class nay chi con dung
    self.root lam alias noi bo (tro ve chinh minh) de giam thieu thay doi code
    ben trong _build_ui/_search_worker so voi ban goc."""

    def __init__(self, master=None, **kwargs):
        super().__init__(master, **kwargs)
        self.root = self  # alias: giu nguyen moi cho self.root.xxx() ben duoi hoat dong dung

        os.makedirs(OUTPUT_DIR, exist_ok=True)
        self.logger = setup_logger(LOG_PATH)

        self.msg_queue: "queue.Queue" = queue.Queue()
        self.cancel_event = threading.Event()
        # Cua so dang dong -> dung vong _poll_queue (xem shutdown()).
        self._closing = False
        self._poll_after_id = None
        self.api_client: Optional[PanApiClient] = None
        # Du lieu THO cua luot chay gan nhat - nut Export dung lai dung bo nay,
        # khong chay lai pipeline.
        self._last: Optional[Dict[str, Any]] = None
        self.config_root: Optional[ET.Element] = None
        self.registered_ip_tags: Dict[str, Set[str]] = {}

        self._build_ui()
        self._on_toggle_nat()  # khoi tao dung noi dung label IP theo che do mac dinh (No/Search)
        self._poll_after_id = self.root.after(100, self._poll_queue)
        # WM_DELETE_WINDOW chi ton tai o Toplevel/Tk, KHONG ap dung duoc cho Frame
        # nua - viec xu ly dong cua so chinh (bao gom huy tac vu dang chay cua tab
        # nay qua self.shutdown()) gio do NOI GOI cap cao nhat (main.py) chiu
        # trach nhiem, xem docstring self.shutdown() ben duoi.
        self._log(f"San sang. Thu muc output: {OUTPUT_DIR}")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        frm_conn = ttk.LabelFrame(self.root, text="1. Ket noi PANORAMA")
        frm_conn.pack(fill="x", **pad)

        ttk.Label(frm_conn, text="Panorama IP:").grid(row=0, column=0, sticky="w", **pad)
        self.ent_host = ttk.Entry(frm_conn, width=28)
        self.ent_host.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(frm_conn, text="API Key:").grid(row=0, column=2, sticky="w", **pad)
        self.ent_apikey = ttk.Entry(frm_conn, width=42, show="*")
        self.ent_apikey.grid(row=0, column=3, sticky="w", **pad)

        self.var_show_key = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_conn, text="Hien", variable=self.var_show_key,
                         command=self._toggle_key_visibility).grid(row=0, column=4, sticky="w")

        self.var_verify_ssl = tk.BooleanVar(value=False)
        ttk.Checkbutton(frm_conn, text="Kiem tra SSL Certificate",
                         variable=self.var_verify_ssl).grid(row=1, column=0, columnspan=2, sticky="w", **pad)

        # BAN PANORAMA (0.1): dropdown "VSYS" doi thanh "Device Group" - pham vi moi
        # tra cuu la Shared + chuoi DG cha-con cua DG nay (ca pre lan post-rulebase).
        ttk.Label(frm_conn, text="Device Group:").grid(row=1, column=2, sticky="e", **pad)
        self.cmb_dg = ttk.Combobox(frm_conn, width=18, state="readonly")
        self.cmb_dg.grid(row=1, column=3, sticky="w", **pad)
        self.cmb_dg.bind("<<ComboboxSelected>>", lambda e: self._show_dg_chain())

        self.btn_connect = ttk.Button(frm_conn, text="Connect", command=self._on_connect)
        self.btn_connect.grid(row=0, column=5, rowspan=2, sticky="ns", **pad)

        # BAN PANORAMA (0.1): Target Firewall - TUY CHON. Tab CHECK IP khong goi Live
        # Match/Hit-count nen o nay chi de ghi chu vao log "ket qua dang doi chieu cho
        # firewall nao"; de trong hoan toan binh thuong.
        ttk.Label(frm_conn, text="Target Firewall (Serial) - tuy chon:").grid(
            row=2, column=0, sticky="w", **pad)
        self.ent_serial = ttk.Entry(frm_conn, width=28)
        self.ent_serial.grid(row=2, column=1, sticky="w", **pad)
        self.lbl_dg_chain = ttk.Label(frm_conn, text="", foreground="#555555")
        self.lbl_dg_chain.grid(row=2, column=2, columnspan=4, sticky="w", **pad)

        frm_input = ttk.LabelFrame(
            self.root,
            text="2. Danh sach IP can tim trong SECURITY RULE")
        frm_input.pack(fill="both", expand=False, **pad)
        self.txt_ips = scrolledtext.ScrolledText(frm_input, height=4, font=("Consolas", 10))
        self.txt_ips.pack(fill="both", expand=True, **pad)

        frm_log = ttk.LabelFrame(self.root, text="3. File Log doi chieu")
        frm_log.pack(fill="x", **pad)
        self.ent_logfile = ttk.Entry(frm_log)
        self.ent_logfile.grid(row=0, column=0, sticky="we", padx=6, pady=4)
        frm_log.columnconfigure(0, weight=1)
        ttk.Button(frm_log, text="Import", command=self._on_browse_logfile).grid(row=0, column=1, padx=6, pady=4)
        ttk.Button(frm_log, text="Xoa", command=self._on_clear_logfile).grid(row=0, column=2, padx=6, pady=4)
        # THAY DOI (10/2026 - theo yeu cau): nut "Check" rieng cua muc 3 DA DUOC GOP
        # xuong hang nut chung o duoi muc 4 (self.btn_run) - 1 nut DUY NHAT chay ca
        # Check Rule (muc 2+3) lan Export NAT (muc 4), tuy theo o nao duoc nhap.
        # Nut "Open Output Folder" o day cung bo vi da co san 1 nut y het o hang do.

        frm_nat = ttk.LabelFrame(
            self.root,
            text="4. Export bang NAT")
        frm_nat.pack(fill="x", **pad)
        ttk.Label(frm_nat, text="Export bang NAT:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.var_export_nat = tk.StringVar(value="No")
        ttk.Radiobutton(frm_nat, text="Yes (Full)", variable=self.var_export_nat,
                         value="Yes", command=self._on_toggle_nat).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(frm_nat, text="No (Search)", variable=self.var_export_nat,
                         value="No", command=self._on_toggle_nat).grid(row=0, column=2, sticky="w", padx=(8, 0))
        ttk.Label(frm_nat, text="  Dinh dang file:").grid(row=0, column=3, sticky="e", padx=(16, 4))
        self.cmb_nat_format = ttk.Combobox(frm_nat, width=8, state="readonly",
                                            values=["xlsx", "csv"])
        self.cmb_nat_format.set("xlsx")
        self.cmb_nat_format.grid(row=0, column=4, sticky="w", padx=4, pady=4)

        self.lbl_nat_ips = ttk.Label(frm_nat, text="")
        self.lbl_nat_ips.grid(row=1, column=0, columnspan=5, sticky="w", padx=6, pady=(4, 0))
        self.txt_nat_ips = scrolledtext.ScrolledText(frm_nat, height=3, font=("Consolas", 9))
        self.txt_nat_ips.grid(row=2, column=0, columnspan=5, sticky="we", padx=6, pady=(0, 4))
        frm_nat.columnconfigure(4, weight=1)

        # MUC 5 - CHECK OBJECT ("Where Used"): 1 IP dang nam trong Address Object
        # nao, Group nao, rule nao dung toi. KHONG co o nhap IP rieng o day - no
        # dung CHUNG danh sach IP cua muc 2, vi bat go lai cung 1 danh sach cho
        # tung viec la cach chac chan de 2 o lech nhau roi nguoi doc so sai.
        frm_obj = ttk.LabelFrame(
            self.root,
            text="5. Check Object (Where Used)")
        frm_obj.pack(fill="x", **pad)
        self.var_where_used = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            frm_obj,
            text="Tra object/group/rule lien quan toi cac IP o muc 2",
            variable=self.var_where_used,
            command=self._refresh_plan_hint).grid(row=0, column=0, columnspan=3,
                                                  sticky="w", padx=6, pady=(4, 0))
        ttk.Label(frm_obj, text="Ten Address Object/Group:").grid(
            row=1, column=0, sticky="w", padx=6, pady=4)
        self.ent_where_objects = ttk.Entry(frm_obj)
        self.ent_where_objects.grid(row=1, column=1, sticky="we", padx=6, pady=4)
        frm_obj.columnconfigure(1, weight=1)
        self.ent_where_objects.bind("<KeyRelease>", lambda e: self._refresh_plan_hint())

        # 1 NUT DUY NHAT cho ca 2 viec (thay cho cap "Check" o muc 3 + "Export NAT"
        # o day truoc kia): chay Check Rule neu muc 2 HOAC muc 3 co du lieu, chay
        # Export NAT neu muc 4 duoc chon - nhap ca 2 thi chay ca 2 trong CUNG 1 luot.
        frm_actions = ttk.Frame(self.root)
        frm_actions.pack(fill="x", **pad)
        self.btn_run = ttk.Button(frm_actions, text="Check",
                                   command=self._on_run_all, state="disabled")
        self.btn_run.pack(side="left", padx=4)
        self.btn_cancel = ttk.Button(frm_actions, text="Cancel", command=self._on_cancel, state="disabled")
        self.btn_cancel.pack(side="left", padx=4)
        # Export TACH khoi Check (10/2026 - theo yeu cau): chay xong ket qua
        # hien THANG tren bang; chi ghi file khi nguoi dung thuc su muon.
        self.btn_export = ttk.Button(frm_actions, text="Export",
                                      command=self._on_export, state="disabled")
        self.btn_export.pack(side="left", padx=4)
        self.btn_open_output = ttk.Button(frm_actions, text="Open Output Folder", command=self._on_open_output)
        self.btn_open_output.pack(side="left", padx=4)

        ttk.Label(frm_actions, text="  So thread xu ly (20-50):").pack(side="left", padx=(16, 4))
        self.spn_threads = ttk.Spinbox(frm_actions, from_=20, to=50, width=5, increment=1, justify="center")
        self.spn_threads.set(min(50, max(20, DEFAULT_WORKERS)))
        self.spn_threads.pack(side="left", padx=4)

        # Nhan cho biet TRUOC khi bam: luot chay nay se lam gi (cap nhat lien tuc
        # theo noi dung muc 2/3/4) - de khong con phai doan nut nao chay cai gi.
        self.lbl_plan = ttk.Label(frm_actions, text="", foreground="#555555")
        self.lbl_plan.pack(side="left", padx=(12, 4))

        frm_progress = ttk.Frame(self.root)
        frm_progress.pack(fill="x", **pad)
        self.lbl_progress = ttk.Label(frm_progress, text="San sang.")
        self.lbl_progress.pack(anchor="w")
        self.progress = ttk.Progressbar(frm_progress, mode="determinate", maximum=100)
        self.progress.pack(fill="x")

        frm_res = ttk.LabelFrame(self.root, text="6. Ket qua")
        frm_res.pack(fill="both", expand=True, **pad)
        # Bang ket qua la mot widget Text, KHONG phai Treeview: Treeview chi to
        # mau duoc ca mot dong, ma thong tin lai nam o tung DOAN chu trong o -
        # xanh la = IP dang tra, do = phan con lai cua group. Xem rows.layout().
        fixed, fixed_bold = _font_deu(frm_res)
        self.txt_res = tk.Text(frm_res, height=14, wrap="none", font=fixed,
                               state="disabled", background="#FFFFFF")
        self.txt_res.grid(row=0, column=0, sticky="nsew", padx=(6, 0), pady=4)
        vsb = ttk.Scrollbar(frm_res, orient="vertical", command=self.txt_res.yview)
        vsb.grid(row=0, column=1, sticky="ns", pady=4)
        hsb = ttk.Scrollbar(frm_res, orient="horizontal", command=self.txt_res.xview)
        hsb.grid(row=1, column=0, sticky="ew", padx=(6, 0))
        self.txt_res.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        frm_res.columnconfigure(0, weight=1)
        frm_res.rowconfigure(0, weight=1)
        self.txt_res.tag_configure("section", background="#1F4E79", foreground="#FFFFFF")
        self.txt_res.tag_configure("hdr", background="#DCE6F1", foreground="#1F4E79")
        self.txt_res.tag_configure("note", foreground="#9C5700")
        self.txt_res.tag_configure("off", foreground="#C00000")
        self.txt_res.tag_configure("ok", background="#E2EFDA")
        self.txt_res.tag_configure("no", background="#FCE4D6")
        # Tag cua tung doan chu - phai nam TREN tag ca dong, neu khong mau do
        # cua dong "[DISABLED]" se de len mau xanh la cua IP dang tra.
        self.txt_res.tag_configure("name", font=fixed_bold)
        self.txt_res.tag_configure("value", foreground="#C00000")
        self.txt_res.tag_configure("value_matched", foreground="#107C10",
                                   font=fixed_bold)
        for _t in ("name", "value", "value_matched"):
            self.txt_res.tag_raise(_t)

        # KEO CO GIAN COT. Treeview co san tro nay, widget Text thi khong - ma
        # bang phai la Text de to duoc mau tung doan chu. Nen tu lam: bang la
        # chu DEU nen "cot thu may" chi la mot phep dem ky tu, va
        # `rows.column_edges()` da noi duong ke nam o ky tu so may.
        self._col_chars = list(rowbuild.COL_WIDTHS)
        self._keo = None                 # (chi so duong ke, ky tu luc bam)
        self._rows_hien = []
        self._rows_bay_gio = []
        self._dong_man_hinh = []
        self._muc_dong = set()        # khoa cac muc dang thu gon
        self.txt_res.tag_configure("sep", foreground="#9aa4b2")
        self.txt_res.bind("<Motion>", self._tren_duong_ke)
        self.txt_res.bind("<Button-1>", self._bat_dau_keo)
        self.txt_res.bind("<ButtonRelease-1>", self._tha_keo)
        self.txt_res.bind("<Double-Button-1>", self._vua_khit_cot)
        self.lbl_counts = ttk.Label(frm_res, text="Chua chay.")
        self.lbl_counts.grid(row=2, column=0, columnspan=2, sticky="w", padx=6, pady=(0, 4))

        frm_log = ttk.LabelFrame(self.root, text="Log")
        frm_log.pack(fill="both", expand=False, **pad)
        self.txt_log = scrolledtext.ScrolledText(frm_log, height=8, state="disabled", font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, **pad)

    def _show_dg_chain(self):
        """BAN PANORAMA (0.2): hien ngay chuoi thua ke cua Device Group dang chon
        (Shared -> DG to tien -> ... -> DG hien tai). Day la PHAM VI THAT cua moi
        ket qua tra cuu - rat de hieu nham la "chi trong DG nay" neu khong noi ro."""
        try:
            dg = self.cmb_dg.get()
            if not dg or self.config_root is None:
                self.lbl_dg_chain.config(text="")
                return
            chain, _els = resolve_devicegroup_chain(self.config_root, dg)
            self.lbl_dg_chain.config(text="Pham vi: " + " -> ".join(chain))
        except Exception:
            self.lbl_dg_chain.config(text="")

    def _toggle_key_visibility(self):
        self.ent_apikey.config(show="" if self.var_show_key.get() else "*")

    def _on_toggle_nat(self):
        # Ca 2 che do (Full/Search) deu co the dung o nay:
        #   - Yes (Full): xuat toan bo bang NAT, o nhap IP la TUY CHON (chi de highlight).
        #   - No (Search): KHONG xuat full - o nhap IP la BAT BUOC, dung de loc/tim
        #     NAT rule khop (giong tinh nang Search Rule muc 2, nhung ap dung cho NAT).
        is_full = self.var_export_nat.get() == "Yes"
        self.cmb_nat_format.config(state="readonly")
        self.txt_nat_ips.config(state="normal")
        if is_full:
            self.lbl_nat_ips.config(
                text="IP can highlight:")
        else:
            # THAY DOI (10/2026): o nay khong con "BAT BUOC" theo kieu chan ca luot
            # chay nua - de trong chi co nghia la BO QUA phan NAT (van chay Check
            # Rule neu muc 2/3 co du lieu).
            self.lbl_nat_ips.config(
                text="IP can tim trong bang NAT:")
        self._refresh_plan_hint()

    # ------------------------------------------------- lap ke hoach & validate
    #
    # THAY DOI (10/2026 - theo yeu cau): 1 NUT DUY NHAT (self.btn_run) chay ca
    # Check Rule (muc 2+3) lan Export NAT (muc 4). TOAN BO luat quyet dinh nam o
    # core.build_run_plan() (ham thuan tuy, khong tkinter, co unit test rieng o
    # tests/test_check_ip_run_plan.py) - 2 ham duoi day CHI doc widget va hien thi.

    def _collect_plan(self):
        """Doc input tu widget roi uy quyen TOAN BO luat quyet dinh cho
        core.build_run_plan() (ham thuan tuy, co unit test rieng - xem
        tests/test_check_ip_run_plan.py). O day KHONG chua luat nao."""
        return build_run_plan(
            ip_text=self.txt_ips.get("1.0", "end"),
            logfile_path=self.ent_logfile.get(),
            nat_mode_full=(self.var_export_nat.get() == "Yes"),
            nat_ip_text=self.txt_nat_ips.get("1.0", "end"),
            nat_format=self.cmb_nat_format.get(),
            worker_count_raw=self.spn_threads.get(),
            where_used_on=bool(self.var_where_used.get()),
            where_object_text=self.ent_where_objects.get(),
        )

    def _refresh_plan_hint(self):
        """Cap nhat nhan canh nut Run: luot chay sap toi se lam gi. Chi tinh lai
        khi noi dung 3 o input thuc su doi (tranh parse lai moi 100ms khi nguoi
        dung paste hang nghin IP)."""
        try:
            sig = (self.txt_ips.get("1.0", "end"), self.ent_logfile.get(),
                   self.txt_nat_ips.get("1.0", "end"), self.var_export_nat.get(),
                   self.var_where_used.get(), self.ent_where_objects.get())
        except Exception:
            return
        if sig == getattr(self, "_plan_sig", None):
            return
        self._plan_sig = sig
        plan, _errors = self._collect_plan()
        self.lbl_plan.config(text=describe_run_plan(plan))

    # -------------------------------------------------------------- queue
    def _log(self, msg: str):
        self.msg_queue.put(("log", msg))

    def _set_status(self, text: str):
        """An toan goi tu worker thread: xep yeu cau doi dong trang thai."""
        self.msg_queue.put(("status", text))

    def _set_progress(self, phase: str, done: int, total: int):
        self.msg_queue.put(("progress", (phase, done, total)))

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
                elif kind == "status":
                    # Doi dong chu trang thai. Worker thread PHAI di duong nay,
                    # khong duoc goi thang self.lbl_progress.config() - Tkinter
                    # khong thread-safe, va khi mainloop da thoat thi no nem
                    # RuntimeError("main thread is not in main loop").
                    self.lbl_progress.config(text=payload)
                elif kind == "progress":
                    phase, done, total = payload
                    pct = int(done / total * 100) if total else 0
                    self.progress["value"] = pct
                    self.lbl_progress.config(text=f"{phase}: {done}/{total} ({pct}%)")
                elif kind == "error":
                    messagebox.showerror("Loi", payload)
                elif kind == "done_connect":
                    self._finish_connect(payload)
                elif kind == "done_run_all":
                    self._finish_run_all(payload)
                elif kind == "done_export":
                    self._finish_export(payload)
                elif kind == "enable_ui":
                    self._set_busy(False)
        except queue.Empty:
            pass
        self._refresh_plan_hint()
        if self._closing:
            self._poll_after_id = None
            return
        self._poll_after_id = self.root.after(100, self._poll_queue)

    # ------------------------------------------------------------- connect
    def _on_connect(self):
        host = self.ent_host.get().strip()
        api_key = self.ent_apikey.get().strip()
        if not host or not api_key:
            messagebox.showwarning("Thieu thong tin", "Vui long nhap Management IP va API Key.")
            return
        self._set_busy(True)
        self.cancel_event.clear()
        self.progress["value"] = 0
        self.lbl_progress.config(text="Dang ket noi...")
        threading.Thread(target=self._connect_worker,
                          args=(host, api_key, self.var_verify_ssl.get()), daemon=True).start()

    def _connect_worker(self, host, api_key, verify_ssl):
        try:
            client = PanApiClient(host, api_key, verify_ssl=verify_ssl)
            self._log("Dang ket noi toi Panorama...")
            hostname = client.test_connection()
            self._log(f"Connect OK (Panorama hostname: {hostname})")

            self._log("Dang tai FULL running-config PANORAMA (co the mat vai giay tuy so luong object)...")
            config_root = client.fetch_running_config()
            dg_list = get_devicegroup_list(config_root)
            if not dg_list:
                raise PanApiError(
                    "No device-group found",
                    "Khong tim thay Device Group nao trong cau hinh Panorama. Kiem tra lai "
                    "API Key co quyen doc toan bo /config hay khong.")
            self._log(f"Doc danh sach Device Group OK ({len(dg_list)}): {', '.join(dg_list)}")

            registered_ip_tags = client.fetch_registered_ip()
            if registered_ip_tags:
                self._log(f"Doc Registered-IP OK ({len(registered_ip_tags)} IP) - dung cho Dynamic Address Group")

            self.api_client = client
            self.config_root = config_root
            self.registered_ip_tags = registered_ip_tags
            self.msg_queue.put(("done_connect", dg_list))
        except PanApiError as e:
            self._log(f"Connect FAILED: {e.user_message}")
            self.logger.exception("Connect error")
            self.msg_queue.put(("error", e.user_message))
        except Exception:
            self._log("Connect FAILED: loi khong xac dinh (xem log.txt)")
            self.logger.exception("Unexpected connect error")
            self.msg_queue.put(("error", "Da xay ra loi khong xac dinh khi Connect. Xem log.txt de biet chi tiet."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _finish_connect(self, dg_list):
        self.cmb_dg["values"] = dg_list
        self.cmb_dg.current(0)
        self._show_dg_chain()
        self.btn_run.config(state="normal")
        self.lbl_progress.config(text="Connect thanh cong. San sang Check / Export.")

    # ----------------------------------------------------- RUN ALL (1 nut)
    def _on_run_all(self):
        """1 nut DUY NHAT cho ca Check Rule (muc 2+3) lan Export NAT (muc 4).
        Luat quyet dinh phan nao duoc chay: xem core.build_run_plan()."""
        if self.config_root is None:
            messagebox.showwarning("Chua ket noi", "Vui long Connect truoc khi chay.")
            return
        dg_name = self.cmb_dg.get()
        if not dg_name:
            messagebox.showwarning("Thieu Device Group", "Vui long chon Device Group.")
            return

        plan, errors = self._collect_plan()
        if errors:
            messagebox.showwarning("Kiem tra lai input", "\n\n".join(errors))
            return

        # Dong khong hop le LE TE (van con IP hop le khac) -> chi ghi log, van chay.
        if plan["invalid_ips"]:
            preview = ", ".join(plan["invalid_ips"][:10]) + (" ..." if len(plan["invalid_ips"]) > 10 else "")
            self._log(f"[Muc 2] Bo qua {len(plan['invalid_ips'])} dong khong hop le: {preview}")
        if plan["nat_invalid"]:
            preview = ", ".join(plan["nat_invalid"][:10]) + (" ..." if len(plan["nat_invalid"]) > 10 else "")
            self._log(f"[Muc 4] Bo qua {len(plan['nat_invalid'])} dong khong hop le: {preview}")

        serial = self.ent_serial.get().strip()
        if serial:
            self._log(f"[Ghi chu] Target Firewall: {serial} - ket qua duoi day la rulebase "
                      f"Panorama (Shared + chuoi DG) ap xuong firewall nay, CHUA tinh rule "
                      f"cuc bo rieng cua chinh no (neu co).")
        self.spn_threads.set(plan["worker_count"])
        self._set_busy(True)
        self.cancel_event.clear()
        self.progress["value"] = 0
        self.lbl_progress.config(text="Dang xu ly...")
        threading.Thread(target=self._run_all_worker, args=(dg_name, plan), daemon=True).start()

    @staticmethod
    def _paths_note(output_paths):
        """Khi bi Cancel giua chung, van cho biet file nao DA kip xuat (neu co)."""
        if not output_paths:
            return ""
        return " File da xuat truoc do: " + ", ".join(os.path.basename(p) for p in output_paths)

    def _run_all_worker(self, dg_name, plan):
        """Chay tuan tu trong CUNG 1 thread: pipeline Check Rule truoc, pipeline
        NAT sau (phan nao duoc chon), roi MOI export.

        THAY DOI (10/2026 - theo yeu cau "dong chung 1 file cho gon"): khi 1 luot
        lam CA HAI phan va dinh dang NAT la xlsx -> xuat DUNG 1 file
        `rule_nat[_search]_<ts>.xlsx` gom 2 sheet "Security Rules" + "NAT Rules"
        (template/dinh dang tung sheet giu nguyen 100%), thay vi 2 file roi rac.
        Chi lam 1 phan -> van la 1 file nhu cu (`rule_*.xlsx` / `nat_*.xlsx`).
        NAT chon dinh dang CSV thi KHONG gop duoc (csv khong co khai niem sheet)
        -> van xuat 2 file va ghi log noi ro ly do."""
        output_paths = []
        try:
            rule_data = nat_data = None

            if plan["do_rule"]:
                rule_data = self._run_rule_pipeline(
                    dg_name, plan["valid_ips"], plan["logfile_path"], plan["worker_count"])
                if self.cancel_event.is_set():
                    self._log("Da huy theo yeu cau (Cancel)." + self._paths_note(output_paths))
                    return
            else:
                self._log("[Muc 2/3] De trong -> BO QUA Check Rule.")

            if plan["do_nat"]:
                nat_data = self._run_nat_pipeline(
                    dg_name, plan["nat_mode_full"],
                    plan["nat_filter_ips"], plan["nat_highlight_ips"])
                if self.cancel_event.is_set():
                    self._log("Da huy theo yeu cau (Cancel)." + self._paths_note(output_paths))
                    return
            else:
                self._log("[Muc 4] De trong -> BO QUA Export NAT.")

            where_reports = None
            if plan["do_where"]:
                where_reports = self._run_where_used(dg_name, plan, rule_data, nat_data)
                if self.cancel_event.is_set():
                    self._log("Da huy theo yeu cau (Cancel)." + self._paths_note(output_paths))
                    return
            else:
                self._log("[Muc 5] Khong bat -> BO QUA Check Object.")

            # KHONG xuat file o day nua (10/2026 - theo yeu cau): chay xong
            # thi KET QUA HIEN THANG tren bang o muc 6. File chi duoc ghi khi
            # nguoi dung bam nut Export - luc do dung lai dung bo du lieu tho
            # nay, khong chay lai pipeline.
            self.msg_queue.put(("done_run_all", {
                "plan": plan, "rule": rule_data, "nat": nat_data,
                "where": where_reports,
            }))
        except PanApiError as e:
            self._log(f"FAILED: {e.user_message}")
            self.logger.exception("Run all error")
            self.msg_queue.put(("error", e.user_message))
        except Exception:
            self._log("FAILED: loi khong xac dinh (xem log.txt)")
            self.logger.exception("Unexpected run all error")
            self.msg_queue.put(("error", "Da xay ra loi khong xac dinh. Xem log.txt de biet chi tiet."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _run_where_used(self, dg_name, plan, rule_data, nat_data):
        """Muc 5 - Check Object. IN THANG ket qua ra o Log, roi tra ve de xuat file.

        Pham vi = Shared + ca chuoi Device Group dang chon, GIONG HET muc 2 -
        neu khac thi 2 muc cua cung 1 luot chay se tra loi ve hai he quy chieu
        khac nhau.

        In ra man hinh la YEU CAU chinh cua tinh nang nay: nguoi dung muon doc
        duoc ngay, file Excel chi la ban luu lai.
        """
        self._set_status("Check Object (Where Used)...")
        ips = plan["where_ips"]
        names = plan["where_names"]
        self._log(f"Bat dau (Check Object): {len(ips)} IP + {len(names)} ten object, "
                  f"Device Group={dg_name}")

        reports = run_where_used_pipeline(
            self.config_root, dg_name, ips, names,
            log_func=self._log,
            registered_ip_tags=self.registered_ip_tags,
            resolver=(rule_data or {}).get("resolver") or (nat_data or {}).get("resolver"),
            rules=(rule_data or {}).get("rules"),
            nat_rules=(nat_data or {}).get("nat_rules"),
            cancel_event=self.cancel_event)

        self._log("=" * 70)
        self._log("KET QUA CHECK OBJECT (Where Used)")
        self._log("=" * 70)
        for report in reports:
            for line in format_report(report):
                self._log(line)
        self._log("=" * 70)
        return reports

    def _run_rule_pipeline(self, dg_name, valid_ips, logfile_path, worker_count):
        """Chay pipeline Check Rule (muc 2+3) va TRA VE DU LIEU THO - chua export.
        Tach phan 'chay' khoi phan 'xuat file' de khi lam ca Rule lan NAT trong 1
        luot thi gop duoc vao CUNG 1 file 2 sheet (xem export_combined_to_excel).
        Noi dung pipeline GIU NGUYEN tu ban cu. Tra ve None neu bi Cancel."""
        has_ip_search = bool(valid_ips)
        has_log_file = bool(logfile_path)
        self._log(f"Bat dau (Check Rule): {len(valid_ips)} IP, Device Group={dg_name}, worker={worker_count}, "
                  f"File Log={'Co' if has_log_file else 'Khong'}")

        log_entries = None
        if has_log_file:
            try:
                log_entries = parse_log_file(logfile_path)
                self._log(f"Doc File Log OK ({len(log_entries)} dong traffic) tu {os.path.basename(logfile_path)}")
                if not log_entries:
                    self._log("CANH BAO: File Log khong co dong du lieu hop le nao (kiem tra lai header Source IP/Dest IP/Port)")
            except Exception as e:
                self.logger.exception("Log file parse error")
                raise PanApiError(f"Khong doc duoc File Log:\n{e}") from e

        if not (has_ip_search or has_log_file):
            return None

        rules, match_results, resolver, service_objects, service_groups = run_search_pipeline(
            self.config_root, dg_name, valid_ips, worker_count,
            log_func=self._log,
            progress_cb=lambda phase, d, t: self._set_progress(phase, d, t),
            cancel_event=self.cancel_event,
            registered_ip_tags=self.registered_ip_tags,
        )
        if self.cancel_event.is_set():
            return None
        return {
            "rules": rules,
            "match_results": match_results,
            "resolver": resolver,
            "service_objects": service_objects,
            "service_groups": service_groups,
            "log_entries": log_entries,
        }

    # -------------------------------------------------------------- export nat
    def _run_nat_pipeline(self, dg_name, nat_mode_full, nat_filter_ips, nat_highlight_ips):
        """Doc bang NAT (muc 4) va TRA VE DU LIEU THO - chua export (xem
        _run_rule_pipeline). `resolver` van RIENG, khong dung chung voi Check Rule
        - dung nguyen quyet dinh cu. Tra ve None neu bi Cancel."""
        nat_desc = "Full" if nat_mode_full else f"Search ({len(set(nat_filter_ips))} IP)"
        self._log(f"Bat dau (Export NAT): Device Group={dg_name}, che do={nat_desc}"
                  + (f", Highlight NAT={len(set(nat_highlight_ips))} IP" if nat_highlight_ips else ""))
        if self.cancel_event.is_set():
            return None

        self._set_status("Dang doc bang NAT...")
        nat_rules, resolver, nat_service_objects, nat_service_groups = run_nat_export_pipeline(
            self.config_root, dg_name,
            log_func=self._log,
            registered_ip_tags=self.registered_ip_tags,
            resolver=None,  # resolver doc lap hoan toan voi Check Rule
        )
        if self.cancel_event.is_set():
            return None
        return {
            "nat_rules": nat_rules,
            "resolver": resolver,
            "service_objects": nat_service_objects,
            "service_groups": nat_service_groups,
            "highlight_ips": set(nat_highlight_ips),
            "filter_ips": set(nat_filter_ips),
        }

    def _finish_run_all(self, payload):
        """Ve ket qua len bang o muc 6. KHONG xuat file."""
        if payload is None:
            return
        if isinstance(payload, (str, list)):        # tuong thich nguoc
            self._finish_export(payload if isinstance(payload, list) else [payload])
            return
        self._last = payload
        rule_data = payload.get("rule")
        nat_data = payload.get("nat")
        where_reports = payload.get("where")
        plan = payload.get("plan") or {}

        display = []
        if rule_data:
            display.extend(rowbuild.section("rule"))
            display.extend(rowbuild.rule_rows(
                rule_data["rules"], rule_data["match_results"], rule_data["resolver"],
                rule_data["service_objects"], rule_data["service_groups"],
                target_ips=set(plan.get("valid_ips") or [])))
            if rule_data.get("log_entries"):
                display.extend(rowbuild.section("log"))
                display.extend(rowbuild.log_rows(
                    rule_data["log_entries"], rule_data["rules"], rule_data["resolver"],
                    rule_data["service_objects"], rule_data["service_groups"]))
        if nat_data:
            display.extend(rowbuild.section("nat"))
            display.extend(rowbuild.nat_rows(
                nat_data["nat_rules"], nat_data["resolver"],
                nat_data["service_objects"], nat_data["service_groups"],
                target_ips=set(nat_data.get("filter_ips") or
                               nat_data.get("highlight_ips") or []),
                search_mode=bool(nat_data.get("filter_ips"))))
        if where_reports:
            display.extend(rowbuild.section("where"))
            display.extend(rowbuild.where_rows(where_reports))

        self._render_rows(display)
        self.btn_export.config(state="normal" if display else "disabled")

    def _render_rows(self, display):
        """Do danh sach dong ket qua vao bang. Luat trinh bay (ngat dong trong
        cot, tag ca dong, tag tung doan chu) nam ca trong rows.py - o day chi
        con `insert`."""
        self._display_rows = list(display)
        self._ve_bang(display)
        data = sum(1 for row in display if rowbuild.is_data_row(row))
        self.lbl_counts.config(
            text=f"{data} dong ket qua ({len(display)} dong ke ca tieu de muc).")
        self.lbl_progress.config(text=f"Xong: {data} dong ket qua.")

    # ------------------------------------------------------- keo co gian cot
    def _ky_tu_tai(self, x, y):
        """Toa do chuot -> chi so KY TU tren dong do."""
        try:
            return int(str(self.txt_res.index(f"@{x},{y}")).split(".")[1])
        except Exception:                               # noqa: BLE001
            return -1

    def _duong_ke_gan(self, cot):
        """Duong ke nao dang o ngay duoi con tro (lech 1 ky tu van tinh)."""
        for i, edge in enumerate(rowbuild.column_edges(self._col_chars)):
            if abs(cot - edge) <= 1:
                return i
        return None

    def _tren_duong_ke(self, ev):
        """Doi con tro khi re qua duong ke - neu khong thi khong ai biet la
        keo duoc."""
        tren = self._duong_ke_gan(self._ky_tu_tai(ev.x, ev.y)) is not None
        self.txt_res.configure(cursor="sb_h_double_arrow" if tren else "")

    def _bat_dau_keo(self, ev):
        cot = self._ky_tu_tai(ev.x, ev.y)
        i = self._duong_ke_gan(cot)
        self._keo = (i, cot) if i is not None else None
        if self._keo is None and self._bam_vao_tieu_de_muc(ev):
            return "break"
        return None

    def _dong_ket_qua_tai(self, ev):
        """Dong ket qua (khong phai dong man hinh) o ngay duoi con tro."""
        try:
            dong = int(str(self.txt_res.index(f"@{ev.x},{ev.y}")).split(".")[0])
        except Exception:                               # noqa: BLE001
            return None
        if 1 <= dong <= len(self._dong_man_hinh):
            return self._dong_man_hinh[dong - 1].get("row")
        return None

    def _bam_vao_tieu_de_muc(self, ev) -> bool:
        """Bam vao dong tieu de muc -> thu gon / mo lai muc do.

        Bat CA DONG chu khong rieng o mui ten: mui ten rong dung mot ky tu,
        bat moi no thi nguoi dung phai nham - ma ca dong do von khong dung de
        lam gi khac.
        """
        i = self._dong_ket_qua_tai(ev)
        if i is None or not (0 <= i < len(self._rows_bay_gio)):
            return False
        row = self._rows_bay_gio[i]
        if row.get("kind") != "section":
            return False
        khoa = row.get("khoa_muc") or rowbuild.khoa_muc(row)
        if khoa in self._muc_dong:
            self._muc_dong.discard(khoa)
        else:
            self._muc_dong.add(khoa)
        self._ve_bang(self._rows_hien)
        return True

    def _tha_keo(self, ev):
        """Ve lai khi THA chuot, khong ve theo tung buoc re.

        Mot bang vai tram dong x muoi cot la hang chuc nghin lan `insert`; ve
        lai o moi su kien Motion thi keo giat den muc khong dung duoc.
        """
        if not self._keo:
            return
        i, cot_dau = self._keo
        self._keo = None
        delta = self._ky_tu_tai(ev.x, ev.y) - cot_dau
        if not delta:
            return
        self._doi_be_ngang(i, self._col_chars[i] + delta)

    def _vua_khit_cot(self, ev):
        """Bam dup len duong ke: co cot ve vua du noi dung dai nhat cua no."""
        i = self._duong_ke_gan(self._ky_tu_tai(ev.x, ev.y))
        if i is None:
            return "break"
        dai = 0
        for row in (self._rows_hien or []):
            o = row.get("runs") or [[("text", c)] for c in row["cells"]]
            if i < len(o):
                dai = max(dai, len("".join(t for _k, t in o[i]).strip()))
        self._doi_be_ngang(i, dai or rowbuild.COL_WIDTHS[i])
        return "break"

    def _doi_be_ngang(self, i, moi):
        cu = self._col_chars[i]
        self._col_chars[i] = max(6, min(200, int(moi)))
        if self._col_chars[i] != cu:
            self._ve_bang(self._rows_hien or [])

    def _ve_bang(self, display):
        """Do danh sach dong ket qua vao bang (dung lai khi keo cot / thu gon muc)."""
        self._rows_hien = list(display)
        # `_rows_bay_gio` la ban DANG hien (da bo dong cua muc thu gon), con
        # `_rows_hien` giu ban DAY DU de mo lai duoc.
        self._rows_bay_gio = rowbuild.ap_dung_thu_gon(self._rows_hien, self._muc_dong)
        self._dong_man_hinh = rowbuild.layout(self._rows_bay_gio,
                                              widths=self._col_chars)
        self.txt_res.config(state="normal")
        self.txt_res.delete("1.0", "end")
        for line in self._dong_man_hinh:
            row_tag = line["tag"]
            for kind, text in line["segments"]:
                tags = tuple(t for t in (row_tag, "" if kind == "text" else kind) if t)
                if text == rowbuild.COL_GAP:
                    tags = tags + ("sep",)
                self.txt_res.insert("end", text, tags)
            self.txt_res.insert("end", "\n")
        self.txt_res.config(state="disabled")

    def _on_export(self):
        """Ghi ra file tu dung bo du lieu tho cua luot chay vua roi."""
        if not getattr(self, "_last", None):
            messagebox.showinfo("Chua co gi de xuat", "Bam Check truoc da.")
            return
        payload = dict(self._last)
        self._set_busy(True)
        threading.Thread(target=self._export_worker, args=(payload,),
                          daemon=True).start()

    def _export_worker(self, payload):
        output_paths = []
        try:
            plan = payload.get("plan") or {}
            rule_data = payload.get("rule")
            nat_data = payload.get("nat")
            where_reports = payload.get("where")
            nat_is_csv = (plan.get("nat_format") == "csv")

            if rule_data and nat_data and not nat_is_csv:
                self._set_status("Exporting Excel (Rule + NAT)...")
                output_paths.append(export_combined_to_excel(
                    OUTPUT_DIR,
                    rules=rule_data["rules"],
                    match_results=rule_data["match_results"],
                    resolver=rule_data["resolver"],
                    service_objects=rule_data["service_objects"],
                    service_groups=rule_data["service_groups"],
                    nat_rules=nat_data["nat_rules"],
                    nat_resolver=nat_data["resolver"],
                    nat_service_objects=nat_data["service_objects"],
                    nat_service_groups=nat_data["service_groups"],
                    log_entries=rule_data["log_entries"],
                    highlight_ips=nat_data["highlight_ips"],
                    filter_ips=nat_data["filter_ips"],
                    where_reports=where_reports,
                    log_func=self._log))
                where_reports = None
            else:
                if rule_data and nat_data and nat_is_csv:
                    self._log("[NAT] Dinh dang CSV khong gop duoc vao file Excel "
                              "-> xuat rieng 2 file.")
                if rule_data:
                    self._set_status("Exporting Excel (Rule)...")
                    if where_reports:
                        output_paths.append(export_combined_to_excel(
                            OUTPUT_DIR,
                            rules=rule_data["rules"],
                            match_results=rule_data["match_results"],
                            resolver=rule_data["resolver"],
                            service_objects=rule_data["service_objects"],
                            service_groups=rule_data["service_groups"],
                            log_entries=rule_data["log_entries"],
                            where_reports=where_reports,
                            log_func=self._log))
                        where_reports = None
                    else:
                        output_paths.append(export_to_excel(
                            OUTPUT_DIR, rule_data["rules"], rule_data["match_results"],
                            rule_data["resolver"], rule_data["service_objects"],
                            rule_data["service_groups"],
                            log_entries=rule_data["log_entries"], log_func=self._log))
                if nat_data:
                    self._set_status("Exporting bang NAT...")
                    exporter = export_nat_to_csv if nat_is_csv else export_nat_to_excel
                    output_paths.append(exporter(
                        OUTPUT_DIR, nat_data["nat_rules"], nat_data["resolver"],
                        nat_data["service_objects"], nat_data["service_groups"],
                        highlight_ips=nat_data["highlight_ips"],
                        filter_ips=nat_data["filter_ips"], log_func=self._log))
                if where_reports:
                    self._set_status("Exporting Check Object...")
                    exporter = (export_where_used_to_csv if nat_is_csv and nat_data
                                else export_where_used_to_excel)
                    output_paths.append(exporter(OUTPUT_DIR, where_reports,
                                                  log_func=self._log))
            self.msg_queue.put(("done_export", output_paths))
        except Exception:
            self.logger.exception("Export error")
            self.msg_queue.put(("error", "Loi khi xuat file. Xem log.txt."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _finish_export(self, output_paths):
        if not output_paths:
            self.lbl_progress.config(text="Khong co file nao duoc xuat.")
            return
        names = ", ".join(os.path.basename(p) for p in output_paths)
        self.lbl_progress.config(text=f"Da xuat: {names}")
        for path in output_paths:
            self._log(f"Export OK -> {path}")
        # MO THU MUC OUTPUT DUNG MOT LAN.
        #
        # Thu muc output cua tab nay co dinh, nen lan xuat thu hai tro di viec
        # bat them mot cua so file manager (va mot hop thoai) khong cho biet
        # them dieu gi - chi la rac phai bam di. Tu lan 2 chi con dong trang
        # thai + dong log, van du de biet file nao da ra.
        if not getattr(self, "_output_opened", False):
            self._output_opened = True
            messagebox.showinfo("Hoan tat", "Da xuat ket qua:\n"
                                + "\n".join(output_paths))
            self._on_open_output()

    # -------------------------------------------------------------- misc
    def _on_browse_logfile(self):
        path = filedialog.askopenfilename(
            title="Chon File Log doi chieu (Source IP | Dest IP | Port)",
            filetypes=[("Excel/CSV files", "*.xlsx *.csv"), ("Excel files", "*.xlsx"), ("CSV files", "*.csv")],
        )
        if path:
            self.ent_logfile.delete(0, "end")
            self.ent_logfile.insert(0, path)

    def _on_clear_logfile(self):
        self.ent_logfile.delete(0, "end")

    def _on_cancel(self):
        self.cancel_event.set()
        self._log("Yeu cau Cancel... cho tien trinh hien tai dung lai.")

    def _on_open_output(self):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
        try:
            os.startfile(OUTPUT_DIR)  # Windows only, dung nhu spec yeu cau
        except Exception:
            messagebox.showinfo("Thu muc Output", OUTPUT_DIR)


    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.btn_connect.config(state=state)
        self.btn_run.config(state="disabled" if busy else ("normal" if self.config_root is not None else "disabled"))
        self.btn_cancel.config(state="normal" if busy else "disabled")
        # Export chi bat khi DA co ket qua tren bang.
        self.btn_export.config(
            state="disabled" if busy or not getattr(self, "_last", None) else "normal")
        if busy:
            self.cmb_nat_format.config(state="disabled")
            self.txt_nat_ips.config(state="disabled")
        else:
            self._on_toggle_nat()

    def shutdown(self):
        """Goi khi CUA SO CHINH cua Suite dang dong lai (WM_DELETE_WINDOW do main.py
        xu ly) - CHI huy cac tac vu Search/Connect dang chay o tab nay (set
        cancel_event), KHONG tu destroy() gi ca (viec dong toan bo cua so la trach
        nhiem cua main.py, vi tab nay chi la 1 phan cua cua so chung voi tab
        CHECK RULE). Thay the cho _on_close() ban goc (truoc day tu bind vao
        root.protocol khi con la tk.Tk rieng)."""
        self._closing = True
        self.cancel_event.set()
        if self._poll_after_id is not None:
            try:
                self.root.after_cancel(self._poll_after_id)
            except Exception:
                pass
            self._poll_after_id = None


if __name__ == "__main__":
    # Cho phep chay/test doc lap tool CHECK IP (khong qua Suite chinh) - tu dung
    # 1 cua so tk.Tk() rieng lam container, giu nguyen hanh vi title/geometry/
    # minsize nhu truoc day khi main.py cua tool nay con tu tao Tk() rieng.
    _root = tk.Tk()
    _root.title(APP_TITLE)
    _root.geometry("980x780")
    _root.minsize(860, 680)
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
