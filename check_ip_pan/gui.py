# -*- coding: utf-8 -*-
"""
gui.py - Giao dien Tkinter (class App).
"""

import os
import threading
import queue
import xml.etree.ElementTree as ET
from typing import Dict, Optional, Set

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

from .core import APP_TITLE, OUTPUT_DIR, LOG_PATH, DEFAULT_WORKERS, setup_logger, PanApiError
from .core import parse_ip_list_input
from .pan_api import PanApiClient, get_devicegroup_list
from .matching_engine import parse_log_file, run_search_pipeline, run_nat_export_pipeline
from .excel_export import export_to_excel, export_nat_to_excel, export_nat_to_csv

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
        self.api_client: Optional[PanApiClient] = None
        self.config_root: Optional[ET.Element] = None
        self.registered_ip_tags: Dict[str, Set[str]] = {}

        self._build_ui()
        self._on_toggle_nat()  # khoi tao dung noi dung label IP theo che do mac dinh (No/Search)
        self.root.after(100, self._poll_queue)
        # WM_DELETE_WINDOW chi ton tai o Toplevel/Tk, KHONG ap dung duoc cho Frame
        # nua - viec xu ly dong cua so chinh (bao gom huy tac vu dang chay cua tab
        # nay qua self.shutdown()) gio do NOI GOI cap cao nhat (main.py) chiu
        # trach nhiem, xem docstring self.shutdown() ben duoi.
        self._log(f"San sang. Thu muc output: {OUTPUT_DIR}")

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        pad = {"padx": 6, "pady": 4}

        frm_conn = ttk.LabelFrame(self.root, text="1. Ket noi Panorama")
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

        ttk.Label(frm_conn, text="Device Group:").grid(row=1, column=2, sticky="e", **pad)
        self.cmb_vsys = ttk.Combobox(frm_conn, width=18, state="readonly")
        self.cmb_vsys.grid(row=1, column=3, sticky="w", **pad)

        ttk.Label(frm_conn, text="Target Firewall (Serial) - tuy chon:").grid(row=2, column=0, sticky="w", **pad)
        self.ent_target = ttk.Entry(frm_conn, width=28)
        self.ent_target.grid(row=2, column=1, sticky="w", **pad)

        self.btn_connect = ttk.Button(frm_conn, text="Connect", command=self._on_connect)
        self.btn_connect.grid(row=0, column=5, rowspan=2, sticky="ns", **pad)

        frm_input = ttk.LabelFrame(self.root, text="2. Danh sach IP can tim (moi IP 1 dong, hoac paste truc tiep tu Excel)")
        frm_input.pack(fill="both", expand=False, **pad)
        self.txt_ips = scrolledtext.ScrolledText(frm_input, height=7, font=("Consolas", 10))
        self.txt_ips.pack(fill="both", expand=True, **pad)

        frm_log = ttk.LabelFrame(self.root, text="3. File Log doi chieu - tuy chon (.xlsx/.csv: Source IP | Dest IP | Port)")
        frm_log.pack(fill="x", **pad)
        self.ent_logfile = ttk.Entry(frm_log)
        self.ent_logfile.grid(row=0, column=0, sticky="we", padx=6, pady=4)
        frm_log.columnconfigure(0, weight=1)
        ttk.Button(frm_log, text="Browse...", command=self._on_browse_logfile).grid(row=0, column=1, padx=6, pady=4)
        ttk.Button(frm_log, text="Xoa", command=self._on_clear_logfile).grid(row=0, column=2, padx=6, pady=4)

        frm_nat = ttk.LabelFrame(self.root, text="4. Export bang NAT - tuy chon (khong bat buoc nhap muc 2/3)")
        frm_nat.pack(fill="x", **pad)
        ttk.Label(frm_nat, text="Export bang NAT:").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        self.var_export_nat = tk.StringVar(value="No")
        ttk.Radiobutton(frm_nat, text="Yes (Full - xuat toan bo bang NAT)", variable=self.var_export_nat,
                         value="Yes", command=self._on_toggle_nat).grid(row=0, column=1, sticky="w")
        ttk.Radiobutton(frm_nat, text="No (Search - chi xuat rule khop IP nhap ben duoi)", variable=self.var_export_nat,
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

        frm_actions = ttk.Frame(self.root)
        frm_actions.pack(fill="x", **pad)
        self.btn_search = ttk.Button(frm_actions, text="Search", command=self._on_search, state="disabled")
        self.btn_search.pack(side="left", padx=4)
        self.btn_cancel = ttk.Button(frm_actions, text="Cancel", command=self._on_cancel, state="disabled")
        self.btn_cancel.pack(side="left", padx=4)
        self.btn_open_output = ttk.Button(frm_actions, text="Open Output Folder", command=self._on_open_output)
        self.btn_open_output.pack(side="left", padx=4)

        ttk.Label(frm_actions, text="  So thread xu ly (20-50):").pack(side="left", padx=(16, 4))
        self.spn_threads = ttk.Spinbox(frm_actions, from_=20, to=50, width=5, increment=1, justify="center")
        self.spn_threads.set(min(50, max(20, DEFAULT_WORKERS)))
        self.spn_threads.pack(side="left", padx=4)

        frm_progress = ttk.Frame(self.root)
        frm_progress.pack(fill="x", **pad)
        self.lbl_progress = ttk.Label(frm_progress, text="San sang.")
        self.lbl_progress.pack(anchor="w")
        self.progress = ttk.Progressbar(frm_progress, mode="determinate", maximum=100)
        self.progress.pack(fill="x")

        frm_log = ttk.LabelFrame(self.root, text="Log")
        frm_log.pack(fill="both", expand=True, **pad)
        self.txt_log = scrolledtext.ScrolledText(frm_log, height=13, state="disabled", font=("Consolas", 9))
        self.txt_log.pack(fill="both", expand=True, **pad)

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
                text="IP can highlight (tuy chon, mau XANH LA - de trong = xuat full khong highlight):")
        else:
            self.lbl_nat_ips.config(
                text="IP can tim trong bang NAT (BAT BUOC voi che do Search - moi IP 1 dong):")

    # -------------------------------------------------------------- queue
    def _log(self, msg: str):
        self.msg_queue.put(("log", msg))

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
                elif kind == "progress":
                    phase, done, total = payload
                    pct = int(done / total * 100) if total else 0
                    self.progress["value"] = pct
                    self.lbl_progress.config(text=f"{phase}: {done}/{total} ({pct}%)")
                elif kind == "error":
                    messagebox.showerror("Loi", payload)
                elif kind == "done_connect":
                    self._finish_connect(payload)
                elif kind == "done_search":
                    self._finish_search(payload)
                elif kind == "enable_ui":
                    self._set_busy(False)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

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

            self._log("Dang tai FULL running-config Panorama (co the mat vai giay tuy so luong object)...")
            config_root = client.fetch_running_config()
            dg_list = get_devicegroup_list(config_root)
            if not dg_list:
                dg_list = ["shared"]
            self._log(f"Doc danh sach Device Group OK: {', '.join(dg_list)}")

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

    def _finish_connect(self, vsys_list):
        self.cmb_vsys["values"] = vsys_list
        self.cmb_vsys.current(0)
        self.btn_search.config(state="normal")
        self.lbl_progress.config(text="Connect thanh cong. San sang Search.")

    # -------------------------------------------------------------- search
    def _on_search(self):
        if self.config_root is None:
            messagebox.showwarning("Chua ket noi", "Vui long Connect truoc khi Search.")
            return
        dg_name = self.cmb_vsys.get()
        if not dg_name:
            messagebox.showwarning("Thieu Device Group", "Vui long chon Device Group.")
            return
        raw_text = self.txt_ips.get("1.0", "end")
        valid_ips, invalid_lines = parse_ip_list_input(raw_text)
        if invalid_lines:
            preview = ", ".join(invalid_lines[:10]) + (" ..." if len(invalid_lines) > 10 else "")
            self._log(f"Bo qua {len(invalid_lines)} dong khong hop le: {preview}")

        logfile_path = self.ent_logfile.get().strip()
        if logfile_path and not os.path.isfile(logfile_path):
            messagebox.showwarning("File Log khong hop le", f"Khong tim thay file:\n{logfile_path}")
            return

        nat_mode_full = self.var_export_nat.get() == "Yes"
        nat_format = self.cmb_nat_format.get() or "xlsx"

        nat_ip_raw = self.txt_nat_ips.get("1.0", "end")
        nat_ips_input, nat_invalid_lines = parse_ip_list_input(nat_ip_raw)
        if nat_invalid_lines:
            preview = ", ".join(nat_invalid_lines[:10]) + (" ..." if len(nat_invalid_lines) > 10 else "")
            self._log(f"[NAT] Bo qua {len(nat_invalid_lines)} dong IP khong hop le: {preview}")

        if nat_mode_full:
            # Yes = Full: luon xuat toan bo bang NAT; IP nhap (neu co) chi de highlight.
            export_nat = True
            nat_highlight_ips = nat_ips_input
            nat_filter_ips = []
        else:
            # No = Search: KHONG xuat full - chi chay khi nguoi dung thuc su nhap
            # IT NHAT 1 IP hop le de tim; IP do dung de LOC (chi giu rule khop) +
            # highlight XANH LA gia tri khop, khong phai xuat toan bo bang NAT.
            nat_filter_ips = nat_ips_input
            export_nat = bool(nat_filter_ips)
            nat_highlight_ips = []

        # Muc 2 (danh sach IP) va muc 3 (File Log) khong bat buoc - nguoi dung
        # co the chi dung rieng muc 4 (Export bang NAT). Chi bao loi neu KHONG
        # co bat ky tinh nang nao duoc yeu cau.
        if not valid_ips and not logfile_path and not export_nat:
            if not nat_mode_full and nat_ip_raw.strip():
                # Truong hop gay bao loi truoc day: chon "No" (Search) va co go
                # IP vao o nhung TOAN BO khong hop le -> bao loi ro rang, khong
                # phai bao loi chung chung "Thieu thong tin".
                messagebox.showwarning(
                    "IP tim NAT khong hop le",
                    "Cac dong IP ban nhap de Search bang NAT deu khong hop le.\n"
                    "Vui long kiem tra lai dinh dang IP (moi IP 1 dong).")
            else:
                messagebox.showwarning(
                    "Thieu thong tin",
                    "Vui long dan danh sach IP can tim (muc 2), hoac chon File Log (muc 3),\n"
                    "hoac chon 'Export bang NAT': Yes (Full) hoac No + nhap IP can tim (Search).")
            return

        try:
            worker_count = int(self.spn_threads.get())
        except (ValueError, TypeError):
            worker_count = DEFAULT_WORKERS
        worker_count = max(20, min(50, worker_count))  # luon kep trong khoang 20-50 nguoi dung yeu cau
        self.spn_threads.set(worker_count)

        self._set_busy(True)
        self.cancel_event.clear()
        self.progress["value"] = 0
        self.lbl_progress.config(text="Dang xu ly...")
        threading.Thread(target=self._search_worker,
                          args=(dg_name, valid_ips, logfile_path, worker_count,
                                export_nat, nat_format, nat_mode_full, nat_highlight_ips, nat_filter_ips),
                          daemon=True).start()

    def _search_worker(self, dg_name, valid_ips, logfile_path, worker_count,
                        export_nat, nat_format, nat_mode_full, nat_highlight_ips, nat_filter_ips):
        try:
            has_ip_search = bool(valid_ips)
            has_log_file = bool(logfile_path)
            nat_highlight_set = set(nat_highlight_ips)
            nat_filter_set = set(nat_filter_ips)
            nat_desc = "Khong chay" if not export_nat else ("Full" if nat_mode_full else f"Search ({len(nat_filter_set)} IP)")
            self._log(f"Bat dau: {len(valid_ips)} IP, Device Group={dg_name}, worker={worker_count}, "
                      f"File Log={'Co' if has_log_file else 'Khong'}, Export NAT={nat_desc}"
                      + (f", Highlight NAT={len(nat_highlight_set)} IP" if nat_highlight_set else ""))

            output_paths = []
            resolver = None  # tai su dung giua Search Rule va Export NAT neu ca 2 cung chay

            log_entries = None
            if has_log_file:
                try:
                    log_entries = parse_log_file(logfile_path)
                    self._log(f"Doc File Log OK ({len(log_entries)} dong traffic) tu {os.path.basename(logfile_path)}")
                    if not log_entries:
                        self._log("CANH BAO: File Log khong co dong du lieu hop le nao (kiem tra lai header Source IP/Dest IP/Port)")
                except Exception as e:
                    self.logger.exception("Log file parse error")
                    self.msg_queue.put(("error", f"Khong doc duoc File Log:\n{e}"))
                    return

            if has_ip_search or has_log_file:
                rules, match_results, resolver, service_objects, service_groups = run_search_pipeline(
                    self.config_root, dg_name, valid_ips, worker_count,
                    log_func=self._log,
                    progress_cb=lambda phase, d, t: self._set_progress(phase, d, t),
                    cancel_event=self.cancel_event,
                    registered_ip_tags=self.registered_ip_tags,
                )
                if self.cancel_event.is_set():
                    self._log("Da huy theo yeu cau (Cancel).")
                    return

                self.lbl_progress.config(text="Exporting Excel (Rule)...")
                rule_output_path = export_to_excel(OUTPUT_DIR, rules, match_results, resolver,
                                                    service_objects, service_groups,
                                                    log_entries=log_entries, log_func=self._log)
                output_paths.append(rule_output_path)

            if self.cancel_event.is_set():
                self._log("Da huy theo yeu cau (Cancel).")
                return

            if export_nat:
                self.lbl_progress.config(text="Dang doc bang NAT...")
                nat_rules, resolver, nat_service_objects, nat_service_groups = run_nat_export_pipeline(
                    self.config_root, dg_name,
                    log_func=self._log,
                    registered_ip_tags=self.registered_ip_tags,
                    resolver=resolver,
                )
                if self.cancel_event.is_set():
                    self._log("Da huy theo yeu cau (Cancel).")
                    return

                self.lbl_progress.config(
                    text=f"Exporting bang NAT ({'Full' if nat_mode_full else 'Search'}, {nat_format})...")
                if nat_format == "csv":
                    nat_output_path = export_nat_to_csv(OUTPUT_DIR, nat_rules, resolver,
                                                         nat_service_objects, nat_service_groups,
                                                         highlight_ips=nat_highlight_set,
                                                         filter_ips=nat_filter_set,
                                                         log_func=self._log)
                else:
                    nat_output_path = export_nat_to_excel(OUTPUT_DIR, nat_rules, resolver,
                                                           nat_service_objects, nat_service_groups,
                                                           highlight_ips=nat_highlight_set,
                                                           filter_ips=nat_filter_set,
                                                           log_func=self._log)
                output_paths.append(nat_output_path)

            self.msg_queue.put(("done_search", output_paths))
        except PanApiError as e:
            self._log(f"Search FAILED: {e.user_message}")
            self.logger.exception("Search error")
            self.msg_queue.put(("error", e.user_message))
        except Exception:
            self._log("Search FAILED: loi khong xac dinh (xem log.txt)")
            self.logger.exception("Unexpected search error")
            self.msg_queue.put(("error", "Da xay ra loi khong xac dinh khi Search. Xem log.txt de biet chi tiet."))
        finally:
            self.msg_queue.put(("enable_ui", None))

    def _finish_search(self, output_paths):
        if isinstance(output_paths, str):  # tuong thich nguoc, phong khi con noi goi kieu cu
            output_paths = [output_paths]
        names = ", ".join(os.path.basename(p) for p in output_paths)
        self.lbl_progress.config(text=f"Hoan tat: {names}")
        messagebox.showinfo("Hoan tat", "Da xuat ket qua:\n" + "\n".join(output_paths))
        self._on_open_output()  # tu dong mo output folder, khong can bam tay

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
        self.btn_search.config(state="disabled" if busy else ("normal" if self.config_root is not None else "disabled"))
        self.btn_cancel.config(state="normal" if busy else "disabled")
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
        self.cancel_event.set()


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
