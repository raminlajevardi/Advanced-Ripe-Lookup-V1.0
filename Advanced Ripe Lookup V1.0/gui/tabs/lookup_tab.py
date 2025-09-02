import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pandas as pd
import ipaddress
import threading
import requests
from datetime import datetime

# وابستگی‌های اختیاری به کلاینت‌های API پروژه (اگر موجود بودند استفاده می‌کنیم)
try:
    from api_clients.bgpview_api import BGPViewAPI
except Exception:
    BGPViewAPI = None
try:
    from api_clients.ripe_db_api import RipeDBAPI
except Exception:
    RipeDBAPI = None

COLUMNS = [
    "IP/Prefix", "inetnum", "netname", "country", "status",
    "mnt-by", "abuse-mailbox", "created", "last-modified",
    "route", "descr", "origin", "rpki-validation"
]

class LookupTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.single_ip = tk.StringVar()
        self._lock = threading.Lock()
        self._build_ui()

    # ===== UI =====
    def _build_ui(self):
        file_frame = tk.LabelFrame(self, text="File Input", padx=6, pady=6)
        file_frame.pack(fill="x", padx=10, pady=6)

        tk.Label(file_frame, text="Input File (Excel/Text):").grid(row=0, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.input_file, width=54).grid(row=0, column=1, sticky="we", padx=4)
        tk.Button(file_frame, text="Browse", command=self.browse_input_file).grid(row=0, column=2, padx=2)

        tk.Label(file_frame, text="Output File (Excel):").grid(row=1, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.output_file, width=54).grid(row=1, column=1, sticky="we", padx=4)
        tk.Button(file_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=2, padx=2)

        single_frame = tk.LabelFrame(self, text="RIPE Lookup (IP / CIDR / Range)", padx=6, pady=6)
        single_frame.pack(fill="x", padx=10, pady=6)

        tk.Label(single_frame, text="IP / Range:").grid(row=0, column=0, sticky="w")
        tk.Entry(single_frame, textvariable=self.single_ip, width=36).grid(row=0, column=1, sticky="we", padx=4)
        tk.Button(single_frame, text="Lookup", command=self.lookup_single_ip).grid(row=0, column=2, padx=2)

        result_frame = tk.LabelFrame(self, text="Results", padx=6, pady=6)
        result_frame.pack(fill="both", expand=True, padx=10, pady=6)

        scroll_y = ttk.Scrollbar(result_frame)
        scroll_y.pack(side="right", fill="y")
        scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        scroll_x.pack(side="bottom", fill="x")

        self.tree = ttk.Treeview(result_frame, columns=COLUMNS, show="headings",
                                 yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        for col in COLUMNS:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=120, stretch=False)
        # عرض مناسب‌تر برای چند ستون کلیدی
        self.tree.column("IP/Prefix", width=140, stretch=True)
        self.tree.column("descr", width=200, stretch=True)

        self.tree.tag_configure('has_route', background='white')
        self.tree.tag_configure('no_route', background='#d4edda')  # سبز روشن (مطابق نسخه‌ی قبلی)

        self.tree.pack(fill="both", expand=True)
        scroll_y.config(command=self.tree.yview)
        scroll_x.config(command=self.tree.xview)

        button_frame = tk.Frame(self)
        button_frame.pack(fill="x", padx=10, pady=6)

        tk.Button(button_frame, text="Process File", command=self.process_file).pack(side="left", padx=4)
        tk.Button(button_frame, text="Export to Excel", command=self.export_to_excel).pack(side="left", padx=4)
        tk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side="left", padx=4)

        self.status_var = tk.StringVar(value="Ready")
        tk.Label(self, textvariable=self.status_var, anchor="w").pack(fill="x", padx=12, pady=(0,8))

    # ===== File pickers =====
    def browse_input_file(self):
        filetypes = (("Excel files", "*.xlsx;*.xls"), ("Text/CSV", "*.txt;*.csv"), ("All files", "*.*"))
        filename = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if filename:
            self.input_file.set(filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(title="Save output as ...", defaultextension=".xlsx",
                                                filetypes=(("Excel files", "*.xlsx"), ("All files", "*.*")))
        if filename:
            self.output_file.set(filename)

    # ===== Processing =====
    def process_file(self):
        infile = self.input_file.get().strip()
        if not infile:
            messagebox.showwarning("Warning", "Please select an input file.")
            return
        try:
            if infile.lower().endswith((".txt", ".csv")):
                with open(infile, "r", encoding="utf-8", errors="ignore") as f:
                    items = [line.strip() for line in f if line.strip()]
            else:
                df = pd.read_excel(infile)
                first_col = df.columns[0]
                items = df[first_col].dropna().astype(str).tolist()
            if not items:
                messagebox.showinfo("Info", "No items found in input file.")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Failed to read input file:\n{e}")
            return

        self.clear_results()
        self.status_var.set(f"Processing {len(items)} item(s)...")
        threading.Thread(target=self._process_items_thread, args=(items,), daemon=True).start()

    def _process_items_thread(self, items):
        total = len(items)
        for idx, s in enumerate(items, start=1):
            for token in self._expand_input(s):
                record = self.lookup_ip(token)
                self._insert_record_safe(record)
            self._update_status_safe(f"Processed {idx}/{total}")
        self._update_status_safe("Done")

    def lookup_single_ip(self):
        text = self.single_ip.get().strip()
        if not text:
            messagebox.showwarning("Warning", "Please enter an IP, prefix, or range.")
            return
        try:
            # اگر محدوده‌ی خیلی بزرگی است، پیشنهاد تقسیم به /24
            if self._is_large_network(text):
                answer = messagebox.askyesno("Subnet Division",
                                             "Range is large. Do you want to divide it into /24 subnets and check each one?")
                if answer:
                    net = self._parse_to_network(text)
                    if net and isinstance(net, ipaddress.IPv4Network):
                        threading.Thread(target=self.process_subnets, args=(net,), daemon=True).start()
                        return
            # در غیر اینصورت همان ورودی را پردازش کن
            self.clear_results()
            for token in self._expand_input(text):
                record = self.lookup_ip(token)
                self._insert_record_safe(record)
            self.status_var.set("Done")
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid input: {e}")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing input: {e}")

    def process_subnets(self, network: ipaddress._BaseNetwork):
        # تقسیم به /24 برای IPv4
        for subnet in network.subnets(new_prefix=24):
            rec = self.lookup_ip(str(subnet))
            self._insert_record_safe(rec)
        self._update_status_safe("Done (subnets)")

    # ===== Lookup Core =====
    def lookup_ip(self, resource: str) -> dict:
        """
        ورودی می‌تواند IP، CIDR یا یک subnet باشد.
        خروجی: dict با کلیدهای COLUMNS
        """
        info = {k: "" for k in COLUMNS}
        info["IP/Prefix"] = resource

        try:
            # تشخیص نوع
            network = self._parse_to_network(resource)
            is_v6 = isinstance(network, ipaddress.IPv6Network) if network else (':' in resource)

            # 1) RIPE DB: inetnum/inet6num
            ripe_inet = self._ripe_inet_lookup(resource, is_v6=is_v6)
            info.update({k: ripe_inet.get(k, "") for k in ["inetnum", "netname", "country", "status",
                                                           "mnt-by", "abuse-mailbox", "created", "last-modified", "descr"]})
            # 2) RIPE DB: route/route6 + origin
            ripe_route = self._ripe_route_lookup(resource, is_v6=is_v6)
            info["route"] = ripe_route.get("route", "")
            info["origin"] = ripe_route.get("origin", "")
            if not info.get("descr"):
                info["descr"] = ripe_route.get("descr", "") or info.get("descr", "")

            # 3) RPKI Validation via RIPEstat (best-effort)
            info["rpki-validation"] = self._rpki_validate(resource) or ""

            # 4) اگر خواستی به BGPView هم چک کن (fallback برای route/origin)
            if not info["route"] and BGPViewAPI:
                try:
                    j = BGPViewAPI.get_prefix_info(resource)
                    data = j.get("data", {})
                    prefixes = data.get("prefixes", []) or []
                    if prefixes:
                        p = prefixes[0]
                        info["route"] = p.get("prefix", info["route"])
                        # origin ASها
                        origins = [str(o.get("asn")) for o in data.get("origins", []) if isinstance(o, dict) and o.get("asn")]
                        if origins:
                            info["origin"] = ",".join(origins)
                except Exception:
                    pass

            # برچسب برای نمایش
            tag = "has_route" if info.get("route") else "no_route"
            info["_tag"] = tag
        except Exception as e:
            info["_tag"] = "no_route"
            info["descr"] = f"Lookup error: {e}"
        return info

    # ===== Helpers: RIPE / RPKI =====
    def _ripe_inet_lookup(self, resource: str, is_v6: bool) -> dict:
        # تلاش با RipeDBAPI اگر موجود است
        if RipeDBAPI:
            try:
                obj_type = "inet6num" if is_v6 else "inetnum"
                j = RipeDBAPI.query(obj_type, resource)
                got = self._extract_from_ripe_json(j, prefer_type=obj_type)
                if got:
                    return got
            except Exception:
                pass
        # fallback مستقیم
        try:
            url = "https://rest.db.ripe.net/search.json"
            params = {"query-string": resource, "type-filter": "inet6num" if is_v6 else "inetnum"}
            j = requests.get(url, params=params, timeout=15).json()
            got = self._extract_from_ripe_json(j, prefer_type=("inet6num" if is_v6 else "inetnum"))
            return got or {}
        except Exception:
            return {}

    def _ripe_route_lookup(self, resource: str, is_v6: bool) -> dict:
        try:
            url = "https://rest.db.ripe.net/search.json"
            params = {"query-string": resource, "type-filter": "route6" if is_v6 else "route"}
            j = requests.get(url, params=params, timeout=15).json()
            got = self._extract_from_ripe_json(j, prefer_type=("route6" if is_v6 else "route"))
            return got or {}
        except Exception:
            return {}

    def _rpki_validate(self, resource: str) -> str:
        try:
            url = "https://stat.ripe.net/data/rpki-validation/data.json"
            j = requests.get(url, params={"resource": resource}, timeout=15).json()
            status = j.get("data", {}).get("status", "")
            return status
        except Exception:
            return ""

    def _extract_from_ripe_json(self, j: dict, prefer_type: str) -> dict:
        """
        j: خروجی rest.db.ripe.net
        prefer_type: یکی از inetnum/inet6num/route/route6
        خروجی: dict با کلیدهای موردنیاز
        """
        out = {}
        objs = (j or {}).get("objects", {}).get("object", []) or []
        # اول دنبال آبجکت با type دلخواه
        for obj in objs:
            if obj.get("type") != prefer_type:
                continue
            attrs = obj.get("attributes", {}).get("attribute", []) or []
            for a in attrs:
                k = a.get("name", "").lower()
                v = a.get("value", "")
                if not v:
                    continue
                if k in ("inetnum", "inet6num", "netname", "country", "status", "mnt-by", "abuse-mailbox",
                         "created", "last-modified", "descr", "route", "route6", "origin"):
                    if k == "route6":
                        out["route"] = v
                    else:
                        out[k] = v
            # اگر همه‌ی اطلاعات مهم پیدا شد، تمام
            if out:
                break
        # اگر route پیدا نکردیم، یک تلاش دیگر
        if "route" not in out:
            for obj in objs:
                if obj.get("type") not in ("route", "route6"):
                    continue
                attrs = obj.get("attributes", {}).get("attribute", []) or []
                for a in attrs:
                    k = a.get("name", "").lower()
                    v = a.get("value", "")
                    if k in ("route", "route6"):
                        out["route"] = v
                    elif k == "origin":
                        out["origin"] = v
                    elif k == "descr" and "descr" not in out:
                        out["descr"] = v
        return out

    # ===== Helpers: input parsing & UI thread safe insert =====
    def _expand_input(self, s: str):
        s = s.strip()
        # 1) Range: "start-end"
        if '-' in s and not '/' in s:
            try:
                left, right = [x.strip() for x in s.split('-', 1)]
                start = ipaddress.ip_address(left)
                end = ipaddress.ip_address(right)
                for net in ipaddress.summarize_address_range(start, end):
                    yield str(net)
                return
            except Exception:
                pass
        # 2) Single IP or CIDR
        yield s

    def _parse_to_network(self, s: str):
        # اگر IP تنها بود، آن را به /32 یا /128 تبدیل می‌کنیم
        try:
            if '/' in s:
                return ipaddress.ip_network(s, strict=False)
            ip_obj = ipaddress.ip_address(s)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                return ipaddress.ip_network(f"{s}/32", strict=False)
            else:
                return ipaddress.ip_network(f"{s}/128", strict=False)
        except Exception:
            return None

    def _is_large_network(self, s: str) -> bool:
        net = self._parse_to_network(s)
        if not net:
            return False
        if isinstance(net, ipaddress.IPv4Network):
            return net.prefixlen < 24  # بزرگتر از /24
        # برای IPv6 خیلی بزرگ است؛ اینجا فقط هشدار نمی‌دهیم
        return False

    def _insert_record_safe(self, record: dict):
        def _ins():
            vals = [record.get(col, "") for col in COLUMNS]
            tag = record.get("_tag", "has_route")
            self.tree.insert("", "end", values=vals, tags=(tag,))
        self.after(0, _ins)

    def _update_status_safe(self, txt: str):
        def _upd():
            self.status_var.set(txt)
        self.after(0, _upd)

    # ===== Export & Clear =====
    def export_to_excel(self):
        outfile = self.output_file.get().strip()
        if not outfile:
            messagebox.showwarning("Warning", "Please select an output file.")
            return
        try:
            rows = [self.tree.item(i)["values"] for i in self.tree.get_children()]
            if not rows:
                messagebox.showinfo("Info", "No rows to export.")
                return
            df = pd.DataFrame(rows, columns=COLUMNS)
            # افزودن زمان ایجاد
            with pd.ExcelWriter(outfile, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Results")
                # یک شیت کوچک برای متادیتا
                meta = pd.DataFrame({
                    "key": ["generated_at", "rows"],
                    "value": [datetime.now().isoformat(timespec="seconds"), len(rows)]
                })
                meta.to_excel(writer, index=False, sheet_name="Meta")
            messagebox.showinfo("Success", f"Exported to {outfile}")
        except Exception as e:
            messagebox.showerror("Error", f"Export failed: {e}")

    def clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.status_var.set("Cleared")