import ipaddress
import pandas as pd
import requests
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from datetime import datetime
import socket
import json
import threading
import time
import os
import sys
import winsound
import smtplib
from email.mime.text import MIMEText
import re
import csv
import paramiko
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple, Set
from concurrent.futures import ThreadPoolExecutor, as_completed
import traceback

@dataclass
class RouteItem:
    prefix: str
    origin_as: Optional[int]
    communities: List[str]

def extract_last_as(as_path: str) -> Optional[int]:
    if not as_path:
        return None
    nums = re.findall(r"\b(\d{1,10})\b", as_path)
    if not nums:
        return None
    return int(nums[-1])

def match_community(comm_list: List[str], pattern: str) -> bool:
    pat = pattern.strip()
    if not pat:
        return True
    if ':' not in pat:
        return any(pat in c for c in comm_list)
    left, right = pat.split(':', 1)
    for c in comm_list:
        if ':' not in c:
            continue
        l, r = c.split(':', 1)
        if (left == '*' or left == l) and (right == '*' or right == r):
            return True
    return False

def ssh_collect_output(host: str, username: str, password: str, commands: List[str],
                      port: int = 22, timeout: int = 30, prompt_wait: float = 0.6) -> str:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=host, port=port, username=username, password=password,
                   look_for_keys=False, allow_agent=False, timeout=timeout)
    try:
        chan = client.invoke_shell()
        chan.settimeout(timeout)
        output_chunks = []
        def send(cmd: str):
            if not cmd.endswith("\n"):
                cmd += "\n"
            chan.send(cmd)
        send("terminal length 0")
        time.sleep(prompt_wait)
        while chan.recv_ready():
            output_chunks.append(chan.recv(65535).decode(errors="ignore"))
        for cmd in commands:
            send(cmd)
            last_read = time.time()
            while True:
                time.sleep(0.1)
                if chan.recv_ready():
                    chunk = chan.recv(65535).decode(errors="ignore")
                    output_chunks.append(chunk)
                    last_read = time.time()
                else:
                    if time.time() - last_read > prompt_wait:
                        break
        return "".join(output_chunks)
    finally:
        client.close()

class RPKIValidator:
    def __init__(self, timeout=15, parent=None):  # افزایش timeout به 15 ثانیه
        self.timeout = timeout
        self.parent = parent

    def validate(self, prefix, asn):
        url = "https://stat.ripe.net/data/rpki-validation/data.json"
        params = {"resource": str(asn), "prefix": prefix}
        retries = 5  # افزایش تعداد تلاش‌ها به 5
        for attempt in range(retries):
            try:
                resp = requests.get(url, params=params, timeout=self.timeout)
                resp.raise_for_status()
                data = resp.json()
                validation_data = data.get("data", {})
                status = validation_data.get("status", "error")
                desc = validation_data.get("description", "")
                if status == "valid":
                    return "valid", desc
                elif status == "invalid":
                    return "invalid", desc
                else:
                    return "not-found", desc
            except requests.exceptions.RequestException as e:
                error_msg = f"Attempt {attempt + 1}/{retries} failed for prefix {prefix}, ASN {asn}: {str(e)}"
                if attempt == retries - 1:
                    self.parent.bgprpki_append_log(error_msg)  # لاگ کردن خطا در تلاش آخر
                    return "error", error_msg
                time.sleep(2)  # تأخیر 2 ثانیه‌ای قبل از تلاش مجدد

def parse_text_bgp(output: str) -> List[RouteItem]:
    routes: List[RouteItem] = []
    lines = output.splitlines()
    current_prefix: Optional[str] = None
    current_as_path: str = ""
    current_comms: List[str] = []
    re_prefix_line = re.compile(r"(?P<prefix>\d+\.\d+\.\d+\.\d+/\d+)\s")
    re_aspath_numbers = re.compile(r"\b(\d{1,10})\b")
    re_comm_line = re.compile(r"Community:\s+(.+)$", re.IGNORECASE)
    
    def flush():
        nonlocal current_prefix, current_as_path, current_comms
        if current_prefix:
            origin = extract_last_as(current_as_path)
            routes.append(RouteItem(prefix=current_prefix, origin_as=origin, communities=current_comms[:]))
        current_prefix = None
        current_as_path = ""
        current_comms = []
    
    for raw in lines:
        line = raw.strip()
        m = re_prefix_line.search(line)
        if m:
            flush()
            current_prefix = m.group("prefix")
            after = line[m.end():]
            nums = re_aspath_numbers.findall(after)
            if nums:
                current_as_path = " ".join(nums)
            continue
        if current_prefix and not current_as_path:
            nums = re_aspath_numbers.findall(line)
            if nums:
                current_as_path = " ".join(nums)
        cm = re_comm_line.search(line)
        if current_prefix and cm:
            parts = cm.group(1).split()
            current_comms.extend([p for p in parts if ":" in p])
    flush()
    
    # یکتاسازی بر اساس (prefix, origin_as)
    seen: Set[Tuple[str, int]] = set()
    uniq: List[RouteItem] = []
    for r in routes:
        if r.origin_as is None:
            continue
        key = (r.prefix, r.origin_as)
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    
    return uniq

class AuditWorker(threading.Thread):
    def __init__(self, params: Dict[str, Any], parent):
        super().__init__()
        self.params = params
        self.parent = parent
        self._stop = threading.Event()
    
    def stop(self):
        self._stop.set()
    
    def run(self):
        try:
            self._run_impl()
        except Exception as e:
            tb = ''.join(traceback.format_exc())
            self.parent.root.after(0, lambda: self.parent.bgprpki_on_error(f"{e}\n{tb}"))

    def _run_impl(self):
        p = self.params
        host = p["host"]
        port = int(p.get("port", 22))
        user = p["username"]
        pwd = p["password"]
        afi = p.get("afi", "ipv4")
        vendor = p.get("vendor", "ios-xe")
        limit = int(p.get("limit", 0))
        only_bad = bool(p.get("only_bad", False))
        filter_asn = p.get("filter_asn")
        filter_comm = p.get("filter_comm")
        concurrency = max(1, int(p.get("concurrency", 8)))
        rpki_url = p.get("rpki_url", "https://stat.ripe.net/data/rpki-validation/data.json")
        
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status("Connecting to router via SSH..."))
        
        cmds: List[str] = []
        if afi == "ipv4":
            if vendor == "ios-xe":
                base_cmd = "show ip bgp"
            elif vendor == "ios-xr":
                base_cmd = "show bgp ipv4 unicast"
            else:
                base_cmd = "show ip bgp"
        else:
            if vendor == "ios-xe":
                base_cmd = "show bgp ipv6 unicast"
            elif vendor == "ios-xr":
                base_cmd = "show bgp ipv6 unicast"
            else:
                base_cmd = "show bgp ipv6 unicast"
        
        if filter_asn:
            try:
                asn = str(filter_asn).replace("AS", "").strip()
                cmds = [f"{base_cmd} regexp ^{asn}_"]
                self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Using ASN filter command: {cmds[0]}"))
            except Exception as e:
                self.parent.root.after(0, lambda: self.parent.bgprpki_on_error(f"Invalid ASN filter: {str(e)}"))
                return
        elif filter_comm:
            community = str(filter_comm).strip()
            cmds = [f"{base_cmd} community {community}"]
            self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Using community filter command: {cmds[0]}"))
        else:
            cmds = [base_cmd]
        
        output = ssh_collect_output(host, user, pwd, cmds, port=port)
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status("Parsing BGP output..."))
        routes = parse_text_bgp(output)
        
        if self._stop.is_set():
            self.parent.root.after(0, lambda: self.parent.bgprpki_on_status("Stopped."))
            self.parent.root.after(0, lambda: self.parent.update_pending_to_error())
            return
        
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Total routes parsed before filtering: {len(routes)}"))
        
        if filter_asn and not cmds:  # اگر فیلتر ASN نامعتبر بود، فیلتر اعمال نشود
            try:
                fasn = int(str(filter_asn).replace("AS", "").strip())
                routes = [r for r in routes if r.origin_as == fasn]
            except Exception:
                pass
        if filter_comm and not cmds:  # اگر فیلتر Community نامعتبر بود، فیلتر اعمال نشود
            routes = [r for r in routes if match_community(r.communities, str(filter_comm).strip())]
        
        if limit and limit > 0:
            routes = routes[:limit]
        
        total = len(routes)
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Routes after filters: {total}"))
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_progress(0, total))
        
        unique_keys: Set[Tuple[str, int]] = set()
        uniq_routes: List[RouteItem] = []
        for r in routes:
            key = (r.prefix, r.origin_as or -1)
            if key not in unique_keys:
                unique_keys.add(key)
                uniq_routes.append(r)
        
        total = len(uniq_routes)
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Unique (prefix, origin-AS) pairs to validate: {total}"))
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_progress(0, total))
        
        if total == 0:
            self.parent.root.after(0, lambda: self.parent.bgprpki_on_summary({"total": 0, "valid": 0, "invalid": 0, "not_found": 0, "error": 0}))
            return
        
        for r in uniq_routes:
            if not only_bad:
                self.parent.root.after(0, lambda: self.parent.bgprpki_on_route_parsed(r.prefix, r.origin_as or -1, " ".join(r.communities)))
        
        validator = RPKIValidator()
        valid_count = invalid_count = notfound_count = error_count = 0
        processed = 0
        
        def job(route: RouteItem) -> Tuple[RouteItem, str, str]:
            if self._stop.is_set():
                return route, "error", "stopped"
            validity, detail = validator.validate(route.prefix, route.origin_as or -1)
            retries = 0
            while validity == "error" and retries < 3:
                time.sleep(1)
                validity, detail = validator.validate(route.prefix, route.origin_as or -1)
                retries += 1
            return route, validity, detail
        
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status(f"Starting RPKI validation with concurrency={concurrency}..."))
        with ThreadPoolExecutor(max_workers=concurrency) as ex:
            futures_map = {ex.submit(job, r): r for r in uniq_routes}
            for fut in as_completed(futures_map):
                if self._stop.is_set():
                    self.parent.root.after(0, lambda: self.parent.update_pending_to_error())
                    break
                route, validity, detail = fut.result()
                processed += 1
                self.parent.root.after(0, lambda: self.parent.bgprpki_on_progress(processed, total))
                
                if validity == "valid":
                    valid_count += 1
                    if not only_bad:
                        self.parent.root.after(0, lambda: self.parent.bgprpki_on_route_validated(route.prefix, route.origin_as or -1, validity, detail))
                elif validity == "invalid":
                    invalid_count += 1
                    self.parent.root.after(0, lambda: self.parent.bgprpki_on_route_validated(route.prefix, route.origin_as or -1, validity, detail))
                elif validity == "not-found":
                    notfound_count += 1
                    self.parent.root.after(0, lambda: self.parent.bgprpki_on_route_validated(route.prefix, route.origin_as or -1, validity, detail))
                else:
                    error_count += 1
                    self.parent.root.after(0, lambda: self.parent.bgprpki_on_route_validated(route.prefix, route.origin_as or -1, "error", detail))
        
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_summary({
            "total": total,
            "valid": valid_count,
            "invalid": invalid_count,
            "not_found": notfound_count,
            "error": error_count
        }))
        self.parent.root.after(0, lambda: self.parent.bgprpki_on_status("Done."))

class AdvancedRIPEIPLookup:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced RIPE IP Lookup Tool V1.0")
        self.root.geometry("1200x800")
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True)
        self.prefix_file = 'prefixes.json'
        self.prefix_list = self.load_prefixes()
        self.monitoring = False
        self.monitor_thread = None
        self.beep_enabled = tk.BooleanVar(value=False)
        self.email_alarm_enabled = tk.BooleanVar(value=False)
        self.supernet_analyzer_enabled = tk.BooleanVar(value=False)
        self.countdown_seconds = 0
        self.refresh_interval_ms = 0
        self.start_time = None
        self.after_id = None
        self.countdown_after_id = None
        self.alarm_interval_ms = 0
        self.last_not_available_prefixes = set()
        self.settings_file = 'settings.json'
        self.settings = self.load_settings()
        self.bgprpki_worker = None
        self.bgprpki_total_expected = 0
        self.create_lookup_tab()
        self.create_looking_glass_tab()
        self.create_prefix_availability_tab()
        self.create_bgprpki_auditor_tab()
        self.create_settings_tab()

        # Frame for bottom labels
        bottom_frame = tk.Frame(self.root)
        bottom_frame.pack(side="bottom", fill="x")

        # Creator label
        creator_label = tk.Label(bottom_frame, text="Created by Ramin Lajevardi", fg="gray")
        creator_label.pack(side="right", padx=10, pady=5)

        # Network status label
        self.network_status_label = tk.Label(bottom_frame, text="Network Status: Checking...", fg="black")
        self.network_status_label.pack(side="left", padx=10, pady=5)

        self.check_network_status()

    def load_prefixes(self):
        """Load prefixes from the prefixes.json file."""
        try:
            if os.path.exists(self.prefix_file):
                with open(self.prefix_file, 'r') as f:
                    return json.load(f)
            else:
                return []
        except (json.JSONDecodeError, IOError):
            return []

    def load_settings(self):
        """Load settings from the settings.json file."""
        try:
            if os.path.exists(self.settings_file):
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            else:
                return {}
        except (json.JSONDecodeError, IOError):
            return {}

    def check_network_status(self):
        try:
            socket.setdefaulttimeout(2)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect(('8.8.8.8', 53))
            sock.close()
            self.network_status_label.config(text="Network Status: OK", fg="green")
        except (socket.timeout, socket.error):
            self.network_status_label.config(text="Network Status: Down", fg="red")
        self.root.after(10000, self.check_network_status)

    def create_lookup_tab(self):
        self.lookup_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lookup_tab, text="RIPE Lookup")
        self.input_file = tk.StringVar()
        self.output_file = tk.StringVar()
        self.single_ip = tk.StringVar()
        file_frame = tk.LabelFrame(self.lookup_tab, text="File Input", padx=5, pady=5)
        file_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(file_frame, text="Input File (Excel/Text):").grid(row=0, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.input_file, width=50).grid(row=0, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_input_file).grid(row=0, column=2)
        tk.Label(file_frame, text="Output File (Excel):").grid(row=1, column=0, sticky="w")
        tk.Entry(file_frame, textvariable=self.output_file, width=50).grid(row=1, column=1)
        tk.Button(file_frame, text="Browse", command=self.browse_output_file).grid(row=1, column=2)
        single_frame = tk.LabelFrame(self.lookup_tab, text="Ripe Lookup", padx=5, pady=5)
        single_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(single_frame, text="IP Address/Range:").grid(row=0, column=0, sticky="w")
        tk.Entry(single_frame, textvariable=self.single_ip, width=30).grid(row=0, column=1)
        tk.Button(single_frame, text="Lookup", command=self.lookup_single_ip).grid(row=0, column=2)
        result_frame = tk.LabelFrame(self.lookup_tab, text="Results", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        scroll_y = ttk.Scrollbar(result_frame)
        scroll_y.pack(side="right", fill="y")
        scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        scroll_x.pack(side="bottom", fill="x")
        self.tree = ttk.Treeview(result_frame, yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.pack(fill="both", expand=True)
        self.tree.tag_configure('has_route', background='white')
        self.tree.tag_configure('no_route', background='#d4edda')
        scroll_y.config(command=self.tree.yview)
        scroll_x.config(command=self.tree.xview)
        button_frame = tk.Frame(self.lookup_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        tk.Button(button_frame, text="Process File", command=self.process_file).pack(side="left", padx=5)
        tk.Button(button_frame, text="Export to Excel", command=self.export_to_excel).pack(side="left", padx=5)
        tk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side="left", padx=5)
        self.configure_treeview()

    def browse_input_file(self):
        filetypes = (("Excel files", "*.xlsx;*.xls"), ("Text files", "*.txt;*.csv"), ("All files", "*.*"))
        filename = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if filename:
            self.input_file.set(filename)

    def browse_output_file(self):
        filename = filedialog.asksaveasfilename(title="Save output file", defaultextension=".xlsx", filetypes=(("Excel files", "*.xlsx"), ("All files", "*.*")))
        if filename:
            self.output_file.set(filename)

    def configure_treeview(self):
        columns = ["IP Address", "inetnum", "netname", "country", "admin-c", "tech-c", "abuse-c", "status", "mnt-by", "created", "last-modified", "route", "descr", "origin", "rpki-validation"]
        self.tree["columns"] = columns
        self.tree.column("#0", width=0, stretch=tk.NO)
        column_widths = {"IP Address": 120, "inetnum": 150, "netname": 120, "country": 80, "admin-c": 100, "tech-c": 100, "abuse-c": 100, "status": 100, "mnt-by": 120, "created": 100, "last-modified": 100, "route": 120, "descr": 150, "origin": 120, "rpki-validation": 120}
        for col in columns:
            self.tree.column(col, width=column_widths.get(col, 100), anchor="w", minwidth=50, stretch=tk.YES)
            self.tree.heading(col, text=col)

    def lookup_single_ip(self):
        ip_input = self.single_ip.get().strip()
        if not ip_input:
            messagebox.showerror("Error", "Please enter an IP address or range")
            return
        try:
            if '/' in ip_input:
                network = ipaddress.ip_network(ip_input, strict=False)
                if network.prefixlen < 24:
                    answer = messagebox.askyesno("Subnet Division", f"The entered range ({ip_input}) is larger than /24.\nDo you want to divide it into /24 subnets and check each one?")
                    if answer:
                        threading.Thread(target=self.process_subnets, args=(network,)).start()
                        return
            threading.Thread(target=self.process_single_ip, args=(ip_input,)).start()
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid IP address or range: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing IP: {str(e)}")

    def process_subnets(self, network):
        for subnet in network.subnets(new_prefix=24):
            result = self.lookup_ip(str(subnet))
            if result:
                self.root.after(0, lambda r=result: self.root.after(0, lambda r=r: self.display_single_result(r)))

    def process_single_ip(self, ip_input):
        result = self.lookup_ip(ip_input)
        if result:
            self.root.after(0, lambda r=result: self.root.after(0, lambda r=r: self.display_single_result(r)))

    def process_file(self):
        input_file = self.input_file.get()
        if not input_file:
            messagebox.showerror("Error", "Please select an input file")
            return
        try:
            if input_file.endswith(('.xlsx', '.xls')):
                df = pd.read_excel(input_file)
                ips = df.iloc[:, 0].astype(str).tolist()
            else:
                with open(input_file, 'r') as f:
                    ips = [line.strip() for line in f if line.strip()]
            self.clear_results()
            threading.Thread(target=self.process_ips, args=(ips,)).start()
        except Exception as e:
            messagebox.showerror("Error", f"Error processing file: {str(e)}")

    def process_ips(self, ips):
        for ip in ips:
            result = self.lookup_ip(ip)
            if result:
                self.root.after(0, lambda r=result: self.root.after(0, lambda r=r: self.display_single_result(r)))

    def display_single_result(self, result):
        values = [result.get(col, "") for col in self.tree["columns"]]
        tags = []
        if result.get("route", "").strip():
            tags.append('has_route')
        else:
            tags.append('no_route')
        self.tree.insert("", "end", values=values, tags=tuple(tags))

    def lookup_ip(self, ip):
        try:
            ripe_result = self.get_ripe_db_info(ip)
            if ripe_result.get("origin"):
                origins = [o.strip() for o in ripe_result["origin"].split(",")]
                rpki_results = []
                for origin in origins:
                    if origin.startswith("AS"):
                        origin = origin[2:]
                    rpki_status = self.check_rpki_validation(ip, origin)
                    if rpki_status:
                        if rpki_status.get("status") == "valid":
                            rpki_results.append(f"AS{rpki_status.get('resource')}")
                        elif rpki_status.get("status") == "error":
                            rpki_results.append("It should be an IP prefix")
                if rpki_results:
                    ripe_result["rpki-validation"] = ", ".join(rpki_results)
            return ripe_result
        except Exception as e:
            messagebox.showerror("Error", f"Error looking up IP {ip}: {str(e)}")
            return None

    def get_ripe_db_info(self, ip):
        url = f"https://rest.db.ripe.net/search.json?query-string={ip}&flags=no-filtering"
        headers = {"Accept": "application/json"}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()
        objects = data.get("objects", {}).get("object", [])
        result = {
            "IP Address": ip,
            "inetnum": "",
            "netname": "",
            "country": "",
            "admin-c": "",
            "tech-c": "",
            "abuse-c": "",
            "status": "",
            "mnt-by": "",
            "created": "",
            "last-modified": "",
            "route": "",
            "descr": "",
            "origin": "",
            "rpki-validation": ""
        }
        origins = set()
        for obj in objects:
            obj_type = obj.get("type", "")
            attributes = obj.get("attributes", {}).get("attribute", [])
            if obj_type == "inetnum":
                for attr in attributes:
                    name = attr.get("name", "")
                    value = attr.get("value", "")
                    if name in ["inetnum", "netname", "country", "admin-c", "tech-c", "abuse-c", "status", "mnt-by", "created", "last-modified"]:
                        if result[name]:
                            result[name] += f", {value}"
                        else:
                            result[name] = value
                    elif name == "descr":
                        if result["descr"]:
                            result["descr"] += f", {value}"
                        else:
                            result["descr"] = value
            elif obj_type == "route":
                for attr in attributes:
                    name = attr.get("name", "")
                    value = attr.get("value", "")
                    if name == "route":
                        result["route"] = value
                    elif name == "origin":
                        origins.add(value)
        if origins:
            result["origin"] = ", ".join(sorted(origins))
        return result

    def check_rpki_validation(self, prefix, asn):
        try:
            url = f"https://stat.ripe.net/data/rpki-validation/data.json?resource=AS{asn}&prefix={prefix}"
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            if data.get("data", {}).get("status") == "valid":
                return {"status": "valid", "resource": data["data"].get("resource"), "prefix": data["data"].get("prefix")}
            return {"status": "error"}
        except Exception as e:
            print(f"Error checking RPKI validation: {str(e)}  ripev7.0.py:611  ripev8.0.py:606  ripev9.0.py:614 - ripe-v9.1.py:614")
            return {"status": "error"}

    def display_results(self, results):
        for item in self.tree.get_children():
            self.tree.delete(item)
        for result in results:
            values = [result.get(col, "") for col in self.tree["columns"]]
            tags = []
            if result.get("route", "").strip():
                tags.append('has_route')
            else:
                tags.append('no_route')
            self.tree.insert("", "end", values=values, tags=tuple(tags))

    def export_to_excel(self):
        output_file = self.output_file.get()
        if not output_file:
            messagebox.showerror("Error", "Please specify an output file")
            return
        try:
            data = []
            for item in self.tree.get_children():
                values = self.tree.item(item)["values"]
                data.append(values)
            if not data:
                messagebox.showwarning("Warning", "No data to export")
                return
            columns = self.tree["columns"]
            df = pd.DataFrame(data, columns=columns)
            df.to_excel(output_file, index=False)
            messagebox.showinfo("Success", f"Data exported to {output_file}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to Excel: {str(e)}")

    def clear_results(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

    def create_looking_glass_tab(self):
        self.lg_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.lg_tab, text="Looking Glass")
        self.lg_ip = tk.StringVar()
        input_frame = tk.LabelFrame(self.lg_tab, text="Looking Glass Query", padx=5, pady=5)
        input_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(input_frame, text="IP Address/Range:").grid(row=0, column=0, sticky="w")
        tk.Entry(input_frame, textvariable=self.lg_ip, width=30).grid(row=0, column=1)
        self.lg_query_button = tk.Button(input_frame, text="Query", command=self.query_looking_glass)
        self.lg_query_button.grid(row=0, column=2)
        result_frame = tk.LabelFrame(self.lg_tab, text="Looking Glass Results", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        lg_scroll_y = ttk.Scrollbar(result_frame)
        lg_scroll_y.pack(side="right", fill="y")
        lg_scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        lg_scroll_x.pack(side="bottom", fill="x")
        self.lg_tree = ttk.Treeview(result_frame, yscrollcommand=lg_scroll_y.set, xscrollcommand=lg_scroll_x.set)
        self.lg_tree.pack(fill="both", expand=True)
        lg_scroll_y.config(command=self.lg_tree.yview)
        lg_scroll_x.config(command=self.lg_tree.xview)
        lg_columns = ["location", "peer", "prefix", "asn_origin", "as_path", "last_as", "community", "last_updated"]
        self.lg_tree["columns"] = lg_columns
        self.lg_tree.column("#0", width=0, stretch=tk.NO)
        for col in lg_columns:
            self.lg_tree.column(col, width=120, anchor="w", minwidth=50, stretch=tk.YES)
            self.lg_tree.heading(col, text=col.replace("_", " ").title())
        button_frame = tk.Frame(self.lg_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        self.lg_export_button = tk.Button(button_frame, text="Export to Excel", command=self.export_lg_to_excel)
        self.lg_export_button.pack(side="left", padx=5)
        self.location_colors = {}
        self.as_path_tags = {}
        tk.Label(self.lg_tab, text="Log").pack(anchor="w", padx=10)
        self.lg_log = tk.Text(self.lg_tab, height=8, state="disabled")
        self.lg_log.pack(fill="x", padx=10, pady=5)

    def lg_on_status(self, msg):
        self.lg_log.config(state="normal")
        self.lg_log.insert(tk.END, f"[Looking Glass] {msg}\n")
        self.lg_log.see(tk.END)
        self.lg_log.config(state="disabled")

    def query_looking_glass(self):
        ip_input = self.lg_ip.get().strip()
        if not ip_input:
            self.root.after(0, lambda: messagebox.showerror("Error", "Please enter an IP address or range"))
            return
        
        # غیرفعال کردن دکمه‌های Query و Export
        self.lg_query_button.config(state="disabled")
        self.lg_export_button.config(state="disabled")
        
        # پاک کردن نتایج قبلی
        self.root.after(0, lambda: [self.lg_tree.delete(item) for item in self.lg_tree.get_children()])
        self.root.after(0, lambda: self.lg_on_status("Querying Looking Glass API..."))
        
        # اجرای درخواست API در یک ترد جداگانه
        threading.Thread(target=self.process_looking_glass_query, args=(ip_input,), daemon=True).start()

    def process_looking_glass_query(self, ip_input):
        try:
            data = self.query_looking_glass_api(ip_input)
            if not data or not data.get("data", {}).get("rrcs"):
                self.root.after(0, lambda: messagebox.showinfo("Info", "No looking glass data found"))
                self.root.after(0, lambda: self.lg_on_status("Query completed: No data found"))
                self.root.after(0, lambda: self.lg_query_button.config(state="normal"))
                self.root.after(0, lambda: self.lg_export_button.config(state="normal"))
                return
            
            colors = ['#e6f3ff', '#ffe6e6', '#e6ffe6', '#fff2e6', '#f6e6ff']
            color_index = 0
            results = []
            self.location_colors = {}
            self.as_path_tags = {}
            
            for rrc in data["data"]["rrcs"]:
                location = rrc.get("location", "Unknown")
                if location not in self.location_colors:
                    self.location_colors[location] = colors[color_index % len(colors)]
                    color_index += 1
                    self.root.after(0, lambda: self.lg_tree.tag_configure(f"loc_{location}", background=self.location_colors[location]))
                peers = rrc.get("peers", [])[:2]  # محدود به 2 peer
                for peer in peers:
                    as_path = peer.get("as_path", "")
                    last_as = as_path.split()[-1] if as_path else ""
                    if last_as:
                        tag_name = f"last_as_{hash(last_as)}_{id(peer)}"
                        if tag_name not in self.as_path_tags:
                            self.root.after(0, lambda: self.lg_tree.tag_configure(tag_name, foreground='black'))
                            self.as_path_tags[last_as] = tag_name
                    as_path_display = " ".join(as_path.split()[:-1]) if as_path else ""
                    results.append({
                        "location": location,
                        "peer": peer.get("peer", ""),
                        "prefix": peer.get("prefix", ""),
                        "asn_origin": peer.get("asn_origin", ""),
                        "as_path": as_path_display,
                        "last_as": last_as,
                        "community": peer.get("community", ""),
                        "last_updated": peer.get("last_updated", ""),
                        "color": self.location_colors[location],
                        "last_as_tag": tag_name if last_as else ""
                    })
            
            for result in results:
                values = [result.get(col, "") for col in self.lg_tree["columns"]]
                tags = [f"loc_{result['location']}"]
                if result.get("last_as_tag"):
                    tags.append(result["last_as_tag"])
                self.root.after(0, lambda v=values, t=tags: self.lg_tree.insert("", "end", values=v, tags=tuple(t)))
            
            self.root.after(0, lambda: self.lg_on_status("Query completed successfully"))
            self.root.after(0, lambda: self.lg_query_button.config(state="normal"))
            self.root.after(0, lambda: self.lg_export_button.config(state="normal" if len(self.lg_tree.get_children()) > 0 else "disabled"))
        
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Error", f"Unexpected error: {str(e)}"))
            self.root.after(0, lambda: self.lg_on_status(f"Query failed: {str(e)}"))
            self.root.after(0, lambda: self.lg_query_button.config(state="normal"))
            self.root.after(0, lambda: self.lg_export_button.config(state="normal"))

    def export_lg_to_excel(self):
        filename = filedialog.asksaveasfilename(title="Save Looking Glass to Excel", defaultextension=".xlsx", filetypes=(("Excel files", "*.xlsx"), ("All files", "*.*")))
        if not filename:
            return
        try:
            data = []
            for item in self.lg_tree.get_children():
                values = self.lg_tree.item(item)["values"]
                data.append(values)
            if not data:
                messagebox.showwarning("Warning", "No data to export")
                return
            columns = self.lg_tree["columns"]
            df = pd.DataFrame(data, columns=columns)
            df.to_excel(filename, index=False)
            messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to Excel: {str(e)}")

    def query_looking_glass_api(self, ip_input, timeout=20, retries=3):
        url = f"https://stat.ripe.net/data/looking-glass/data.json?resource={ip_input}"
        for attempt in range(retries):
            try:
                response = requests.get(url, timeout=timeout)
                response.raise_for_status()
                return response.json()
            except requests.exceptions.RequestException as e:
                if attempt == retries - 1:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Network error querying looking glass after {retries} attempts: {str(e)}"))
                    return None
                time.sleep(2)  # تأخیر 2 ثانیه‌ای قبل از تلاش مجدد

    def get_more_specifics_ripe(self, prefix):
        url = "https://stat.ripe.net/data/routing-status/data.json"
        params = {"resource": prefix}
        try:
            resp = requests.get(url, params=params)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            more = data.get("more_specifics", [])
            return [(item["prefix"], item.get("origin")) for item in more]
        except Exception as e:
            print(f"Error fetching more specifics from RIPEstat: {str(e)}  ripev7.0.py:782  ripev8.0.py:777  ripev9.0.py:785 - ripe-v9.1.py:816")
            return []

    def get_asn_prefixes_bgpview(self, asn):
        url = f"https://api.bgpview.io/asn/{asn}/prefixes"
        try:
            resp = requests.get(url)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            ipv4 = [p["prefix"] for p in data.get("ipv4_prefixes", [])]
            ipv6 = [p["prefix"] for p in data.get("ipv6_prefixes", [])]
            return ipv4 + ipv6
        except Exception as e:
            print(f"Error fetching prefixes from BGPView: {str(e)}  ripev7.0.py:795  ripev8.0.py:790  ripev9.0.py:798 - ripe-v9.1.py:829")
            return []

    def create_prefix_availability_tab(self):
        self.pa_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.pa_tab, text="Prefix Availability")
        input_frame = tk.LabelFrame(self.pa_tab, text="Add Prefix", padx=5, pady=5)
        input_frame.pack(fill="x", padx=10, pady=5)
        self.prefix_label = tk.Label(input_frame, text="Prefix (e.g., 212.16.64.0/24):")
        self.prefix_label.grid(row=0, column=0, sticky="w")
        self.pa_prefix_entry = tk.Entry(input_frame, width=30)
        self.pa_prefix_entry.grid(row=0, column=1)
        self.supernet_analyzer_check = tk.Checkbutton(input_frame, text="Supernet Analyzer", variable=self.supernet_analyzer_enabled, command=self.update_prefix_label)
        self.supernet_analyzer_check.grid(row=0, column=2)
        self.add_button = tk.Button(input_frame, text="Add", command=self.add_prefix)
        self.add_button.grid(row=0, column=3)
        self.import_button = tk.Button(input_frame, text="Import File", command=self.import_prefix_file)
        self.import_button.grid(row=0, column=4)
        monitor_frame = tk.LabelFrame(self.pa_tab, text="Monitoring", padx=5, pady=5)
        monitor_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(monitor_frame, text="Refresh Time (minutes):").grid(row=0, column=0, sticky="w")
        self.pa_refresh_entry = tk.Entry(monitor_frame, width=10)
        self.pa_refresh_entry.insert(0, "5")
        self.pa_refresh_entry.grid(row=0, column=1)
        self.start_button = tk.Button(monitor_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_button.grid(row=0, column=2)
        self.stop_button = tk.Button(monitor_frame, text="Stop Monitoring", command=self.stop_monitoring)
        self.stop_button.grid(row=0, column=3)
        tk.Checkbutton(monitor_frame, text="Enable Beep", variable=self.beep_enabled).grid(row=0, column=4)
        tk.Checkbutton(monitor_frame, text="Enable Email Alarm", variable=self.email_alarm_enabled).grid(row=0, column=5)
        self.monitor_status_label = tk.Label(monitor_frame, text="Monitoring: Inactive", fg="red")
        self.monitor_status_label.grid(row=0, column=6)
        self.countdown_label = tk.Label(monitor_frame, text="", fg="blue")
        self.countdown_label.grid(row=0, column=7, padx=5)
        self.start_time_label = tk.Label(monitor_frame, text="", fg="blue")
        self.start_time_label.grid(row=0, column=8, padx=5)
        result_frame = tk.LabelFrame(self.pa_tab, text="Prefix List", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        pa_scroll_y = ttk.Scrollbar(result_frame)
        pa_scroll_y.pack(side="right", fill="y")
        pa_scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        pa_scroll_x.pack(side="bottom", fill="x")
        self.pa_tree = ttk.Treeview(result_frame, yscrollcommand=pa_scroll_y.set, xscrollcommand=pa_scroll_x.set, selectmode="extended")
        self.pa_tree.pack(fill="both", expand=True)
        pa_scroll_y.config(command=self.pa_tree.yview)
        pa_scroll_x.config(command=self.pa_tree.xview)
        pa_columns = ["#", "Prefix", "ASN Origin", "Last Update", "Status"]  # fixed with row number
        self.pa_tree["columns"] = pa_columns
        self.pa_tree.configure(show="headings")
        self.pa_tree.column("#0", width=0, stretch=tk.NO)
        for col in pa_columns:
            self.pa_tree.column(col, width=150, anchor="w", minwidth=50, stretch=tk.YES)
            self.pa_tree.heading(col, text=col)
        self.pa_tree.tag_configure('available', background='lightgreen')
        self.pa_tree.tag_configure('not_available', background='lightcoral')
        button_frame = tk.Frame(self.pa_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        self.delete_selected_button = tk.Button(button_frame, text="Delete Selected", command=self.delete_selected)
        self.delete_selected_button.pack(side="left", padx=5)
        self.delete_all_button = tk.Button(button_frame, text="Delete All", command=self.delete_all)
        self.delete_all_button.pack(side="left", padx=5)
        self.pa_export_button = tk.Button(button_frame, text="Export to Excel", command=self.export_pa_to_excel)
        self.pa_export_button.pack(side="left", padx=5)
        self.display_prefix_list()

    def update_prefix_label(self):
        if self.supernet_analyzer_enabled.get():
            self.prefix_label.config(text="Enter IP prefix or ASN (e.g., 212.16.64.0/19 or AS12345):")
        else:
            self.prefix_label.config(text="Prefix (e.g., 212.16.64.0/24):")

    def export_pa_to_excel(self):
        filename = filedialog.asksaveasfilename(title="Save Prefix Availability to Excel", defaultextension=".xlsx", filetypes=(("Excel files", "*.xlsx"), ("All files", "*.*")))
        if not filename:
            return
        try:
            data = []
            for item in self.pa_tree.get_children():
                values = self.pa_tree.item(item)["values"]
                data.append(values)
            if not data:
                messagebox.showwarning("Warning", "No data to export")
                return
            columns = self.pa_tree["columns"]
            df = pd.DataFrame(data, columns=columns)
            df.to_excel(filename, index=False)
            messagebox.showinfo("Success", f"Data exported to {filename}")
        except Exception as e:
            messagebox.showerror("Error", f"Error exporting to Excel: {str(e)}")

    def create_bgprpki_auditor_tab(self):
        self.bgprpki_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.bgprpki_tab, text="BGP RPKI Auditor")
        form_frame = tk.LabelFrame(self.bgprpki_tab, text="Settings", padx=5, pady=5)
        form_frame.pack(fill="x", padx=10, pady=5)
        form_grid = tk.Frame(form_frame)
        form_grid.pack(fill="x", padx=5, pady=5)
        self.bgprpki_host = tk.StringVar()
        tk.Label(form_grid, text="Router IP").grid(row=0, column=0, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_host, width=20).grid(row=0, column=1)
        self.bgprpki_port = tk.StringVar(value="22")
        tk.Label(form_grid, text="Port").grid(row=0, column=2, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_port, width=10).grid(row=0, column=3)
        self.bgprpki_user = tk.StringVar()
        tk.Label(form_grid, text="Username").grid(row=1, column=0, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_user, width=20).grid(row=1, column=1)
        self.bgprpki_pass = tk.StringVar()
        tk.Label(form_grid, text="Password").grid(row=1, column=2, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_pass, show="*", width=20).grid(row=1, column=3)
        self.bgprpki_vendor = tk.StringVar(value="ios-xe")
        tk.Label(form_grid, text="Vendor").grid(row=2, column=0, sticky="w")
        vendor_combo = ttk.Combobox(form_grid, textvariable=self.bgprpki_vendor, values=["ios-xe", "ios-xr", "auto"], width=17)
        vendor_combo.grid(row=2, column=1)
        self.bgprpki_afi = tk.StringVar(value="ipv4")
        tk.Label(form_grid, text="AFI").grid(row=2, column=2, sticky="w")
        afi_combo = ttk.Combobox(form_grid, textvariable=self.bgprpki_afi, values=["ipv4", "ipv6"], width=17)
        afi_combo.grid(row=2, column=3)
        self.bgprpki_filter_asn = tk.StringVar()
        tk.Label(form_grid, text="Filter ASN").grid(row=3, column=0, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_filter_asn, width=20).grid(row=3, column=1)
        self.bgprpki_filter_asn.set("e.g. 12880 or AS12880")
        self.bgprpki_filter_comm = tk.StringVar()
        tk.Label(form_grid, text="Filter Community").grid(row=3, column=2, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_filter_comm, width=20).grid(row=3, column=3)
        self.bgprpki_filter_comm.set("e.g. 65001:100 or 65001:*")
        self.bgprpki_limit = tk.StringVar(value="20")
        tk.Label(form_grid, text="Max Prefixes (0=all)").grid(row=4, column=0, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_limit, width=10).grid(row=4, column=1)
        self.bgprpki_concurrency = tk.StringVar(value="1")
        tk.Label(form_grid, text="Concurrency").grid(row=4, column=2, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_concurrency, width=10).grid(row=4, column=3)
        self.bgprpki_only_bad = tk.BooleanVar(value=False)
        tk.Checkbutton(form_grid, text="Show only Invalid/Not Found", variable=self.bgprpki_only_bad).grid(row=5, column=0, columnspan=2, sticky="w")
        self.bgprpki_rpki_url = tk.StringVar(value="https://stat.ripe.net/data/rpki-validation/data.json")
        tk.Label(form_grid, text="RPKI API URL").grid(row=6, column=0, sticky="w")
        tk.Entry(form_grid, textvariable=self.bgprpki_rpki_url, width=50).grid(row=6, column=1, columnspan=3)
        button_frame = tk.Frame(self.bgprpki_tab)
        button_frame.pack(fill="x", padx=10, pady=5)
        self.bgprpki_start_button = tk.Button(button_frame, text="Start", command=self.bgprpki_on_start)
        self.bgprpki_start_button.pack(side="left", padx=5)
        self.bgprpki_stop_button = tk.Button(button_frame, text="Stop", command=self.bgprpki_on_stop)
        self.bgprpki_stop_button.pack(side="left", padx=5)
        self.bgprpki_stop_button.config(state="disabled")
        self.bgprpki_lookup_button = tk.Button(button_frame, text="Lookup Query", command=self.bgprpki_lookup_query)
        self.bgprpki_lookup_button.pack(side="left", padx=5)
        tk.Label(button_frame, text="").pack(side="left", expand=True, fill="x")
        self.bgprpki_export_button = tk.Button(button_frame, text="Export CSV", command=self.bgprpki_on_export)
        self.bgprpki_export_button.pack(side="left", padx=5)
        self.bgprpki_export_button.config(state="disabled")
        self.bgprpki_progress = ttk.Progressbar(self.bgprpki_tab, mode="determinate")
        self.bgprpki_progress.pack(fill="x", padx=10, pady=5)
        tk.Label(self.bgprpki_tab, text="Results").pack(anchor="w", padx=10)
        result_frame = tk.LabelFrame(self.bgprpki_tab, text="BGP Routes", padx=5, pady=5)
        result_frame.pack(fill="both", expand=True, padx=10, pady=5)
        scroll_y = ttk.Scrollbar(result_frame)
        scroll_y.pack(side="right", fill="y")
        scroll_x = ttk.Scrollbar(result_frame, orient="horizontal")
        scroll_x.pack(side="bottom", fill="x")
        self.bgprpki_tree = ttk.Treeview(result_frame, yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.bgprpki_tree.pack(fill="both", expand=True)
        scroll_y.config(command=self.bgprpki_tree.yview)
        scroll_x.config(command=self.bgprpki_tree.xview)
        columns = ["Prefix", "Origin-AS", "Communities", "RPKI", "Detail", "AS Name", "Netname"]
        self.bgprpki_tree["columns"] = columns
        self.bgprpki_tree.column("#0", width=0, stretch=tk.NO)
        for col in columns:
            self.bgprpki_tree.column(col, width=150, anchor="w", minwidth=50, stretch=tk.YES)
            self.bgprpki_tree.heading(col, text=col, command=lambda c=col: self.sort_by_column(c, False))
        self.bgprpki_tree.tag_configure("valid", background="lightgreen")
        self.bgprpki_tree.tag_configure("invalid", background="lightcoral")
        self.bgprpki_tree.tag_configure("not-found", background="orange")
        self.bgprpki_tree.tag_configure("error", background="lightblue")
        tk.Label(self.bgprpki_tab, text="Log").pack(anchor="w", padx=10)
        self.bgprpki_log = tk.Text(self.bgprpki_tab, height=8, state="disabled")
        self.bgprpki_log.pack(fill="x", padx=10, pady=5)

    def sort_by_column(self, col, reverse):
        l = [(self.bgprpki_tree.set(k, col), k) for k in self.bgprpki_tree.get_children('')]
        if col == "Origin-AS":
            l = [(int(val[2:]) if val.startswith("AS") and val[2:].isdigit() else 0, k) for val, k in l]
        l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.bgprpki_tree.move(k, '', index)
        self.bgprpki_tree.heading(col, command=lambda: self.sort_by_column(col, not reverse))

    def get_as_name(self, asn):
        try:
            url = f"https://rest.db.ripe.net/search.json?query-string=AS{asn}&type-filter=aut-num&flags=no-referenced&flags=no-irt"
            headers = {"Accept": "application/json"}
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            data = response.json()
            objects = data.get("objects", {}).get("object", [])
            for obj in objects:
                attributes = obj.get("attributes", {}).get("attribute", [])
                for attr in attributes:
                    if attr.get("name") == "as-name":
                        return attr.get("value", "")
            return ""
        except Exception:
            return ""

    def get_netname(self, prefix):
        try:
            ripe_result = self.get_ripe_db_info(prefix)
            return ripe_result.get("netname", "")
        except Exception:
            return ""

    def get_as_name_and_netname(self, prefix, asn):
        as_name = self.get_as_name(asn)
        netname = self.get_netname(prefix)
        return as_name, netname

    def fetch_additional_info(self):
        items = list(self.bgprpki_tree.get_children())
        total = len(items)
        if total == 0:
            return
        self.bgprpki_append_log("Fetching AS Name and Netname...")
        self.bgprpki_progress["maximum"] = total
        self.bgprpki_progress["value"] = 0
        with ThreadPoolExecutor(max_workers=5) as ex:
            futures = []
            for item in items:
                values = self.bgprpki_tree.item(item)["values"]
                prefix = values[0]
                asn_str = values[1]
                asn = asn_str[2:] if asn_str.startswith("AS") else asn_str
                futures.append((ex.submit(self.get_as_name_and_netname, prefix, asn), item))
            processed = 0
            for fut, item in futures:
                as_name, netname = fut.result()
                values = self.bgprpki_tree.item(item)["values"]
                new_values = values[:5] + [as_name, netname]
                self.bgprpki_tree.item(item, values=new_values)
                processed += 1
                self.bgprpki_progress["value"] = processed
        self.bgprpki_append_log("Additional info fetched.")
        self.bgprpki_progress["value"] = 0

    def bgprpki_append_log(self, text):
        self.bgprpki_log.config(state="normal")
        self.bgprpki_log.insert(tk.END, text + "\n")
        self.bgprpki_log.see(tk.END)
        self.bgprpki_log.config(state="disabled")

    def bgprpki_on_start(self):
        if self.bgprpki_worker and self.bgprpki_worker.is_alive():
            messagebox.showwarning("Warning", "A job is already running.")
            return
        host = self.bgprpki_host.get().strip()
        user = self.bgprpki_user.get().strip()
        pwd = self.bgprpki_pass.get()
        if not host or not user or not pwd:
            messagebox.showwarning("Warning", "Please fill Router IP/Username/Password.")
            return
        try:
            port = int(self.bgprpki_port.get())
            limit = int(self.bgprpki_limit.get())
            concurrency = int(self.bgprpki_concurrency.get())
        except ValueError:
            messagebox.showerror("Error", "Port, Max Prefixes, and Concurrency must be valid numbers.")
            return
        params = {
            "host": host,
            "port": port,
            "username": user,
            "password": pwd,
            "vendor": self.bgprpki_vendor.get(),
            "afi": self.bgprpki_afi.get(),
            "filter_asn": self.bgprpki_filter_asn.get() if self.bgprpki_filter_asn.get() != "e.g. 12880 or AS12880" else None,
            "filter_comm": self.bgprpki_filter_comm.get() if self.bgprpki_filter_comm.get() != "e.g. 65001:100 or 65001:*" else None,
            "limit": limit,
            "concurrency": concurrency,
            "only_bad": self.bgprpki_only_bad.get(),
            "rpki_url": self.bgprpki_rpki_url.get(),
        }
        for item in self.bgprpki_tree.get_children():
            self.bgprpki_tree.delete(item)
        self.bgprpki_progress["maximum"] = 100
        self.bgprpki_progress["value"] = 0
        self.bgprpki_log.config(state="normal")
        self.bgprpki_log.delete("1.0", tk.END)
        self.bgprpki_log.config(state="disabled")
        self.bgprpki_start_button.config(state="disabled")
        self.bgprpki_stop_button.config(state="normal")
        self.bgprpki_export_button.config(state="disabled")
        self.bgprpki_worker = AuditWorker(params, self)
        self.bgprpki_worker.start()

    def bgprpki_on_stop(self):
        if self.bgprpki_worker and self.bgprpki_worker.is_alive():
            self.bgprpki_worker.stop()
            self.bgprpki_append_log("Requested stop...")

    def bgprpki_on_status(self, msg):
        if not any(phrase in msg for phrase in ["SSH output", "JSON parse failed"]):
            self.bgprpki_append_log(msg)

    def bgprpki_on_progress(self, processed, total):
        self.bgprpki_total_expected = total
        if total <= 0:
            self.bgprpki_progress["maximum"] = 100
            self.bgprpki_progress["value"] = 0
            return
        self.bgprpki_progress["maximum"] = total
        self.bgprpki_progress["value"] = processed

    def bgprpki_on_route_parsed(self, prefix, origin_as, communities):
        # بررسی وجود prefix در Treeview
        for item in self.bgprpki_tree.get_children():
            values = self.bgprpki_tree.item(item)["values"]
            if values[0] == prefix:
                self.bgprpki_append_log(f"Skipping duplicate prefix: {prefix}")
                return  # نادیده گرفتن prefix تکراری
        self.bgprpki_append_log(f"Parsed route: prefix={prefix}, origin_as=AS{origin_as}, communities={communities}")
        values = [prefix, f"AS{origin_as}", communities, "pending", "", "", ""]
        self.bgprpki_tree.insert("", "end", values=values)
        self.bgprpki_tree.yview_moveto(1)

    def bgprpki_on_route_validated(self, prefix, origin_as, validity, detail):
        for item in self.bgprpki_tree.get_children():
            values = self.bgprpki_tree.item(item)["values"]
            if values[0] == prefix and values[1] == f"AS{origin_as}":
                # به‌روزرسانی آیتم موجود
                communities = values[2]  # حفظ Communities موجود
                as_name = values[5] if len(values) > 5 else ""
                netname = values[6] if len(values) > 6 else ""
                self.bgprpki_tree.item(item, values=[prefix, f"AS{origin_as}", communities, validity, detail or "", as_name, netname], tags=(validity,))
                return  # خروج پس از به‌روزرسانی
        # اگر آیتم پیدا نشد، آیتم جدید اضافه کن
        self.bgprpki_tree.insert("", "end", values=[prefix, f"AS{origin_as}", "", validity, detail or "", "", ""], tags=(validity,))
        self.bgprpki_tree.yview_moveto(1)

    def bgprpki_on_summary(self, data):
        self.bgprpki_append_log("=== Summary ===")
        self.bgprpki_append_log(f"Total: {data.get('total', 0)}")
        self.bgprpki_append_log(f"Valid: {data.get('valid', 0)}")
        self.bgprpki_append_log(f"Invalid: {data.get('invalid', 0)}")
        self.bgprpki_append_log(f"Not Found: {data.get('not_found', 0)}")
        self.bgprpki_append_log(f"Errors: {data.get('error', 0)}")
        self.bgprpki_start_button.config(state="normal")
        self.bgprpki_stop_button.config(state="disabled")
        self.bgprpki_export_button.config(state="normal" if len(self.bgprpki_tree.get_children()) > 0 else "disabled")
        self.bgprpki_worker = None  # Reset worker to allow restarting

    def bgprpki_lookup_query(self):
        selected = self.bgprpki_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a prefix to lookup.")
            return
        item = selected[0]
        values = self.bgprpki_tree.item(item)["values"]
        prefix = values[0]
        asn_str = values[1]
        asn = asn_str[2:] if asn_str.startswith("AS") else asn_str
        try:
            as_name, netname = self.get_as_name_and_netname(prefix, asn)
            self.bgprpki_tree.item(item, values=[values[0], values[1], values[2], values[3], values[4], as_name, netname])
            self.bgprpki_append_log(f"Fetched AS Name and Netname for prefix={prefix}: AS Name={as_name}, Netname={netname}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to fetch AS Name and Netname for {prefix}: {str(e)}")
            self.bgprpki_append_log(f"Error fetching AS Name and Netname for prefix={prefix}: {str(e)}")

    def bgprpki_on_error(self, err):
        messagebox.showerror("Error", err)
        self.bgprpki_append_log(f"ERROR: {err}")
        self.bgprpki_start_button.config(state="normal")
        self.bgprpki_stop_button.config(state="disabled")
        self.bgprpki_export_button.config(state="normal" if len(self.bgprpki_tree.get_children()) > 0 else "disabled")
        self.bgprpki_worker = None  # Reset worker to allow restarting

    def bgprpki_on_export(self):
        path = filedialog.asksaveasfilename(title="Save CSV", defaultextension=".csv", filetypes=(("CSV Files", "*.csv"), ("All files", "*.*")))
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["prefix", "origin_as", "communities", "rpki_validity", "detail", "as_name", "netname"])
                for item in self.bgprpki_tree.get_children():
                    values = self.bgprpki_tree.item(item)["values"]
                    writer.writerow(values)
            messagebox.showinfo("Success", f"CSV saved: {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def update_pending_to_error(self):
        for item in self.bgprpki_tree.get_children():
            values = self.bgprpki_tree.item(item)["values"]
            if values[3] == "pending":  # Check if RPKI status is pending
                self.bgprpki_tree.item(item, values=[values[0], values[1], values[2], "error", "Operation stopped", values[5], values[6]], tags=("error",))

    def create_settings_tab(self):
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        email_frame = tk.LabelFrame(self.settings_tab, text="Email Settings", padx=5, pady=5)
        email_frame.pack(fill="x", padx=10, pady=5)
        tk.Label(email_frame, text="SMTP Host:").grid(row=0, column=0, sticky="w")
        self.smtp_host_entry = tk.Entry(email_frame, width=30)
        self.smtp_host_entry.grid(row=0, column=1)
        self.smtp_host_entry.insert(0, self.settings.get('smtp_host', ''))
        tk.Label(email_frame, text="SMTP Port:").grid(row=1, column=0, sticky="w")
        self.smtp_port_entry = tk.Entry(email_frame, width=30)
        self.smtp_port_entry.grid(row=1, column=1)
        self.smtp_port_entry.insert(0, self.settings.get('smtp_port', ''))
        tk.Label(email_frame, text="Username:").grid(row=2, column=0, sticky="w")
        self.smtp_username_entry = tk.Entry(email_frame, width=30)
        self.smtp_username_entry.grid(row=2, column=1)
        self.smtp_username_entry.insert(0, self.settings.get('smtp_username', ''))
        tk.Label(email_frame, text="Password:").grid(row=3, column=0, sticky="w")
        self.smtp_password_entry = tk.Entry(email_frame, width=30, show="*")
        self.smtp_password_entry.grid(row=3, column=1)
        self.smtp_password_entry.insert(0, self.settings.get('smtp_password', ''))
        tk.Label(email_frame, text="From Email:").grid(row=4, column=0, sticky="w")
        self.smtp_from_email_entry = tk.Entry(email_frame, width=30)
        self.smtp_from_email_entry.grid(row=4, column=1)
        self.smtp_from_email_entry.insert(0, self.settings.get('smtp_from_email', ''))
        tk.Label(email_frame, text="Alarm Interval (minutes):").grid(row=5, column=0, sticky="w")
        self.alarm_interval_entry = tk.Entry(email_frame, width=30)
        self.alarm_interval_entry.grid(row=5, column=1)
        self.alarm_interval_entry.insert(0, self.settings.get('alarm_interval', '5'))
        tk.Label(email_frame, text="Send To:").grid(row=6, column=0, sticky="w")
        self.send_to_entry = tk.Entry(email_frame, width=30)
        self.send_to_entry.grid(row=6, column=1)
        self.send_to_entry.insert(0, self.settings.get('send_to', ''))
        tk.Button(email_frame, text="Save", command=self.save_email_settings).grid(row=7, column=1, padx=5, pady=5)
        tk.Button(email_frame, text="Test Email", command=self.test_email).grid(row=7, column=2, padx=5, pady=5)
        self.email_status_label = tk.Label(email_frame, text="", fg="blue")
        self.email_status_label.grid(row=8, column=1, columnspan=2, pady=5)

    def save_prefixes(self):
        try:
            with open(self.prefix_file, 'w') as f:
                json.dump(self.prefix_list, f)
        except Exception as e:
            print(f"Error saving prefixes to {self.prefix_file}: {str(e)}  ripev7.0.py:1136  ripev8.0.py:1209  ripev9.0.py:1234 - ripe-v9.1.py:1265")

    def save_email_settings(self):
        self.settings['smtp_host'] = self.smtp_host_entry.get()
        self.settings['smtp_port'] = self.smtp_port_entry.get()
        self.settings['smtp_username'] = self.smtp_username_entry.get()
        self.settings['smtp_password'] = self.smtp_password_entry.get()
        self.settings['smtp_from_email'] = self.smtp_from_email_entry.get()
        self.settings['alarm_interval'] = self.alarm_interval_entry.get()
        self.settings['send_to'] = self.send_to_entry.get()
        self.save_settings()
        self.email_status_label.config(text="Settings saved successfully", fg="green")
        self.root.after(5000, lambda: self.email_status_label.config(text=""))

    def save_settings(self):
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f)
        except Exception as e:
            print(f"Error saving settings to {self.settings_file}: {str(e)}  ripev7.0.py:1155  ripev8.0.py:1228  ripev9.0.py:1253 - ripe-v9.1.py:1284")

    def test_email(self):
        if not all([self.settings.get('smtp_host'), self.settings.get('smtp_port'), self.settings.get('smtp_username'), 
                    self.settings.get('smtp_password'), self.settings.get('smtp_from_email'), self.settings.get('send_to')]):
            self.email_status_label.config(text="Failed to send email: Please fill all SMTP settings", fg="red")
            self.root.after(5000, lambda: self.email_status_label.config(text=""))
            return
        subject = "Test Email from Advanced RIPE IP Lookup Tool"
        body = "This is a test email sent from Advanced RIPE IP Lookup Tool"
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.settings.get('smtp_from_email', '')
        msg['To'] = self.settings.get('send_to', '')
        try:
            server = smtplib.SMTP(self.settings.get('smtp_host', ''), int(self.settings.get('smtp_port', 0)))
            server.starttls()
            server.login(self.settings.get('smtp_username', ''), self.settings.get('smtp_password', ''))
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
            self.email_status_label.config(text="Email sent successfully", fg="green")
            self.root.after(5000, lambda: self.email_status_label.config(text=""))
        except Exception as e:
            self.email_status_label.config(text=f"Failed to send email: {str(e)}", fg="red")
            self.root.after(5000, lambda: self.email_status_label.config(text=""))

    def add_prefix(self):
        prefix_or_asn = self.pa_prefix_entry.get().strip()
        if not prefix_or_asn:
            messagebox.showerror("Error", "Please enter a prefix or ASN")
            return
        try:
            if self.supernet_analyzer_enabled.get():
                if prefix_or_asn.startswith("AS") or prefix_or_asn.isdigit():
                    asn = prefix_or_asn.replace("AS", "")
                    prefixes = self.get_asn_prefixes_bgpview(asn)
                    for prefix in prefixes:
                        self.add_single_prefix(prefix)
                else:
                    network = ipaddress.ip_network(prefix_or_asn, strict=False)
                    if network.prefixlen > 24:
                        messagebox.showerror("Error", "Supernet Analyzer only accepts prefixes larger than /24")
                        return
                    more_specifics = self.get_more_specifics_ripe(prefix_or_asn)
                    for prefix, _ in more_specifics:
                        self.add_single_prefix(prefix)
            else:
                network = ipaddress.ip_network(prefix_or_asn, strict=False)
                if network.prefixlen < 24:
                    answer = messagebox.askyesno("Subnet Division", f"The entered range ({prefix_or_asn}) is larger than /24.\nDo you want to divide it into /24 subnets?")
                    if answer:
                        for subnet in network.subnets(new_prefix=24):
                            self.add_single_prefix(str(subnet))
                    else:
                        self.add_single_prefix(prefix_or_asn)
                else:
                    self.add_single_prefix(prefix_or_asn)
            self.display_prefix_list()
            self.save_prefixes()
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid prefix or ASN: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Error processing input: {str(e)}")

    def add_single_prefix(self, prefix):
        if prefix not in [p['prefix'] for p in self.prefix_list]:
            self.prefix_list.append({"prefix": prefix, "asn_origin": "", "last_update": "", "status": ""})

    def import_prefix_file(self):
        filetypes = (("Excel files", "*.xlsx;*.xls"), ("Text files", "*.txt;*.csv"), ("All files", "*.*"))
        filename = filedialog.askopenfilename(title="Select input file", filetypes=filetypes)
        if filename:
            try:
                if filename.endswith(('.xlsx', '.xls')):
                    df = pd.read_excel(filename)
                    prefixes = df.iloc[:, 0].astype(str).tolist()
                else:
                    with open(filename, 'r') as f:
                        prefixes = [line.strip() for line in f if line.strip()]
                for prefix in prefixes:
                    self.add_prefix_from_file(prefix)
                self.display_prefix_list()
                self.save_prefixes()
            except Exception as e:
                messagebox.showerror("Error", f"Error importing file: {str(e)}")

    def add_prefix_from_file(self, prefix):
        try:
            network = ipaddress.ip_network(prefix, strict=False)
            if network.prefixlen < 24:
                answer = messagebox.askyesno("Subnet Division", f"The imported range ({prefix}) is larger than /24.\nDo you want to divide it into /24 subnets?")
                if answer:
                    for subnet in network.subnets(new_prefix=24):
                        self.add_single_prefix(str(subnet))
                else:
                    self.add_single_prefix(prefix)
            else:
                self.add_single_prefix(prefix)
        except ValueError:
            pass

    def display_prefix_list(self):
        for item in self.pa_tree.get_children():
            self.pa_tree.delete(item)
        sorted_list = sorted(self.prefix_list, key=lambda x: x["status"] != "Not Available")
        for idx, entry in enumerate(sorted_list, start=1):
            values = (idx, entry["prefix"], entry["asn_origin"], entry["last_update"], entry["status"])
            tag = 'available' if entry["status"] == "Available" else 'not_available'
            self.pa_tree.insert("", "end", values=values, tags=(tag,))

    def delete_selected(self):
        selected = self.pa_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "No items selected")
            return
        prefixes_to_delete = [self.pa_tree.item(item)['values'][1] for item in selected]
        self.prefix_list = [p for p in self.prefix_list if p['prefix'] not in prefixes_to_delete]
        self.display_prefix_list()
        self.save_prefixes()

    def delete_all(self):
        if messagebox.askyesno("Confirm", "Delete all prefixes?"):
            self.prefix_list = []
            self.display_prefix_list()
            self.save_prefixes()

    def start_monitoring(self):
        if self.monitoring:
            return
        try:
            refresh_time = int(self.pa_refresh_entry.get())
            if refresh_time <= 0:
                raise ValueError
        except ValueError:
            messagebox.showerror("Error", "Invalid refresh time (must be positive integer)")
            return
        self.monitoring = True
        self.monitor_status_label.config(text="Monitoring: Active", fg="green")
        self.pa_refresh_entry.config(state='disabled')
        self.pa_prefix_entry.config(state='disabled')
        self.add_button.config(state='disabled')
        self.import_button.config(state='disabled')
        self.delete_selected_button.config(state='disabled')
        self.delete_all_button.config(state='disabled')
        self.pa_tree.config(selectmode='none')
        self.pa_export_button.config(state='disabled')
        self.supernet_analyzer_check.config(state='disabled')
        self.refresh_interval_ms = refresh_time * 60 * 1000
        self.start_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.start_time_label.config(text=f"Started at: {self.start_time}")
        self.countdown_seconds = refresh_time * 60
        if self.countdown_after_id:
            self.root.after_cancel(self.countdown_after_id)
        self.update_countdown()
        threading.Thread(target=self.update_prefixes_thread).start()
        self.after_id = self.root.after(self.calculate_update_time(self.refresh_interval_ms), self.monitor_update, self.refresh_interval_ms)
        if self.email_alarm_enabled.get():
            try:
                alarm_interval = int(self.settings.get('alarm_interval', 5))
                if alarm_interval <= 0:
                    raise ValueError
                self.alarm_interval_ms = alarm_interval * 60 * 1000
                self.root.after(self.alarm_interval_ms, self.alarm_email_update, self.alarm_interval_ms)
            except ValueError:
                messagebox.showerror("Error", "Invalid alarm interval (must be positive integer)")

    def stop_monitoring(self):
        self.monitoring = False
        self.monitor_status_label.config(text="Monitoring: Inactive", fg="red")
        self.pa_refresh_entry.config(state='normal')
        self.pa_prefix_entry.config(state='normal')
        self.add_button.config(state='normal')
        self.import_button.config(state='normal')
        self.delete_selected_button.config(state='normal')
        self.delete_all_button.config(state='normal')
        self.pa_tree.config(selectmode='extended')
        self.pa_export_button.config(state='normal')
        self.supernet_analyzer_check.config(state='normal')
        self.countdown_label.config(text="")
        self.countdown_seconds = 0
        self.start_time_label.config(text="")
        self.start_time = None
        self.alarm_interval_ms = 0
        if self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
        if self.countdown_after_id:
            self.root.after_cancel(self.countdown_after_id)
            self.countdown_after_id = None

    def update_countdown(self):
        if not self.monitoring or self.countdown_seconds <= 0:
            return
        minutes = self.countdown_seconds // 60
        seconds = self.countdown_seconds % 60
        self.countdown_label.config(text=f"Next Update: {minutes:02d}:{seconds:02d}")
        self.countdown_seconds -= 1
        self.countdown_after_id = self.root.after(1000, self.update_countdown)

    def calculate_update_time(self, interval_ms):
        num_prefixes = len(self.prefix_list)
        estimated_time = num_prefixes * 1000
        adjusted_time = interval_ms - estimated_time
        return max(adjusted_time, 0)

    def monitor_update(self, interval_ms):
        if not self.monitoring:
            return
        threading.Thread(target=self.update_prefixes_thread).start()
        self.after_id = self.root.after(self.calculate_update_time(interval_ms), self.monitor_update, interval_ms)

    def send_email_alarm(self):
        not_available_prefixes = set(entry['prefix'] for entry in self.prefix_list if entry['status'] == "Not Available")
        if not not_available_prefixes:
            return
        subject = f"No Route Available for the Following IP Addresses {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        body = "This is to inform you that currently no route exists for the following IP addresses:\n\n" + "\n".join(not_available_prefixes)
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.settings.get('smtp_from_email', '')
        msg['To'] = self.settings.get('send_to', '')
        try:
            server = smtplib.SMTP(self.settings.get('smtp_host', ''), int(self.settings.get('smtp_port', 0)))
            server.starttls()
            server.login(self.settings.get('smtp_username', ''), self.settings.get('smtp_password', ''))
            server.sendmail(msg['From'], msg['To'], msg.as_string())
            server.quit()
        except Exception as e:
            print(f"Error sending email: {str(e)}  ripev7.0.py:1384  ripev8.0.py:1456  ripev9.0.py:1481 - ripe-v9.1.py:1512")

    def alarm_email_update(self, interval_ms):
        if not self.monitoring or not self.email_alarm_enabled.get():
            return
        self.send_email_alarm()
        self.root.after(interval_ms, self.alarm_email_update, interval_ms)

    def update_prefixes_thread(self):
        has_not_available = False
        for entry in self.prefix_list:
            data = self.query_looking_glass_api(entry["prefix"])
            if data and data.get("data", {}).get("rrcs"):
                peers = data["data"]["rrcs"][0].get("peers", [])
                if peers:
                    entry["asn_origin"] = peers[0].get("asn_origin", "")
                    entry["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    entry["status"] = "Available"
                else:
                    entry["asn_origin"] = ""
                    entry["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    entry["status"] = "Not Available"
                    has_not_available = True
            else:
                entry["asn_origin"] = ""
                entry["last_update"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                entry["status"] = "Not Available"
                has_not_available = True
        self.root.after(0, self.display_prefix_list)
        self.save_prefixes()
        if self.beep_enabled.get() and has_not_available:
            if sys.platform.startswith('win'):
                winsound.Beep(500, 1000)
            else:
                print("\a  ripev7.0.py:1418  ripev8.0.py:1490  ripev9.0.py:1515 - ripe-v9.1.py:1546")
        # Reset countdown after update completes
        self.countdown_seconds = self.refresh_interval_ms // 1000
        if self.countdown_after_id:
            self.root.after_cancel(self.countdown_after_id)
        self.update_countdown()

if __name__ == "__main__":
    root = tk.Tk()
    app = AdvancedRIPEIPLookup(root)
    root.mainloop()