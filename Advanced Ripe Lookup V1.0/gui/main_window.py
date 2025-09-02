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

# === Imported tab builders (auto-generated) ===
from .tabs.lookup_tab import LookupTab
from .tabs.looking_glass_tab import create_looking_glass_tab
from .tabs.prefix_availability_tab import create_prefix_availability_tab
from .tabs.bgprpki_auditor_tab import create_bgprpki_auditor_tab
from .tabs.settings_tab import SettingsTab

class AdvancedRIPEIPLookup:
    """
    AdvancedRIPEIPLookup: رابط کاربری Tkinter برای تعامل با قابلیت‌های core.
    """
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
        self.lookup_tab = LookupTab(self.notebook)
        self.notebook.add(self.lookup_tab, text="RIPE Lookup")
        self.settings_tab = SettingsTab(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        self.create_looking_glass_tab()
        self.create_prefix_availability_tab()
        self.create_bgprpki_auditor_tab()

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
        return create_looking_glass_tab(self)

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
        return create_prefix_availability_tab(self)

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
        return create_bgprpki_auditor_tab(self)

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
