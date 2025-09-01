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

""" منطق پردازش خروجی BGP (Prefix/AS/Community). """

try:
    # کمک برای resolve شدن نام‌ها بین ماژول‌ها (best-effort)
    from core.api import *  # noqa
except Exception:
    pass

class RouteItem:
    """
    RouteItem: منطق پردازش خروجی BGP (Prefix/AS/Community).
    """
    prefix: str
    origin_as: Optional[int]
    communities: List[str]

def extract_last_as(as_path: str) -> Optional[int]:
    """
    extract_last_as: منطق پردازش خروجی BGP (Prefix/AS/Community).
    """
    if not as_path:
        return None
    nums = re.findall(r"\b(\d{1,10})\b", as_path)
    if not nums:
        return None
    return int(nums[-1])

def match_community(comm_list: List[str], pattern: str) -> bool:
    """
    match_community: منطق پردازش خروجی BGP (Prefix/AS/Community).
    """
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

def parse_text_bgp(output: str) -> List[RouteItem]:
    """
    parse_text_bgp: منطق پردازش خروجی BGP (Prefix/AS/Community).
    """
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
    """
    AuditWorker: منطق پردازش خروجی BGP (Prefix/AS/Community).
    """
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

