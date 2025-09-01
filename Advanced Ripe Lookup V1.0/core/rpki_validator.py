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

""" اعتبارسنجی RPKI و بررسی ROA برای Prefix/AS. """

try:
    # کمک برای resolve شدن نام‌ها بین ماژول‌ها (best-effort)
    from core.api import *  # noqa
except Exception:
    pass

class RPKIValidator:
    """
    RPKIValidator: اعتبارسنجی RPKI و بررسی ROA برای Prefix/AS.
    """
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

