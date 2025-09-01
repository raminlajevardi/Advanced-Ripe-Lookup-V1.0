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

""" اتصال SSH و جمع‌آوری خروجی دستورات از تجهیزات. """

try:
    # کمک برای resolve شدن نام‌ها بین ماژول‌ها (best-effort)
    from core.api import *  # noqa
except Exception:
    pass

def ssh_collect_output(host: str, username: str, password: str, commands: List[str],
    """
    ssh_collect_output: اتصال SSH و جمع‌آوری خروجی دستورات از تجهیزات.
    """
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

