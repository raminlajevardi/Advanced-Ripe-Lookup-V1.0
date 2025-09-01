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

""" فراخوانی‌های HTTP به RIPEstat/RIPE DB و پردازش پاسخ. """

try:
    # کمک برای resolve شدن نام‌ها بین ماژول‌ها (best-effort)
    from core.api import *  # noqa
except Exception:
    pass

