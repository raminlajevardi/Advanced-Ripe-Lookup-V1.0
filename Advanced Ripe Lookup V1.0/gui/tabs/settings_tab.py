import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# Extracted from AdvancedRIPEIPLookup for modular UI.
# This function expects 'app' to be an instance of AdvancedRIPEIPLookup (or compatible).

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
