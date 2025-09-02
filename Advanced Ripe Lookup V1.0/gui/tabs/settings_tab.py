import os
import json
import smtplib
import tkinter as tk
from tkinter import ttk, messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

SETTINGS_FILE = "settings.json"

class SettingsTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)

        # ساخت بخش Email Settings
        email_frame = tk.LabelFrame(self, text="Email Settings", padx=5, pady=5)
        email_frame.pack(fill="x", padx=10, pady=5)

        self.smtp_host_var = tk.StringVar()
        self.smtp_port_var = tk.StringVar()
        self.smtp_username_var = tk.StringVar()
        self.smtp_password_var = tk.StringVar()
        self.smtp_from_email_var = tk.StringVar()
        self.alarm_interval_var = tk.StringVar()
        self.send_to_var = tk.StringVar()

        labels = [
            ("SMTP Host:", self.smtp_host_var),
            ("SMTP Port:", self.smtp_port_var),
            ("Username:", self.smtp_username_var),
            ("Password:", self.smtp_password_var),
            ("From Email:", self.smtp_from_email_var),
            ("Alarm Interval (minutes):", self.alarm_interval_var),
            ("Send To:", self.send_to_var)
        ]

        for i, (lbl, var) in enumerate(labels):
            tk.Label(email_frame, text=lbl).grid(row=i, column=0, sticky="w")
            show = "*" if "Password" in lbl else None
            entry = tk.Entry(email_frame, textvariable=var, width=30, show=show)
            entry.grid(row=i, column=1, padx=5, pady=2)

        # دکمه‌ها
        tk.Button(email_frame, text="Save", command=self.save_settings).grid(row=len(labels), column=1, padx=5, pady=5)
        tk.Button(email_frame, text="Test Email", command=self.test_email).grid(row=len(labels), column=2, padx=5, pady=5)

        # وضعیت
        self.email_status_label = tk.Label(email_frame, text="", fg="blue")
        self.email_status_label.grid(row=len(labels)+1, column=1, columnspan=2, pady=5)

        # بارگذاری اولیه
        self.load_settings()

    def load_settings(self):
        if os.path.exists(SETTINGS_FILE):
            try:
                with open(SETTINGS_FILE, "r") as f:
                    data = json.load(f)
                self.smtp_host_var.set(data.get("smtp_host", ""))
                self.smtp_port_var.set(data.get("smtp_port", ""))
                self.smtp_username_var.set(data.get("smtp_username", ""))
                self.smtp_password_var.set(data.get("smtp_password", ""))
                self.smtp_from_email_var.set(data.get("smtp_from_email", ""))
                self.alarm_interval_var.set(data.get("alarm_interval", "5"))
                self.send_to_var.set(data.get("send_to", ""))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load settings: {e}")

    def save_settings(self):
        data = {
            "smtp_host": self.smtp_host_var.get(),
            "smtp_port": self.smtp_port_var.get(),
            "smtp_username": self.smtp_username_var.get(),
            "smtp_password": self.smtp_password_var.get(),
            "smtp_from_email": self.smtp_from_email_var.get(),
            "alarm_interval": self.alarm_interval_var.get(),
            "send_to": self.send_to_var.get()
        }
        try:
            with open(SETTINGS_FILE, "w") as f:
                json.dump(data, f, indent=4)
            self.show_status("Settings saved successfully", "green")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")

    def test_email(self):
        try:
            host = self.smtp_host_var.get()
            port = int(self.smtp_port_var.get())
            username = self.smtp_username_var.get()
            password = self.smtp_password_var.get()
            from_email = self.smtp_from_email_var.get()
            to_email = self.send_to_var.get()

            msg = MIMEMultipart()
            msg["From"] = from_email
            msg["To"] = to_email
            msg["Subject"] = "Test Email from Advanced Ripe Lookup"
            msg.attach(MIMEText("This is a test email to verify SMTP settings.", "plain"))

            with smtplib.SMTP(host, port, timeout=10) as server:
                server.starttls()
                server.login(username, password)
                server.sendmail(from_email, [to_email], msg.as_string())

            self.show_status("Test email sent successfully", "green")
        except Exception as e:
            self.show_status(f"Failed to send test email: {e}", "red")

    def show_status(self, message, color="blue"):
        self.email_status_label.config(text=message, fg=color)
