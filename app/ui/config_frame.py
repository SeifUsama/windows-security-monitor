"""
app/ui/config_frame.py
-----------------------
Configuration page — reads and writes settings.ini.
"""

import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from configparser import ConfigParser
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow


class ConfigFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._entries = {}
        self._build_ui()
        self._load_from_config()

    def _build_ui(self):
        ctk.CTkLabel(
            self, text="⚙️  Configuration",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(anchor="w", padx=16, pady=(12, 4))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=8, pady=4)

        def _section(title: str) -> ctk.CTkFrame:
            fr = ctk.CTkFrame(scroll, fg_color="#1a1a2e", corner_radius=8)
            fr.pack(fill="x", padx=4, pady=6)
            ctk.CTkLabel(fr, text=f"  {title}",
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#74c0fc", fg_color="transparent").pack(anchor="w", pady=(8, 2))
            return fr

        def _field(parent, key: str, label: str, tooltip: str = ""):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=12, pady=3)
            ctk.CTkLabel(row, text=label, width=220, anchor="w",
                         font=ctk.CTkFont(size=10), text_color="#cccccc",
                         fg_color="transparent").pack(side="left")
            e = ctk.CTkEntry(row, width=200, fg_color="#0d0d1a", border_color="#2a2a4a")
            e.pack(side="left")
            if tooltip:
                ctk.CTkLabel(row, text=f"  ({tooltip})", font=ctk.CTkFont(size=8),
                             text_color="#666677", fg_color="transparent").pack(side="left")
            self._entries[key] = e

        # Monitoring
        mon = _section("Monitoring")
        _field(mon, "monitoring.interval_seconds",    "Polling interval (seconds)", "30")
        _field(mon, "monitoring.max_events_per_cycle","Max events per cycle",       "500")

        # Detection
        det = _section("Detection Rules")
        _field(det, "detection.brute_force_threshold",       "Brute Force: min failed logins",  "default: 5")
        _field(det, "detection.brute_force_window_seconds",  "Brute Force: time window (sec)",  "default: 60")
        _field(det, "detection.port_scan_threshold",         "Port Scan: min unique ports",     "default: 10")
        _field(det, "detection.port_scan_window_seconds",    "Port Scan: time window (sec)",    "default: 30")

        # Log Sources
        src_frame = _section("Log Sources")
        self._src_vars = {}
        for key, label in [
            ("log_sources.security_log",    "Security Log (requires admin)"),
            ("log_sources.system_log",      "System Log"),
            ("log_sources.application_log", "Application Log"),
            ("log_sources.powershell_log",  "PowerShell Operational Log"),
            ("log_sources.firewall_log",    "Firewall Log (optional)"),
        ]:
            var = ctk.BooleanVar(value=True)
            ctk.CTkCheckBox(
                src_frame, text=label, variable=var,
                font=ctk.CTkFont(size=10), text_color="#cccccc",
            ).pack(anchor="w", padx=16, pady=2)
            self._src_vars[key] = var

        # Database
        db_frame = _section("Database")
        _field(db_frame, "database.db_path", "Database file path", "relative or absolute")

        # Firewall
        fw_frame = _section("Firewall")
        _field(fw_frame, "firewall.log_path", "Firewall log path")

        # Save button
        btn_row = ctk.CTkFrame(scroll, fg_color="transparent")
        btn_row.pack(fill="x", padx=4, pady=8)

        ctk.CTkButton(
            btn_row, text="💾  Save Configuration", width=200,
            fg_color="#28a745", hover_color="#1e7e34",
            command=self._save_config,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_row, text="↩ Reset to Defaults", width=160,
            fg_color="#6c757d", hover_color="#545b62",
            command=self._reset_defaults,
        ).pack(side="left", padx=4)

        # Status note
        ctk.CTkLabel(
            scroll,
            text=(
                "ℹ️  Changes take effect on the next monitoring cycle.\n"
                "Detection rule changes require restarting monitoring."
            ),
            font=ctk.CTkFont(size=9),
            text_color="#666677", fg_color="transparent",
        ).pack(anchor="w", padx=12, pady=4)

    def _load_from_config(self):
        cfg = self.app.config
        for key, entry in self._entries.items():
            section, option = key.split(".", 1)
            val = cfg.get(section, option, fallback="")
            entry.delete(0, "end")
            entry.insert(0, val)

        for key, var in self._src_vars.items():
            section, option = key.split(".", 1)
            val = cfg.getboolean(section, option, fallback=True)
            var.set(val)

    def _save_config(self):
        cfg = self.app.config
        for key, entry in self._entries.items():
            section, option = key.split(".", 1)
            if not cfg.has_section(section):
                cfg.add_section(section)
            cfg.set(section, option, entry.get().strip())

        for key, var in self._src_vars.items():
            section, option = key.split(".", 1)
            if not cfg.has_section(section):
                cfg.add_section(section)
            cfg.set(section, option, "true" if var.get() else "false")

        try:
            with open(self.app.config_path, "w") as f:
                cfg.write(f)
            messagebox.showinfo("Configuration", "Settings saved successfully.")
        except Exception as e:
            messagebox.showerror("Save Failed", f"Could not save settings:\n{e}")

    def _reset_defaults(self):
        defaults = {
            "monitoring.interval_seconds": "30",
            "monitoring.max_events_per_cycle": "500",
            "detection.brute_force_threshold": "5",
            "detection.brute_force_window_seconds": "60",
            "detection.port_scan_threshold": "10",
            "detection.port_scan_window_seconds": "30",
            "database.db_path": "security_monitor.db",
            "firewall.log_path": r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log",
        }
        for key, val in defaults.items():
            if key in self._entries:
                self._entries[key].delete(0, "end")
                self._entries[key].insert(0, val)
        for var in self._src_vars.values():
            var.set(True)

