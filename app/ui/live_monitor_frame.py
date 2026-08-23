"""
app/ui/live_monitor_frame.py
------------------------------
Live monitoring frame with start/stop/refresh controls,
filter bar, and a color-coded event table.
"""

import threading
import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import TYPE_CHECKING, Optional, List, Dict, Any
from datetime import datetime

from app.ui.widgets.severity_badge import get_severity_colors
from app.ui.widgets.raw_event_viewer import RawEventViewer

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow

SEVERITY_FG = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d",
}

COLUMNS = [
    ("timestamp", 150, "Timestamp"),
    ("source_log", 90, "Source"),
    ("event_id", 65, "Event ID"),
    ("level", 100, "Level"),
    ("username", 110, "Username"),
    ("source_ip", 120, "Source IP"),
    ("description", 200, "Description"),
    ("severity", 75, "Severity"),
]


class LiveMonitorFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._monitoring  = False
        self._monitor_job: Optional[str] = None
        self._current_events: List[Dict] = []
        self._selected_event_id: Optional[int] = None
        self._build_ui()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self):
        # Title row
        title_row = ctk.CTkFrame(self, fg_color="transparent")
        title_row.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            title_row, text="🔴  Live Log Monitor",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#ff6b6b", fg_color="transparent",
        ).pack(side="left")

        self._status_label = ctk.CTkLabel(
            title_row, text="● Stopped",
            font=ctk.CTkFont(size=11),
            text_color="#888888", fg_color="transparent",
        )
        self._status_label.pack(side="right", padx=8)

        # Control buttons
        ctrl = ctk.CTkFrame(self, fg_color="#16213e", corner_radius=8)
        ctrl.pack(fill="x", padx=12, pady=4)

        self._btn_start = ctk.CTkButton(
            ctrl, text="▶  Start Monitoring", width=160,
            fg_color="#28a745", hover_color="#1e7e34",
            command=self._start_monitoring,
        )
        self._btn_start.pack(side="left", padx=8, pady=6)

        self._btn_stop = ctk.CTkButton(
            ctrl, text="■  Stop", width=100,
            fg_color="#dc3545", hover_color="#b02a37",
            command=self._stop_monitoring, state="disabled",
        )
        self._btn_stop.pack(side="left", padx=4, pady=6)

        ctk.CTkButton(
            ctrl, text="🔄 Refresh", width=100,
            fg_color="#0f3460", hover_color="#16213e",
            command=self._refresh_events,
        ).pack(side="left", padx=4, pady=6)

        ctk.CTkButton(
            ctrl, text="🔍 View Raw", width=110,
            fg_color="#2d2d5e", hover_color="#3d3d7e",
            command=self._view_raw_event,
        ).pack(side="left", padx=4, pady=6)

        self._count_label = ctk.CTkLabel(
            ctrl, text="0 events",
            font=ctk.CTkFont(size=10),
            text_color="#aaaacc", fg_color="transparent",
        )
        self._count_label.pack(side="right", padx=12)

        # Filter bar
        filt = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=8)
        filt.pack(fill="x", padx=12, pady=4)
        ctk.CTkLabel(
            filt, text="Filters:",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(side="left", padx=8)

        self._filters: Dict[str, ctk.CTkEntry] = {}
        filter_fields = [
            ("keyword",   "Search..."),
            ("username",  "Username"),
            ("source_ip", "Source IP"),
            ("event_id",  "Event ID"),
        ]
        for key, placeholder in filter_fields:
            e = ctk.CTkEntry(filt, placeholder_text=placeholder, width=110,
                             fg_color="#0d0d1a", border_color="#2a2a4a")
            e.pack(side="left", padx=4, pady=6)
            self._filters[key] = e
            e.bind("<Return>", lambda _: self._refresh_events())

        # Severity dropdown
        self._sev_var = ctk.StringVar(value="All Severities")
        sev_menu = ctk.CTkOptionMenu(
            filt, values=["All Severities", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            variable=self._sev_var, width=130,
            command=lambda _: self._refresh_events(),
        )
        sev_menu.pack(side="left", padx=4, pady=6)

        # Source dropdown
        self._src_var = ctk.StringVar(value="All Sources")
        src_menu = ctk.CTkOptionMenu(
            filt, values=["All Sources", "Security", "System", "Application", "PowerShell", "Firewall", "DEMO"],
            variable=self._src_var, width=130,
            command=lambda _: self._refresh_events(),
        )
        src_menu.pack(side="left", padx=4, pady=6)

        ctk.CTkButton(
            filt, text="Clear", width=70,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            command=self._clear_filters,
        ).pack(side="left", padx=4, pady=6)

        # Treeview table
        tree_frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=8)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=4)

        style = ttk.Style()
        style.configure("Live.Treeview",
            background="#1a1a2e", foreground="#e0e0e0",
            fieldbackground="#1a1a2e", rowheight=22,
            font=("Consolas", 9),
        )
        style.configure("Live.Treeview.Heading",
            background="#16213e", foreground="#74c0fc",
            font=("Helvetica", 9, "bold"),
        )
        style.map("Live.Treeview", background=[("selected", "#2d2d5e")])

        vsb = ttk.Scrollbar(tree_frame, orient="vertical")
        hsb = ttk.Scrollbar(tree_frame, orient="horizontal")

        self._tree = ttk.Treeview(
            tree_frame,
            columns=[c[0] for c in COLUMNS],
            show="headings",
            style="Live.Treeview",
            yscrollcommand=vsb.set,
            xscrollcommand=hsb.set,
        )
        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)

        for col_id, width, label in COLUMNS:
            self._tree.heading(col_id, text=label,
                               command=lambda c=col_id: self._sort_by(c))
            self._tree.column(col_id, width=width, anchor="w")

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        # Severity row tags
        for sev, fg in SEVERITY_FG.items():
            self._tree.tag_configure(sev, foreground=fg)
        self._tree.tag_configure("DEMO", foreground="#aaaaaa",
                                  font=("Consolas", 9, "italic"))

        self._tree.bind("<Double-1>", self._on_row_double_click)
        self._tree.bind("<<TreeviewSelect>>", self._on_row_select)

    # ------------------------------------------------------------------
    # Monitoring control
    # ------------------------------------------------------------------

    def _start_monitoring(self):
        self._monitoring = True
        self._btn_start.configure(state="disabled")
        self._btn_stop.configure(state="normal")
        self._status_label.configure(text="● Monitoring", text_color="#28a745")
        # Run collection cycle immediately in a background thread
        threading.Thread(target=self._collect_and_refresh, daemon=True).start()
        self._schedule_refresh()

    def _stop_monitoring(self):
        self._monitoring = False
        if self._monitor_job:
            self.after_cancel(self._monitor_job)
            self._monitor_job = None
        self._btn_start.configure(state="normal")
        self._btn_stop.configure(state="disabled")
        self._status_label.configure(text="● Stopped", text_color="#888888")

    def _schedule_refresh(self):
        if not self._monitoring:
            return
        try:
            interval = int(self.app.config["monitoring"].get("interval_seconds", 30)) * 1000
        except Exception:
            interval = 30_000
        self._monitor_job = self.after(interval, self._auto_refresh)

    def _auto_refresh(self):
        if not self._monitoring:
            return
        # Run collection in a thread to avoid blocking UI
        threading.Thread(target=self._collect_and_refresh, daemon=True).start()
        self._schedule_refresh()

    def _collect_and_refresh(self):
        """Run collection cycle (called from background thread)."""
        try:
            self.app.run_collection_cycle()
            self.after(0, self._refresh_events)
        except Exception as e:
            pass  # Errors logged by collection engine

    # ------------------------------------------------------------------
    # Event loading and filtering
    # ------------------------------------------------------------------

    def _build_filters(self) -> Dict[str, Any]:
        f: Dict[str, Any] = {}
        for key, entry in self._filters.items():
            val = entry.get().strip()
            if val:
                f[key] = val
        sev = self._sev_var.get()
        if sev != "All Severities":
            f["severity"] = sev
        src = self._src_var.get()
        if src != "All Sources":
            f["source_log"] = src
        return f

    def _refresh_events(self):
        filters = self._build_filters()
        rows = self.app.db.query_events(filters, limit=500, order_by="timestamp DESC")
        self._populate_table(rows)

    def _populate_table(self, rows):
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._current_events = []

        for row in rows:
            d = dict(row)
            self._current_events.append(d)
            sev   = (d.get("severity") or "INFO").upper()
            ts    = str(d.get("timestamp", ""))[:19]
            is_demo = d.get("is_demo") or d.get("source_log") == "DEMO"
            tags  = (sev, "DEMO") if is_demo else (sev,)

            self._tree.insert("", "end", iid=str(d.get("id")), values=(
                ts,
                ("🔬 " if is_demo else "") + (d.get("source_log") or "—"),
                d.get("event_id") or "—",
                d.get("level") or "—",
                d.get("username") or "—",
                d.get("source_ip") or "—",
                d.get("description") or "—",
                sev,
            ), tags=tags)

        self._count_label.configure(text=f"{len(rows)} events")

    def _on_row_select(self, event):
        sel = self._tree.selection()
        if sel:
            try:
                self._selected_event_id = int(sel[0])
            except ValueError:
                self._selected_event_id = None

    def _on_row_double_click(self, event):
        self._view_raw_event()

    def _view_raw_event(self):
        if self._selected_event_id is None:
            return
        ev = self.app.db.get_event_by_id(self._selected_event_id)
        if ev:
            RawEventViewer(self, ev)

    def _clear_filters(self):
        for entry in self._filters.values():
            entry.delete(0, "end")
        self._sev_var.set("All Severities")
        self._src_var.set("All Sources")
        self._refresh_events()

    def _sort_by(self, col: str):
        """Simple column sort toggle."""
        self._refresh_events()  # simplified — full sort would track direction

