"""
app/ui/incidents_frame.py
--------------------------
Incidents list and detail pane.

Left: scrollable list of all incidents with severity color coding
Right: full incident detail including:
  - Summary fields
  - Detection explanation
  - Attack timeline (TimelineWidget)
  - Related events table
  - Action buttons (Mark Investigated, Mark False Positive, Export)
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
from typing import TYPE_CHECKING, Optional, List, Dict, Any

from app.ui.widgets.timeline_widget import TimelineWidget
from app.ui.widgets.severity_badge import get_severity_colors
from app.ui.widgets.raw_event_viewer import RawEventViewer
from app.reports.csv_exporter import export_incident_to_csv
from app.reports.pdf_exporter import export_incident_to_pdf

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow

SEVERITY_FG = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d",
}

ATTACK_ICONS = {
    "BRUTE_FORCE":        "🔨",
    "BRUTE_FORCE_LOCKOUT":"🔨🔒",
    "ACCOUNT_LOCKOUT":    "🔒",
    "PRIVILEGE_ESCALATION":"👑",
    "UNAUTHORIZED_ACCOUNT":"👤",
    "PORT_SCAN":          "🌐",
}


class IncidentsFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._selected_incident_id: Optional[int] = None
        self._current_filter_demo: Optional[bool] = None
        self._build_ui()

    def _build_ui(self):
        # Title
        ctk.CTkLabel(
            self, text="🚨  Incident Management",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#ff6b6b", fg_color="transparent",
        ).pack(anchor="w", padx=16, pady=(12, 4))

        # Main split
        split = ctk.CTkFrame(self, fg_color="transparent")
        split.pack(fill="both", expand=True, padx=8, pady=4)
        split.grid_columnconfigure(0, weight=1)
        split.grid_columnconfigure(1, weight=2)
        split.grid_rowconfigure(0, weight=1)

        # --- Left: Incident list ---
        left = ctk.CTkFrame(split, fg_color="#1a1a2e", corner_radius=8)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 4))

        # Filter bar
        fbar = ctk.CTkFrame(left, fg_color="transparent")
        fbar.pack(fill="x", padx=8, pady=6)

        self._sev_filter = ctk.StringVar(value="All")
        ctk.CTkOptionMenu(
            fbar, values=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            variable=self._sev_filter, width=100,
            command=lambda _: self.refresh(),
        ).pack(side="left", padx=2)

        self._status_filter = ctk.StringVar(value="All Status")
        ctk.CTkOptionMenu(
            fbar, values=["All Status", "NEW", "INVESTIGATING", "FALSE_POSITIVE", "CLOSED"],
            variable=self._status_filter, width=120,
            command=lambda _: self.refresh(),
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            fbar, text="🔄", width=36,
            fg_color="#2a2a4a", command=self.refresh,
        ).pack(side="left", padx=2)

        # Incident list
        style = ttk.Style()
        style.configure("Inc.Treeview",
            background="#1a1a2e", foreground="#e0e0e0",
            fieldbackground="#1a1a2e", rowheight=24,
            font=("Consolas", 9),
        )
        style.configure("Inc.Treeview.Heading",
            background="#16213e", foreground="#74c0fc",
            font=("Helvetica", 9, "bold"),
        )
        style.map("Inc.Treeview", background=[("selected", "#2d2d5e")])

        vsb = ttk.Scrollbar(left, orient="vertical")
        self._list_tree = ttk.Treeview(
            left,
            columns=("id", "type", "severity", "user", "time", "status"),
            show="headings", style="Inc.Treeview",
            yscrollcommand=vsb.set,
        )
        vsb.config(command=self._list_tree.yview)

        for col, w, label in [
            ("id", 35, "#"), ("type", 130, "Type"),
            ("severity", 70, "Severity"), ("user", 100, "Username"),
            ("time", 130, "Last Seen"), ("status", 85, "Status"),
        ]:
            self._list_tree.heading(col, text=label)
            self._list_tree.column(col, width=w, anchor="center")

        self._list_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 8))
        vsb.pack(side="right", fill="y", pady=(0, 8))

        for sev, fg in SEVERITY_FG.items():
            self._list_tree.tag_configure(sev, foreground=fg)

        self._list_tree.bind("<<TreeviewSelect>>", self._on_incident_select)

        # --- Right: Detail pane ---
        self._detail_pane = ctk.CTkScrollableFrame(split, fg_color="#1a1a2e", corner_radius=8)
        self._detail_pane.grid(row=0, column=1, sticky="nsew")

        # Placeholder
        ctk.CTkLabel(
            self._detail_pane,
            text="Select an incident from the list to view details.",
            font=ctk.CTkFont(size=12),
            text_color="#888888", fg_color="transparent",
        ).pack(pady=40)

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def refresh(self, is_demo: Optional[bool] = None) -> None:
        if is_demo is not None:
            self._current_filter_demo = is_demo

        for item in self._list_tree.get_children():
            self._list_tree.delete(item)

        filters: Dict[str, Any] = {}
        sev = self._sev_filter.get()
        if sev != "All":
            filters["severity"] = sev
        status = self._status_filter.get()
        if status != "All Status":
            filters["status"] = status
        if self._current_filter_demo is not None:
            filters["is_demo"] = self._current_filter_demo

        incidents = self.app.db.get_incidents(filters, limit=200)
        for inc in incidents:
            d   = dict(inc)
            sev = d.get("severity", "INFO")
            icon = ATTACK_ICONS.get(d.get("attack_type", ""), "⚠️")
            self._list_tree.insert("", "end", iid=str(d["id"]), values=(
                d["id"],
                f"{icon} {d.get('attack_type', '').replace('_', ' ')}",
                sev,
                d.get("username") or "—",
                str(d.get("last_seen", ""))[:16],
                d.get("status", "NEW"),
            ), tags=(sev,))

    def _on_incident_select(self, event):
        sel = self._list_tree.selection()
        if not sel:
            return
        try:
            incident_id = int(sel[0])
        except ValueError:
            return
        self._selected_incident_id = incident_id
        self._show_incident_detail(incident_id)

    def _show_incident_detail(self, incident_id: int) -> None:
        # Clear detail pane
        for w in self._detail_pane.winfo_children():
            w.destroy()

        inc = self.app.db.get_incident_by_id(incident_id)
        if not inc:
            return
        d = dict(inc)
        related = self.app.db.get_incident_events(incident_id)

        sev = d.get("severity", "INFO")
        sev_bg, sev_fg = get_severity_colors(sev)
        icon = ATTACK_ICONS.get(d.get("attack_type", ""), "⚠️")
        is_demo = bool(d.get("is_demo"))

        # --- Header ---
        hdr = ctk.CTkFrame(self._detail_pane, fg_color=sev_bg, corner_radius=8)
        hdr.pack(fill="x", padx=8, pady=(8, 4))

        hdr_row = ctk.CTkFrame(hdr, fg_color="transparent")
        hdr_row.pack(fill="x", padx=12, pady=8)

        ctk.CTkLabel(
            hdr_row,
            text=f"{icon}  Incident #{d['id']} — {d.get('attack_type','').replace('_',' ')}",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color=sev_fg, fg_color="transparent",
        ).pack(side="left")

        if is_demo:
            ctk.CTkLabel(
                hdr_row, text=" [DEMO DATA] ",
                font=ctk.CTkFont(size=9, weight="bold"),
                fg_color="#ffa94d", text_color="#000000", corner_radius=4,
            ).pack(side="right")

        ctk.CTkLabel(
            hdr, text=d.get("description", ""),
            font=ctk.CTkFont(size=10), text_color=sev_fg,
            fg_color="transparent", wraplength=550,
        ).pack(padx=12, pady=(0, 8))

        # --- Summary table ---
        def _field_row(parent, label: str, value: str, color: str = "#e0e0ff"):
            row = ctk.CTkFrame(parent, fg_color="transparent")
            row.pack(fill="x", padx=8, pady=1)
            ctk.CTkLabel(row, text=f"{label}:", width=150, anchor="w",
                         font=ctk.CTkFont(size=10, weight="bold"),
                         text_color="#aaaacc", fg_color="transparent").pack(side="left")
            ctk.CTkLabel(row, text=str(value)[:80], anchor="w",
                         font=ctk.CTkFont(size=10), text_color=color,
                         fg_color="transparent").pack(side="left", fill="x", expand=True)

        summary = ctk.CTkFrame(self._detail_pane, fg_color="#0d0d1a", corner_radius=8)
        summary.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(summary, text="  Summary", font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#74c0fc", fg_color="transparent").pack(anchor="w", pady=(6,2))

        _field_row(summary, "Severity",       sev, sev_bg)
        _field_row(summary, "Status",         d.get("status", "—"))
        _field_row(summary, "Detection Rule", d.get("detection_rule", "—"))
        _field_row(summary, "Source IP",      d.get("source_ip") or "Not Available")
        _field_row(summary, "Target Username",d.get("username") or "—")
        _field_row(summary, "First Seen",     str(d.get("first_seen", "—"))[:19])
        _field_row(summary, "Last Seen",      str(d.get("last_seen", "—"))[:19])
        _field_row(summary, "Related Events", str(d.get("event_count", 0)))
        _field_row(summary, "Data Source",    "DEMO (Simulated)" if is_demo else "Real Windows Logs",
                   color="#ffa94d" if is_demo else "#69db7c")

        # --- Detection Explanation ---
        exp_frame = ctk.CTkFrame(self._detail_pane, fg_color="#0d0d1a", corner_radius=8)
        exp_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(exp_frame, text="  Detection Explanation",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#74c0fc", fg_color="transparent").pack(anchor="w", pady=(6, 2))
        reason_box = ctk.CTkTextbox(
            exp_frame, font=ctk.CTkFont(size=9, family="Consolas"),
            fg_color="#0a0a18", text_color="#ccffcc", height=180,
            wrap="word",
        )
        reason_box.pack(fill="x", padx=8, pady=(0, 8))
        reason_box.insert("1.0", d.get("detection_reason") or "No explanation available.")
        reason_box.configure(state="disabled")

        # --- Timeline ---
        tl_frame = ctk.CTkFrame(self._detail_pane, fg_color="#0d0d1a", corner_radius=8)
        tl_frame.pack(fill="x", padx=8, pady=4)
        ctk.CTkLabel(tl_frame, text="  Attack Timeline",
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#74c0fc", fg_color="transparent").pack(anchor="w", pady=(6, 2))
        timeline = TimelineWidget(tl_frame, height=200)
        timeline.pack(fill="x", padx=8, pady=(0, 8))
        timeline.load_timeline(
            [dict(e) for e in related],
            attack_type=d.get("attack_type", "ATTACK"),
            severity=sev,
        )

        # --- Related Events Table ---
        if related:
            ev_frame = ctk.CTkFrame(self._detail_pane, fg_color="#0d0d1a", corner_radius=8)
            ev_frame.pack(fill="x", padx=8, pady=4)
            ctk.CTkLabel(ev_frame, text="  Related Events",
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color="#74c0fc", fg_color="transparent").pack(anchor="w", pady=(6, 2))

            style = ttk.Style()
            style.configure("Ev.Treeview",
                background="#0d0d1a", foreground="#e0e0e0",
                fieldbackground="#0d0d1a", rowheight=20,
                font=("Consolas", 8),
            )
            style.configure("Ev.Treeview.Heading",
                background="#16213e", foreground="#74c0fc",
                font=("Helvetica", 8, "bold"),
            )

            ev_tree = ttk.Treeview(
                ev_frame,
                columns=("ts", "eid", "desc", "user", "ip"),
                show="headings", style="Ev.Treeview", height=min(len(related), 6),
            )
            for col, w, lbl in [
                ("ts", 140, "Timestamp"), ("eid", 60, "Event ID"),
                ("desc", 180, "Description"), ("user", 100, "Username"),
                ("ip", 100, "Source IP"),
            ]:
                ev_tree.heading(col, text=lbl)
                ev_tree.column(col, width=w, anchor="w")

            for ev in related:
                e = dict(ev)
                ev_tree.insert("", "end", iid=str(e.get("id", "")), values=(
                    str(e.get("timestamp", ""))[:19],
                    e.get("event_id") or "—",
                    e.get("description") or "—",
                    e.get("username") or "—",
                    e.get("source_ip") or "—",
                ))

            ev_tree.pack(fill="x", padx=8, pady=(0, 4))

            ev_tree.bind("<Double-1>", lambda _: self._view_raw_from_tree(ev_tree))

            ctk.CTkButton(
                ev_frame, text="🔍 View Raw Event", width=140,
                fg_color="#2d2d5e", command=lambda: self._view_raw_from_tree(ev_tree),
            ).pack(anchor="w", padx=8, pady=(0, 8))

        # --- Action Buttons ---
        btn_frame = ctk.CTkFrame(self._detail_pane, fg_color="transparent")
        btn_frame.pack(fill="x", padx=8, pady=8)

        ctk.CTkButton(
            btn_frame, text="✅ Mark as Investigated",
            fg_color="#28a745", hover_color="#1e7e34", width=180,
            command=lambda: self._update_status(incident_id, "INVESTIGATING"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="🚫 Mark as False Positive",
            fg_color="#6c757d", hover_color="#545b62", width=180,
            command=lambda: self._update_status(incident_id, "FALSE_POSITIVE"),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="📄 Export CSV",
            fg_color="#0f3460", hover_color="#16213e", width=120,
            command=lambda: self._export_csv(incident_id),
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_frame, text="📋 Export PDF",
            fg_color="#0f3460", hover_color="#16213e", width=120,
            command=lambda: self._export_pdf(incident_id),
        ).pack(side="left", padx=4)

    def _view_raw_from_tree(self, tree: ttk.Treeview) -> None:
        sel = tree.selection()
        if not sel:
            return
        try:
            ev_id = int(sel[0])
            ev = self.app.db.get_event_by_id(ev_id)
            if ev:
                RawEventViewer(self, ev)
        except (ValueError, Exception):
            pass

    def _update_status(self, incident_id: int, status: str) -> None:
        self.app.db.update_incident_status(incident_id, status)
        self.refresh()
        self._show_incident_detail(incident_id)

    def _export_csv(self, incident_id: int) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            initialfile=f"incident_{incident_id}.csv",
        )
        if not path:
            return
        inc    = self.app.db.get_incident_by_id(incident_id)
        events = self.app.db.get_incident_events(incident_id)
        ok = export_incident_to_csv(inc, events, path)
        if ok:
            messagebox.showinfo("Export", f"Incident exported to:\n{path}")
        else:
            messagebox.showerror("Export Failed", "Could not export the incident.")

    def _export_pdf(self, incident_id: int) -> None:
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF files", "*.pdf")],
            initialfile=f"incident_{incident_id}.pdf",
        )
        if not path:
            return
        inc    = self.app.db.get_incident_by_id(incident_id)
        events = self.app.db.get_incident_events(incident_id)
        ok = export_incident_to_pdf(inc, events, path)
        if ok:
            messagebox.showinfo("Export", f"PDF report saved to:\n{path}")
        else:
            messagebox.showerror("Export Failed", "PDF export failed. Check that ReportLab is installed.")

