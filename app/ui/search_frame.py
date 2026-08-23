"""
app/ui/search_frame.py
-----------------------
Advanced forensic search and filtering page.
Multi-field search form with results table and CSV export.
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import customtkinter as ctk
from typing import TYPE_CHECKING, Dict, Any

from app.ui.widgets.raw_event_viewer import RawEventViewer
from app.reports.csv_exporter import export_events_to_csv

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow

SEVERITY_FG = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d",
}


class SearchFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._results = []
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(
            self, text="🔍  Forensic Search & Investigation",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(anchor="w", padx=16, pady=(12, 4))

        # Search form
        form = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=8)
        form.pack(fill="x", padx=12, pady=4)
        form.grid_columnconfigure((1, 3, 5), weight=1)

        def _lbl(text, row, col):
            ctk.CTkLabel(form, text=text, font=ctk.CTkFont(size=10, weight="bold"),
                         text_color="#aaaacc", fg_color="transparent").grid(
                row=row, column=col, sticky="w", padx=(12, 4), pady=4)

        def _entry(row, col, placeholder=""):
            e = ctk.CTkEntry(form, placeholder_text=placeholder,
                             fg_color="#0d0d1a", border_color="#2a2a4a")
            e.grid(row=row, column=col, sticky="ew", padx=(0, 12), pady=4)
            return e

        _lbl("Username:", 0, 0);       self._s_username  = _entry(0, 1, "e.g. Administrator")
        _lbl("Source IP:", 0, 2);      self._s_ip        = _entry(0, 3, "e.g. 192.168.1.50")
        _lbl("Event ID:", 0, 4);       self._s_eid       = _entry(0, 5, "e.g. 4625")
        _lbl("Keyword:", 1, 0);        self._s_keyword   = _entry(1, 1, "keyword in message/description")
        _lbl("From (YYYY-MM-DD HH:MM:SS):", 1, 2); self._s_from = _entry(1, 3)
        _lbl("To (YYYY-MM-DD HH:MM:SS):", 1, 4);   self._s_to   = _entry(1, 5)

        # Dropdowns
        drop_row = ctk.CTkFrame(form, fg_color="transparent")
        drop_row.grid(row=2, column=0, columnspan=6, sticky="ew", padx=8, pady=4)

        self._s_sev = ctk.StringVar(value="Any Severity")
        ctk.CTkOptionMenu(
            drop_row, values=["Any Severity", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
            variable=self._s_sev, width=140,
        ).pack(side="left", padx=4)

        self._s_src = ctk.StringVar(value="Any Source")
        ctk.CTkOptionMenu(
            drop_row, values=["Any Source", "Security", "System", "Application", "PowerShell", "Firewall", "DEMO"],
            variable=self._s_src, width=140,
        ).pack(side="left", padx=4)

        self._s_demo = ctk.StringVar(value="All Events")
        ctk.CTkOptionMenu(
            drop_row, values=["All Events", "Real Only", "Demo Only"],
            variable=self._s_demo, width=120,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            drop_row, text="🔍  Search", width=120,
            fg_color="#0f3460", hover_color="#16213e",
            command=self._run_search,
        ).pack(side="left", padx=8)

        ctk.CTkButton(
            drop_row, text="Clear", width=80,
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            command=self._clear_form,
        ).pack(side="left")

        ctk.CTkButton(
            drop_row, text="📥 Export CSV", width=120,
            fg_color="#28a745", hover_color="#1e7e34",
            command=self._export_csv,
        ).pack(side="right", padx=8)

        self._result_label = ctk.CTkLabel(
            drop_row, text="", font=ctk.CTkFont(size=10),
            text_color="#aaaacc", fg_color="transparent",
        )
        self._result_label.pack(side="right", padx=4)

        # Results table
        res_frame = ctk.CTkFrame(self, fg_color="#1a1a2e", corner_radius=8)
        res_frame.pack(fill="both", expand=True, padx=12, pady=4)

        style = ttk.Style()
        style.configure("Search.Treeview",
            background="#1a1a2e", foreground="#e0e0e0",
            fieldbackground="#1a1a2e", rowheight=22,
            font=("Consolas", 9),
        )
        style.configure("Search.Treeview.Heading",
            background="#16213e", foreground="#74c0fc",
            font=("Helvetica", 9, "bold"),
        )
        style.map("Search.Treeview", background=[("selected", "#2d2d5e")])

        vsb = ttk.Scrollbar(res_frame, orient="vertical")
        hsb = ttk.Scrollbar(res_frame, orient="horizontal")
        self._tree = ttk.Treeview(
            res_frame,
            columns=("ts", "src", "eid", "lvl", "user", "ip", "desc", "sev", "demo"),
            show="headings", style="Search.Treeview",
            yscrollcommand=vsb.set, xscrollcommand=hsb.set,
        )
        vsb.config(command=self._tree.yview)
        hsb.config(command=self._tree.xview)

        for col, w, lbl in [
            ("ts", 145, "Timestamp"), ("src", 90, "Source"), ("eid", 65, "Event ID"),
            ("lvl", 90, "Level"), ("user", 110, "Username"), ("ip", 120, "Source IP"),
            ("desc", 190, "Description"), ("sev", 75, "Severity"), ("demo", 50, "Demo"),
        ]:
            self._tree.heading(col, text=lbl)
            self._tree.column(col, width=w, anchor="w")

        self._tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        res_frame.grid_rowconfigure(0, weight=1)
        res_frame.grid_columnconfigure(0, weight=1)

        for sev, fg in SEVERITY_FG.items():
            self._tree.tag_configure(sev, foreground=fg)
        self._tree.tag_configure("DEMO", foreground="#aaaaaa",
                                  font=("Consolas", 9, "italic"))

        self._tree.bind("<Double-1>", self._view_raw_event)

        # Tip label
        ctk.CTkLabel(
            self, text="Double-click any row to view the raw Windows event XML",
            font=ctk.CTkFont(size=9), text_color="#555566", fg_color="transparent",
        ).pack(anchor="w", padx=16, pady=(0, 4))

    def _build_search_filters(self) -> Dict[str, Any]:
        f: Dict[str, Any] = {}
        if u := self._s_username.get().strip(): f["username"] = u
        if ip := self._s_ip.get().strip(): f["source_ip"] = ip
        try:
            if eid := self._s_eid.get().strip(): f["event_id"] = int(eid)
        except ValueError:
            pass
        if kw := self._s_keyword.get().strip(): f["keyword"] = kw
        if fr := self._s_from.get().strip(): f["from_time"] = fr
        if to := self._s_to.get().strip(): f["to_time"] = to
        sev = self._s_sev.get()
        if sev != "Any Severity": f["severity"] = sev
        src = self._s_src.get()
        if src != "Any Source": f["source_log"] = src
        demo = self._s_demo.get()
        if demo == "Real Only": f["is_demo"] = False
        elif demo == "Demo Only": f["is_demo"] = True
        return f

    def _run_search(self):
        filters = self._build_search_filters()
        rows = self.app.db.query_events(filters, limit=1000, order_by="timestamp DESC")
        self._results = [dict(r) for r in rows]
        self._populate_results(rows)

    def _populate_results(self, rows):
        for item in self._tree.get_children():
            self._tree.delete(item)
        for row in rows:
            d = dict(row)
            sev = (d.get("severity") or "INFO").upper()
            is_demo = bool(d.get("is_demo"))
            tags = (sev, "DEMO") if is_demo else (sev,)
            self._tree.insert("", "end", iid=str(d.get("id")), values=(
                str(d.get("timestamp", ""))[:19],
                d.get("source_log") or "—",
                d.get("event_id") or "—",
                d.get("level") or "—",
                d.get("username") or "—",
                d.get("source_ip") or "—",
                d.get("description") or "—",
                sev,
                "✓" if is_demo else "",
            ), tags=tags)
        self._result_label.configure(text=f"{len(rows)} results")

    def _view_raw_event(self, _event=None):
        sel = self._tree.selection()
        if not sel:
            return
        try:
            ev = self.app.db.get_event_by_id(int(sel[0]))
            if ev:
                RawEventViewer(self, ev)
        except Exception:
            pass

    def _clear_form(self):
        for e in [self._s_username, self._s_ip, self._s_eid,
                  self._s_keyword, self._s_from, self._s_to]:
            e.delete(0, "end")
        self._s_sev.set("Any Severity")
        self._s_src.set("Any Source")
        self._s_demo.set("All Events")
        self._results = []
        for item in self._tree.get_children():
            self._tree.delete(item)
        self._result_label.configure(text="")

    def _export_csv(self):
        if not self._results:
            messagebox.showinfo("Export", "Run a search first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile="search_results.csv",
        )
        if not path:
            return
        ok = export_events_to_csv(self._results, path)
        if ok:
            messagebox.showinfo("Export", f"Exported {len(self._results)} events to:\n{path}")
        else:
            messagebox.showerror("Export", "Export failed.")

