"""
app/ui/widgets/raw_event_viewer.py
------------------------------------
Split-pane widget showing a Normalized Event alongside its Raw XML.

This directly demonstrates the parse → normalize pipeline for the
academic audience.

Left panel:  Normalized event fields
Right panel: Raw XML from wevtutil (stored in events.raw_xml)
"""

import tkinter as tk
import customtkinter as ctk
from typing import Any, Dict


class RawEventViewer(ctk.CTkToplevel):
    """
    A popup window showing normalized event fields and raw XML side by side.
    """

    def __init__(self, master, event: Any, **kwargs):
        super().__init__(master, **kwargs)
        ev = dict(event) if hasattr(event, "keys") else event

        self.title(f"Event Viewer — ID {ev.get('id', 'N/A')} | EventID {ev.get('event_id', '—')}")
        self.geometry("1000x600")
        self.resizable(True, True)
        self.grab_set()

        # Configure grid
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Header ---
        header = ctk.CTkFrame(self, fg_color="#16213e", corner_radius=0)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        ctk.CTkLabel(
            header,
            text="🔍  Event Investigation — Normalized View  |  Raw XML View",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#74c0fc",
            fg_color="transparent",
        ).pack(side="left", padx=16, pady=8)

        demo_badge = ev.get("is_demo") or ev.get("source_log") == "DEMO"
        if demo_badge:
            ctk.CTkLabel(
                header, text=" [DEMO DATA] ",
                font=ctk.CTkFont(size=10, weight="bold"),
                fg_color="#ffa94d", text_color="#000000",
                corner_radius=4,
            ).pack(side="right", padx=12, pady=8)

        # --- Left: Normalized ---
        left_frame = ctk.CTkFrame(self, fg_color="#0d0d1a", corner_radius=0)
        left_frame.grid(row=1, column=0, sticky="nsew", padx=(4, 2), pady=4)

        ctk.CTkLabel(
            left_frame,
            text="Normalized Event",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(anchor="w", padx=12, pady=(8, 4))

        fields = [
            ("Event ID",         ev.get("event_id", "—")),
            ("Timestamp",        str(ev.get("timestamp", "—"))[:19]),
            ("Source Log",       ev.get("source_log", "—")),
            ("Level",            ev.get("level", "—")),
            ("Severity",         ev.get("severity", "—")),
            ("Username",         ev.get("username") or "Not Available"),
            ("Source IP",        ev.get("source_ip") or "Not Available"),
            ("Destination IP",   ev.get("destination_ip") or "—"),
            ("Source Port",      str(ev.get("source_port") or "—")),
            ("Destination Port", str(ev.get("destination_port") or "—")),
            ("Protocol",         ev.get("protocol") or "—"),
            ("Computer",         ev.get("computer") or "—"),
            ("Logon Type",       ev.get("logon_type") or "—"),
            ("Description",      ev.get("description") or "—"),
            ("Data Source",      "DEMO (Simulated)" if demo_badge else "Real Windows Log"),
        ]

        SEVERITY_COLORS = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d",
        }

        for field_name, field_val in fields:
            row_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
            row_frame.pack(fill="x", padx=12, pady=1)

            ctk.CTkLabel(
                row_frame,
                text=f"{field_name}:",
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#aaaacc", fg_color="transparent",
                width=130, anchor="w",
            ).pack(side="left")

            val_color = "#e0e0ff"
            if field_name == "Severity":
                val_color = SEVERITY_COLORS.get(str(field_val).upper(), "#e0e0ff")
            elif field_name == "Data Source" and "DEMO" in str(field_val):
                val_color = "#ffa94d"

            ctk.CTkLabel(
                row_frame,
                text=str(field_val)[:80],
                font=ctk.CTkFont(size=10),
                text_color=val_color, fg_color="transparent",
                anchor="w",
            ).pack(side="left", fill="x", expand=True)

        # Message (full width)
        msg_frame = ctk.CTkFrame(left_frame, fg_color="#1a1a2e", corner_radius=6)
        msg_frame.pack(fill="both", expand=True, padx=12, pady=8)
        ctk.CTkLabel(
            msg_frame, text="Message:",
            font=ctk.CTkFont(size=10, weight="bold"),
            text_color="#aaaacc", fg_color="transparent",
            anchor="w",
        ).pack(anchor="w", padx=8, pady=(4, 0))
        msg_text = ctk.CTkTextbox(
            msg_frame, font=ctk.CTkFont(size=9, family="Consolas"),
            fg_color="#1a1a2e", text_color="#ccccff",
            wrap="word",
        )
        msg_text.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        msg_text.insert("1.0", ev.get("message") or "No message available.")
        msg_text.configure(state="disabled")

        # --- Right: Raw XML ---
        right_frame = ctk.CTkFrame(self, fg_color="#0d0d1a", corner_radius=0)
        right_frame.grid(row=1, column=1, sticky="nsew", padx=(2, 4), pady=4)

        ctk.CTkLabel(
            right_frame,
            text="Raw Event (Windows XML)",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(anchor="w", padx=12, pady=(8, 4))

        raw_xml = ev.get("raw_xml") or "Raw event data not available for this event."
        xml_box = ctk.CTkTextbox(
            right_frame,
            font=ctk.CTkFont(size=9, family="Consolas"),
            fg_color="#0a0a18", text_color="#aaffaa",
            wrap="none",
        )
        xml_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        xml_box.insert("1.0", raw_xml)
        xml_box.configure(state="disabled")

        # Close button
        ctk.CTkButton(
            self, text="Close",
            command=self.destroy, width=100,
        ).grid(row=2, column=0, columnspan=2, pady=8)
