"""
app/ui/widgets/timeline_widget.py
-----------------------------------
Vertical attack timeline widget.

Displays a sequence of timestamped events as a visual timeline,
ending with a conclusion box (e.g. "BRUTE FORCE DETECTED").

Used in the Incident Details view.
"""

import tkinter as tk
import customtkinter as ctk
from typing import List, Dict, Any

from app.ui.widgets.severity_badge import get_severity_colors


class TimelineWidget(ctk.CTkScrollableFrame):
    """
    Vertical timeline showing events and the detected attack.
    
    Each event is shown as:
      [●] HH:MM:SS  Event ID — Description  (Username / IP)

    The final node shows the detected attack type.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._items: List[ctk.CTkFrame] = []

    def load_timeline(
        self,
        events: List[Dict[str, Any]],
        attack_type: str,
        severity: str,
    ) -> None:
        """
        Populate the timeline with events and conclude with the attack.
        
        Args:
            events:      List of event dicts ordered by timestamp.
            attack_type: String to display in the conclusion node.
            severity:    Used to color the conclusion node.
        """
        # Clear existing
        for widget in self.winfo_children():
            widget.destroy()
        self._items.clear()

        if not events:
            ctk.CTkLabel(
                self, text="No timeline events available.",
                text_color="#888888", font=ctk.CTkFont(size=11),
            ).pack(pady=20)
            return

        # Event description mapping
        EVENT_NAMES = {
            4625: "Failed Logon", 4624: "Successful Logon",
            4740: "Account Locked Out", 4672: "Privileges Assigned",
            4720: "Account Created", 4634: "Logoff", None: "Firewall Block",
        }

        SEVERITY_DOT_COLORS = {
            4625: "#fd7e14", 4624: "#28a745", 4740: "#dc3545",
            4672: "#ffc107", 4720: "#dc3545",
        }

        for i, ev in enumerate(events):
            ev_dict = dict(ev) if hasattr(ev, "keys") else ev
            ts      = ev_dict.get("timestamp", "")
            ts_str  = str(ts)[:19] if ts else "—"
            eid     = ev_dict.get("event_id")
            desc    = ev_dict.get("description") or EVENT_NAMES.get(eid, f"Event {eid}")
            user    = ev_dict.get("username") or ""
            ip      = ev_dict.get("source_ip") or ""
            dot_color = SEVERITY_DOT_COLORS.get(eid, "#74c0fc")
            is_last   = (i == len(events) - 1)

            row = ctk.CTkFrame(self, fg_color="transparent")
            row.pack(fill="x", pady=1)

            # Left: dot + vertical line
            left = ctk.CTkFrame(row, fg_color="transparent", width=28)
            left.pack(side="left", fill="y")
            left.pack_propagate(False)

            dot = ctk.CTkLabel(
                left, text="●", font=ctk.CTkFont(size=14),
                text_color=dot_color, fg_color="transparent",
            )
            dot.pack(pady=(4, 0))

            if not is_last:
                line = ctk.CTkLabel(
                    left, text="│", font=ctk.CTkFont(size=11),
                    text_color="#444455", fg_color="transparent",
                )
                line.pack()

            # Right: event info
            right = ctk.CTkFrame(row, fg_color="#1e1e3a", corner_radius=6)
            right.pack(side="left", fill="x", expand=True, padx=(4, 4), pady=2)

            # Timestamp
            ctk.CTkLabel(
                right, text=ts_str,
                font=ctk.CTkFont(size=10, weight="bold"),
                text_color="#aaaacc", fg_color="transparent",
            ).grid(row=0, column=0, sticky="w", padx=8, pady=(4, 0))

            # Event name
            label = f"[4625] {desc}" if eid else desc
            if eid:
                label = f"[{eid}] {desc}"
            ctk.CTkLabel(
                right, text=label,
                font=ctk.CTkFont(size=11),
                text_color="#e0e0ff", fg_color="transparent",
            ).grid(row=0, column=1, sticky="w", padx=8, pady=(4, 0))

            # User / IP detail
            detail = " | ".join(filter(None, [
                f"User: {user}" if user else None,
                f"IP: {ip}" if ip else None,
            ]))
            if detail:
                ctk.CTkLabel(
                    right, text=detail,
                    font=ctk.CTkFont(size=9),
                    text_color="#888899", fg_color="transparent",
                ).grid(row=1, column=0, columnspan=2, sticky="w", padx=8, pady=(0, 4))

            right.grid_columnconfigure(1, weight=1)

        # Arrow
        arrow_frame = ctk.CTkFrame(self, fg_color="transparent")
        arrow_frame.pack(pady=2)
        ctk.CTkLabel(
            arrow_frame, text="↓",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#888899", fg_color="transparent",
        ).pack()

        # Conclusion node
        sev_bg, sev_fg = get_severity_colors(severity)
        conclusion = ctk.CTkFrame(self, fg_color=sev_bg, corner_radius=8)
        conclusion.pack(fill="x", padx=20, pady=4)

        ctk.CTkLabel(
            conclusion,
            text=f"⚠  {attack_type.replace('_', ' ')}  ⚠",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color=sev_fg,
            fg_color="transparent",
        ).pack(pady=10)
