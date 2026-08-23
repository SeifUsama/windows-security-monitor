"""
app/ui/analytics_frame.py
--------------------------
Analytics page with additional charts:
  - Top Source IPs
  - Top Targeted Usernames
  - Incident severity breakdown
  - Event count by day
"""

import customtkinter as ctk
from typing import TYPE_CHECKING

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow

CHART_BG   = "#1a1a2e"
CHART_FG   = "#e0e0e0"
CHART_GRID = "#2a2a4a"


def _style_ax(ax, fig):
    fig.patch.set_facecolor(CHART_BG)
    ax.set_facecolor(CHART_BG)
    ax.tick_params(colors=CHART_FG, labelsize=7)
    ax.spines[:].set_color(CHART_GRID)
    ax.title.set_color(CHART_FG)
    ax.xaxis.label.set_color(CHART_FG)
    ax.yaxis.label.set_color(CHART_FG)


class AnalyticsFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._build_ui()

    def _build_ui(self):
        ctk.CTkLabel(
            self, text="📈  Analytics",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(anchor="w", padx=16, pady=(12, 4))

        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=8)

        # Row 1: Top IPs and Usernames
        row1 = ctk.CTkFrame(scroll, fg_color="transparent")
        row1.pack(fill="x", pady=4)
        row1.grid_columnconfigure((0, 1), weight=1)

        self._top_ips_frame    = ctk.CTkFrame(row1, fg_color=CHART_BG, corner_radius=8)
        self._top_users_frame  = ctk.CTkFrame(row1, fg_color=CHART_BG, corner_radius=8)
        self._top_ips_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._top_users_frame.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        # Row 2: Events by day, Incident type breakdown
        row2 = ctk.CTkFrame(scroll, fg_color="transparent")
        row2.pack(fill="x", pady=4)
        row2.grid_columnconfigure((0, 1), weight=1)

        self._events_day_frame = ctk.CTkFrame(row2, fg_color=CHART_BG, corner_radius=8)
        self._inc_type_frame   = ctk.CTkFrame(row2, fg_color=CHART_BG, corner_radius=8)
        self._events_day_frame.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._inc_type_frame.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

    def refresh(self, is_demo: bool = False) -> None:
        self._draw_top_ips(is_demo)
        self._draw_top_usernames(is_demo)
        self._draw_events_by_day(is_demo)
        self._draw_incident_types(is_demo)

    def _clear(self, frame):
        for w in frame.winfo_children():
            w.destroy()

    def _draw_top_ips(self, is_demo: bool):
        self._clear(self._top_ips_frame)
        data = self.app.db.get_top_source_ips(10, is_demo=is_demo)
        fig = Figure(figsize=(5, 3), dpi=80)
        ax = fig.add_subplot(111)
        _style_ax(ax, fig)
        if data:
            ips    = [d["ip"] for d in data]
            counts = [d["count"] for d in data]
            ax.barh(ips[::-1], counts[::-1], color="#fd7e14")
            ax.set_xlabel("Events", fontsize=7)
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes)
        ax.set_title("Top Source IPs (by event count)", fontsize=9)
        ax.grid(True, axis="x", color=CHART_GRID, alpha=0.5)
        fig.tight_layout()
        FigureCanvasTkAgg(fig, self._top_ips_frame).get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_top_usernames(self, is_demo: bool):
        self._clear(self._top_users_frame)
        data = self.app.db.get_top_usernames(10, is_demo=is_demo)
        fig = Figure(figsize=(5, 3), dpi=80)
        ax = fig.add_subplot(111)
        _style_ax(ax, fig)
        if data:
            users  = [d["username"] for d in data]
            counts = [d["count"] for d in data]
            ax.barh(users[::-1], counts[::-1], color="#dc3545")
            ax.set_xlabel("Failed Logins", fontsize=7)
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes)
        ax.set_title("Top Targeted Usernames (failed logins)", fontsize=9)
        ax.grid(True, axis="x", color=CHART_GRID, alpha=0.5)
        fig.tight_layout()
        FigureCanvasTkAgg(fig, self._top_users_frame).get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_events_by_day(self, is_demo: bool):
        self._clear(self._events_day_frame)
        data = self.app.db.get_events_over_time(hours=168, is_demo=is_demo)  # 7 days
        fig = Figure(figsize=(5, 3), dpi=80)
        ax = fig.add_subplot(111)
        _style_ax(ax, fig)
        if data:
            hours  = [d["hour"] for d in data]
            counts = [d["count"] for d in data]
            ax.plot(range(len(hours)), counts, color="#74c0fc", linewidth=1.5)
            ax.fill_between(range(len(hours)), counts, alpha=0.15, color="#74c0fc")
            if len(hours) > 0:
                step = max(1, len(hours) // 7)
                ax.set_xticks(range(0, len(hours), step))
                ax.set_xticklabels(
                    [hours[i][:10] for i in range(0, len(hours), step)],
                    rotation=30, fontsize=6,
                )
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes)
        ax.set_title("Events Over Time (7 days)", fontsize=9)
        ax.grid(True, color=CHART_GRID, alpha=0.5)
        ax.set_ylabel("Events", fontsize=7)
        fig.tight_layout()
        FigureCanvasTkAgg(fig, self._events_day_frame).get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_incident_types(self, is_demo: bool):
        self._clear(self._inc_type_frame)
        incidents = self.app.db.get_incidents({"is_demo": is_demo} if is_demo is not None else {})
        type_counts: dict = {}
        for inc in incidents:
            t = dict(inc).get("attack_type", "UNKNOWN")
            type_counts[t] = type_counts.get(t, 0) + 1

        fig = Figure(figsize=(5, 3), dpi=80)
        ax = fig.add_subplot(111)
        _style_ax(ax, fig)
        if type_counts:
            types  = list(type_counts.keys())
            counts = list(type_counts.values())
            clrs   = ["#dc3545", "#fd7e14", "#ffc107", "#28a745", "#74c0fc", "#da77f2"][:len(types)]
            ax.bar([t.replace("_", "\n") for t in types], counts, color=clrs)
        else:
            ax.text(0.5, 0.5, "No incidents yet", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes)
        ax.set_title("Incidents by Attack Type", fontsize=9)
        ax.grid(True, axis="y", color=CHART_GRID, alpha=0.5)
        ax.tick_params(axis="x", labelsize=6)
        fig.tight_layout()
        FigureCanvasTkAgg(fig, self._inc_type_frame).get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

