"""
app/ui/dashboard_frame.py
--------------------------
Main dashboard frame.

Shows:
  - 8 stat cards (total events, failed/successful logins, incidents, etc.)
  - 4 charts via Matplotlib embedded in Tkinter:
    * Events over time (line chart)
    * Login Success vs Failed (bar chart)
    * Severity distribution (donut)
    * Events by log source (horizontal bar)
  - Recent incidents table (last 5)
"""

import tkinter as tk
from tkinter import ttk
import customtkinter as ctk
from typing import TYPE_CHECKING, List, Dict, Any
from datetime import datetime

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

from app.ui.widgets.stat_card import StatCard
from app.utils.helpers import format_timestamp

if TYPE_CHECKING:
    from app.ui.app_window import AppWindow

# Chart color theme (dark background)
CHART_BG    = "#1a1a2e"
CHART_FG    = "#e0e0e0"
CHART_GRID  = "#2a2a4a"
SEVERITY_COLORS = {
    "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
    "MEDIUM": "#ffc107", "LOW": "#28a745", "INFO": "#6c757d",
}
SOURCE_COLORS = ["#74c0fc", "#69db7c", "#ffa94d", "#da77f2", "#f783ac"]


def _style_figure(fig: Figure) -> None:
    fig.patch.set_facecolor(CHART_BG)
    for ax in fig.get_axes():
        ax.set_facecolor(CHART_BG)
        ax.tick_params(colors=CHART_FG, labelsize=7)
        ax.spines[:].set_color(CHART_GRID)
        ax.title.set_color(CHART_FG)
        ax.xaxis.label.set_color(CHART_FG)
        ax.yaxis.label.set_color(CHART_FG)


class DashboardFrame(ctk.CTkFrame):
    def __init__(self, master, app: "AppWindow" = None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app = app or master
        self._chart_canvases: List[FigureCanvasTkAgg] = []
        self._build_ui()

    def _build_ui(self):
        # Title
        title_bar = ctk.CTkFrame(self, fg_color="transparent")
        title_bar.pack(fill="x", padx=16, pady=(12, 4))
        ctk.CTkLabel(
            title_bar, text="📊  Security Dashboard",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#74c0fc", fg_color="transparent",
        ).pack(side="left")

        self._mode_label = ctk.CTkLabel(
            title_bar, text="",
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#ffa94d", text_color="#000000",
            corner_radius=6, padx=8,
        )
        self._mode_label.pack(side="right", padx=4)

        # Scrollable body
        self._scroll = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self._scroll.pack(fill="both", expand=True, padx=8, pady=4)

        # --- Stat Cards Row 1 ---
        row1 = ctk.CTkFrame(self._scroll, fg_color="transparent")
        row1.pack(fill="x", padx=4, pady=4)
        row1.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._card_total     = StatCard(row1, "Total Events",      icon="📁", color="info")
        self._card_failed    = StatCard(row1, "Failed Logins",     icon="🚫", color="danger")
        self._card_success   = StatCard(row1, "Successful Logins", icon="✅", color="success")
        self._card_incidents = StatCard(row1, "Active Incidents",  icon="🚨", color="warning")
        for i, card in enumerate([self._card_total, self._card_failed,
                                   self._card_success, self._card_incidents]):
            card.grid(row=0, column=i, sticky="nsew", padx=4)

        # --- Stat Cards Row 2 ---
        row2 = ctk.CTkFrame(self._scroll, fg_color="transparent")
        row2.pack(fill="x", padx=4, pady=4)
        row2.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._card_suspicious  = StatCard(row2, "Suspicious Events", icon="⚠️",  color="danger",  subtitle="HIGH/CRITICAL")
        self._card_high_crit   = StatCard(row2, "High/Critical Incidents", icon="🔴", color="danger",  subtitle="requiring action")
        self._card_last_hour   = StatCard(row2, "Events (Last Hour)",  icon="⏱️",  color="info",    subtitle="real logs only")
        self._card_last_day    = StatCard(row2, "Events (Last 24h)",   icon="📅",  color="info",    subtitle="real logs only")
        for i, card in enumerate([self._card_suspicious, self._card_high_crit,
                                   self._card_last_hour, self._card_last_day]):
            card.grid(row=0, column=i, sticky="nsew", padx=4)

        # --- Charts Row ---
        chart_row = ctk.CTkFrame(self._scroll, fg_color="transparent")
        chart_row.pack(fill="x", padx=4, pady=4)
        chart_row.grid_columnconfigure((0, 1), weight=1)

        self._chart_left  = ctk.CTkFrame(chart_row, fg_color="#1a1a2e", corner_radius=8)
        self._chart_right = ctk.CTkFrame(chart_row, fg_color="#1a1a2e", corner_radius=8)
        self._chart_left.grid( row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._chart_right.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        # --- Charts Row 2 ---
        chart_row2 = ctk.CTkFrame(self._scroll, fg_color="transparent")
        chart_row2.pack(fill="x", padx=4, pady=4)
        chart_row2.grid_columnconfigure((0, 1), weight=1)

        self._chart_sev    = ctk.CTkFrame(chart_row2, fg_color="#1a1a2e", corner_radius=8)
        self._chart_source = ctk.CTkFrame(chart_row2, fg_color="#1a1a2e", corner_radius=8)
        self._chart_sev.grid(   row=0, column=0, sticky="nsew", padx=4, pady=4)
        self._chart_source.grid(row=0, column=1, sticky="nsew", padx=4, pady=4)

        # --- Recent Incidents ---
        recent_frame = ctk.CTkFrame(self._scroll, fg_color="#1a1a2e", corner_radius=8)
        recent_frame.pack(fill="x", padx=4, pady=4)
        ctk.CTkLabel(
            recent_frame, text="  🚨 Recent Incidents",
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#ff6b6b", fg_color="transparent",
        ).pack(anchor="w", padx=12, pady=(8, 4))

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Dash.Treeview",
            background="#1a1a2e", foreground="#e0e0e0",
            fieldbackground="#1a1a2e", rowheight=22,
            font=("Consolas", 9),
        )
        style.configure("Dash.Treeview.Heading",
            background="#16213e", foreground="#74c0fc",
            font=("Helvetica", 9, "bold"),
        )

        self._recent_tree = ttk.Treeview(
            recent_frame,
            columns=("id", "type", "severity", "username", "ip", "time", "status"),
            show="headings", style="Dash.Treeview", height=5,
        )
        for col, w, label in [
            ("id", 40, "#"),
            ("type", 160, "Attack Type"),
            ("severity", 80, "Severity"),
            ("username", 110, "Username"),
            ("ip", 120, "Source IP"),
            ("time", 140, "Last Seen"),
            ("status", 90, "Status"),
        ]:
            self._recent_tree.heading(col, text=label)
            self._recent_tree.column(col, width=w, anchor="center")

        self._recent_tree.pack(fill="x", padx=8, pady=(0, 8))

        # Tag colors for severity rows
        self._recent_tree.tag_configure("CRITICAL", foreground="#dc3545")
        self._recent_tree.tag_configure("HIGH",     foreground="#fd7e14")
        self._recent_tree.tag_configure("MEDIUM",   foreground="#ffc107")
        self._recent_tree.tag_configure("LOW",      foreground="#28a745")
        self._recent_tree.tag_configure("INFO",     foreground="#6c757d")

    def refresh(self, is_demo: bool = False) -> None:
        """Refresh all dashboard data from the database."""
        db   = self.app.db
        stats = db.get_statistics()

        # Update mode label
        if is_demo:
            self._mode_label.configure(text=" DEMO MODE ", fg_color="#ffa94d")
        else:
            self._mode_label.configure(text=" REAL MONITORING ", fg_color="#28a745")

        # Update stat cards
        if is_demo:
            self._card_total.set_value(str(stats.get("total_demo_events", 0)))
            self._card_failed.set_value(str(stats.get("demo_failed_logins", 0)))
            self._card_success.set_value(str(stats.get("demo_successful_logins", 0)))
            self._card_incidents.set_value(str(stats.get("demo_incidents", 0)))
            self._card_suspicious.set_value("—")
            self._card_high_crit.set_value(str(stats.get("demo_high_critical", 0)))
            self._card_last_hour.set_value("—")
            self._card_last_day.set_value("—")
        else:
            self._card_total.set_value(str(stats.get("total_events", 0)))
            self._card_failed.set_value(str(stats.get("failed_logins", 0)))
            self._card_success.set_value(str(stats.get("successful_logins", 0)))
            self._card_incidents.set_value(str(stats.get("active_incidents", 0)))
            self._card_suspicious.set_value(str(stats.get("suspicious_events", 0)))
            self._card_high_crit.set_value(str(stats.get("high_critical_incidents", 0)))
            self._card_last_hour.set_value(str(stats.get("events_last_hour", 0)))
            self._card_last_day.set_value(str(stats.get("events_last_day", 0)))

        # Update charts
        self._draw_timeline_chart(is_demo)
        self._draw_login_chart(stats, is_demo)
        self._draw_severity_chart(is_demo)
        self._draw_source_chart(is_demo)

        # Recent incidents
        self._refresh_recent_incidents(is_demo)

    def _clear_frame(self, frame: ctk.CTkFrame) -> None:
        for w in frame.winfo_children():
            w.destroy()

    def _draw_timeline_chart(self, is_demo: bool) -> None:
        self._clear_frame(self._chart_left)
        data = self.app.db.get_events_over_time(hours=24, is_demo=is_demo)

        fig = Figure(figsize=(5, 2.8), dpi=80)
        ax  = fig.add_subplot(111)
        _style_figure(fig)

        if data:
            hours  = [d["hour"][-5:] for d in data]   # "HH:00"
            counts = [d["count"] for d in data]
            ax.plot(hours, counts, color="#74c0fc", linewidth=2, marker="o", markersize=4)
            ax.fill_between(range(len(hours)), counts, alpha=0.2, color="#74c0fc")
            ax.set_xticks(range(0, len(hours), max(1, len(hours) // 6)))
            ax.set_xticklabels(
                [hours[i] for i in range(0, len(hours), max(1, len(hours) // 6))],
                rotation=30, fontsize=7,
            )
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes, fontsize=10)

        ax.set_title("Events Over Time (24h)", fontsize=9, pad=6)
        ax.grid(True, color=CHART_GRID, alpha=0.5)
        ax.set_ylabel("Events", fontsize=7)
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self._chart_left)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_login_chart(self, stats: Dict[str, Any], is_demo: bool) -> None:
        self._clear_frame(self._chart_right)

        failed  = stats.get("demo_failed_logins" if is_demo else "failed_logins", 0)
        success = stats.get("demo_successful_logins" if is_demo else "successful_logins", 0)

        fig = Figure(figsize=(5, 2.8), dpi=80)
        ax  = fig.add_subplot(111)
        _style_figure(fig)

        bars = ax.bar(
            ["Failed Logins", "Successful Logins"],
            [failed, success],
            color=["#dc3545", "#28a745"],
            width=0.5,
        )
        for bar, val in zip(bars, [failed, success]):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.1,
                str(val), ha="center", va="bottom",
                color=CHART_FG, fontsize=9, fontweight="bold",
            )

        ax.set_title("Login Attempts", fontsize=9, pad=6)
        ax.set_ylim(0, max(failed, success, 1) * 1.3)
        ax.grid(True, axis="y", color=CHART_GRID, alpha=0.5)
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self._chart_right)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_severity_chart(self, is_demo: bool) -> None:
        self._clear_frame(self._chart_sev)
        dist = self.app.db.get_severity_distribution(is_demo=is_demo)

        fig = Figure(figsize=(5, 2.8), dpi=80)
        ax  = fig.add_subplot(111)
        _style_figure(fig)

        if dist:
            labels = list(dist.keys())
            sizes  = list(dist.values())
            clrs   = [SEVERITY_COLORS.get(lbl, "#888888") for lbl in labels]
            wedges, texts, auto = ax.pie(
                sizes, labels=None, colors=clrs,
                autopct="%1.0f%%", startangle=90,
                pctdistance=0.75,
                wedgeprops={"width": 0.6, "edgecolor": CHART_BG, "linewidth": 2},
            )
            for t in auto:
                t.set_color(CHART_FG)
                t.set_fontsize(7)
            ax.legend(
                wedges, [f"{l} ({v})" for l, v in zip(labels, sizes)],
                loc="lower center", bbox_to_anchor=(0.5, -0.2),
                fontsize=7, ncol=3,
                labelcolor=CHART_FG, framealpha=0,
            )
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes, fontsize=10)

        ax.set_title("Severity Distribution", fontsize=9, pad=6)
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self._chart_sev)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _draw_source_chart(self, is_demo: bool) -> None:
        self._clear_frame(self._chart_source)
        dist = self.app.db.get_source_distribution(is_demo=is_demo)

        fig = Figure(figsize=(5, 2.8), dpi=80)
        ax  = fig.add_subplot(111)
        _style_figure(fig)

        if dist:
            sources = list(dist.keys())
            counts  = list(dist.values())
            clrs    = SOURCE_COLORS[:len(sources)]
            bars    = ax.barh(sources, counts, color=clrs)
            for bar, val in zip(bars, counts):
                ax.text(
                    bar.get_width() + 0.1, bar.get_y() + bar.get_height() / 2,
                    str(val), va="center", color=CHART_FG, fontsize=8,
                )
            ax.set_xlim(0, max(counts, default=1) * 1.2)
        else:
            ax.text(0.5, 0.5, "No data", ha="center", va="center",
                    color=CHART_FG, transform=ax.transAxes, fontsize=10)

        ax.set_title("Events by Log Source", fontsize=9, pad=6)
        ax.grid(True, axis="x", color=CHART_GRID, alpha=0.5)
        fig.tight_layout()

        canvas = FigureCanvasTkAgg(fig, master=self._chart_source)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=4, pady=4)

    def _refresh_recent_incidents(self, is_demo: bool) -> None:
        for item in self._recent_tree.get_children():
            self._recent_tree.delete(item)

        incidents = self.app.db.get_incidents({"is_demo": is_demo}, limit=5)
        for inc in incidents:
            d   = dict(inc)
            sev = d.get("severity", "INFO")
            self._recent_tree.insert("", "end", values=(
                d.get("id"),
                d.get("attack_type", "").replace("_", " "),
                sev,
                d.get("username") or "—",
                d.get("source_ip") or "—",
                str(d.get("last_seen", ""))[:19],
                d.get("status", "—"),
            ), tags=(sev,))

