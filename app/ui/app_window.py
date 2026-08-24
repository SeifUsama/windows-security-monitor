"""
app/ui/app_window.py
---------------------
Main application window.

Provides:
  - Dark-themed 1280×800 CustomTkinter window
  - Left sidebar navigation
  - Status bar (monitoring status, log source health, admin status)
  - Demo Mode toggle button
  - Page switching logic
  - Collection cycle orchestration
"""

import threading
import tkinter as tk
from tkinter import messagebox
import customtkinter as ctk
from configparser import ConfigParser
from pathlib import Path
from typing import Optional, Dict, List
from datetime import datetime

from app.database.db_manager import DatabaseManager
from app.collectors.security_log    import SecurityLogCollector
from app.collectors.system_log      import SystemLogCollector
from app.collectors.application_log import ApplicationLogCollector
from app.collectors.powershell_log  import PowerShellLogCollector
from app.collectors.firewall_log    import FirewallLogCollector
from app.collectors.desktop_collector import DesktopCollector
from app.detection.engine           import DetectionEngine
from app.correlation.correlator     import CorrelationEngine
from app.demo_loader                import DemoLoader
from app.utils.helpers              import is_running_as_admin
from app.utils.logger               import log


class AppWindow(ctk.CTk):
    """
    Main application window.

    Attributes:
        db:          DatabaseManager instance shared across all frames.
        config:      ConfigParser instance.
        config_path: Path to settings.ini.
    """

    def __init__(self, db: DatabaseManager, config: ConfigParser, config_path: str):
        super().__init__()

        self.db          = db
        self.config      = config
        self.config_path = config_path
        self._is_demo    = False
        self._collectors = {}
        self._detection_engine: Optional[DetectionEngine] = None
        self._demo_loader = DemoLoader(db, config)

        # Status per log source
        self._source_status: Dict[str, str] = {}

        # Setup UI
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Configure ttk style theme to clam to fix invisible text on Windows tables
        try:
            from tkinter import ttk
            style = ttk.Style()
            style.theme_use("clam")
        except Exception as e:
            log.warning("Failed to configure ttk theme to clam: %s", e)

        self.title("Windows Security Monitor — Fundamentals of Cybersecurity")
        self.geometry("1280x800")
        self.minsize(1024, 700)

        self._setup_layout()
        self._setup_collectors()
        self._show_page("dashboard")

        # Check admin status
        self.after(500, self._check_admin)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------

    def _setup_layout(self):
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=1)

        # ---- Sidebar ----
        self._sidebar = ctk.CTkFrame(self, width=210, fg_color="#16213e", corner_radius=0)
        self._sidebar.grid(row=0, column=0, sticky="nsew")
        self._sidebar.grid_propagate(False)

        # App title
        ctk.CTkLabel(
            self._sidebar,
            text="🛡 SecMonitor",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color="#74c0fc",
            fg_color="transparent",
        ).pack(pady=(16, 4), padx=12)
        ctk.CTkLabel(
            self._sidebar,
            text="Fundamentals of Cybersecurity",
            font=ctk.CTkFont(size=8),
            text_color="#555577",
            fg_color="transparent",
        ).pack(pady=(0, 16), padx=12)

        ctk.CTkFrame(self._sidebar, height=1, fg_color="#2a2a5a").pack(fill="x", padx=12, pady=4)

        # Nav buttons
        self._nav_buttons: Dict[str, ctk.CTkButton] = {}
        nav_items = [
            ("dashboard",     "📊  Dashboard"),
            ("live_monitor",  "🔴  Live Monitor"),
            ("incidents",     "🚨  Incidents"),
            ("search",        "🔍  Search"),
            ("config",        "⚙️   Config"),
        ]
        for page_id, label in nav_items:
            btn = ctk.CTkButton(
                self._sidebar,
                text=label,
                anchor="w",
                fg_color="transparent",
                hover_color="#2a2a5a",
                text_color="#ccccdd",
                font=ctk.CTkFont(size=12),
                command=lambda p=page_id: self._show_page(p),
            )
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_buttons[page_id] = btn

        ctk.CTkFrame(self._sidebar, height=1, fg_color="#2a2a5a").pack(fill="x", padx=12, pady=8)

        # Demo Mode toggle
        self._demo_btn = ctk.CTkButton(
            self._sidebar,
            text="🔬  Load Demo Data",
            fg_color="#3d2b00", hover_color="#5c4200",
            text_color="#ffa94d",
            font=ctk.CTkFont(size=11, weight="bold"),
            command=self._toggle_demo,
        )
        self._demo_btn.pack(fill="x", padx=8, pady=4)

        self._clear_db_btn = ctk.CTkButton(
            self._sidebar,
            text="🗑  Clear Database",
            fg_color="#2a2a4a", hover_color="#3a3a5a",
            text_color="#888899",
            font=ctk.CTkFont(size=10),
            command=self._clear_db,
        )
        self._clear_db_btn.pack(fill="x", padx=8, pady=2)

        # ---- Status bar ----
        self._status_bar = ctk.CTkFrame(self._sidebar, fg_color="#0d0d1a", corner_radius=6)
        self._status_bar.pack(side="bottom", fill="x", padx=8, pady=8)

        self._admin_label = ctk.CTkLabel(
            self._status_bar, text="",
            font=ctk.CTkFont(size=9), fg_color="transparent",
            text_color="#aaaaaa",
        )
        self._admin_label.pack(fill="x", padx=6, pady=(4, 2))

        self._status_labels: Dict[str, ctk.CTkLabel] = {}
        for src in ["Security", "System", "Application", "PowerShell", "Firewall", "Desktop"]:
            lbl = ctk.CTkLabel(
                self._status_bar, text=f"  {src}: —",
                font=ctk.CTkFont(size=8), fg_color="transparent",
                text_color="#555566", anchor="w",
            )
            lbl.pack(fill="x", padx=4)
            self._status_labels[src] = lbl

        # ---- Content area ----
        self._content = ctk.CTkFrame(self, fg_color="#0d0d1a", corner_radius=0)
        self._content.grid(row=0, column=1, sticky="nsew")
        self._content.grid_rowconfigure(0, weight=1)
        self._content.grid_columnconfigure(0, weight=1)

        # Lazy-create frames
        self._frames: Dict[str, ctk.CTkFrame] = {}

    def _get_frame(self, page_id: str) -> ctk.CTkFrame:
        """Lazy-initialize frames to avoid import cycles."""
        if page_id not in self._frames:
            if page_id == "dashboard":
                from app.ui.dashboard_frame  import DashboardFrame
                self._frames[page_id] = DashboardFrame(self._content, app=self)
            elif page_id == "live_monitor":
                from app.ui.live_monitor_frame import LiveMonitorFrame
                self._frames[page_id] = LiveMonitorFrame(self._content, app=self)
            elif page_id == "incidents":
                from app.ui.incidents_frame    import IncidentsFrame
                self._frames[page_id] = IncidentsFrame(self._content, app=self)
            elif page_id == "search":
                from app.ui.search_frame       import SearchFrame
                self._frames[page_id] = SearchFrame(self._content, app=self)
            elif page_id == "config":
                from app.ui.config_frame       import ConfigFrame
                self._frames[page_id] = ConfigFrame(self._content, app=self)
            else:
                self._frames[page_id] = ctk.CTkFrame(self._content)

            self._frames[page_id].grid(row=0, column=0, sticky="nsew")

        return self._frames[page_id]

    def _show_page(self, page_id: str) -> None:
        """Switch to the given page and refresh its content."""
        # Highlight active nav button
        for pid, btn in self._nav_buttons.items():
            btn.configure(
                fg_color="#2a2a5a" if pid == page_id else "transparent",
                text_color="#74c0fc" if pid == page_id else "#ccccdd",
            )

        frame = self._get_frame(page_id)
        frame.tkraise()

        # Refresh page content
        if page_id == "dashboard":
            frame.refresh(is_demo=self._is_demo)
        elif page_id == "incidents":
            frame.refresh(is_demo=self._is_demo)
        elif page_id == "analytics":
            frame.refresh(is_demo=self._is_demo)
        elif page_id == "live_monitor":
            frame._refresh_events()

    # ------------------------------------------------------------------
    # Collectors setup
    # ------------------------------------------------------------------

    def _setup_collectors(self) -> None:
        cfg = self.config
        max_ev = int(cfg.get("monitoring", "max_events_per_cycle", fallback=500))

        self._collectors = {}
        if cfg.getboolean("log_sources", "security_log", fallback=True):
            self._collectors["Security"] = SecurityLogCollector(max_events=max_ev)
        if cfg.getboolean("log_sources", "system_log", fallback=True):
            self._collectors["System"] = SystemLogCollector()
        if cfg.getboolean("log_sources", "application_log", fallback=True):
            self._collectors["Application"] = ApplicationLogCollector()
        if cfg.getboolean("log_sources", "powershell_log", fallback=True):
            self._collectors["PowerShell"] = PowerShellLogCollector()

        # Instantiate DesktopCollector for real-time Desktop file system monitoring
        desktop = DesktopCollector()
        try:
            desktop.collect()  # Baseline current files silently on startup
        except Exception as e:
            log.error("Failed to baseline DesktopCollector: %s", e)
        self._collectors["Desktop"] = desktop

        fw_path = cfg.get("firewall", "log_path",
                          fallback=r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log")
        fw_enabled = cfg.getboolean("log_sources", "firewall_log", fallback=True)
        if fw_enabled:
            self._collectors["Firewall"] = FirewallLogCollector(fw_path)

        # Determine firewall availability for detection engine
        fw_collector = self._collectors.get("Firewall")
        fw_available = fw_collector is not None and fw_collector.is_available

        self._detection_engine = DetectionEngine(cfg, firewall_available=fw_available)
        self._correlator = CorrelationEngine(self.db)

        log.info("Collectors initialized: %s", list(self._collectors.keys()))
        log.info("Firewall available: %s", fw_available)

    # ------------------------------------------------------------------
    # Collection cycle
    # ------------------------------------------------------------------

    def _initial_collection(self) -> None:
        """Run the first collection pass (reads from checkpoint or last 500 events)."""
        try:
            self.run_collection_cycle()
            self.after(0, lambda: self._show_page("dashboard"))
        except Exception as e:
            log.error("Initial collection failed: %s", e)

    def run_collection_cycle(self) -> None:
        """
        Single collection cycle:
          1. For each enabled collector, read checkpoint from DB
          2. Collect new events since checkpoint
          3. Insert events into DB
          4. Update checkpoint
          5. Run detection on new events
          6. Run correlation on detected incidents
        """
        all_new_events = []

        for src_name, collector in self._collectors.items():
            try:
                last_ts, _ = self.db.get_checkpoint(src_name)
                if last_ts is None:
                    # No checkpoint exists. To start monitoring only new events,
                    # set checkpoint to 'now' in UTC.
                    now_str = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
                    self.db.update_checkpoint(src_name, now_str)
                    last_ts = now_str
                
                result = collector.collect(since_timestamp=last_ts)

                # Update status label
                self.after(0, lambda s=src_name, r=result: self._update_source_status(s, r))

                if not result.events:
                    continue

                # Insert into DB
                db_ids = self.db.insert_events_bulk(result.events)

                # Attach IDs back to event dicts
                for ev, db_id in zip(result.events, db_ids):
                    if db_id > 0:
                        ev["id"] = db_id

                all_new_events.extend(result.events)

                # Update checkpoint to latest timestamp
                sorted_events = sorted(
                    result.events,
                    key=lambda e: e.get("timestamp") or "",
                    reverse=True,
                )
                if sorted_events:
                    latest = sorted_events[0].get("timestamp")
                    if latest:
                        ts_str = latest.isoformat() if hasattr(latest, "isoformat") else str(latest)
                        self.db.update_checkpoint(src_name, ts_str)

            except Exception as e:
                log.error("Collection error for %s: %s", src_name, e)

        # Detection + correlation on all new events from this cycle
        if all_new_events and self._detection_engine:
            try:
                raw_incidents = self._detection_engine.analyze(all_new_events)
                if raw_incidents:
                    self._correlator.process(raw_incidents, all_new_events)
            except Exception as e:
                log.error("Detection/correlation error: %s", e)

    def _update_source_status(self, source: str, result) -> None:
        """Update the sidebar status label for a log source."""
        if source not in self._status_labels:
            return
        lbl = self._status_labels[source]
        if result.access_denied:
            lbl.configure(text=f"  ⚠ {source}: No permission", text_color="#ffc107")
        elif result.unavailable:
            lbl.configure(text=f"  ℹ {source}: Unavailable", text_color="#555566")
        else:
            count = len(result.events)
            lbl.configure(text=f"  ✓ {source}: +{count}", text_color="#28a745")

    # ------------------------------------------------------------------
    # Demo Mode
    # ------------------------------------------------------------------

    def _toggle_demo(self) -> None:
        if self._demo_loader.is_demo_loaded():
            self._is_demo = True
            self._demo_btn.configure(text="🔬  Demo Active", fg_color="#5c3d00")
            self._show_page("dashboard")
            return

        self._demo_btn.configure(text="⏳ Loading...", state="disabled")

        def _load():
            try:
                result = self._demo_loader.load_demo()
                self.after(0, lambda: self._on_demo_loaded(result))
            except Exception as e:
                log.error("Demo load failed: %s", e)
                self.after(0, lambda: self._demo_btn.configure(
                    text="❌ Demo Failed", state="normal",
                    fg_color="#dc3545",
                ))

        threading.Thread(target=_load, daemon=True).start()

    def _on_demo_loaded(self, result: dict) -> None:
        self._is_demo = True
        self._demo_btn.configure(
            text=f"🔬  Demo Active ({result['events']} events)",
            fg_color="#5c3d00", state="normal",
        )
        self._show_page("dashboard")
        messagebox.showinfo(
            "Demo Mode Active",
            f"Demo data loaded:\n"
            f"  • {result['events']} synthetic events\n"
            f"  • {result['incidents']} detected incidents\n\n"
            f"All demo events are marked [DEMO] in the UI.\n"
            f"The same detection & correlation pipeline processed them."
        )

    def _clear_db(self) -> None:
        self.db.clear_all_data()
        
        # Reset collector state for DesktopCollector so it gets initialized fresh
        desktop_coll = self._collectors.get("Desktop")
        if desktop_coll:
            try:
                desktop_coll.state = {}
                desktop_coll._initialized = False
                desktop_coll.collect()  # Baseline again right now
            except Exception as e:
                log.error("Failed to re-baseline DesktopCollector during clear: %s", e)

        self._is_demo = False
        self._demo_btn.configure(
            text="🔬  Load Demo Data",
            fg_color="#3d2b00",
            text_color="#ffa94d",
        )
        
        # Force refresh all loaded frames to wipe UI data instantly
        for page_id, frame in self._frames.items():
            try:
                if page_id == "dashboard":
                    frame.refresh(is_demo=False)
                elif page_id == "incidents":
                    frame.refresh(is_demo=False)
                elif page_id == "live_monitor":
                    frame._refresh_events()
            except Exception as e:
                log.error("Failed to refresh frame %s during clear: %s", page_id, e)

        self._show_page("dashboard")
        messagebox.showinfo("Database Cleared", "All logs, incidents, and checkpoints have been successfully cleared.")

    # ------------------------------------------------------------------
    # Admin check
    # ------------------------------------------------------------------

    def _check_admin(self) -> None:
        if is_running_as_admin():
            self._admin_label.configure(
                text="🔓 Running as Administrator",
                text_color="#28a745",
            )
        else:
            self._admin_label.configure(
                text="⚠ Not Admin — Security log\n   may be limited",
                text_color="#ffc107",
            )
