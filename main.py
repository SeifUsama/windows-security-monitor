"""
main.py
--------
Windows Security Monitor — Entry Point

Usage:
    python main.py              # Normal startup
    python main.py --demo       # Start with demo data pre-loaded
    python main.py --headless   # Run one collection cycle without UI (for testing)
"""

import sys
import os
import argparse
from configparser import ConfigParser
from pathlib import Path

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from app.database.db_manager import DatabaseManager
from app.utils.logger import log, setup_logger


CONFIG_PATH = Path("config/settings.ini")
DEFAULT_CONFIG = {
    "monitoring":   {"interval_seconds": "30", "max_events_per_cycle": "500"},
    "detection":    {
        "brute_force_threshold": "5",
        "brute_force_window_seconds": "60",
        "port_scan_threshold": "10",
        "port_scan_window_seconds": "30",
    },
    "log_sources":  {
        "security_log": "true", "system_log": "true",
        "application_log": "true", "powershell_log": "true",
        "firewall_log": "true",
    },
    "database":     {"db_path": "security_monitor.db"},
    "firewall":     {"log_path": r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"},
    "ui":           {"theme": "dark", "color_theme": "blue", "default_page": "dashboard"},
}


def load_config() -> ConfigParser:
    """Load configuration from settings.ini, creating defaults if missing."""
    config = ConfigParser()
    # Load defaults first
    for section, options in DEFAULT_CONFIG.items():
        config.add_section(section)
        for k, v in options.items():
            config.set(section, k, v)

    if CONFIG_PATH.exists():
        config.read(str(CONFIG_PATH))
        log.info("Configuration loaded from %s", CONFIG_PATH)
    else:
        log.warning("Config file not found at %s — using defaults", CONFIG_PATH)
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w") as f:
            config.write(f)
        log.info("Default config written to %s", CONFIG_PATH)

    return config


def main():
    parser = argparse.ArgumentParser(description="Windows Security Monitor")
    parser.add_argument("--demo",     action="store_true", help="Pre-load demo data on startup")
    parser.add_argument("--headless", action="store_true", help="Run one collection cycle without UI")
    parser.add_argument("--test",     action="store_true", help="Run unit tests")
    args = parser.parse_args()

    # Run tests
    if args.test:
        import pytest
        sys.exit(pytest.main(["tests/", "-v"]))

    # Load config
    config = load_config()
    db_path = config.get("database", "db_path", fallback="security_monitor.db")

    # Initialize database
    db = DatabaseManager(db_path)
    try:
        db.initialize()
    except Exception as e:
        log.critical("Failed to initialize database: %s", e)
        sys.exit(1)

    log.info("Windows Security Monitor starting...")
    log.info("Database: %s", db_path)

    # Headless mode (for testing/CI)
    if args.headless:
        log.info("Headless mode: running one collection cycle")
        from app.collectors.security_log    import SecurityLogCollector
        from app.collectors.firewall_log    import FirewallLogCollector
        from app.detection.engine           import DetectionEngine
        from app.correlation.correlator     import CorrelationEngine

        collector = SecurityLogCollector()
        result    = collector.collect()
        log.info("Collected %d Security events", len(result.events))
        if result.access_denied:
            log.warning("Security log: %s", result.error_message)

        db_ids = db.insert_events_bulk(result.events)
        for ev, db_id in zip(result.events, db_ids):
            ev["id"] = db_id

        fw = FirewallLogCollector()
        engine = DetectionEngine(config, firewall_available=fw.is_available)
        raw_incidents = engine.analyze(result.events)

        correlator = CorrelationEngine(db)
        inc_ids = correlator.process(raw_incidents, result.events)
        log.info("Detected %d incident(s)", len(inc_ids))
        db.close()
        return

    # GUI mode
    try:
        import customtkinter as ctk
    except ImportError:
        print("ERROR: customtkinter not installed. Run: pip install customtkinter")
        sys.exit(1)

    from app.ui.app_window import AppWindow

    app = AppWindow(db=db, config=config, config_path=str(CONFIG_PATH))

    # Pre-load demo if requested
    if args.demo:
        app.after(1000, app._toggle_demo)

    log.info("UI started")
    app.mainloop()
    db.close()
    log.info("Application closed")


if __name__ == "__main__":
    main()
