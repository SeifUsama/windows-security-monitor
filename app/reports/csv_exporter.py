"""
app/reports/csv_exporter.py
-----------------------------
Exports events or incident data to CSV format.
"""

import csv
import io
from pathlib import Path
from typing import List, Any
from datetime import datetime

from app.utils.logger import log


EVENT_COLUMNS = [
    "id", "timestamp", "source_log", "event_id", "level",
    "username", "source_ip", "destination_ip", "source_port",
    "destination_port", "protocol", "message", "severity", "description",
    "computer", "logon_type", "is_demo",
]

INCIDENT_COLUMNS = [
    "id", "attack_type", "severity", "status", "source_ip", "username",
    "first_seen", "last_seen", "description", "detection_rule",
    "detection_reason", "event_count", "is_demo",
]


def export_events_to_csv(events: List[Any], output_path: str) -> bool:
    """
    Write a list of event rows (sqlite3.Row or dict) to a CSV file.
    Returns True on success.
    """
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=EVENT_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for row in events:
                d = dict(row) if hasattr(row, "keys") else row
                d["is_demo"] = "DEMO" if d.get("is_demo") else "REAL"
                writer.writerow(d)
        log.info("Events exported to %s (%d rows)", output_path, len(events))
        return True
    except Exception as e:
        log.error("CSV export failed: %s", e)
        return False


def export_incident_to_csv(
    incident: Any,
    related_events: List[Any],
    output_path: str,
) -> bool:
    """Export a single incident and its related events to CSV."""
    try:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            # Incident summary section
            writer = csv.writer(f)
            writer.writerow(["=== INCIDENT SUMMARY ==="])
            inc = dict(incident) if hasattr(incident, "keys") else incident
            for col in INCIDENT_COLUMNS:
                writer.writerow([col, inc.get(col, "")])

            writer.writerow([])
            writer.writerow(["=== RELATED EVENTS ==="])
            if related_events:
                ev_writer = csv.DictWriter(f, fieldnames=EVENT_COLUMNS, extrasaction="ignore")
                ev_writer.writeheader()
                for row in related_events:
                    d = dict(row) if hasattr(row, "keys") else row
                    ev_writer.writerow(d)

        log.info("Incident CSV exported to %s", output_path)
        return True
    except Exception as e:
        log.error("Incident CSV export failed: %s", e)
        return False
