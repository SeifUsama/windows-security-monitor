"""
app/detection/rules/file_integrity.py
----------------------------------------
File Integrity Auditing Rule (FILE_INTEGRITY_001)

Detects Event ID 4663 — An attempt was made to access an object.
Filters for file system accesses (WriteData, Delete, etc.) on configured paths.
"""

from typing import List, Dict, Any
from datetime import datetime

from app.utils.helpers import format_timestamp
from app.utils.logger import log


class FileIntegrityRule:

    RULE_ID   = "FILE_INTEGRITY_001"
    RULE_NAME = "File Integrity Auditing"

    def __init__(self, watch_paths: List[str] = None, severity: str = "LOW"):
        # Lowercase for case-insensitive matching
        self.watch_paths = [p.strip().lower() for p in watch_paths] if watch_paths else []
        self.severity = severity

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect file modifications / deletions / creations (Event ID 4663).
        """
        audits = [
            ev for ev in events
            if ev.get("event_id") == 4663
        ]

        incidents = []
        for ev in audits:
            # Handle object name path matching
            event_data = ev.get("_event_data", {})
            obj_name = (event_data.get("ObjectName") or "").lower()
            
            # If watch_paths is configured, only trigger on matching paths
            if self.watch_paths:
                matched = False
                for wpath in self.watch_paths:
                    if wpath in obj_name:
                        matched = True
                        break
                if not matched:
                    continue

            incident = self._build_incident(ev)
            incidents.append(incident)
            
            # Extract action for log message
            message = ev.get("message", "")
            action = "Accessed"
            for candidate in ["Created/Edited", "Appended/Edited", "Deleted", "Modified Attributes"]:
                if candidate in message:
                    action = candidate
                    break
                    
            log.warning(
                "File integrity event detected: user=%s file=%s action=%s",
                ev.get("username", "unknown"),
                event_data.get("ObjectName", "unknown"),
                action
            )

        return incidents

    def _build_incident(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        username = ev.get("username") or "<unknown>"
        ts       = ev.get("timestamp", datetime.utcnow())
        ip       = ev.get("source_ip")
        
        event_data = ev.get("_event_data", {})
        obj_name   = event_data.get("ObjectName") or "<unknown>"
        accesses   = event_data.get("Accesses") or "<unknown>"
        proc_name  = event_data.get("ProcessName") or "<unknown>"
        
        message    = ev.get("message", "")
        # Try to parse the action from our parsed message
        action = "accessed"
        for candidate in ["Created/Edited", "Appended/Edited", "Deleted", "Modified Attributes"]:
            if candidate in message:
                action = candidate.lower()
                break

        description = (
            f"File integrity event: user '{username}' {action} file/folder: '{obj_name}'."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n\n"
            f"Detected File Action:\n"
            f"  Event ID:       4663 (An attempt was made to access an object)\n"
            f"  Actor:          {username}\n"
            f"  File/Folder:    {obj_name}\n"
            f"  Action type:    {action.capitalize()}\n"
            f"  Process name:   {proc_name}\n"
            f"  Access Mask:    {accesses}\n"
            f"  Timestamp:      {format_timestamp(ts) if isinstance(ts, datetime) else ts}\n\n"
            f"Recommended action: Verify if the user is authorized to perform {action} operations on this target."
        )

        return {
            "attack_type":      "FILE_INTEGRITY",
            "severity":         self.severity,
            "status":           "NEW",
            "source_ip":        ip,
            "username":         username,
            "first_seen":       ts,
            "last_seen":        ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "event_count":      1,
            "is_demo":          bool(ev.get("is_demo")),
            "_related_events":  [ev],
        }
