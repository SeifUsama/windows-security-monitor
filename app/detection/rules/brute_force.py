"""
app/detection/rules/brute_force.py
------------------------------------
Brute Force Detection Rule (BRUTE_FORCE_001)

Detects multiple failed authentication attempts from the same
source IP against the same username within a configurable time window.

Rule criteria:
  - Event ID 4625 (Failed Logon)
  - Same username (case-insensitive)
  - Same source IP (or grouped separately if IP unavailable)
  - Count >= threshold within window_seconds

Generated detection_reason includes:
  - Rule name and thresholds
  - Actual username, IP, count, timestamps
  - Related event IDs
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict

from app.utils.helpers import format_timestamp
from app.utils.logger import log


class BruteForceRule:
    """
    Sliding-window brute force detection.
    
    Groups 4625 events by (username_lower, source_ip) and checks
    whether any group exceeds the configured threshold within the window.
    
    If source_ip is None/unavailable, groups by username only and
    clearly labels it as "Source IP: Not Available".
    """

    RULE_ID   = "BRUTE_FORCE_001"
    RULE_NAME = "Brute Force Attack Detection"

    def __init__(self, threshold: int = 5, window_seconds: int = 60):
        self.threshold      = threshold
        self.window_seconds = window_seconds

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze events for brute force patterns.

        Args:
            events: List of normalized event dicts (may include all sources).

        Returns:
            List of incident dicts ready for DB insertion.
        """
        # Filter: only failed logon events
        failed = [
            ev for ev in events
            if ev.get("event_id") == 4625
            and ev.get("timestamp") is not None
        ]

        if not failed:
            return []

        # Group by (username_lower, source_ip)
        # source_ip=None is kept as-is and handled separately
        groups: Dict[Tuple, List[Dict[str, Any]]] = defaultdict(list)
        for ev in failed:
            username = (ev.get("username") or "").lower().strip() or "<unknown>"
            ip       = ev.get("source_ip")  # None if not present
            groups[(username, ip)].append(ev)

        incidents = []
        for (username, ip), group_events in groups.items():
            # Sort by timestamp
            group_events.sort(key=lambda e: e["timestamp"])

            # Sliding window: find any window of `window_seconds` with >= threshold events
            triggered = self._find_window(group_events)
            if triggered:
                window_events = triggered
                incident = self._build_incident(username, ip, window_events)
                incidents.append(incident)
                log.warning(
                    "Brute force detected: user=%s ip=%s attempts=%d",
                    username, ip or "N/A", len(window_events)
                )

        return incidents

    def _find_window(self, events: List[Dict[str, Any]]) -> Optional[List[Dict[str, Any]]]:
        """
        Return the events in the first qualifying sliding window,
        or None if no window meets the threshold.
        """
        n = len(events)
        for i in range(n):
            t_start = events[i]["timestamp"]
            if not isinstance(t_start, datetime):
                continue
            window = [events[i]]
            for j in range(i + 1, n):
                t_j = events[j]["timestamp"]
                if not isinstance(t_j, datetime):
                    continue
                if (t_j - t_start).total_seconds() <= self.window_seconds:
                    window.append(events[j])
                else:
                    break
            if len(window) >= self.threshold:
                return window
        return None

    def _build_incident(
        self,
        username: str,
        ip: Optional[str],
        events: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Build an incident dict from detected brute-force events."""
        first_ts  = events[0]["timestamp"]
        last_ts   = events[-1]["timestamp"]
        count     = len(events)
        ip_display = ip if ip else "Not Available"
        is_demo   = any(ev.get("is_demo") for ev in events)

        # Collect DB IDs of related events (if already stored)
        related_ids = [ev["id"] for ev in events if ev.get("id")]

        duration_secs = (last_ts - first_ts).total_seconds() if isinstance(first_ts, datetime) and isinstance(last_ts, datetime) else 0

        description = (
            f"Possible Brute Force Attack detected against account '{username}' "
            f"from source IP {ip_display}. "
            f"{count} failed login attempts within {duration_secs:.0f} seconds."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n"
            f"Threshold: {self.threshold} failed attempts within {self.window_seconds} seconds\n\n"
            f"Detected:\n"
            f"  {count} failed authentication attempts (Event ID 4625)\n"
            f"  Target Username: {username}\n"
            f"  Source IP: {ip_display}\n"
            f"  First Attempt: {format_timestamp(first_ts) if isinstance(first_ts, datetime) else first_ts}\n"
            f"  Last Attempt:  {format_timestamp(last_ts) if isinstance(last_ts, datetime) else last_ts}\n"
            f"  Duration: {duration_secs:.0f} seconds\n\n"
            f"Related Events: {count}× Event ID 4625"
            + (f"\nEvent DB IDs: {related_ids}" if related_ids else "")
        )

        return {
            "attack_type":      "BRUTE_FORCE",
            "severity":         "HIGH",
            "status":           "NEW",
            "source_ip":        ip,
            "username":         username,
            "first_seen":       first_ts,
            "last_seen":        last_ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "event_count":      count,
            "is_demo":          is_demo,
            "_related_events":  events,  # for correlation engine
        }
