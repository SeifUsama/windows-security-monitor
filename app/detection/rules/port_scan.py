"""
app/detection/rules/port_scan.py
----------------------------------
Port Scan Detection Rule (PORTSCAN_001) — OPTIONAL MODULE

Detects a large number of connection attempts from the same source IP
targeting many different destination ports within a short time window.

This rule is automatically DISABLED if firewall logs are unavailable.

Rule criteria:
  - Firewall events from the same source IP
  - >= port_scan_threshold unique destination ports
  - Within port_scan_window_seconds
"""

from typing import List, Dict, Any, Optional
from datetime import datetime
from collections import defaultdict

from app.utils.helpers import format_timestamp
from app.utils.logger import log


class PortScanRule:
    """
    Optional port scan detection.
    
    Automatically disabled if firewall_available=False.
    When disabled, detect() always returns [].
    """

    RULE_ID   = "PORTSCAN_001"
    RULE_NAME = "Port Scan Detection"

    def __init__(
        self,
        threshold: int = 10,
        window_seconds: int = 30,
        firewall_available: bool = True,
    ):
        self.threshold          = threshold
        self.window_seconds     = window_seconds
        self.enabled            = firewall_available

        if not self.enabled:
            log.info("Port Scan rule DISABLED: firewall logs unavailable")

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect port scan patterns from firewall events.
        Returns [] if the rule is disabled.
        """
        if not self.enabled:
            return []

        # Filter to firewall events with a usable source IP and destination port
        fw_events = [
            ev for ev in events
            if ev.get("source_log") == "Firewall"
            and ev.get("source_ip") is not None
            and ev.get("destination_port") is not None
            and ev.get("timestamp") is not None
        ]

        if not fw_events:
            return []

        # Group by source IP
        by_ip: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for ev in fw_events:
            by_ip[ev["source_ip"]].append(ev)

        incidents = []
        for ip, ip_events in by_ip.items():
            ip_events.sort(key=lambda e: e["timestamp"])
            triggered = self._find_window(ip, ip_events)
            if triggered:
                incident = self._build_incident(ip, triggered)
                incidents.append(incident)
                log.warning("Port scan detected from IP: %s", ip)

        return incidents

    def _find_window(
        self, ip: str, events: List[Dict[str, Any]]
    ) -> Optional[List[Dict[str, Any]]]:
        """
        Find the first time window where the source IP hits
        >= threshold unique destination ports.
        """
        n = len(events)
        for i in range(n):
            t_start = events[i]["timestamp"]
            if not isinstance(t_start, datetime):
                continue
            window_events = [events[i]]
            unique_ports  = {events[i]["destination_port"]}
            for j in range(i + 1, n):
                t_j = events[j]["timestamp"]
                if not isinstance(t_j, datetime):
                    continue
                if (t_j - t_start).total_seconds() <= self.window_seconds:
                    window_events.append(events[j])
                    unique_ports.add(events[j]["destination_port"])
                else:
                    break
            if len(unique_ports) >= self.threshold:
                return window_events
        return None

    def _build_incident(
        self, ip: str, events: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        first_ts     = events[0]["timestamp"]
        last_ts      = events[-1]["timestamp"]
        unique_ports = sorted({ev["destination_port"] for ev in events})
        count        = len(unique_ports)
        is_demo      = any(ev.get("is_demo") for ev in events)
        duration     = (last_ts - first_ts).total_seconds() if isinstance(first_ts, datetime) and isinstance(last_ts, datetime) else 0

        ports_str = ", ".join(str(p) for p in unique_ports[:20])
        if count > 20:
            ports_str += f" ... and {count - 20} more"

        description = (
            f"Possible Port Scan from {ip}. "
            f"{count} unique destination ports probed within {duration:.0f} seconds."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n"
            f"Threshold: {self.threshold} unique destination ports within {self.window_seconds} seconds\n\n"
            f"Detected:\n"
            f"  Source IP: {ip}\n"
            f"  Unique Ports Probed: {count}\n"
            f"  Ports: {ports_str}\n"
            f"  First Event: {format_timestamp(first_ts) if isinstance(first_ts, datetime) else first_ts}\n"
            f"  Last Event:  {format_timestamp(last_ts) if isinstance(last_ts, datetime) else last_ts}\n"
            f"  Duration: {duration:.0f} seconds\n\n"
            f"Port scanning is used by attackers to discover open services.\n"
            f"Source: Windows Firewall Log"
        )

        return {
            "attack_type":      "PORT_SCAN",
            "severity":         "HIGH",
            "status":           "NEW",
            "source_ip":        ip,
            "username":         None,
            "first_seen":       first_ts,
            "last_seen":        last_ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "event_count":      len(events),
            "is_demo":          is_demo,
            "_related_events":  events,
        }
