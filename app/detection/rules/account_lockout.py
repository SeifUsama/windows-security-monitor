"""
app/detection/rules/account_lockout.py
----------------------------------------
Account Lockout Detection Rule (LOCKOUT_001)

Detects Event ID 4740 — User Account Locked Out.

Each 4740 event generates a HIGH severity incident.
The detection_reason is generated from the actual event data.
"""

from typing import List, Dict, Any
from datetime import datetime

from app.utils.helpers import format_timestamp
from app.utils.logger import log


class AccountLockoutRule:

    RULE_ID   = "LOCKOUT_001"
    RULE_NAME = "Account Lockout Detection"

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect account lockout events (Event ID 4740).
        Each lockout event generates a separate HIGH incident.
        """
        lockouts = [
            ev for ev in events
            if ev.get("event_id") == 4740
        ]

        incidents = []
        for ev in lockouts:
            incident = self._build_incident(ev)
            incidents.append(incident)
            log.warning("Account lockout detected: user=%s", ev.get("username", "unknown"))

        return incidents

    def _build_incident(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        username  = ev.get("username") or "<unknown>"
        ts        = ev.get("timestamp", datetime.utcnow())
        ip        = ev.get("source_ip")
        ip_display = ip if ip else "Not Available"
        is_demo   = bool(ev.get("is_demo"))

        description = (
            f"Account Lockout Detected for account '{username}'. "
            f"The account has been locked due to too many failed authentication attempts."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n\n"
            f"Detected:\n"
            f"  Event ID 4740 (Account Lockout)\n"
            f"  Locked Account: {username}\n"
            f"  Source IP: {ip_display}\n"
            f"  Timestamp: {format_timestamp(ts) if isinstance(ts, datetime) else ts}\n\n"
            f"Windows locked this account because the configured logon attempt limit was exceeded.\n"
            f"This often follows a brute force or password spray attack."
        )

        return {
            "attack_type":      "ACCOUNT_LOCKOUT",
            "severity":         "HIGH",
            "status":           "NEW",
            "source_ip":        ip,
            "username":         username,
            "first_seen":       ts,
            "last_seen":        ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "mitre_tactic":     "Credential Access (TA0006)",
            "mitre_technique":  "Brute Force (T1110)",
            "event_count":      1,
            "is_demo":          is_demo,
            "_related_events":  [ev],
        }
