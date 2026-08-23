"""
app/detection/rules/privilege.py
----------------------------------
Suspicious Privilege Assignment Detection Rule (PRIVILEGE_001)

Detects Event ID 4672 — Special Privileges Assigned to New Logon.

Severity:
  - CRITICAL if the account is a well-known admin account (Administrator, SYSTEM)
  - HIGH for other accounts

The detection_reason is generated from actual event data.
"""

from typing import List, Dict, Any
from datetime import datetime

from app.utils.helpers import format_timestamp
from app.utils.logger import log

# Accounts that are expected to have high privileges
# (not suspicious by themselves but worth noting)
EXPECTED_ADMIN_ACCOUNTS = {"system", "administrator", "local service", "network service"}


class PrivilegeAssignmentRule:

    RULE_ID   = "PRIVILEGE_001"
    RULE_NAME = "Special Privilege Assignment Detection"

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect privilege assignment events (Event ID 4672).
        """
        privilege_events = [
            ev for ev in events
            if ev.get("event_id") == 4672
        ]

        incidents = []
        for ev in privilege_events:
            incident = self._build_incident(ev)
            incidents.append(incident)
            log.info("Privilege assignment: user=%s", ev.get("username", "unknown"))

        return incidents

    def _build_incident(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        username   = ev.get("username") or "<unknown>"
        ts         = ev.get("timestamp", datetime.utcnow())
        is_demo    = bool(ev.get("is_demo"))
        raw_data   = ev.get("_event_data", {})
        privs      = raw_data.get("PrivilegeList", "Unknown privileges")[:200]

        is_system  = username.lower() in EXPECTED_ADMIN_ACCOUNTS
        severity   = "MEDIUM" if is_system else "HIGH"

        description = (
            f"Special Privileges Assigned to '{username}' during logon. "
            f"This may indicate privilege escalation if the account is not expected to hold elevated rights."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n\n"
            f"Detected:\n"
            f"  Event ID 4672 (Special Privileges Assigned to New Logon)\n"
            f"  Account: {username}\n"
            f"  Assigned Privileges: {privs}\n"
            f"  Timestamp: {format_timestamp(ts) if isinstance(ts, datetime) else ts}\n\n"
            f"{'This account is a known system account — consider reviewing if unexpected.' if is_system else 'This account is NOT a standard system account — potential privilege escalation.'}\n\n"
            f"Recommended action: Verify that this privilege assignment is expected for this account."
        )

        return {
            "attack_type":      "PRIVILEGE_ESCALATION",
            "severity":         severity,
            "status":           "NEW",
            "source_ip":        ev.get("source_ip"),
            "username":         username,
            "first_seen":       ts,
            "last_seen":        ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "event_count":      1,
            "is_demo":          is_demo,
            "_related_events":  [ev],
        }
