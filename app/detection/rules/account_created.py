"""
app/detection/rules/account_created.py
-----------------------------------------
New Account Creation Detection Rule (NEWACCOUNT_001)

Detects Event ID 4720 — A new user account was created.

Every new account creation is suspicious in a security context
and is reported as a HIGH severity incident requiring investigation.
"""

from typing import List, Dict, Any
from datetime import datetime

from app.utils.helpers import format_timestamp
from app.utils.logger import log


class AccountCreatedRule:

    RULE_ID   = "NEWACCOUNT_001"
    RULE_NAME = "New User Account Creation Detection"

    def detect(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Detect new account creation events (Event ID 4720)."""
        new_accounts = [
            ev for ev in events
            if ev.get("event_id") == 4720
        ]

        incidents = []
        for ev in new_accounts:
            incident = self._build_incident(ev)
            incidents.append(incident)
            log.warning("New account created: %s", ev.get("username", "unknown"))

        return incidents

    def _build_incident(self, ev: Dict[str, Any]) -> Dict[str, Any]:
        new_user  = ev.get("username") or "<unknown>"
        ts        = ev.get("timestamp", datetime.utcnow())
        is_demo   = bool(ev.get("is_demo"))
        raw_data  = ev.get("_event_data", {})
        creator   = raw_data.get("SubjectUserName", "<unknown>")

        description = (
            f"New Windows Account Created: '{new_user}'. "
            f"Account was created by '{creator}'. "
            f"Unauthorized account creation may indicate a backdoor or persistence mechanism."
        )

        detection_reason = (
            f"Rule: {self.RULE_ID} — {self.RULE_NAME}\n\n"
            f"Detected:\n"
            f"  Event ID 4720 (A user account was created)\n"
            f"  New Account Name: {new_user}\n"
            f"  Created By: {creator}\n"
            f"  Timestamp: {format_timestamp(ts) if isinstance(ts, datetime) else ts}\n\n"
            f"Account creation is a high-priority security event.\n"
            f"Attackers often create new accounts to maintain persistence after initial compromise.\n\n"
            f"Recommended action: Verify that this account was created by an authorized administrator."
        )

        return {
            "attack_type":      "UNAUTHORIZED_ACCOUNT",
            "severity":         "HIGH",
            "status":           "NEW",
            "source_ip":        ev.get("source_ip"),
            "username":         new_user,
            "first_seen":       ts,
            "last_seen":        ts,
            "description":      description,
            "detection_rule":   self.RULE_ID,
            "detection_reason": detection_reason,
            "event_count":      1,
            "is_demo":          is_demo,
            "_related_events":  [ev],
        }
