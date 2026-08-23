"""
app/correlation/correlator.py
------------------------------
Event Correlation Engine.

Takes raw incident dicts from the Detection Engine and:
  1. Checks for correlatable incident pairs (e.g. BRUTE_FORCE + ACCOUNT_LOCKOUT)
  2. Upgrades correlated incidents to CRITICAL severity
  3. Merges related events into a single timeline
  4. Saves incidents and event links to the database
  5. Checks for suspicious post-attack access (4624 after brute force)
     WITHOUT automatically attributing it to the attacker

Correlation logic:
  - Brute Force + Account Lockout (same username, within 5 minutes)
    → Merged into BRUTE_FORCE_LOCKOUT incident, severity=CRITICAL

IMPORTANT: A 4624 (successful logon) from the same IP after a brute force
is noted as "possible post-attack access" in the incident notes,
but is NOT automatically merged into the incident as a confirmed compromise.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional, Tuple

from app.database.db_manager import DatabaseManager
from app.utils.helpers import format_timestamp
from app.utils.logger import log


# Time window within which a lockout is considered related to a brute force
CORRELATION_WINDOW_MINUTES = 5

# Time window to check for suspicious 4624 after brute force
POST_ATTACK_WINDOW_MINUTES = 10


class CorrelationEngine:
    """
    Correlates detected incidents into higher-fidelity composite incidents.
    Also persists all incidents and event links to the database.
    """

    def __init__(self, db: DatabaseManager):
        self.db = db

    def process(
        self,
        raw_incidents: List[Dict[str, Any]],
        all_events: List[Dict[str, Any]],
    ) -> List[int]:
        """
        Process raw incidents from the detection engine.

        Args:
            raw_incidents: Output from DetectionEngine.analyze()
            all_events:    All events from the current collection cycle
                           (used to check for post-attack access)

        Returns:
            List of DB incident IDs that were created or updated.
        """
        if not raw_incidents:
            return []

        # Separate by type for correlation
        brute_force_incidents  = [i for i in raw_incidents if i["attack_type"] == "BRUTE_FORCE"]
        lockout_incidents      = [i for i in raw_incidents if i["attack_type"] == "ACCOUNT_LOCKOUT"]
        other_incidents        = [
            i for i in raw_incidents
            if i["attack_type"] not in ("BRUTE_FORCE", "ACCOUNT_LOCKOUT")
        ]

        saved_ids: List[int] = []

        # --- Correlate: Brute Force + Account Lockout ---
        correlated_bf_ids  = set()
        correlated_lo_ids  = set()

        for bf in brute_force_incidents:
            for lo in lockout_incidents:
                if self._can_correlate(bf, lo):
                    incident_id = self._save_correlated_bf_lockout(bf, lo, all_events)
                    if incident_id > 0:
                        saved_ids.append(incident_id)
                    correlated_bf_ids.add(id(bf))
                    correlated_lo_ids.add(id(lo))
                    break  # One lockout per brute force is enough

        # Save uncorrelated brute force incidents individually
        for bf in brute_force_incidents:
            if id(bf) not in correlated_bf_ids:
                inc_id = self._save_incident(bf)
                if inc_id > 0:
                    saved_ids.append(inc_id)
                    self._check_post_attack_access(bf, inc_id, all_events)

        # Save uncorrelated lockout incidents
        for lo in lockout_incidents:
            if id(lo) not in correlated_lo_ids:
                inc_id = self._save_incident(lo)
                if inc_id > 0:
                    saved_ids.append(inc_id)

        # Save all other incidents
        for other in other_incidents:
            inc_id = self._save_incident(other)
            if inc_id > 0:
                saved_ids.append(inc_id)

        log.info("Correlation complete: %d incidents saved", len(saved_ids))
        return saved_ids

    # ------------------------------------------------------------------
    # Correlation logic
    # ------------------------------------------------------------------

    def _can_correlate(
        self, bf: Dict[str, Any], lo: Dict[str, Any]
    ) -> bool:
        """
        Return True if a brute force and lockout incident are related.
        
        Criteria:
          - Same username (case-insensitive)
          - Lockout occurred after the brute force started
          - Within CORRELATION_WINDOW_MINUTES
        """
        bf_user = (bf.get("username") or "").lower().strip()
        lo_user = (lo.get("username") or "").lower().strip()
        if not bf_user or not lo_user or bf_user != lo_user:
            return False

        bf_last = bf.get("last_seen")
        lo_time = lo.get("first_seen")
        if not isinstance(bf_last, datetime) or not isinstance(lo_time, datetime):
            return False

        # Lockout must occur after the brute force started
        if lo_time < bf.get("first_seen", lo_time):
            return False

        # Within correlation window
        return (lo_time - bf_last) <= timedelta(minutes=CORRELATION_WINDOW_MINUTES)

    def _save_correlated_bf_lockout(
        self,
        bf: Dict[str, Any],
        lo: Dict[str, Any],
        all_events: List[Dict[str, Any]],
    ) -> int:
        """Save a correlated Brute Force + Account Lockout incident (CRITICAL)."""
        username   = bf.get("username") or lo.get("username") or "<unknown>"
        ip         = bf.get("source_ip") or "Not Available"
        first_seen = bf.get("first_seen")
        last_seen  = lo.get("last_seen") or bf.get("last_seen")
        bf_count   = bf.get("event_count", 0)
        is_demo    = bf.get("is_demo") or lo.get("is_demo")

        ts_first = format_timestamp(first_seen) if isinstance(first_seen, datetime) else str(first_seen)
        ts_last  = format_timestamp(last_seen)  if isinstance(last_seen, datetime)  else str(last_seen)

        description = (
            f"Brute Force Attack + Account Lockout: '{username}' was subjected to "
            f"{bf_count} failed login attempts from {ip}, followed by account lockout. "
            f"This is a high-confidence attack pattern."
        )

        detection_reason = (
            f"Rule: CORRELATION_001 — Brute Force + Account Lockout Correlation\n\n"
            f"Correlated Incidents:\n"
            f"  • {bf.get('detection_rule')} (Brute Force)\n"
            f"  • {lo.get('detection_rule')} (Account Lockout)\n\n"
            f"Correlation Evidence:\n"
            f"  Target Account:   {username}\n"
            f"  Source IP:        {ip}\n"
            f"  Failed Attempts:  {bf_count}\n"
            f"  Account Locked:   Yes\n"
            f"  Attack Start:     {ts_first}\n"
            f"  Lockout Time:     {ts_last}\n\n"
            f"Individual Rule Details:\n"
            f"--- Brute Force ---\n{bf.get('detection_reason', '')}\n\n"
            f"--- Account Lockout ---\n{lo.get('detection_reason', '')}\n\n"
            f"NOTE: A subsequent successful logon (Event 4624) from the same IP "
            f"would require separate manual investigation to determine if it represents "
            f"a successful compromise."
        )

        incident = {
            "attack_type":      "BRUTE_FORCE_LOCKOUT",
            "severity":         "CRITICAL",
            "status":           "NEW",
            "source_ip":        bf.get("source_ip"),
            "username":         username,
            "first_seen":       first_seen,
            "last_seen":        last_seen,
            "description":      description,
            "detection_rule":   "CORRELATION_001",
            "detection_reason": detection_reason,
            "event_count":      bf_count + 1,
            "is_demo":          is_demo,
        }

        inc_id = self.db.insert_incident(incident)
        if inc_id > 0:
            # Link all brute force events + the lockout event
            for ev in bf.get("_related_events", []):
                if ev.get("id"):
                    self.db.link_event_to_incident(inc_id, ev["id"])
            for ev in lo.get("_related_events", []):
                if ev.get("id"):
                    self.db.link_event_to_incident(inc_id, ev["id"])

            log.warning(
                "CRITICAL incident #%d created: BRUTE_FORCE_LOCKOUT user=%s ip=%s",
                inc_id, username, ip
            )
            self._check_post_attack_access(bf, inc_id, all_events, is_correlated=True)

        return inc_id

    def _save_incident(self, incident: Dict[str, Any]) -> int:
        """Save a standalone incident to the database."""
        inc_id = self.db.insert_incident(incident)
        if inc_id > 0:
            for ev in incident.get("_related_events", []):
                if ev.get("id"):
                    self.db.link_event_to_incident(inc_id, ev["id"])
        return inc_id

    def _check_post_attack_access(
        self,
        bf_incident: Dict[str, Any],
        inc_id: int,
        all_events: List[Dict[str, Any]],
        is_correlated: bool = False,
    ) -> None:
        """
        Check for a 4624 (successful logon) from the same source IP
        within POST_ATTACK_WINDOW_MINUTES after the brute force.

        If found, adds an advisory note to the incident's detection_reason.
        Does NOT automatically mark the incident as a confirmed compromise.
        """
        bf_ip      = bf_incident.get("source_ip")
        bf_last    = bf_incident.get("last_seen")
        username   = bf_incident.get("username", "")

        if not bf_ip or not isinstance(bf_last, datetime):
            return

        window_end = bf_last + timedelta(minutes=POST_ATTACK_WINDOW_MINUTES)

        suspicious_logins = [
            ev for ev in all_events
            if ev.get("event_id") == 4624
            and ev.get("source_ip") == bf_ip
            and isinstance(ev.get("timestamp"), datetime)
            and bf_last <= ev["timestamp"] <= window_end
        ]

        if not suspicious_logins:
            return

        first_login = suspicious_logins[0]
        ts_login    = format_timestamp(first_login["timestamp"])

        log.warning(
            "⚠️ Possible post-attack access: 4624 from %s at %s after brute force",
            bf_ip, ts_login
        )

        # Fetch current incident and append advisory note
        existing = self.db.get_incident_by_id(inc_id)
        if existing:
            note = (
                f"\n\n⚠️  POST-ATTACK ACCESS ADVISORY:\n"
                f"A successful logon (Event ID 4624) was detected from the same source IP ({bf_ip})\n"
                f"at {ts_login} — {POST_ATTACK_WINDOW_MINUTES} minutes after the brute force attack.\n"
                f"Username logged in: {first_login.get('username', 'unknown')}\n\n"
                f"This MAY indicate the attacker gained access, but could also be a coincidence.\n"
                f"MANUAL INVESTIGATION REQUIRED — Do not assume compromise without further evidence."
            )
            try:
                conn = self.db.get_connection()
                conn.execute(
                    "UPDATE incidents SET detection_reason = detection_reason || ? WHERE id = ?",
                    (note, inc_id),
                )
                conn.commit()
            except Exception as e:
                log.error("Failed to append post-attack note: %s", e)
