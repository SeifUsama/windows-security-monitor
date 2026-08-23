"""
app/collectors/security_log.py
-------------------------------
Collects events from the Windows Security Event Log using wevtutil.

Targets these Event IDs:
  4624 — Successful Logon
  4625 — Failed Logon
  4634 — Logoff
  4647 — User Initiated Logoff
  4672 — Special Privileges Assigned
  4720 — User Account Created
  4722 — User Account Enabled
  4725 — User Account Disabled
  4726 — User Account Deleted
  4740 — Account Locked Out
  1102 — Audit Log Cleared (also in Security log)

Implements incremental collection:
  - On first run, fetches the last N events
  - On subsequent runs, only fetches events after the stored checkpoint timestamp
"""

import subprocess
import shlex
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.parsers.event_parser import parse_events_xml_blob
from app.utils.logger import log


# Event IDs we care about (Security log)
TARGET_EVENT_IDS = [4624, 4625, 4634, 4647, 4672, 4720, 4722, 4725, 4726, 4740, 4771, 4776, 4663, 1102]

# XPath filter to only collect our target event IDs
_ID_FILTER = " or ".join(f"EventID={eid}" for eid in TARGET_EVENT_IDS)
_XPATH_ALL = f"*[System[({_ID_FILTER})]]"

# Initial scan: pull last N events (no checkpoint yet)
INITIAL_SCAN_COUNT = 500


def _build_xpath_with_time(since_iso: str) -> str:
    """Build XPath query to get events after a given ISO timestamp."""
    return (
        f"*[System[({_ID_FILTER}) and "
        f"TimeCreated[@SystemTime>='{since_iso}']]]"
    )


class SecurityLogCollector(BaseCollector):
    """
    Reads Windows Security Event Log via wevtutil.

    Gracefully handles:
      - Access Denied (PermissionError / non-zero exit code from wevtutil)
      - Log not found
      - Empty result
    """

    def __init__(self, max_events: int = INITIAL_SCAN_COUNT):
        super().__init__("Security")
        self.max_events = max_events

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        """
        Collect Security log events.
        
        Args:
            since_timestamp: ISO 8601 string from checkpoint. If None, reads
                             the most recent `max_events` events.
        """
        try:
            xml_blob = self._run_wevtutil(since_timestamp)
        except PermissionError as e:
            msg = (
                "Security Log: Access Denied — "
                "Administrator privileges may be required for full visibility."
            )
            log.warning(msg)
            return self._make_result([], access_denied=True, error_message=msg)
        except FileNotFoundError:
            msg = "Security Log: wevtutil not found — is this a Windows system?"
            log.error(msg)
            return self._make_result([], unavailable=True, error_message=msg)
        except Exception as e:
            log.error("SecurityLogCollector error: %s", e)
            return self._make_result([], unavailable=True, error_message=str(e))

        events = parse_events_xml_blob(xml_blob)
        for ev in events:
            ev["source_log"] = "Security"

        log.info("Security log: collected %d new events", len(events))
        return self._make_result(events)

    def _run_wevtutil(self, since_timestamp: Optional[str]) -> str:
        """
        Run wevtutil and return the XML output.
        
        Raises PermissionError if the log is inaccessible.
        Raises FileNotFoundError if wevtutil is not found.
        """
        if since_timestamp:
            # Incremental: use XPath time filter
            xpath = _build_xpath_with_time(since_timestamp)
            cmd = [
                "wevtutil", "qe", "Security",
                f"/q:{xpath}",
                "/f:XML",
                "/rd:false",
                f"/c:{self.max_events}",
            ]
        else:
            # Initial scan: get last N events of our target IDs
            cmd = [
                "wevtutil", "qe", "Security",
                f"/q:{_XPATH_ALL}",
                "/f:XML",
                "/rd:true",          # most recent first
                f"/c:{self.max_events}",
            ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )

        stderr = result.stderr.lower()
        if result.returncode != 0:
            if "access is denied" in stderr or result.returncode == 5:
                raise PermissionError("Access denied to Security log")
            if "not found" in stderr or result.returncode == 15007:
                raise FileNotFoundError("Security log not found")
            # Other wevtutil errors — treat as empty rather than crashing
            log.warning("wevtutil Security exit %d: %s", result.returncode, result.stderr[:200])
            return ""

        return result.stdout
