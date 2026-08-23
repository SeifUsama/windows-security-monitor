"""
app/collectors/system_log.py
-----------------------------
Collects events from the Windows System Event Log.

Target Event IDs:
  6005 — Event Log Service Started (System Startup)
  6006 — Event Log Service Stopped (System Shutdown)
  6008 — Unexpected System Shutdown
  7036 — Service State Change
  1074 — System Shutdown / Restart Initiated
  1102 — Audit Log Cleared (some systems log this here too)
"""

import subprocess
from typing import Optional

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.parsers.event_parser import parse_events_xml_blob
from app.utils.logger import log


TARGET_IDS  = [6005, 6006, 6008, 7036, 1074]
_ID_FILTER  = " or ".join(f"EventID={eid}" for eid in TARGET_IDS)
_XPATH_ALL  = f"*[System[({_ID_FILTER})]]"
_MAX_EVENTS = 300


class SystemLogCollector(BaseCollector):
    def __init__(self):
        super().__init__("System")

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        try:
            if since_timestamp:
                xpath = (
                    f"*[System[({_ID_FILTER}) and "
                    f"TimeCreated[@SystemTime>='{since_timestamp}']]]"
                )
                cmd = ["wevtutil", "qe", "System", f"/q:{xpath}",
                       "/f:XML", "/rd:false", f"/c:{_MAX_EVENTS}"]
            else:
                cmd = ["wevtutil", "qe", "System", f"/q:{_XPATH_ALL}",
                       "/f:XML", "/rd:true", f"/c:{_MAX_EVENTS}"]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
            stderr = result.stderr.lower()
            if result.returncode != 0:
                if "access is denied" in stderr or result.returncode == 5:
                    msg = "System Log: Access Denied."
                    return self._make_result([], access_denied=True, error_message=msg)
                log.warning("wevtutil System exit %d", result.returncode)
                return self._make_result([])

            events = parse_events_xml_blob(result.stdout)
            for ev in events:
                ev["source_log"] = "System"

            log.info("System log: collected %d events", len(events))
            return self._make_result(events)

        except PermissionError:
            return self._make_result([], access_denied=True,
                                     error_message="System Log: Access Denied.")
        except Exception as e:
            log.error("SystemLogCollector: %s", e)
            return self._make_result([], unavailable=True, error_message=str(e))
