"""
app/collectors/application_log.py
----------------------------------
Collects events from the Windows Application Event Log.
Captures errors and warnings (levels 1-3).
"""

import subprocess
from typing import Optional

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.parsers.event_parser import parse_events_xml_blob
from app.utils.logger import log

_XPATH_WARNINGS = "*[System[(Level=1 or Level=2 or Level=3)]]"
_MAX_EVENTS = 200


class ApplicationLogCollector(BaseCollector):
    def __init__(self):
        super().__init__("Application")

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        try:
            if since_timestamp:
                xpath = (
                    f"*[System[(Level=1 or Level=2 or Level=3) and "
                    f"TimeCreated[@SystemTime>='{since_timestamp}']]]"
                )
                cmd = ["wevtutil", "qe", "Application", f"/q:{xpath}",
                       "/f:XML", "/rd:false", f"/c:{_MAX_EVENTS}"]
            else:
                cmd = ["wevtutil", "qe", "Application", f"/q:{_XPATH_WARNINGS}",
                       "/f:XML", "/rd:true", f"/c:{_MAX_EVENTS}"]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
            stderr = result.stderr.lower()
            if result.returncode != 0:
                if "access is denied" in stderr or result.returncode == 5:
                    return self._make_result([], access_denied=True,
                                             error_message="Application Log: Access Denied.")
                return self._make_result([])

            events = parse_events_xml_blob(result.stdout)
            for ev in events:
                ev["source_log"] = "Application"
                # Ensure at least LOW severity for application errors
                if ev.get("severity") == "INFO" and ev.get("level") in ("Error", "Critical"):
                    ev["severity"] = "MEDIUM"

            log.info("Application log: collected %d events", len(events))
            return self._make_result(events)

        except PermissionError:
            return self._make_result([], access_denied=True,
                                     error_message="Application Log: Access Denied.")
        except Exception as e:
            log.error("ApplicationLogCollector: %s", e)
            return self._make_result([], unavailable=True, error_message=str(e))
