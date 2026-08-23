"""
app/collectors/powershell_log.py
---------------------------------
Collects events from the PowerShell Operational log.
Log name: Microsoft-Windows-PowerShell/Operational

Key Event IDs:
  4103 — Pipeline execution details (module logging)
  4104 — Script block logging (script content)
  4105 — ScriptBlock started
  4106 — ScriptBlock completed

PowerShell logging must be enabled in Group Policy or the registry.
This collector silently returns unavailable=True if the log doesn't exist.
"""

import subprocess
from typing import Optional

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.parsers.event_parser import parse_events_xml_blob
from app.utils.logger import log

LOG_NAME    = "Microsoft-Windows-PowerShell/Operational"
_ID_FILTER  = "EventID=4103 or EventID=4104 or EventID=4105 or EventID=4106"
_XPATH_ALL  = f"*[System[({_ID_FILTER})]]"
_MAX_EVENTS = 200


class PowerShellLogCollector(BaseCollector):
    def __init__(self):
        super().__init__("PowerShell")

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        try:
            if since_timestamp:
                xpath = (
                    f"*[System[({_ID_FILTER}) and "
                    f"TimeCreated[@SystemTime>='{since_timestamp}']]]"
                )
                cmd = ["wevtutil", "qe", LOG_NAME, f"/q:{xpath}",
                       "/f:XML", "/rd:false", f"/c:{_MAX_EVENTS}"]
            else:
                cmd = ["wevtutil", "qe", LOG_NAME, f"/q:{_XPATH_ALL}",
                       "/f:XML", "/rd:true", f"/c:{_MAX_EVENTS}"]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
            stderr_lower = result.stderr.lower()

            if result.returncode != 0:
                if "not found" in stderr_lower or "does not exist" in stderr_lower or result.returncode == 15007:
                    msg = "PowerShell Log: Unavailable (PowerShell logging may not be enabled)."
                    log.info(msg)
                    return self._make_result([], unavailable=True, error_message=msg)
                if "access is denied" in stderr_lower or result.returncode == 5:
                    return self._make_result([], access_denied=True,
                                             error_message="PowerShell Log: Access Denied.")
                return self._make_result([])

            events = parse_events_xml_blob(result.stdout)
            for ev in events:
                ev["source_log"] = "PowerShell"
                ev["severity"]   = "MEDIUM"  # PowerShell execution is always worth noting

            log.info("PowerShell log: collected %d events", len(events))
            return self._make_result(events)

        except PermissionError:
            return self._make_result([], access_denied=True,
                                     error_message="PowerShell Log: Access Denied.")
        except Exception as e:
            log.error("PowerShellLogCollector: %s", e)
            return self._make_result([], unavailable=True, error_message=str(e))
