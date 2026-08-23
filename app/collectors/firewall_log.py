"""
app/collectors/firewall_log.py
-------------------------------
Collects events from the Windows Firewall log file.
Uses firewall_parser.py for actual parsing.

This is an optional collector — if the log file doesn't exist,
the collector reports unavailable=True and all other features continue normally.

To enable Windows Firewall logging:
  Control Panel → Windows Defender Firewall → Advanced Settings
  → Windows Firewall Properties → [Profile] Tab → Logging → Customize
  → Log dropped packets: Yes
  → Log successful connections: Yes
"""

from pathlib import Path
from typing import Optional
from datetime import datetime

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.parsers.firewall_parser import parse_firewall_log, DEFAULT_FIREWALL_LOG
from app.utils.helpers import parse_timestamp
from app.utils.logger import log


class FirewallLogCollector(BaseCollector):
    """
    Reads and parses the Windows Firewall log file.
    
    Returns unavailable=True gracefully if logging is not enabled.
    """

    def __init__(self, log_path: str = DEFAULT_FIREWALL_LOG):
        super().__init__("Firewall")
        self.log_path = log_path

    def _is_logging_enabled(self) -> bool:
        """Run netsh to check if LogDroppedConnections is enabled for the current profile."""
        import subprocess
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "currentprofile", "logging"],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    if "LogDroppedConnections" in line and "Enable" in line:
                        return True
            return False
        except Exception:
            # Fallback to True if netsh fails so we don't break existing setups
            return True

    @property
    def is_available(self) -> bool:
        """True if the firewall log file exists and logging is active on the current profile."""
        if not Path(self.log_path).exists():
            return False
        return self._is_logging_enabled()

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        if not self.is_available:
            msg = (
                "Firewall Log: Unavailable — Windows Firewall logging may be disabled. "
                "Port Scan detection is disabled."
            )
            log.info(msg)
            return self._make_result([], unavailable=True, error_message=msg)

        since_dt: Optional[datetime] = None
        if since_timestamp:
            since_dt = parse_timestamp(since_timestamp)

        try:
            events = parse_firewall_log(self.log_path, since_dt)
            log.info("Firewall log: collected %d events", len(events))
            return self._make_result(events)
        except PermissionError:
            msg = "Firewall Log: Access Denied."
            return self._make_result([], access_denied=True, error_message=msg)
        except Exception as e:
            log.error("FirewallLogCollector: %s", e)
            return self._make_result([], unavailable=True, error_message=str(e))
