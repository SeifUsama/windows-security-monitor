"""
app/detection/engine.py
------------------------
Detection Engine Orchestrator.

Runs all active detection rules against a batch of normalized events.
Returns a list of raw incident dicts for the correlation engine to process.

Architecture:
  normalized events
       |
       v
  [BruteForceRule]       → 0..N incidents
  [AccountLockoutRule]   → 0..N incidents
  [PrivilegeRule]        → 0..N incidents
  [AccountCreatedRule]   → 0..N incidents
  [PortScanRule]         → 0..N incidents (if enabled)
       |
       v
  raw incident list → correlation engine
"""

from configparser import ConfigParser
from typing import List, Dict, Any

from app.detection.rules.brute_force      import BruteForceRule
from app.detection.rules.account_lockout  import AccountLockoutRule
from app.detection.rules.privilege        import PrivilegeAssignmentRule
from app.detection.rules.account_created  import AccountCreatedRule
from app.detection.rules.port_scan        import PortScanRule
from app.detection.rules.file_integrity   import FileIntegrityRule
from app.utils.logger import log


class DetectionEngine:
    """
    Orchestrates all detection rules.
    
    Rules are applied to every batch of new events.
    The engine does NOT maintain state between calls —
    each call analyzes the events passed to it.

    For correlation (e.g. brute force + lockout), the correlation
    engine handles cross-incident linking AFTER detection.
    """

    def __init__(self, config: ConfigParser, firewall_available: bool = False):
        det = config["detection"] if "detection" in config else {}

        bf_threshold = int(det.get("brute_force_threshold", 5))
        bf_window    = int(det.get("brute_force_window_seconds", 60))
        ps_threshold = int(det.get("port_scan_threshold", 10))
        ps_window    = int(det.get("port_scan_window_seconds", 30))

        self.rules = [
            BruteForceRule(threshold=bf_threshold, window_seconds=bf_window),
            AccountLockoutRule(),
            PrivilegeAssignmentRule(),
            AccountCreatedRule(),
            PortScanRule(
                threshold=ps_threshold,
                window_seconds=ps_window,
                firewall_available=firewall_available,
            ),
        ]

        # File Integrity configuration
        fi_enabled = True
        if "file_integrity" in config:
            fi = config["file_integrity"]
            if hasattr(fi, "getboolean"):
                fi_enabled = fi.getboolean("enabled", fallback=True)
            else:
                fi_enabled = str(fi.get("enabled", "true")).lower() in ("true", "1", "yes")
        
        if fi_enabled:
            fi = config["file_integrity"] if "file_integrity" in config else {}
            watch_paths_str = fi.get("watch_paths", "")
            watch_paths = [p.strip() for p in watch_paths_str.split(",") if p.strip()] if watch_paths_str else []
            fi_severity = fi.get("alert_severity", "LOW")
            self.rules.append(FileIntegrityRule(watch_paths=watch_paths, severity=fi_severity))

        log.info(
            "Detection engine initialized: %d rules active (firewall=%s)",
            len(self.rules), firewall_available
        )

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Run all rules against the provided events.
        
        Args:
            events: List of normalized event dicts (any mix of sources).
        
        Returns:
            List of raw incident dicts (not yet saved to DB).
            Each incident dict contains a '_related_events' key with the
            contributing events for use by the correlation engine.
        """
        if not events:
            return []

        all_incidents: List[Dict[str, Any]] = []

        for rule in self.rules:
            try:
                detected = rule.detect(events)
                if detected:
                    log.info(
                        "%s: detected %d incident(s)",
                        rule.__class__.__name__, len(detected)
                    )
                all_incidents.extend(detected)
            except Exception as e:
                log.error("Rule %s failed: %s", rule.__class__.__name__, e)

        return all_incidents

    @property
    def port_scan_enabled(self) -> bool:
        """True if the port scan rule is active."""
        for rule in self.rules:
            if isinstance(rule, PortScanRule):
                return rule.enabled
        return False
