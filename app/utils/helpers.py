"""
app/utils/helpers.py
--------------------
Shared utility functions used across the application.
"""

import re
import ctypes
import sys
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Event ID → Human-readable description + default severity
# ---------------------------------------------------------------------------
EVENT_DESCRIPTIONS = {
    # Security log
    4624: ("Successful Logon", "INFO"),
    4625: ("Failed Logon Attempt", "HIGH"),
    4634: ("Account Logoff", "INFO"),
    4647: ("User Initiated Logoff", "INFO"),
    4672: ("Special Privileges Assigned to New Logon", "MEDIUM"),
    4720: ("New User Account Created", "HIGH"),
    4722: ("User Account Enabled", "HIGH"),
    4724: ("Password Reset Attempt", "MEDIUM"),
    4725: ("User Account Disabled", "HIGH"),
    4726: ("User Account Deleted", "HIGH"),
    4728: ("Member Added to Security-Enabled Global Group", "MEDIUM"),
    4732: ("Member Added to Security-Enabled Local Group", "MEDIUM"),
    4740: ("User Account Locked Out", "HIGH"),
    4756: ("Member Added to Security-Enabled Universal Group", "MEDIUM"),
    4771: ("Kerberos Pre-authentication Failed", "MEDIUM"),
    4776: ("Credential Validation Attempt", "LOW"),
    # File auditing
    4663: ("File System Object Accessed", "LOW"),
    # System log
    6005: ("Event Log Service Started (System Startup)", "INFO"),
    6006: ("Event Log Service Stopped (System Shutdown)", "INFO"),
    6008: ("Unexpected System Shutdown", "MEDIUM"),
    7036: ("Service State Change", "INFO"),
    1074: ("System Shutdown / Restart Initiated", "LOW"),
    1102: ("Audit Log Cleared", "CRITICAL"),
    # Application log
    1000: ("Application Error", "MEDIUM"),
    1001: ("Application Crash", "MEDIUM"),
}

LOGON_TYPES = {
    "2": "Interactive (Local)",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive (RDP)",
    "11": "CachedInteractive",
    "12": "CachedRemoteInteractive",
    "13": "CachedUnlock",
}


def get_event_description(event_id: int) -> tuple[str, str]:
    """Return (description, severity) for a known event ID."""
    return EVENT_DESCRIPTIONS.get(event_id, (f"Event ID {event_id}", "INFO"))


def get_logon_type_name(logon_type: Optional[str]) -> str:
    """Convert a numeric logon type to its human-readable name."""
    if logon_type is None:
        return "Unknown"
    return LOGON_TYPES.get(str(logon_type), f"Type {logon_type}")


def is_running_as_admin() -> bool:
    """Check whether the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def sanitize_string(value: Optional[str]) -> Optional[str]:
    """Strip null bytes and control characters from a string."""
    if value is None:
        return None
    value = value.replace("\x00", "").strip()
    return value if value else None


def format_timestamp(dt: datetime) -> str:
    """Format a datetime object as a readable string."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse a timestamp string into a datetime object.
    Handles ISO 8601 format from Windows Event Logs.
    """
    if not ts_str:
        return None
    # Windows uses format: 2024-01-15T21:14:02.123456789Z
    ts_str = ts_str.rstrip("Z").split(".")[0]  # strip nanoseconds and Z
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        pass
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None


def severity_to_int(severity: str) -> int:
    """Convert severity string to numeric value for sorting."""
    return {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(
        severity.upper(), 0
    )


def is_valid_ip(ip: Optional[str]) -> bool:
    """Return True if the string looks like a valid IPv4 or IPv6 address."""
    if not ip:
        return False
    if ip in ("-", "::1", "127.0.0.1", "LOCAL"):
        return False
    # Basic IPv4 check
    ipv4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    if ipv4.match(ip):
        parts = ip.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 — allow if it has colons
    return ":" in ip


def normalize_ip(ip: Optional[str]) -> Optional[str]:
    """Return a clean IP or None if the value is not a usable IP address."""
    if not ip:
        return None
    ip = ip.strip()
    if ip in ("-", "::1", "127.0.0.1", "LOCAL", "", "0.0.0.0"):
        return None
    if is_valid_ip(ip):
        return ip
    return None
