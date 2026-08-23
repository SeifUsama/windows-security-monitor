"""
app/parsers/firewall_parser.py
-------------------------------
Parses the Windows Firewall log file (pfirewall.log).

Log format (space-separated):
  date time action protocol src-ip dst-ip src-port dst-port size ...
  
Example line:
  2024-01-15 21:14:02 DROP TCP 192.168.1.50 10.0.0.5 54321 445 40 ...
  2024-01-15 21:14:03 ALLOW UDP 10.0.0.1 8.8.8.8 12345 53 - - ...

Lines starting with '#' are comments/headers.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from app.utils.helpers import normalize_ip
from app.utils.logger import log


# Default Windows Firewall log path
DEFAULT_FIREWALL_LOG = r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"

# Column indices in the log (0-based after splitting by space)
# date(0) time(1) action(2) protocol(3) src-ip(4) dst-ip(5) src-port(6) dst-port(7) ...
COL_DATE     = 0
COL_TIME     = 1
COL_ACTION   = 2
COL_PROTO    = 3
COL_SRC_IP   = 4
COL_DST_IP   = 5
COL_SRC_PORT = 6
COL_DST_PORT = 7


def parse_firewall_log(
    log_path: str = DEFAULT_FIREWALL_LOG,
    since_timestamp: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """
    Parse the Windows Firewall log file.
    
    Args:
        log_path:        Path to the firewall log file.
        since_timestamp: If provided, only return events after this timestamp.
    
    Returns:
        List of normalized event dicts (source_log="Firewall").
        Returns empty list if the file doesn't exist or can't be read.
    """
    path = Path(log_path)
    if not path.exists():
        log.debug("Firewall log not found at %s", log_path)
        return []

    # Firewall log is local time, while checkpoints are UTC.
    # Convert since_timestamp from UTC to system local time for comparison.
    since_local = None
    if since_timestamp:
        from datetime import timezone
        try:
            since_aware = since_timestamp.replace(tzinfo=timezone.utc)
            since_local = since_aware.astimezone(None).replace(tzinfo=None)
        except Exception:
            since_local = since_timestamp

    events: List[Dict[str, Any]] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                parsed = _parse_line(line)
                if parsed is None:
                    continue

                ts = parsed.get("timestamp")
                if since_local and ts and ts <= since_local:
                    continue

                events.append(parsed)

    except PermissionError:
        log.warning("Access denied reading firewall log: %s", log_path)
    except OSError as e:
        log.warning("Could not read firewall log: %s", e)

    return events


def _parse_line(line: str) -> Optional[Dict[str, Any]]:
    """Parse a single firewall log line into a normalized event dict."""
    parts = line.split()
    if len(parts) < 8:
        return None

    # Parse timestamp
    try:
        ts = datetime.strptime(f"{parts[COL_DATE]} {parts[COL_TIME]}", "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None

    action   = parts[COL_ACTION].upper()    # ALLOW or DROP/BLOCK
    protocol = parts[COL_PROTO].upper()
    src_ip   = normalize_ip(parts[COL_SRC_IP])
    dst_ip   = normalize_ip(parts[COL_DST_IP])

    try:
        src_port = int(parts[COL_SRC_PORT]) if parts[COL_SRC_PORT] != "-" else None
    except ValueError:
        src_port = None

    try:
        dst_port = int(parts[COL_DST_PORT]) if parts[COL_DST_PORT] != "-" else None
    except ValueError:
        dst_port = None

    severity  = "HIGH" if action in ("DROP", "BLOCK") else "INFO"
    direction = "Blocked" if action in ("DROP", "BLOCK") else "Allowed"
    message   = (
        f"Firewall {direction}: {protocol} {src_ip or '-'}:{src_port or '-'} "
        f"→ {dst_ip or '-'}:{dst_port or '-'}"
    )

    return {
        "timestamp":        ts,
        "source_log":       "Firewall",
        "event_id":         None,
        "level":            "Information",
        "username":         None,
        "source_ip":        src_ip,
        "destination_ip":   dst_ip,
        "source_port":      src_port,
        "destination_port": dst_port,
        "protocol":         protocol,
        "message":          message,
        "severity":         severity,
        "description":      f"Firewall {direction}",
        "raw_xml":          line,          # store original log line as "raw"
        "is_demo":          False,
        "computer":         None,
        "logon_type":       None,
        "_action":          action,        # used by port scan detection rule
    }
