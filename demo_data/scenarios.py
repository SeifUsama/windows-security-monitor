"""
demo_data/scenarios.py
-----------------------
Synthetic demo events for the Demo Mode.

ALL events generated here are clearly marked with:
  source_log = "DEMO"
  is_demo    = True

These events pass through the SAME detection and correlation pipeline
as real Windows events. The detection engine does NOT have special
logic for demo data — it treats demo NormalizedEvent dicts identically
to real events.

Scenarios included:
  1. Normal Activity — Successful logins, logoffs, system events, app events
  2. Brute Force Attack Scenario:
       5× Event 4625 (Failed Logon) from 192.168.1.50
       → 1× Event 4740 (Account Lockout)
       → Triggers BRUTE_FORCE + ACCOUNT_LOCKOUT → CRITICAL incident
  3. Port Scan Scenario (Firewall events):
       15 connections from 10.0.0.99 to different ports
       → Triggers PORT_SCAN incident
  4. Account Creation (persistence attempt):
       Event 4720 — new account "hacker_backdoor" created
  5. Privilege Escalation:
       Event 4672 — special privileges for unknown account

The timestamps are relative to "now" so the demo always looks recent.
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any


def _ts(minutes_ago: float) -> datetime:
    """Return a datetime relative to now."""
    return datetime.utcnow() - timedelta(minutes=minutes_ago)


def _demo_event(
    source_log: str,
    event_id: int,
    level: str,
    username: str,
    source_ip: str,
    message: str,
    severity: str,
    description: str,
    timestamp: datetime,
    logon_type: str = None,
    destination_ip: str = None,
    destination_port: int = None,
    source_port: int = None,
    protocol: str = None,
    raw_xml: str = None,
) -> Dict[str, Any]:
    """Helper to build a demo event dict matching the events table schema."""
    if raw_xml is None:
        raw_xml = _synthetic_xml(source_log, event_id, username, source_ip, timestamp, message)
    return {
        "timestamp":        timestamp,
        "source_log":       "DEMO",   # Always "DEMO" for demo events
        "event_id":         event_id,
        "level":            level,
        "username":         username,
        "source_ip":        source_ip,
        "destination_ip":   destination_ip,
        "source_port":      source_port,
        "destination_port": destination_port,
        "protocol":         protocol,
        "message":          message,
        "severity":         severity,
        "description":      description,
        "raw_xml":          raw_xml,
        "is_demo":          True,
        "computer":         "DEMO-WORKSTATION",
        "logon_type":       logon_type,
        "_event_data": {    # For detection rules that inspect raw fields
            "TargetUserName":    username,
            "IpAddress":         source_ip or "",
            "LogonType":         logon_type or "3",
            "PrivilegeList":     "SeDebugPrivilege\nSeTcbPrivilege" if event_id == 4672 else "",
            "SubjectUserName":   "Administrator" if event_id == 4720 else username,
        },
    }


def _synthetic_xml(
    source: str,
    event_id: int,
    username: str,
    source_ip: str,
    timestamp: datetime,
    message: str,
) -> str:
    """Generate a plausible-looking XML for the Raw Event Viewer."""
    ts_str = timestamp.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>
    <EventID>{event_id}</EventID>
    <Version>0</Version>
    <Level>0</Level>
    <Task>12544</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="{ts_str}"/>
    <EventRecordID>99{event_id}</EventRecordID>
    <Correlation/>
    <Execution ProcessID="668" ThreadID="772"/>
    <Channel>{source}</Channel>
    <Computer>DEMO-WORKSTATION</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-18</Data>
    <Data Name="SubjectUserName">SYSTEM</Data>
    <Data Name="SubjectDomainName">NT AUTHORITY</Data>
    <Data Name="TargetUserName">{username or "-"}</Data>
    <Data Name="TargetDomainName">DEMO-DOMAIN</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="WorkstationName">ATTACKER-PC</Data>
    <Data Name="IpAddress">{source_ip or "-"}</Data>
    <Data Name="IpPort">54321</Data>
    <Data Name="Message">{message}</Data>
  </EventData>
</Event>
<!-- [DEMO DATA — NOT FROM REAL WINDOWS LOGS] -->"""


# ===========================================================================
# SCENARIO 1 — Normal Activity
# ===========================================================================

def _normal_activity() -> List[Dict[str, Any]]:
    events = []

    # Normal successful logins
    for i, user in enumerate(["alice", "bob", "charlie"]):
        events.append(_demo_event(
            source_log="Security", event_id=4624, level="Audit Success",
            username=user, source_ip="10.0.0.10",
            message=f"Successful logon: DEMO-DOMAIN\\{user} | Logon type: Interactive (Local)",
            severity="INFO", description="Successful Logon",
            timestamp=_ts(120 - i * 15), logon_type="2",
        ))

    # Normal logoffs
    for i, user in enumerate(["alice", "bob"]):
        events.append(_demo_event(
            source_log="Security", event_id=4634, level="Audit Success",
            username=user, source_ip=None,
            message=f"Logoff: {user}",
            severity="INFO", description="Account Logoff",
            timestamp=_ts(60 - i * 10),
        ))

    # System startup
    events.append(_demo_event(
        source_log="System", event_id=6005, level="Information",
        username="SYSTEM", source_ip=None,
        message="Event Log service started — system has booted",
        severity="INFO", description="System Startup (Event Log Service Started)",
        timestamp=_ts(180),
    ))

    # Service state change
    events.append(_demo_event(
        source_log="System", event_id=7036, level="Information",
        username="SYSTEM", source_ip=None,
        message="Service state change: Windows Update → Running",
        severity="INFO", description="Service State Change",
        timestamp=_ts(150),
    ))

    # Application event
    events.append(_demo_event(
        source_log="Application", event_id=1000, level="Error",
        username=None, source_ip=None,
        message="Application error: notepad.exe crashed (exception 0xC0000005)",
        severity="MEDIUM", description="Application Error",
        timestamp=_ts(90),
    ))

    return events


# ===========================================================================
# SCENARIO 2 — Brute Force Attack → Account Lockout
# ===========================================================================

def _brute_force_scenario() -> List[Dict[str, Any]]:
    """
    Realistic brute force scenario:
      5× 4625 (Failed Logon) from 192.168.1.50 against 'Administrator'
      within 9 seconds → triggers BRUTE_FORCE_001
      Followed by 4740 (Account Lockout) → triggers LOCKOUT_001
      Correlation → CRITICAL incident BRUTE_FORCE_LOCKOUT
    """
    events = []
    attacker_ip = "192.168.1.50"
    target_user = "Administrator"

    # 5 failed logons, ~2 seconds apart (within 60-second window)
    for i in range(5):
        ts = _ts(30) + timedelta(seconds=i * 2)  # 30 min ago, 2 seconds apart — within 60s window
        events.append(_demo_event(
            source_log="Security", event_id=4625, level="Audit Failure",
            username=target_user, source_ip=attacker_ip,
            message=(
                f"Failed logon: DEMO-DOMAIN\\{target_user} | "
                f"Logon type: Network | From: {attacker_ip} | "
                f"SubStatus: 0xC000006A (wrong password)"
            ),
            severity="HIGH", description="Failed Logon Attempt",
            timestamp=ts, logon_type="3",
        ))

    # Account locked out (triggered by Windows after 5 failures)
    events.append(_demo_event(
        source_log="Security", event_id=4740, level="Audit Success",
        username=target_user, source_ip=attacker_ip,
        message=(
            f"Account locked out: {target_user} | "
            f"Caller: DEMO-WORKSTATION | Machine: DEMO-WORKSTATION"
        ),
        severity="HIGH", description="User Account Locked Out",
        timestamp=_ts(30) + timedelta(seconds=15),  # 15 seconds after brute force started
    ))

    return events


# ===========================================================================
# SCENARIO 3 — Port Scan (Firewall Events)
# ===========================================================================

def _port_scan_scenario() -> List[Dict[str, Any]]:
    """
    Simulated port scan from 10.0.0.99 against 15 different ports within 20 seconds.
    Triggers PORTSCAN_001 if firewall events are enabled.
    """
    events = []
    scanner_ip = "10.0.0.99"
    target_ip  = "192.168.1.100"

    target_ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 3389, 8080, 8443, 1433, 3306]

    for i, port in enumerate(target_ports):
        ts = _ts(60) + timedelta(seconds=i * 1.3)   # scan completes in ~19 seconds
        events.append({
            "timestamp":        ts,
            "source_log":       "DEMO",
            "event_id":         None,
            "level":            "Information",
            "username":         None,
            "source_ip":        scanner_ip,
            "destination_ip":   target_ip,
            "source_port":      45000 + i,
            "destination_port": port,
            "protocol":         "TCP",
            "message":          f"Firewall Blocked: TCP {scanner_ip}:{45000+i} → {target_ip}:{port}",
            "severity":         "HIGH",
            "description":      "Firewall Blocked",
            "raw_xml":          f"2024-01-15 {ts.strftime('%H:%M:%S')} DROP TCP {scanner_ip} {target_ip} {45000+i} {port} 40 - - - - -",
            "is_demo":          True,
            "computer":         "DEMO-FIREWALL",
            "logon_type":       None,
            "_event_data":      {},
            "_action":          "DROP",
        })

    return events


# ===========================================================================
# SCENARIO 4 — Suspicious Account Creation
# ===========================================================================

def _account_creation_scenario() -> List[Dict[str, Any]]:
    events = []
    events.append(_demo_event(
        source_log="Security", event_id=4720, level="Audit Success",
        username="hacker_backdoor", source_ip="192.168.1.50",
        message="New account created: hacker_backdoor | Created by: Administrator",
        severity="HIGH", description="New User Account Created",
        timestamp=_ts(15),
    ))
    return events


# ===========================================================================
# SCENARIO 5 — Privilege Escalation
# ===========================================================================

def _privilege_scenario() -> List[Dict[str, Any]]:
    events = []
    events.append(_demo_event(
        source_log="Security", event_id=4672, level="Audit Success",
        username="service_unknown", source_ip=None,
        message="Special privileges assigned to: service_unknown | Privileges: SeDebugPrivilege, SeTcbPrivilege",
        severity="HIGH", description="Special Privileges Assigned to New Logon",
        timestamp=_ts(45),
    ))
    return events


# ===========================================================================
# SCENARIO 6 — File Integrity Auditing
# ===========================================================================

def _file_integrity_scenario() -> List[Dict[str, Any]]:
    events = []
    
    # 1. File Created (WriteData)
    ev_create = _demo_event(
        source_log="Security", event_id=4663, level="Audit Success",
        username="attacker", source_ip="192.168.1.50",
        message="File System: User DEMO-DOMAIN\\attacker Created/Edited object: C:\\Windows\\System32\\drivers\\etc\\hosts | Process: C:\\Windows\\notepad.exe | Access Mask: %%4416",
        severity="LOW", description="File System Object Accessed",
        timestamp=_ts(10),
    )
    ev_create["_event_data"] = {
        "SubjectUserName": "attacker",
        "SubjectDomainName": "DEMO-DOMAIN",
        "ObjectName": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "Accesses": "%%4416",
        "ProcessName": "C:\\Windows\\notepad.exe",
    }
    events.append(ev_create)
    
    # 2. File Deleted (Delete)
    ev_delete = _demo_event(
        source_log="Security", event_id=4663, level="Audit Success",
        username="attacker", source_ip="192.168.1.50",
        message="File System: User DEMO-DOMAIN\\attacker Deleted object: C:\\Windows\\System32\\drivers\\etc\\hosts | Process: C:\\Windows\\cmd.exe | Access Mask: %%4423",
        severity="LOW", description="File System Object Accessed",
        timestamp=_ts(9),
    )
    ev_delete["_event_data"] = {
        "SubjectUserName": "attacker",
        "SubjectDomainName": "DEMO-DOMAIN",
        "ObjectName": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "Accesses": "%%4423",
        "ProcessName": "C:\\Windows\\cmd.exe",
    }
    events.append(ev_delete)

    return events


# ===========================================================================
# Public API
# ===========================================================================

def get_demo_events() -> List[Dict[str, Any]]:
    """
    Return all demo events from all scenarios.
    Events are ordered chronologically.
    
    All events have is_demo=True and source_log="DEMO".
    They will pass through the same detection and correlation pipeline
    as real Windows events.
    """
    all_events = (
        _normal_activity()
        + _brute_force_scenario()
        + _account_creation_scenario()
        + _privilege_scenario()
        + _port_scan_scenario()  # Firewall demo events
        + _file_integrity_scenario()
    )

    # Sort chronologically
    all_events.sort(key=lambda e: e["timestamp"])
    return all_events
