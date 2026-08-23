"""
app/parsers/event_parser.py
---------------------------
Parses raw XML output from `wevtutil qe ... /f:XML` into NormalizedEvent dicts.

Windows Event XML structure:
  <Event>
    <System>
      <Provider Name="..." Guid="..."/>
      <EventID>4625</EventID>
      <Level>0</Level>
      <TimeCreated SystemTime="2024-01-15T21:14:02.000Z"/>
      <Computer>MYPC</Computer>
      <Security UserID="..."/>
    </System>
    <EventData>
      <Data Name="SubjectUserName">...</Data>
      <Data Name="IpAddress">...</Data>
      ...
    </EventData>
  </Event>

The parser:
  1. Extracts all System fields
  2. Extracts all EventData Name/Value pairs into a flat dict
  3. Maps known EventData field names to normalized event fields
  4. Assigns severity and description from the event ID
  5. Stores the full raw XML in raw_xml
"""

import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Optional, Dict, Any, List

from app.utils.helpers import (
    get_event_description,
    normalize_ip,
    sanitize_string,
    parse_timestamp,
    get_logon_type_name,
)
from app.utils.logger import log

# Windows Event Log XML namespace
NS = "http://schemas.microsoft.com/win/2004/08/events/event"

# Level codes → human-readable
LEVEL_MAP = {
    "0": "Information",
    "1": "Critical",
    "2": "Error",
    "3": "Warning",
    "4": "Information",
    "5": "Verbose",
}

# Audit log keyword bits
AUDIT_SUCCESS = 0x8020000000000000
AUDIT_FAILURE = 0x8010000000000000


def _tag(name: str) -> str:
    return f"{{{NS}}}{name}"


def parse_event_xml(raw_xml: str) -> Optional[Dict[str, Any]]:
    """
    Parse a single Windows Event XML string into a normalized event dict.
    
    Returns None if parsing fails or the XML is invalid.
    The raw_xml is stored in the returned dict for the Raw Event Viewer.
    """
    try:
        root = ET.fromstring(raw_xml.strip())
    except ET.ParseError as e:
        log.debug("XML parse error: %s", e)
        return None

    system = root.find(_tag("System"))
    if system is None:
        return None

    # --- Extract System fields ---
    provider_el = system.find(_tag("Provider"))
    provider    = provider_el.get("Name", "") if provider_el is not None else ""

    event_id_el = system.find(_tag("EventID"))
    try:
        event_id = int(event_id_el.text) if event_id_el is not None else None
    except (ValueError, TypeError):
        event_id = None

    level_el  = system.find(_tag("Level"))
    level_str = level_el.text if level_el is not None else "0"
    level     = LEVEL_MAP.get(str(level_str), "Information")

    time_el   = system.find(_tag("TimeCreated"))
    ts_str    = time_el.get("SystemTime", "") if time_el is not None else ""
    timestamp = parse_timestamp(ts_str) or datetime.utcnow()

    computer_el = system.find(_tag("Computer"))
    computer    = sanitize_string(computer_el.text) if computer_el is not None else None

    # Check audit success/failure from Keywords
    keywords_el = system.find(_tag("Keywords"))
    audit_level = None
    if keywords_el is not None and keywords_el.text:
        try:
            kw_int = int(keywords_el.text, 16)
            if kw_int & AUDIT_FAILURE:
                audit_level = "Audit Failure"
            elif kw_int & AUDIT_SUCCESS:
                audit_level = "Audit Success"
        except ValueError:
            pass

    if audit_level:
        level = audit_level

    # --- Extract EventData ---
    event_data: Dict[str, str] = {}
    for container_tag in (_tag("EventData"), _tag("UserData")):
        container = root.find(container_tag)
        if container is not None:
            for data_el in container:
                name  = data_el.get("Name", f"Field_{len(event_data)}")
                value = sanitize_string(data_el.text) or ""
                event_data[name] = value

    # --- Map EventData to normalized fields ---
    username   = _extract_username(event_data, event_id)
    source_ip  = normalize_ip(_extract_ip(event_data))
    logon_type = sanitize_string(event_data.get("LogonType") or event_data.get("LogonType2"))

    # --- Build message ---
    message = _build_message(event_id, event_data, provider)

    # --- Assign severity and description ---
    description, severity = get_event_description(event_id) if event_id else ("Unknown Event", "INFO")

    return {
        "timestamp":       timestamp,
        "source_log":      None,           # filled in by collector
        "event_id":        event_id,
        "level":           level,
        "username":        username,
        "source_ip":       source_ip,
        "destination_ip":  None,
        "source_port":     None,
        "destination_port":None,
        "protocol":        None,
        "message":         message,
        "severity":        severity,
        "description":     description,
        "raw_xml":         raw_xml,
        "is_demo":         False,
        "computer":        computer,
        "logon_type":      logon_type,
        # Keep raw event_data for correlation engine
        "_event_data":     event_data,
    }


def parse_events_xml_blob(xml_blob: str) -> List[Dict[str, Any]]:
    """
    Parse a multi-event XML blob (wevtutil output wraps events in <Events>).
    
    Wraps the blob in a root element if needed, then parses each <Event>.
    Returns a list of normalized event dicts.
    """
    if not xml_blob or not xml_blob.strip():
        return []

    # wevtutil outputs bare <Event> elements separated by newlines
    # Wrap them in a root element so ET can parse the whole blob
    wrapped = f"<Events>{xml_blob}</Events>"
    try:
        root = ET.fromstring(wrapped)
    except ET.ParseError:
        # Try parsing events individually
        events = []
        for chunk in _split_xml_events(xml_blob):
            parsed = parse_event_xml(chunk)
            if parsed:
                events.append(parsed)
        return events

    events = []
    for event_el in root:
        raw = ET.tostring(event_el, encoding="unicode")
        parsed = parse_event_xml(raw)
        if parsed:
            events.append(parsed)
    return events


def _split_xml_events(xml_blob: str) -> List[str]:
    """Split a blob of concatenated <Event>...</Event> strings."""
    chunks = []
    start = 0
    while True:
        s = xml_blob.find("<Event ", start)
        if s == -1:
            s = xml_blob.find("<Event>", start)
        if s == -1:
            break
        e = xml_blob.find("</Event>", s)
        if e == -1:
            break
        chunks.append(xml_blob[s:e + 8])
        start = e + 8
    return chunks


# ---------------------------------------------------------------------------
# Field extraction helpers
# ---------------------------------------------------------------------------

def _extract_username(data: Dict[str, str], event_id: Optional[int]) -> Optional[str]:
    """
    Extract the most relevant username from EventData.
    For logon events (4624/4625), TargetUserName is the account being logged into.
    For account management events, SubjectUserName is the actor.
    """
    # Prefer TargetUserName for logon events
    if event_id in (4624, 4625, 4634, 4647, 4740):
        for key in ("TargetUserName", "TargetUser"):
            val = sanitize_string(data.get(key))
            if val and val not in ("-", "ANONYMOUS LOGON", ""):
                return val

    # For account management
    if event_id in (4720, 4722, 4725, 4726, 4728, 4732, 4756):
        for key in ("TargetUserName", "SubjectUserName"):
            val = sanitize_string(data.get(key))
            if val and val not in ("-", ""):
                return val

    # For file auditing
    if event_id == 4663:
        val = sanitize_string(data.get("SubjectUserName"))
        if val and val not in ("-", ""):
            return val

    # Fallback
    for key in ("SubjectUserName", "TargetUserName", "UserName", "AccountName"):
        val = sanitize_string(data.get(key))
        if val and val not in ("-", ""):
            return val

    return None


def _extract_ip(data: Dict[str, str]) -> Optional[str]:
    """Extract the source IP from EventData."""
    for key in ("IpAddress", "SourceAddress", "ClientAddress", "WorkstationName"):
        val = sanitize_string(data.get(key))
        if val:
            return val
    return None


def _build_message(event_id: Optional[int], data: Dict[str, str], provider: str) -> str:
    """Build a human-readable message string from EventData fields."""
    if event_id == 4624:
        user      = data.get("TargetUserName", "-")
        domain    = data.get("TargetDomainName", "-")
        lt        = data.get("LogonType", "-")
        lt_name   = get_logon_type_name(lt)
        ip        = data.get("IpAddress", "-")
        return f"Successful logon: {domain}\\{user} | Logon type: {lt_name} | From: {ip}"

    elif event_id == 4625:
        user   = data.get("TargetUserName", "-")
        domain = data.get("TargetDomainName", "-")
        lt     = data.get("LogonType", "-")
        lt_name= get_logon_type_name(lt)
        ip     = data.get("IpAddress", "-")
        reason = data.get("SubStatus") or data.get("Status", "-")
        return f"Failed logon: {domain}\\{user} | Logon type: {lt_name} | From: {ip} | SubStatus: {reason}"

    elif event_id == 4740:
        locked  = data.get("TargetUserName", "-")
        caller  = data.get("SubjectUserName", "-")
        machine = data.get("TargetDomainName") or data.get("SubjectMachineName", "-")
        return f"Account locked out: {locked} | Caller: {caller} | Machine: {machine}"

    elif event_id == 4720:
        new_user = data.get("TargetUserName", "-")
        creator  = data.get("SubjectUserName", "-")
        return f"New account created: {new_user} | Created by: {creator}"

    elif event_id == 4672:
        user  = data.get("SubjectUserName", "-")
        privs = data.get("PrivilegeList", "-")
        return f"Special privileges assigned to: {user} | Privileges: {privs[:100]}"

    elif event_id in (4634, 4647):
        user = data.get("TargetUserName", "-")
        return f"Logoff: {user}"

    elif event_id == 6005:
        return "Event Log service started — system has booted"

    elif event_id == 6006:
        return "Event Log service stopped — system is shutting down"

    elif event_id == 7036:
        svc   = data.get("param1") or data.get("ServiceName", "-")
        state = data.get("param2") or data.get("ServiceState", "-")
        return f"Service state change: {svc} → {state}"

    elif event_id == 1102:
        user = data.get("SubjectUserName", "-")
        return f"⚠️ Security audit log was CLEARED by: {user}"

    elif event_id == 4663:
        user    = data.get("SubjectUserName", "-")
        domain  = data.get("SubjectDomainName", "-")
        obj     = data.get("ObjectName", "-")
        access  = data.get("Accesses", "-").strip()
        proc    = data.get("ProcessName", "-")
        
        # Translate access string to standard action
        action = "Accessed"
        access_lower = access.lower()
        if "4416" in access_lower or "writedata" in access_lower:
            action = "Created/Edited"
        elif "4417" in access_lower or "appenddata" in access_lower:
            action = "Appended/Edited"
        elif "4423" in access_lower or "delete" in access_lower:
            action = "Deleted"
        elif "4426" in access_lower or "writeattributes" in access_lower:
            action = "Modified Attributes"
            
        return f"File System: User {domain}\\{user} {action} object: {obj} | Process: {proc} | Access Mask: {access}"

    # Generic fallback
    if data:
        parts = [f"{k}={v}" for k, v in list(data.items())[:5]]
        return " | ".join(parts)

    return f"Event from {provider}"
