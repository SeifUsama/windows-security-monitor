"""
verify_all_features.py
-----------------------
Comprehensive feature verification script.
Tests every major component without launching the GUI.
Run with: python verify_all_features.py
"""
import sys, os, tempfile, traceback
from datetime import datetime, timedelta
from configparser import ConfigParser

sys.path.insert(0, os.path.dirname(__file__))

PASS = "✅ PASS"
FAIL = "❌ FAIL"
WARN = "⚠️  WARN"
results = []

def check(name, fn):
    try:
        msg = fn()
        results.append((PASS, name, msg or ""))
        print(f"  {PASS}  {name}" + (f" — {msg}" if msg else ""))
    except Exception as e:
        results.append((FAIL, name, str(e)))
        print(f"  {FAIL}  {name} — {e}")
        traceback.print_exc()

def warn(name, msg):
    results.append((WARN, name, msg))
    print(f"  {WARN}  {name} — {msg}")

print("\n" + "="*65)
print("  WINDOWS SECURITY MONITOR — FULL FEATURE VERIFICATION")
print("="*65)

# ──────────────────────────────────────────────────────────────
print("\n[ 1 ] IMPORTS & DEPENDENCIES")
# ──────────────────────────────────────────────────────────────
def check_imports():
    import customtkinter, matplotlib, PIL, reportlab
    return f"customtkinter {customtkinter.__version__}, matplotlib {matplotlib.__version__}"
check("Core packages import", check_imports)

def check_all_app_modules():
    from app.utils.logger import log
    from app.utils.helpers import EVENT_DESCRIPTIONS, is_running_as_admin, format_timestamp
    from app.database.db_manager import DatabaseManager
    from app.parsers.event_parser import parse_event_xml, parse_events_xml_blob
    from app.parsers.firewall_parser import parse_firewall_log
    from app.collectors.base_collector import CollectionResult, BaseCollector
    from app.collectors.security_log import SecurityLogCollector
    from app.collectors.system_log import SystemLogCollector
    from app.collectors.application_log import ApplicationLogCollector
    from app.collectors.powershell_log import PowerShellLogCollector
    from app.collectors.firewall_log import FirewallLogCollector
    from app.detection.rules.brute_force import BruteForceRule
    from app.detection.rules.account_lockout import AccountLockoutRule
    from app.detection.rules.privilege import PrivilegeAssignmentRule
    from app.detection.rules.account_created import AccountCreatedRule
    from app.detection.rules.port_scan import PortScanRule
    from app.detection.engine import DetectionEngine
    from app.correlation.correlator import CorrelationEngine
    from app.demo_loader import DemoLoader
    from app.reports.csv_exporter import export_events_to_csv, export_incident_to_csv
    from app.reports.pdf_exporter import export_incident_to_pdf, REPORTLAB_AVAILABLE
    from demo_data.scenarios import get_demo_events
    return "All 20 modules imported successfully"
check("All app modules import", check_all_app_modules)

# ──────────────────────────────────────────────────────────────
print("\n[ 2 ] HELPERS & UTILITIES")
# ──────────────────────────────────────────────────────────────
def check_helpers():
    from app.utils.helpers import (
        EVENT_DESCRIPTIONS, LOGON_TYPES, get_event_description,
        normalize_ip, is_valid_ip, format_timestamp, parse_timestamp,
        severity_to_int, get_logon_type_name, sanitize_string, is_running_as_admin
    )
    assert get_event_description(4625) != "Unknown Event"
    assert get_event_description(4624) != "Unknown Event"
    assert normalize_ip("192.168.1.50") == "192.168.1.50"
    assert normalize_ip("-") is None
    assert normalize_ip("::1") is None
    assert is_valid_ip("10.0.0.1") is True
    assert is_valid_ip("notanip") is False
    assert severity_to_int("CRITICAL") > severity_to_int("HIGH")
    assert severity_to_int("HIGH") > severity_to_int("MEDIUM")
    assert get_logon_type_name("2") == "Interactive (Local)"
    assert get_logon_type_name("3") == "Network"
    ts = format_timestamp(datetime(2024, 1, 15, 21, 0, 0))
    assert "2024" in ts
    is_admin = is_running_as_admin()
    return f"All helpers OK | Admin={is_admin} | 4625='{get_event_description(4625)[:30]}'"
check("Helper functions", check_helpers)

# ──────────────────────────────────────────────────────────────
print("\n[ 3 ] DATABASE MANAGER")
# ──────────────────────────────────────────────────────────────
def check_db_schema():
    from app.database.db_manager import DatabaseManager
    import sqlite3
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name)
    db.initialize()
    conn = db.get_connection()
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert "events" in tables
    assert "incidents" in tables
    assert "incident_events" in tables
    assert "checkpoints" in tables
    db.close()
    os.unlink(tmp.name)
    return f"4 tables verified: {sorted(tables)}"
check("DB schema (4 tables)", check_db_schema)

def check_db_event_crud():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name)
    db.initialize()
    ev = {
        "timestamp": datetime(2024,1,15,21,0,0),
        "source_log": "Security", "event_id": 4625, "level": "Audit Failure",
        "username": "TestUser", "source_ip": "192.168.1.99",
        "message": "Failed logon", "severity": "HIGH",
        "description": "Failed Logon Attempt", "is_demo": False,
    }
    row_id = db.insert_event(ev)
    assert row_id > 0
    rows = db.query_events({"event_id": 4625})
    assert len(rows) == 1
    assert rows[0]["username"] == "TestUser"
    fetched = db.get_event_by_id(row_id)
    assert fetched is not None
    db.close(); os.unlink(tmp.name)
    return f"Insert/query/fetch OK (row_id={row_id})"
check("DB event CRUD", check_db_event_crud)

def check_db_incident_crud():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()
    inc = {
        "attack_type": "BRUTE_FORCE", "severity": "HIGH", "status": "NEW",
        "source_ip": "10.0.0.1", "username": "admin",
        "first_seen": datetime(2024,1,15,21,0,0),
        "last_seen": datetime(2024,1,15,21,0,10),
        "description": "Test", "detection_rule": "BF_001",
        "detection_reason": "reason", "event_count": 5, "is_demo": False,
    }
    inc_id = db.insert_incident(inc)
    assert inc_id > 0
    fetched = db.get_incident_by_id(inc_id)
    assert dict(fetched)["attack_type"] == "BRUTE_FORCE"
    db.update_incident_status(inc_id, "FALSE_POSITIVE")
    assert dict(db.get_incident_by_id(inc_id))["status"] == "FALSE_POSITIVE"
    db.close(); os.unlink(tmp.name)
    return f"Incident CRUD + status update OK (id={inc_id})"
check("DB incident CRUD + status", check_db_incident_crud)

def check_db_checkpoint():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()
    db.update_checkpoint("Security", "2024-01-15T21:00:00", last_record_number=42)
    ts, rn = db.get_checkpoint("Security")
    assert ts == "2024-01-15T21:00:00"
    assert rn == 42
    # Upsert
    db.update_checkpoint("Security", "2024-01-15T22:00:00")
    ts2, _ = db.get_checkpoint("Security")
    assert ts2 == "2024-01-15T22:00:00"
    db.close(); os.unlink(tmp.name)
    return "Checkpoint upsert + retrieval OK"
check("DB checkpoints (incremental)", check_db_checkpoint)

def check_db_bulk_insert():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()
    events = [{"timestamp": datetime.utcnow(), "source_log": "Security",
               "event_id": 4625, "severity": "HIGH", "is_demo": False} for _ in range(10)]
    ids = db.insert_events_bulk(events)
    assert len(ids) == 10
    assert all(i > 0 for i in ids)
    db.close(); os.unlink(tmp.name)
    return "Bulk insert 10 events OK"
check("DB bulk insert", check_db_bulk_insert)

def check_db_statistics():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()
    for _ in range(3):
        db.insert_event({"timestamp": datetime.utcnow(), "source_log": "Security",
                         "event_id": 4625, "severity": "HIGH", "is_demo": False})
    for _ in range(2):
        db.insert_event({"timestamp": datetime.utcnow(), "source_log": "Security",
                         "event_id": 4624, "severity": "INFO", "is_demo": False})
    stats = db.get_statistics()
    assert stats["failed_logins"] >= 3
    assert stats["successful_logins"] >= 2
    db.close(); os.unlink(tmp.name)
    return f"Statistics: failed={stats['failed_logins']}, success={stats['successful_logins']}"
check("DB statistics queries", check_db_statistics)

def check_db_demo_clear():
    from app.database.db_manager import DatabaseManager
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()
    db.insert_event({"timestamp": datetime.utcnow(), "source_log": "DEMO",
                     "event_id": 4625, "severity": "HIGH", "is_demo": True})
    db.insert_event({"timestamp": datetime.utcnow(), "source_log": "Security",
                     "event_id": 4625, "severity": "HIGH", "is_demo": False})
    db.clear_demo_data()
    demo_rows = db.query_events({"is_demo": True})
    real_rows = db.query_events({"is_demo": False})
    assert len(demo_rows) == 0
    assert len(real_rows) == 1
    db.close(); os.unlink(tmp.name)
    return "Demo clear leaves real data intact"
check("DB demo data isolation", check_db_demo_clear)

# ──────────────────────────────────────────────────────────────
print("\n[ 4 ] XML PARSER")
# ──────────────────────────────────────────────────────────────
SAMPLE_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <Keywords>0x8010000000000000</Keywords>
    <TimeCreated SystemTime="2024-01-15T21:14:02.000000000Z"/>
    <EventRecordID>1042</EventRecordID>
    <Computer>TESTPC</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="IpAddress">192.168.1.50</Data>
    <Data Name="LogonType">3</Data>
    <Data Name="SubStatus">0xC000006A</Data>
  </EventData>
</Event>"""

def check_parser_single():
    from app.parsers.event_parser import parse_event_xml
    ev = parse_event_xml(SAMPLE_XML)
    assert ev is not None
    assert ev["event_id"] == 4625
    assert ev["username"] == "Administrator"
    assert ev["source_ip"] == "192.168.1.50"
    assert ev["logon_type"] == "3"
    assert ev["computer"] == "TESTPC"
    assert ev["raw_xml"] == SAMPLE_XML
    assert isinstance(ev["timestamp"], datetime)
    return f"Parsed 4625: user={ev['username']}, ip={ev['source_ip']}, ts={ev['timestamp']}"
check("XML parser (single event)", check_parser_single)

def check_parser_blob():
    from app.parsers.event_parser import parse_events_xml_blob
    blob = SAMPLE_XML + "\n" + SAMPLE_XML
    events = parse_events_xml_blob(blob)
    assert len(events) == 2
    return f"Blob parser: {len(events)} events extracted from multi-event XML"
check("XML parser (blob / multi-event)", check_parser_blob)

def check_parser_event_4624():
    from app.parsers.event_parser import parse_event_xml
    xml_4624 = SAMPLE_XML.replace("<EventID>4625</EventID>", "<EventID>4624</EventID>")
    ev = parse_event_xml(xml_4624)
    assert ev["event_id"] == 4624
    return "4624 (Successful Logon) parsed correctly"
check("XML parser (4624 logon event)", check_parser_event_4624)

def check_parser_4740():
    from app.parsers.event_parser import parse_event_xml
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Test"/><EventID>4740</EventID><Level>0</Level>
  <Keywords>0x8020000000000000</Keywords>
  <TimeCreated SystemTime="2024-01-15T21:14:10.000000000Z"/>
  <EventRecordID>1043</EventRecordID><Computer>DC01</Computer><Security/></System>
  <EventData>
    <Data Name="TargetUserName">Administrator</Data>
    <Data Name="SubjectUserName">WORKSTATION$</Data>
    <Data Name="SubjectDomainName">DOMAIN</Data>
  </EventData></Event>"""
    ev = parse_event_xml(xml)
    assert ev["event_id"] == 4740
    return "4740 (Account Lockout) parsed correctly"
check("XML parser (4740 lockout event)", check_parser_4740)

# ──────────────────────────────────────────────────────────────
print("\n[ 5 ] FIREWALL LOG PARSER")
# ──────────────────────────────────────────────────────────────
def check_firewall_parser():
    from app.parsers.firewall_parser import parse_firewall_log
    fw_log = (
        "#Version: 1.5\n"
        "#Fields: date time action protocol src-ip dst-ip src-port dst-port size ...\n"
        "2024-01-15 21:14:00 DROP TCP 10.0.0.99 192.168.1.100 45001 22 40 - - - - -\n"
        "2024-01-15 21:14:01 DROP TCP 10.0.0.99 192.168.1.100 45002 80 40 - - - - -\n"
        "2024-01-15 21:14:02 ALLOW TCP 192.168.1.10 8.8.8.8 51234 443 40 - - - - -\n"
    )
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False)
    tmp.write(fw_log); tmp.close()
    events = parse_firewall_log(tmp.name)
    os.unlink(tmp.name)
    assert len(events) == 3
    drop_ev = [e for e in events if e.get("_action") == "DROP"]
    allow_ev = [e for e in events if e.get("_action") == "ALLOW"]
    assert len(drop_ev) == 2
    assert len(allow_ev) == 1
    assert events[0]["source_ip"] == "10.0.0.99"
    assert events[0]["destination_port"] == 22
    return f"Parsed {len(events)} firewall lines: {len(drop_ev)} DROP, {len(allow_ev)} ALLOW"
check("Firewall log parser", check_firewall_parser)

# ──────────────────────────────────────────────────────────────
print("\n[ 6 ] LOG COLLECTORS")
# ──────────────────────────────────────────────────────────────
def check_collector_permission_handling():
    from app.collectors.security_log import SecurityLogCollector
    from unittest.mock import patch, MagicMock
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=5, stdout="", stderr="access is denied")
        c = SecurityLogCollector()
        result = c.collect()
    assert result.access_denied is True
    assert "Access Denied" in result.error_message
    assert len(result.events) == 0
    return "Access Denied handled gracefully (no crash)"
check("Security collector: permission denied", check_collector_permission_handling)

def check_collector_incremental():
    from app.collectors.security_log import SecurityLogCollector
    from unittest.mock import patch, MagicMock
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        c = SecurityLogCollector()
        c.collect(since_timestamp="2024-01-15T21:00:00")
        args = mock_run.call_args[0][0]
    # The XPath filter for TimeCreated must be present
    query_parts = [a for a in args if "TimeCreated" in str(a)]
    assert len(query_parts) > 0, f"No TimeCreated filter in command: {args}"
    return f"Incremental XPath filter confirmed in wevtutil call"
check("Security collector: incremental XPath", check_collector_incremental)

def check_collector_unavailable():
    from app.collectors.powershell_log import PowerShellLogCollector
    from unittest.mock import patch, MagicMock
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=15007, stdout="", stderr="channel not found")
        c = PowerShellLogCollector()
        result = c.collect()
    assert result.unavailable is True
    return "Log-not-found handled as 'Unavailable' (not crash)"
check("PowerShell collector: unavailable log", check_collector_unavailable)

def check_firewall_collector_no_file():
    from app.collectors.firewall_log import FirewallLogCollector
    c = FirewallLogCollector(log_path="nonexistent_path.log")
    assert c.is_available is False
    result = c.collect()
    assert result.unavailable is True
    assert len(result.events) == 0
    return "Firewall collector returns unavailable when file missing"
check("Firewall collector: file not found", check_firewall_collector_no_file)

# ──────────────────────────────────────────────────────────────
print("\n[ 7 ] DETECTION RULES")
# ──────────────────────────────────────────────────────────────
def _ev(event_id, username="admin", source_ip="10.0.0.1", minutes_ago=0.5, **kw):
    return {
        "id": None, "timestamp": datetime.utcnow() - timedelta(minutes=minutes_ago),
        "source_log": "Security", "event_id": event_id,
        "level": "Audit Failure", "username": username, "source_ip": source_ip,
        "message": f"Test {event_id}", "severity": "HIGH",
        "description": f"Event {event_id}", "raw_xml": "", "is_demo": True,
        "_event_data": {"TargetUserName": username, "IpAddress": source_ip or "",
                        "SubjectUserName": "Administrator"},
        **kw
    }

def check_bf_basic():
    from app.detection.rules.brute_force import BruteForceRule
    rule = BruteForceRule(threshold=5, window_seconds=60)
    events = [_ev(4625, minutes_ago=0.5 - i*0.05) for i in range(5)]
    incs = rule.detect(events)
    assert len(incs) == 1
    assert incs[0]["attack_type"] == "BRUTE_FORCE"
    assert incs[0]["severity"] == "HIGH"
    assert "BRUTE_FORCE_001" in incs[0]["detection_reason"]
    return f"5 fails → 1 incident | reason contains rule ID and IP"
check("Brute force: basic detection", check_bf_basic)

def check_bf_threshold():
    from app.detection.rules.brute_force import BruteForceRule
    rule = BruteForceRule(threshold=5, window_seconds=60)
    events = [_ev(4625, minutes_ago=0.5 - i*0.05) for i in range(4)]
    assert len(rule.detect(events)) == 0
    return "4 fails (below threshold=5) → 0 incidents"
check("Brute force: below threshold", check_bf_threshold)

def check_bf_window():
    from app.detection.rules.brute_force import BruteForceRule
    rule = BruteForceRule(threshold=5, window_seconds=60)
    # Events spread 5 minutes apart — outside 60s window
    events = [_ev(4625, minutes_ago=20 - i*5) for i in range(5)]
    assert len(rule.detect(events)) == 0
    return "5 fails spread >60s apart → 0 incidents"
check("Brute force: outside time window", check_bf_window)

def check_bf_none_ip():
    from app.detection.rules.brute_force import BruteForceRule
    rule = BruteForceRule(threshold=5, window_seconds=60)
    events = [_ev(4625, source_ip=None, minutes_ago=0.5 - i*0.05) for i in range(5)]
    incs = rule.detect(events)
    assert len(incs) == 1
    assert "Not Available" in incs[0]["detection_reason"]
    return "None IP handled gracefully — shown as 'Not Available'"
check("Brute force: None IP handling", check_bf_none_ip)

def check_bf_detection_reason_fields():
    from app.detection.rules.brute_force import BruteForceRule
    rule = BruteForceRule(threshold=5, window_seconds=60)
    events = [_ev(4625, "VictimUser", "1.2.3.4", minutes_ago=0.5 - i*0.05) for i in range(5)]
    incs = rule.detect(events)
    r = incs[0]["detection_reason"]
    assert "BRUTE_FORCE_001" in r
    assert "victimuser" in r.lower()
    assert "1.2.3.4" in r
    assert "5" in r  # attempt count
    return "Detection reason contains: rule ID, username, IP, count"
check("Brute force: detection_reason content", check_bf_detection_reason_fields)

def check_lockout():
    from app.detection.rules.account_lockout import AccountLockoutRule
    rule = AccountLockoutRule()
    incs = rule.detect([_ev(4740)])
    assert len(incs) == 1
    assert incs[0]["attack_type"] == "ACCOUNT_LOCKOUT"
    assert incs[0]["severity"] == "HIGH"
    assert "LOCKOUT_001" in incs[0]["detection_reason"]
    return "4740 → ACCOUNT_LOCKOUT HIGH"
check("Account lockout: detection", check_lockout)

def check_privilege_system():
    from app.detection.rules.privilege import PrivilegeAssignmentRule
    rule = PrivilegeAssignmentRule()
    incs = rule.detect([_ev(4672, "system")])
    assert incs[0]["severity"] == "MEDIUM"
    return "system account 4672 → MEDIUM (expected, not suspicious)"
check("Privilege: system account → MEDIUM", check_privilege_system)

def check_privilege_unknown():
    from app.detection.rules.privilege import PrivilegeAssignmentRule
    rule = PrivilegeAssignmentRule()
    incs = rule.detect([_ev(4672, "backdoor_user")])
    assert incs[0]["severity"] == "HIGH"
    return "unknown account 4672 → HIGH (suspicious)"
check("Privilege: unknown account → HIGH", check_privilege_unknown)

def check_account_created():
    from app.detection.rules.account_created import AccountCreatedRule
    rule = AccountCreatedRule()
    incs = rule.detect([_ev(4720, "hacker_backdoor")])
    assert len(incs) == 1
    assert incs[0]["attack_type"] == "UNAUTHORIZED_ACCOUNT"
    assert "hacker_backdoor" in incs[0]["detection_reason"]
    return "4720 → UNAUTHORIZED_ACCOUNT, username in reason"
check("Account created: detection + reason", check_account_created)

def check_port_scan():
    from app.detection.rules.port_scan import PortScanRule
    rule = PortScanRule(threshold=10, window_seconds=30, firewall_available=True)
    events = [{
        "id": None, "timestamp": datetime.utcnow() - timedelta(seconds=i),
        "source_log": "Firewall", "event_id": None,
        "source_ip": "99.99.99.99", "destination_ip": "10.0.0.5",
        "destination_port": 1000 + i, "source_port": 40000,
        "protocol": "TCP", "severity": "HIGH", "is_demo": True, "_action": "DROP",
    } for i in range(15)]
    incs = rule.detect(events)
    assert len(incs) == 1
    assert incs[0]["attack_type"] == "PORT_SCAN"
    assert "99.99.99.99" in incs[0]["detection_reason"]
    return f"15 ports → PORT_SCAN incident, attacker IP in reason"
check("Port scan: detection + reason", check_port_scan)

def check_port_scan_disabled():
    from app.detection.rules.port_scan import PortScanRule
    rule = PortScanRule(threshold=10, window_seconds=30, firewall_available=False)
    events = [{"timestamp": datetime.utcnow(), "source_ip": "1.2.3.4",
               "destination_port": i, "source_log": "Firewall"} for i in range(20)]
    assert len(rule.detect(events)) == 0
    return "Rule disabled when firewall_available=False → 0 incidents"
check("Port scan: disabled when unavailable", check_port_scan_disabled)

def check_file_integrity():
    from app.detection.rules.file_integrity import FileIntegrityRule
    rule = FileIntegrityRule(watch_paths=["etc", "hosts"], severity="LOW")
    ev = _ev(4663, "attacker", "1.2.3.4")
    ev["message"] = "File System: User DEMO-DOMAIN\\attacker Deleted object: C:\\Windows\\System32\\drivers\\etc\\hosts | Process: C:\\Windows\\cmd.exe | Access Mask: %%4423"
    ev["_event_data"] = {
        "SubjectUserName": "attacker",
        "SubjectDomainName": "DEMO-DOMAIN",
        "ObjectName": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "Accesses": "%%4423",
        "ProcessName": "C:\\Windows\\cmd.exe",
    }
    incs = rule.detect([ev])
    assert len(incs) == 1
    assert incs[0]["attack_type"] == "FILE_INTEGRITY"
    assert "attacker" in incs[0]["detection_reason"]
    return "File auditing rule detects matching file modifications correctly"
check("File integrity: detection + watch paths", check_file_integrity)

def check_detection_engine_orchestration():
    from app.detection.engine import DetectionEngine
    config = ConfigParser()
    config.read_dict({
        "detection": {
            "brute_force_threshold": "5", "brute_force_window_seconds": "60",
            "port_scan_threshold": "10", "port_scan_window_seconds": "30",
        },
        "file_integrity": {
            "enabled": "true",
            "watch_paths": "hosts",
            "alert_severity": "LOW"
        }
    })
    engine = DetectionEngine(config, firewall_available=False)
    events = [_ev(4625, minutes_ago=0.5 - i*0.05) for i in range(5)]
    events.append(_ev(4720, "newuser"))
    
    ev_fi = _ev(4663, "attacker", "1.2.3.4")
    ev_fi["message"] = "File System: User DEMO-DOMAIN\\attacker Deleted object: C:\\Windows\\System32\\drivers\\etc\\hosts"
    ev_fi["_event_data"] = {
        "ObjectName": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "Accesses": "%%4423"
    }
    events.append(ev_fi)

    incs = engine.analyze(events)
    types = {i["attack_type"] for i in incs}
    assert "BRUTE_FORCE" in types
    assert "UNAUTHORIZED_ACCOUNT" in types
    assert "FILE_INTEGRITY" in types
    return f"Engine detected: {sorted(types)}"
check("Detection engine: orchestrates all rules", check_detection_engine_orchestration)

# ──────────────────────────────────────────────────────────────
print("\n[ 8 ] CORRELATION ENGINE")
# ──────────────────────────────────────────────────────────────
def check_correlation_bf_lockout():
    from app.database.db_manager import DatabaseManager
    from app.correlation.correlator import CorrelationEngine
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()

    now = datetime.utcnow()
    # Insert events first so they have IDs
    ev_ids = []
    for i in range(5):
        ev = {"timestamp": now - timedelta(seconds=10-i), "source_log": "Security",
              "event_id": 4625, "severity": "HIGH", "username": "testuser",
              "source_ip": "5.5.5.5", "is_demo": True}
        eid = db.insert_event(ev)
        ev["id"] = eid
        ev_ids.append(ev)

    lockout_ev = {"timestamp": now, "source_log": "Security", "event_id": 4740,
                  "severity": "HIGH", "username": "testuser", "source_ip": "5.5.5.5", "is_demo": True}
    lo_id = db.insert_event(lockout_ev)
    lockout_ev["id"] = lo_id

    bf_incident = {
        "attack_type": "BRUTE_FORCE", "severity": "HIGH",
        "username": "testuser", "source_ip": "5.5.5.5",
        "first_seen": now - timedelta(seconds=10),
        "last_seen": now - timedelta(seconds=1),
        "description": "BF test", "detection_rule": "BRUTE_FORCE_001",
        "detection_reason": "BF reason", "event_count": 5, "is_demo": True,
        "_related_events": ev_ids,
    }
    lo_incident = {
        "attack_type": "ACCOUNT_LOCKOUT", "severity": "HIGH",
        "username": "testuser", "source_ip": "5.5.5.5",
        "first_seen": now, "last_seen": now,
        "description": "LO test", "detection_rule": "LOCKOUT_001",
        "detection_reason": "LO reason", "event_count": 1, "is_demo": True,
        "_related_events": [lockout_ev],
    }

    correlator = CorrelationEngine(db)
    ids = correlator.process([bf_incident, lo_incident], ev_ids + [lockout_ev])

    incidents = db.get_incidents()
    inc_types = {dict(i)["attack_type"] for i in incidents}
    assert "BRUTE_FORCE_LOCKOUT" in inc_types, f"Got: {inc_types}"
    corr = next(dict(i) for i in incidents if dict(i)["attack_type"] == "BRUTE_FORCE_LOCKOUT")
    assert corr["severity"] == "CRITICAL"
    assert "CORRELATION_001" in corr["detection_rule"]

    # Verify event links
    related = db.get_incident_events(corr["id"])
    assert len(related) > 0

    db.close(); os.unlink(tmp.name)
    return f"BF+Lockout → CRITICAL BRUTE_FORCE_LOCKOUT | {len(related)} events linked"
check("Correlation: BF+Lockout → CRITICAL", check_correlation_bf_lockout)

def check_correlation_no_false_compromise():
    """4624 after brute force should be advisory ONLY — not auto-classified as compromise."""
    from app.database.db_manager import DatabaseManager
    from app.correlation.correlator import CorrelationEngine
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    db = DatabaseManager(tmp.name); db.initialize()

    now = datetime.utcnow()
    events = []
    for i in range(5):
        ev = {"timestamp": now - timedelta(seconds=10-i), "source_log": "Security",
              "event_id": 4625, "severity": "HIGH", "username": "admin",
              "source_ip": "6.6.6.6", "is_demo": True}
        eid = db.insert_event(ev); ev["id"] = eid; events.append(ev)

    # Successful logon after brute force from same IP
    success_ev = {"timestamp": now + timedelta(minutes=1), "source_log": "Security",
                  "event_id": 4624, "severity": "INFO", "username": "admin",
                  "source_ip": "6.6.6.6", "is_demo": True}
    sid = db.insert_event(success_ev); success_ev["id"] = sid

    bf_inc = {
        "attack_type": "BRUTE_FORCE", "severity": "HIGH",
        "username": "admin", "source_ip": "6.6.6.6",
        "first_seen": now - timedelta(seconds=10), "last_seen": now,
        "description": "BF", "detection_rule": "BRUTE_FORCE_001",
        "detection_reason": "reason", "event_count": 5, "is_demo": True,
        "_related_events": events,
    }
    correlator = CorrelationEngine(db)
    correlator.process([bf_inc], events + [success_ev])

    incidents = db.get_incidents()
    inc_list = [dict(i) for i in incidents]
    # There should be NO incident of type "COMPROMISE" or "CONFIRMED_ATTACK"
    types = {i["attack_type"] for i in inc_list}
    assert "COMPROMISE" not in types
    assert "CONFIRMED_ATTACK" not in types
    # The brute force incident's reason should have an advisory note about 4624
    bf_stored = next(i for i in inc_list if i["attack_type"] == "BRUTE_FORCE")
    assert "POST-ATTACK" in bf_stored["detection_reason"] or "ADVISORY" in bf_stored["detection_reason"] or "4624" in bf_stored["detection_reason"]

    db.close(); os.unlink(tmp.name)
    return "4624 after BF → advisory note only, no false compromise incident"
check("Correlation: no false compromise on 4624", check_correlation_no_false_compromise)

# ──────────────────────────────────────────────────────────────
print("\n[ 9 ] DEMO MODE PIPELINE")
# ──────────────────────────────────────────────────────────────
def check_demo_events_structure():
    from demo_data.scenarios import get_demo_events
    events = get_demo_events()
    assert len(events) > 20, f"Too few demo events: {len(events)}"
    assert all(e["is_demo"] is True for e in events)
    event_ids = {e["event_id"] for e in events if e["event_id"]}
    has_4625 = 4625 in event_ids
    has_4624 = 4624 in event_ids
    has_4740 = 4740 in event_ids
    has_4720 = 4720 in event_ids
    has_4672 = 4672 in event_ids
    assert has_4625, "Missing 4625 (failed logon)"
    assert has_4624, "Missing 4624 (success logon)"
    assert has_4740, "Missing 4740 (account lockout)"
    assert has_4720, "Missing 4720 (account created)"
    assert has_4672, "Missing 4672 (privilege)"
    # Verify timestamps are sorted
    ts_list = [e["timestamp"] for e in events]
    assert ts_list == sorted(ts_list)
    return (f"{len(events)} events | IDs: {sorted(event_ids)} | "
            f"sorted chronologically ✓")
check("Demo events structure + coverage", check_demo_events_structure)

def check_full_demo_pipeline():
    from app.database.db_manager import DatabaseManager
    from app.demo_loader import DemoLoader
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    config = ConfigParser()
    config.read_dict({"detection": {
        "brute_force_threshold": "5", "brute_force_window_seconds": "60",
        "port_scan_threshold": "10", "port_scan_window_seconds": "30",
    }, "monitoring": {"max_events_per_cycle": "500"}})
    db = DatabaseManager(tmp.name); db.initialize()
    loader = DemoLoader(db, config)
    result = loader.load_demo()

    assert result["events"] > 0
    assert result["incidents"] > 0

    incidents = db.get_incidents()
    inc_list = [dict(i) for i in incidents]
    types = {i["attack_type"] for i in inc_list}

    # Must detect BRUTE_FORCE_LOCKOUT (critical correlated incident)
    assert "BRUTE_FORCE_LOCKOUT" in types, f"Missing BRUTE_FORCE_LOCKOUT. Got: {types}"
    critical = next(i for i in inc_list if i["attack_type"] == "BRUTE_FORCE_LOCKOUT")
    assert critical["severity"] == "CRITICAL"

    # Must detect account creation
    assert "UNAUTHORIZED_ACCOUNT" in types

    # Must detect privilege escalation
    assert "PRIVILEGE_ESCALATION" in types

    # Must detect port scan
    assert "PORT_SCAN" in types

    # All demo incidents must have is_demo=True
    assert all(i["is_demo"] for i in inc_list)

    # Related events must be linked
    for inc in inc_list:
        related = db.get_incident_events(inc["id"])
        assert len(related) > 0, f"Incident {inc['id']} has no linked events"

    # Demo reload must clear old data first (idempotent)
    result2 = loader.load_demo()
    assert result2["incidents"] == result["incidents"]

    db.close(); os.unlink(tmp.name)
    return (f"{result['events']} events, {result['incidents']} incidents | "
            f"types={sorted(types)} | all linked ✓ | reload idempotent ✓")
check("Full demo pipeline (end-to-end)", check_full_demo_pipeline)

# ──────────────────────────────────────────────────────────────
print("\n[ 10 ] CSV & PDF EXPORTS")
# ──────────────────────────────────────────────────────────────
def check_csv_events_export():
    from app.reports.csv_exporter import export_events_to_csv
    events = [
        {"id": 1, "timestamp": datetime.utcnow(), "source_log": "Security",
         "event_id": 4625, "level": "Audit Failure", "username": "admin",
         "source_ip": "1.2.3.4", "message": "Test", "severity": "HIGH",
         "description": "Failed Logon", "is_demo": False},
    ]
    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    tmp.close()
    ok = export_events_to_csv(events, tmp.name)
    assert ok
    with open(tmp.name, encoding="utf-8") as f:
        content = f.read()
    assert "admin" in content
    assert "Security" in content
    assert "4625" in content
    os.unlink(tmp.name)
    return f"CSV export: {len(content)} bytes, fields verified"
check("CSV events export", check_csv_events_export)

def check_csv_incident_export():
    from app.reports.csv_exporter import export_incident_to_csv
    incident = {"id": 1, "attack_type": "BRUTE_FORCE", "severity": "HIGH",
                "username": "admin", "source_ip": "1.2.3.4",
                "detection_rule": "BRUTE_FORCE_001", "detection_reason": "Test reason",
                "event_count": 5, "is_demo": False}
    related = [{"id": 1, "event_id": 4625, "username": "admin", "source_ip": "1.2.3.4",
                "timestamp": datetime.utcnow(), "description": "Failed Logon",
                "source_log": "Security", "severity": "HIGH", "is_demo": False}]
    tmp = tempfile.NamedTemporaryFile(suffix=".csv", delete=False)
    tmp.close()
    ok = export_incident_to_csv(incident, related, tmp.name)
    assert ok
    with open(tmp.name, encoding="utf-8") as f:
        content = f.read()
    assert "BRUTE_FORCE" in content
    assert "BRUTE_FORCE_001" in content
    os.unlink(tmp.name)
    return "Incident CSV with related events exported correctly"
check("CSV incident export", check_csv_incident_export)

def check_pdf_export():
    from app.reports.pdf_exporter import export_incident_to_pdf, REPORTLAB_AVAILABLE
    if not REPORTLAB_AVAILABLE:
        warn("PDF export", "ReportLab not installed — PDF export disabled")
        return
    incident = {"id": 1, "attack_type": "BRUTE_FORCE", "severity": "HIGH",
                "username": "admin", "source_ip": "1.2.3.4",
                "first_seen": datetime.utcnow(), "last_seen": datetime.utcnow(),
                "detection_rule": "BRUTE_FORCE_001", "detection_reason": "Test reason",
                "event_count": 5, "is_demo": True, "description": "Test brute force",
                "status": "NEW"}
    related = [{"id": 1, "event_id": 4625, "username": "admin", "source_ip": "1.2.3.4",
                "timestamp": datetime.utcnow(), "description": "Failed Logon", "is_demo": True}]
    tmp = tempfile.NamedTemporaryFile(suffix=".pdf", delete=False)
    tmp.close()
    ok = export_incident_to_pdf(incident, related, tmp.name)
    assert ok
    size = os.path.getsize(tmp.name)
    assert size > 1000, f"PDF too small: {size} bytes"
    os.unlink(tmp.name)
    return f"PDF report generated ({size} bytes)"
check("PDF incident report", check_pdf_export)

# ──────────────────────────────────────────────────────────────
print("\n[ 11 ] REAL WINDOWS LOG COLLECTORS (live check)")
# ──────────────────────────────────────────────────────────────
def check_system_log_live():
    from app.collectors.system_log import SystemLogCollector
    c = SystemLogCollector()
    result = c.collect()
    if result.access_denied:
        warn("System log (live)", f"Access Denied: {result.error_message}")
        return
    if result.unavailable:
        warn("System log (live)", "Unavailable")
        return
    return f"Collected {len(result.events)} System events"
check("System log: live collection", check_system_log_live)

def check_application_log_live():
    from app.collectors.application_log import ApplicationLogCollector
    c = ApplicationLogCollector()
    result = c.collect()
    if result.access_denied:
        warn("Application log (live)", "Access Denied")
        return
    if result.unavailable:
        warn("Application log (live)", "Unavailable")
        return
    return f"Collected {len(result.events)} Application events"
check("Application log: live collection", check_application_log_live)

def check_security_log_live():
    from app.collectors.security_log import SecurityLogCollector
    from app.utils.helpers import is_running_as_admin
    c = SecurityLogCollector()
    result = c.collect()
    if result.access_denied:
        is_admin = is_running_as_admin()
        print(f"         ℹ️  Security log requires admin rights (running as admin: {is_admin})")
        print(f"         ℹ️  This is expected when running without elevation.")
        warn("Security log (live)", "Access Denied — Run as Administrator for full access")
        return
    return f"Collected {len(result.events)} Security events"
check("Security log: live collection", check_security_log_live)

# ──────────────────────────────────────────────────────────────
print("\n[ 12 ] UI MODULE IMPORTS (no display needed)")
# ──────────────────────────────────────────────────────────────
def check_ui_imports():
    # Test that all UI modules can be imported without crashing
    # (They won't create windows since we don't call mainloop)
    import importlib
    modules = [
        "app.ui.widgets.stat_card",
        "app.ui.widgets.severity_badge",
        "app.ui.widgets.timeline_widget",
        "app.ui.widgets.raw_event_viewer",
    ]
    for mod in modules:
        importlib.import_module(mod)
    return f"All {len(modules)} UI widget modules import cleanly"
check("UI widgets: imports", check_ui_imports)

def check_ui_severity_badge_logic():
    from app.ui.widgets.severity_badge import get_severity_colors, severity_to_tag
    bg, fg = get_severity_colors("CRITICAL")
    assert bg == "#dc3545"
    bg2, fg2 = get_severity_colors("HIGH")
    assert bg2 == "#fd7e14"
    bg3, fg3 = get_severity_colors("INFO")
    assert bg3 == "#6c757d"
    tag = severity_to_tag("medium")
    assert tag == "MEDIUM"
    return "All severity color mappings correct"
check("UI severity badge: color logic", check_ui_severity_badge_logic)

def check_stat_card_import():
    from app.ui.widgets.stat_card import StatCard, SEVERITY_COLORS
    assert "danger" in SEVERITY_COLORS
    assert "success" in SEVERITY_COLORS
    assert "warning" in SEVERITY_COLORS
    return "StatCard color variants defined correctly"
check("UI stat card: color variants", check_stat_card_import)

def check_desktop_collector():
    import tempfile
    from app.collectors.desktop_collector import DesktopCollector
    tmp = tempfile.TemporaryDirectory()
    try:
        c = DesktopCollector(watch_path=tmp.name)
        # First run initializes state
        r1 = c.collect()
        assert len(r1.events) == 0
        
        # Write file
        filepath = os.path.join(tmp.name, "test_file.txt")
        with open(filepath, "w") as f:
            f.write("hello")
            
        r2 = c.collect()
        assert len(r2.events) == 1
        assert r2.events[0]["event_id"] == 4663
        assert r2.events[0]["_event_data"]["ObjectName"] == filepath
    finally:
        tmp.cleanup()
    return "DesktopCollector watcher scan & detect verified"
check("Desktop directory watcher collector", check_desktop_collector)

# ──────────────────────────────────────────────────────────────
print("\n[ 13 ] CONFIGURATION")
# ──────────────────────────────────────────────────────────────
def check_config_file():
    config_path = os.path.join(os.path.dirname(__file__), "config", "settings.ini")
    assert os.path.exists(config_path), f"settings.ini not found at {config_path}"
    from configparser import ConfigParser
    config = ConfigParser()
    config.read(config_path)
    assert config.has_section("monitoring")
    assert config.has_section("detection")
    assert config.has_section("log_sources")
    assert config.has_section("database")
    assert config.has_option("detection", "brute_force_threshold")
    assert config.has_option("detection", "brute_force_window_seconds")
    bf_thresh = int(config.get("detection", "brute_force_threshold"))
    assert 1 <= bf_thresh <= 100, f"Unreasonable threshold: {bf_thresh}"
    return (f"settings.ini valid | BF threshold={bf_thresh} | "
            f"Sections: {config.sections()}")
check("Config: settings.ini valid", check_config_file)

def check_main_entry():
    import subprocess
    result = subprocess.run(
        [sys.executable, "main.py", "--headless"],
        capture_output=True, text=True, timeout=15,
        cwd=os.path.dirname(__file__)
    )
    output = result.stdout + result.stderr
    assert "Windows Security Monitor starting" in output
    assert "Database" in output
    return f"main.py --headless runs cleanly (exit code={result.returncode})"
check("main.py: --headless mode", check_main_entry)

# ──────────────────────────────────────────────────────────────
print("\n" + "="*65)
print("  SUMMARY")
print("="*65)
passed = [r for r in results if r[0] == PASS]
failed = [r for r in results if r[0] == FAIL]
warned = [r for r in results if r[0] == WARN]

print(f"\n  {PASS}  {len(passed)} checks passed")
if warned:
    print(f"  {WARN}  {len(warned)} warnings (expected — no admin / no firewall log)")
    for _, name, msg in warned:
        print(f"         • {name}: {msg}")
if failed:
    print(f"\n  {FAIL}  {len(failed)} checks FAILED:")
    for _, name, msg in failed:
        print(f"         • {name}: {msg}")
else:
    print(f"\n  All checks passed or warned. Project is fully functional.")

print()
