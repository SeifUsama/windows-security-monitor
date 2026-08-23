"""
tests/test_detection.py
-------------------------
Unit tests for all detection rules.

Tests use synthetic events (is_demo=True) passed through the
same detection engine as real events.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from datetime import datetime, timedelta
from typing import List, Dict, Any

from app.detection.rules.brute_force     import BruteForceRule
from app.detection.rules.account_lockout import AccountLockoutRule
from app.detection.rules.privilege       import PrivilegeAssignmentRule
from app.detection.rules.account_created import AccountCreatedRule
from app.detection.rules.port_scan       import PortScanRule
from app.detection.rules.file_integrity   import FileIntegrityRule


def _make_event(
    event_id: int,
    username: str = "Administrator",
    source_ip: str = "192.168.1.50",
    minutes_ago: float = 0,
    **kwargs
) -> Dict[str, Any]:
    return {
        "id": None,
        "timestamp": datetime.utcnow() - timedelta(minutes=minutes_ago),
        "source_log": "Security",
        "event_id": event_id,
        "level": "Audit Failure",
        "username": username,
        "source_ip": source_ip,
        "message": f"Test event {event_id}",
        "severity": "HIGH",
        "description": f"Event {event_id}",
        "raw_xml": "",
        "is_demo": True,
        "_event_data": {
            "TargetUserName": username,
            "IpAddress": source_ip or "",
            "SubjectUserName": "Administrator",
        },
        **kwargs,
    }


class TestBruteForceRule(unittest.TestCase):

    def setUp(self):
        self.rule = BruteForceRule(threshold=5, window_seconds=60)

    def test_detects_brute_force(self):
        """5 failed logins from same IP within 60 seconds triggers detection."""
        events = []
        for i in range(5):
            events.append(_make_event(
                4625, "Administrator", "192.168.1.50",
                minutes_ago=1 - (i * 0.1),  # within 60 seconds
            ))
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "BRUTE_FORCE")
        self.assertEqual(incidents[0]["severity"], "HIGH")
        self.assertIn("192.168.1.50", incidents[0]["detection_reason"])

    def test_no_detection_below_threshold(self):
        """4 failed logins (below threshold=5) should NOT trigger."""
        events = [_make_event(4625, minutes_ago=1 - (i * 0.1)) for i in range(4)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 0)

    def test_no_detection_outside_window(self):
        """5 failed logins but spread > 60 seconds should NOT trigger."""
        events = [_make_event(4625, minutes_ago=60 - i * 15) for i in range(5)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 0)

    def test_detects_multiple_targets(self):
        """Two different username targets each with 5 fails should give 2 incidents."""
        events = []
        for i in range(5):
            events.append(_make_event(4625, "alice", "10.0.0.1", minutes_ago=1 - i * 0.05))
            events.append(_make_event(4625, "bob",   "10.0.0.1", minutes_ago=1 - i * 0.05))
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 2)

    def test_groups_by_username_and_ip(self):
        """Same username from different IPs should be separate groups."""
        events_a = [_make_event(4625, "admin", "10.0.0.1", minutes_ago=0.5 - i*0.05) for i in range(5)]
        events_b = [_make_event(4625, "admin", "10.0.0.2", minutes_ago=0.5 - i*0.05) for i in range(5)]
        incidents = self.rule.detect(events_a + events_b)
        self.assertEqual(len(incidents), 2)

    def test_handles_none_ip(self):
        """Events without source IP should be grouped by username with 'Not Available' displayed."""
        events = [_make_event(4625, "admin", None, minutes_ago=0.5 - i*0.05) for i in range(5)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertIn("Not Available", incidents[0]["detection_reason"])

    def test_detection_reason_contains_required_info(self):
        """Detection reason must contain rule ID, threshold, username, IP, count, and timestamps."""
        events = [_make_event(4625, "Admin", "10.0.0.5", minutes_ago=0.5 - i*0.05) for i in range(5)]
        incidents = self.rule.detect(events)
        reason = incidents[0]["detection_reason"]
        self.assertIn("BRUTE_FORCE_001", reason)
        self.assertIn("5 failed", reason.lower())
        self.assertIn("admin", reason.lower())

    def test_non_4625_events_ignored(self):
        """Other event IDs should not trigger brute force."""
        events = [_make_event(4624, minutes_ago=0.1 * i) for i in range(10)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 0)

    def test_configurable_threshold(self):
        """Threshold=3 should detect 3 failures."""
        rule = BruteForceRule(threshold=3, window_seconds=60)
        events = [_make_event(4625, minutes_ago=0.1 * i) for i in range(3)]
        incidents = rule.detect(events)
        self.assertEqual(len(incidents), 1)


class TestAccountLockoutRule(unittest.TestCase):

    def setUp(self):
        self.rule = AccountLockoutRule()

    def test_detects_lockout(self):
        events = [_make_event(4740)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "ACCOUNT_LOCKOUT")
        self.assertEqual(incidents[0]["severity"], "HIGH")

    def test_no_false_positives(self):
        events = [_make_event(4624), _make_event(4625)]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 0)

    def test_detection_reason_contains_lockout_info(self):
        events = [_make_event(4740, "admin", "10.0.0.1")]
        incidents = self.rule.detect(events)
        self.assertIn("LOCKOUT_001", incidents[0]["detection_reason"])
        self.assertIn("4740", incidents[0]["detection_reason"])

    def test_multiple_lockouts_give_multiple_incidents(self):
        events = [_make_event(4740, "alice"), _make_event(4740, "bob")]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 2)


class TestPrivilegeRule(unittest.TestCase):

    def setUp(self):
        self.rule = PrivilegeAssignmentRule()

    def test_detects_privilege(self):
        events = [_make_event(4672, "unknown_svc")]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "PRIVILEGE_ESCALATION")

    def test_system_account_is_medium(self):
        events = [_make_event(4672, "system")]
        incidents = self.rule.detect(events)
        self.assertEqual(incidents[0]["severity"], "MEDIUM")

    def test_unknown_account_is_high(self):
        events = [_make_event(4672, "backdoor_user")]
        incidents = self.rule.detect(events)
        self.assertEqual(incidents[0]["severity"], "HIGH")


class TestAccountCreatedRule(unittest.TestCase):

    def setUp(self):
        self.rule = AccountCreatedRule()

    def test_detects_new_account(self):
        events = [_make_event(4720, "hacker_backdoor")]
        incidents = self.rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "UNAUTHORIZED_ACCOUNT")
        self.assertEqual(incidents[0]["severity"], "HIGH")

    def test_detection_reason_contains_username(self):
        events = [_make_event(4720, "new_acct")]
        incidents = self.rule.detect(events)
        self.assertIn("new_acct", incidents[0]["detection_reason"])


class TestPortScanRule(unittest.TestCase):

    def _make_fw_event(self, src_ip: str, dst_port: int, seconds_ago: float = 0):
        return {
            "id": None,
            "timestamp": datetime.utcnow() - timedelta(seconds=seconds_ago),
            "source_log": "Firewall",
            "event_id": None,
            "source_ip": src_ip,
            "destination_ip": "10.0.0.5",
            "source_port": 40000,
            "destination_port": dst_port,
            "protocol": "TCP",
            "severity": "HIGH",
            "is_demo": True,
            "_action": "DROP",
        }

    def test_detects_port_scan(self):
        rule = PortScanRule(threshold=10, window_seconds=30, firewall_available=True)
        events = [self._make_fw_event("10.0.0.99", 1000 + i, i) for i in range(15)]
        incidents = rule.detect(events)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "PORT_SCAN")

    def test_disabled_when_unavailable(self):
        rule = PortScanRule(threshold=10, window_seconds=30, firewall_available=False)
        events = [self._make_fw_event("10.0.0.99", 1000 + i, i) for i in range(20)]
        incidents = rule.detect(events)
        self.assertEqual(len(incidents), 0)

    def test_no_detection_below_threshold(self):
        rule = PortScanRule(threshold=10, window_seconds=30, firewall_available=True)
        events = [self._make_fw_event("10.0.0.99", 1000 + i, i) for i in range(5)]
        incidents = rule.detect(events)
        self.assertEqual(len(incidents), 0)


class TestFileIntegrityRule(unittest.TestCase):

    def setUp(self):
        self.rule = FileIntegrityRule(watch_paths=["etc", "hosts"], severity="LOW")

    def test_detects_matching_file_system_access(self):
        ev = _make_event(4663, "attacker", "192.168.1.50")
        ev["message"] = "File System: User DEMO-DOMAIN\\attacker Deleted object: C:\\Windows\\System32\\drivers\\etc\\hosts | Process: C:\\Windows\\cmd.exe | Access Mask: %%4423"
        ev["_event_data"] = {
            "SubjectUserName": "attacker",
            "SubjectDomainName": "DEMO-DOMAIN",
            "ObjectName": "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "Accesses": "%%4423",
            "ProcessName": "C:\\Windows\\cmd.exe",
        }
        incidents = self.rule.detect([ev])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["attack_type"], "FILE_INTEGRITY")
        self.assertEqual(incidents[0]["severity"], "LOW")
        self.assertIn("attacker", incidents[0]["detection_reason"])
        self.assertIn("etc/hosts", incidents[0]["description"].lower().replace("\\", "/"))

    def test_ignores_non_matching_file_system_access(self):
        ev = _make_event(4663, "user", "192.168.1.20")
        ev["message"] = "File System: User DEMO-DOMAIN\\user Created/Edited object: C:\\Users\\user\\Documents\\report.txt | Process: C:\\Windows\\notepad.exe | Access Mask: %%4416"
        ev["_event_data"] = {
            "SubjectUserName": "user",
            "SubjectDomainName": "DEMO-DOMAIN",
            "ObjectName": "C:\\Users\\user\\Documents\\report.txt",
            "Accesses": "%%4416",
            "ProcessName": "C:\\Windows\\notepad.exe",
        }
        incidents = self.rule.detect([ev])
        self.assertEqual(len(incidents), 0)

    def test_all_files_when_no_paths_specified(self):
        rule = FileIntegrityRule(watch_paths=None, severity="MEDIUM")
        ev = _make_event(4663, "user", "192.168.1.20")
        ev["message"] = "File System: User DEMO-DOMAIN\\user Created/Edited object: C:\\Users\\user\\Documents\\report.txt | Process: C:\\Windows\\notepad.exe | Access Mask: %%4416"
        ev["_event_data"] = {
            "SubjectUserName": "user",
            "SubjectDomainName": "DEMO-DOMAIN",
            "ObjectName": "C:\\Users\\user\\Documents\\report.txt",
            "Accesses": "%%4416",
            "ProcessName": "C:\\Windows\\notepad.exe",
        }
        incidents = rule.detect([ev])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["severity"], "MEDIUM")


if __name__ == "__main__":
    unittest.main()
