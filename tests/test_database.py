"""
tests/test_database.py
------------------------
Unit tests for the DatabaseManager.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
import tempfile
from datetime import datetime

from app.database.db_manager import DatabaseManager


class TestDatabaseManager(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.db = DatabaseManager(self.tmp.name)
        self.db.initialize()

    def tearDown(self):
        self.db.close()
        self.tmp.close()
        try:
            os.unlink(self.tmp.name)
        except PermissionError:
            pass  # Windows may hold the file briefly; not a test failure

    def test_insert_and_query_event(self):
        ev = {
            "timestamp": datetime(2024, 1, 15, 21, 14, 2),
            "source_log": "Security",
            "event_id": 4625,
            "level": "Audit Failure",
            "username": "Administrator",
            "source_ip": "192.168.1.50",
            "message": "Failed logon",
            "severity": "HIGH",
            "description": "Failed Logon Attempt",
            "is_demo": False,
        }
        row_id = self.db.insert_event(ev)
        self.assertGreater(row_id, 0)

        rows = self.db.query_events({"event_id": 4625})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["username"], "Administrator")
        self.assertEqual(rows[0]["source_ip"], "192.168.1.50")

    def test_insert_incident(self):
        inc = {
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "source_ip": "192.168.1.50",
            "username": "Administrator",
            "first_seen": datetime(2024, 1, 15, 21, 14, 2),
            "last_seen": datetime(2024, 1, 15, 21, 14, 11),
            "description": "Test incident",
            "detection_rule": "BRUTE_FORCE_001",
            "detection_reason": "Test reason",
            "event_count": 5,
            "is_demo": False,
        }
        inc_id = self.db.insert_incident(inc)
        self.assertGreater(inc_id, 0)

        fetched = self.db.get_incident_by_id(inc_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(dict(fetched)["attack_type"], "BRUTE_FORCE")

    def test_checkpoint(self):
        self.db.update_checkpoint("Security", "2024-01-15T21:14:02")
        ts, rn = self.db.get_checkpoint("Security")
        self.assertEqual(ts, "2024-01-15T21:14:02")

    def test_statistics(self):
        # Insert some test events
        for i in range(3):
            self.db.insert_event({
                "timestamp": datetime.utcnow(),
                "source_log": "Security",
                "event_id": 4625,
                "severity": "HIGH",
                "is_demo": False,
            })
        stats = self.db.get_statistics()
        self.assertGreaterEqual(stats["failed_logins"], 3)

    def test_demo_clear(self):
        # Insert demo event
        self.db.insert_event({
            "timestamp": datetime.utcnow(),
            "source_log": "DEMO",
            "event_id": 4625,
            "severity": "HIGH",
            "is_demo": True,
        })
        rows = self.db.query_events({"is_demo": True})
        self.assertEqual(len(rows), 1)

        self.db.clear_demo_data()
        rows = self.db.query_events({"is_demo": True})
        self.assertEqual(len(rows), 0)

    def test_update_incident_status(self):
        inc_id = self.db.insert_incident({
            "attack_type": "BRUTE_FORCE",
            "severity": "HIGH",
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow(),
            "detection_rule": "TEST",
            "is_demo": False,
        })
        self.db.update_incident_status(inc_id, "FALSE_POSITIVE")
        fetched = self.db.get_incident_by_id(inc_id)
        self.assertEqual(dict(fetched)["status"], "FALSE_POSITIVE")


if __name__ == "__main__":
    unittest.main()
