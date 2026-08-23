"""
tests/test_collectors.py
--------------------------
Tests for log collectors.

These tests verify that each collector gracefully handles:
- Normal (mock) responses
- Access denied scenarios
- Unavailable log sources
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import unittest
from unittest.mock import patch, MagicMock

from app.collectors.base_collector       import CollectionResult
from app.collectors.security_log        import SecurityLogCollector
from app.collectors.system_log          import SystemLogCollector
from app.collectors.application_log     import ApplicationLogCollector
from app.collectors.powershell_log      import PowerShellLogCollector
from app.collectors.firewall_log        import FirewallLogCollector
from app.collectors.desktop_collector   import DesktopCollector


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
  </EventData>
</Event>"""


class TestSecurityLogCollector(unittest.TestCase):

    @patch("subprocess.run")
    def test_successful_collection(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout=SAMPLE_XML, stderr=""
        )
        collector = SecurityLogCollector()
        result = collector.collect()
        self.assertTrue(result.ok)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0]["event_id"], 4625)
        self.assertEqual(result.events[0]["source_log"], "Security")
        self.assertEqual(result.events[0]["username"], "Administrator")

    @patch("subprocess.run")
    def test_access_denied(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=5, stdout="", stderr="access is denied"
        )
        collector = SecurityLogCollector()
        result = collector.collect()
        self.assertTrue(result.access_denied)
        self.assertEqual(len(result.events), 0)
        self.assertIn("Access Denied", result.error_message)

    @patch("subprocess.run")
    def test_empty_result(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="", stderr=""
        )
        collector = SecurityLogCollector()
        result = collector.collect()
        self.assertTrue(result.ok)
        self.assertEqual(len(result.events), 0)

    @patch("subprocess.run")
    def test_incremental_uses_timestamp(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
        collector = SecurityLogCollector()
        collector.collect(since_timestamp="2024-01-15T21:00:00")
        call_args = mock_run.call_args[0][0]
        # Should contain XPath with TimeCreated filter
        query_arg = [a for a in call_args if "TimeCreated" in a]
        self.assertTrue(len(query_arg) > 0)

    def test_collection_result_status_ok(self):
        r = CollectionResult(events=[], source_name="Security")
        self.assertTrue(r.ok)
        self.assertIn("OK", r.status_text)

    def test_collection_result_status_denied(self):
        r = CollectionResult(events=[], access_denied=True, source_name="Security")
        self.assertFalse(r.ok)
        self.assertIn("Access Denied", r.status_text)

    def test_collection_result_status_unavailable(self):
        r = CollectionResult(events=[], unavailable=True, source_name="PowerShell")
        self.assertFalse(r.ok)
        self.assertIn("Unavailable", r.status_text)


class TestFirewallLogCollector(unittest.TestCase):

    def test_unavailable_when_no_log_file(self):
        collector = FirewallLogCollector(log_path="nonexistent_firewall.log")
        result = collector.collect()
        self.assertFalse(collector.is_available)
        self.assertTrue(result.unavailable)
        self.assertIn("Unavailable", result.error_message)
        self.assertEqual(len(result.events), 0)

    @patch('app.collectors.firewall_log.FirewallLogCollector._is_logging_enabled', return_value=True)
    def test_is_available_check(self, mock_enabled):
        import tempfile, os
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            f.write(b"# Firewall log\n2024-01-15 21:14:00 DROP TCP 10.0.0.1 10.0.0.2 1234 445 40\n")
            tmp_path = f.name
        try:
            collector = FirewallLogCollector(log_path=tmp_path)
            self.assertTrue(collector.is_available)
            result = collector.collect()
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.events[0]["source_log"], "Firewall")
        finally:
            os.unlink(tmp_path)


class TestDesktopCollector(unittest.TestCase):

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.TemporaryDirectory()
        self.collector = DesktopCollector(watch_path=self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_initialization(self):
        # On first run, it should initialize state and detect nothing
        res = self.collector.collect()
        self.assertEqual(len(res.events), 0)
        self.assertTrue(self.collector._initialized)

    def test_detects_creation(self):
        # 1. Initialize
        self.collector.collect()
        
        # 2. Create a file
        filepath = os.path.join(self.tmpdir.name, "newfile.txt")
        with open(filepath, "w") as f:
            f.write("test content")
            
        # 3. Collect
        res = self.collector.collect()
        self.assertEqual(len(res.events), 1)
        self.assertEqual(res.events[0]["event_id"], 4663)
        self.assertIn("Created/Edited", res.events[0]["message"])
        self.assertEqual(res.events[0]["_event_data"]["ObjectName"], filepath)

    def test_detects_deletion(self):
        # 1. Create file and initialize
        filepath = os.path.join(self.tmpdir.name, "file_to_delete.txt")
        with open(filepath, "w") as f:
            f.write("temp")
        self.collector.collect()
        
        # 2. Delete file
        os.remove(filepath)
        
        # 3. Collect
        res = self.collector.collect()
        self.assertEqual(len(res.events), 1)
        self.assertEqual(res.events[0]["event_id"], 4663)
        self.assertIn("Deleted", res.events[0]["message"])
        self.assertEqual(res.events[0]["_event_data"]["ObjectName"], filepath)


if __name__ == "__main__":
    unittest.main()
