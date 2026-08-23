"""
app/collectors/desktop_collector.py
-----------------------------------
A Python-based real-time directory watcher for the user's Desktop.
Allows out-of-the-box file auditing without requiring complex
Windows SACL / Audit Policy setup.

Generates Event ID 4663 events which are fed directly into the pipeline.
"""
import os
from datetime import datetime
from typing import Optional, List, Dict, Any

from app.collectors.base_collector import BaseCollector, CollectionResult
from app.utils.logger import log


class DesktopCollector(BaseCollector):
    """
    Watches the Windows Desktop directory for file/folder creations,
    deletions, and modifications, generating Event ID 4663.
    """

    def __init__(self, watch_path: Optional[str] = None):
        super().__init__("Desktop")
        if not watch_path:
            watch_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.watch_path = watch_path
        
        # State: filepath -> (mtime, is_dir)
        self.state: Dict[str, tuple[float, bool]] = {}
        self._initialized = False

    def _scan_directory(self) -> Dict[str, tuple[float, bool]]:
        """Scan the watched directory and return a map of filepath -> (mtime, is_dir)."""
        current_state = {}
        if not os.path.exists(self.watch_path):
            return current_state
            
        try:
            for entry in os.scandir(self.watch_path):
                try:
                    stat = entry.stat()
                    current_state[entry.path] = (stat.st_mtime, entry.is_dir())
                except OSError:
                    # File might be locked or deleted mid-scan
                    continue
        except Exception as e:
            log.error("DesktopCollector scan error: %s", e)
            
        return current_state

    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        """
        Compare current directory state with previous state to detect
        creations, deletions, and edits.
        """
        events: List[Dict[str, Any]] = []
        
        # Get the current logged-in Windows username
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USERNAME", "UnknownUser")

        # Scan folder
        current = self._scan_directory()

        # If this is the first run, initialize state and return empty list
        # (we don't want to log everything on the Desktop as newly created)
        if not self._initialized:
            self.state = current
            self._initialized = True
            log.info("DesktopCollector initialized. Watching: %s", self.watch_path)
            return self._make_result([])

        # 1. Check for deletions
        for path, (mtime, is_dir) in list(self.state.items()):
            if path not in current:
                events.append(self._create_event(
                    username=username,
                    path=path,
                    action="Deleted",
                    is_dir=is_dir,
                    access_mask="%%4423" # Delete access
                ))

        # 2. Check for creations and edits
        for path, (mtime, is_dir) in current.items():
            if path not in self.state:
                events.append(self._create_event(
                    username=username,
                    path=path,
                    action="Created/Edited",
                    is_dir=is_dir,
                    access_mask="%%4416" # WriteData/Create
                ))
            else:
                old_mtime, _ = self.state[path]
                if mtime > old_mtime:
                    events.append(self._create_event(
                        username=username,
                        path=path,
                        action="Created/Edited",
                        is_dir=is_dir,
                        access_mask="%%4417" # AppendData/Modify
                    ))

        # Update stored state
        self.state = current

        if events:
            log.info("DesktopCollector: detected %d directory changes", len(events))
            
        return self._make_result(events)

    def _create_event(
        self, username: str, path: str, action: str, is_dir: bool, access_mask: str
    ) -> Dict[str, Any]:
        """Build a mock 4663 event dict matching the schema."""
        now = datetime.utcnow()
        obj_type = "Folder" if is_dir else "File"
        
        # Friendly message matching parser structure
        message = (
            f"File System: User WORKSTATION\\{username} {action} object: {path} | "
            f"Process: C:\\Windows\\explorer.exe | Access Mask: {access_mask}"
        )
        
        return {
            "timestamp":        now,
            "source_log":       "Security", # Categorize as Security to flow through existing rules
            "event_id":         4663,
            "level":            "Audit Success",
            "username":         username,
            "source_ip":        "127.0.0.1",
            "destination_ip":   None,
            "source_port":      None,
            "destination_port": None,
            "protocol":         None,
            "message":          message,
            "severity":         "LOW",
            "description":      "File System Object Accessed",
            "raw_xml":          self._generate_xml(username, path, action, obj_type, access_mask, now),
            "is_demo":          False,
            "computer":         "LOCAL-WORKSTATION",
            "logon_type":       None,
            "_event_data": {
                "SubjectUserName":   username,
                "SubjectDomainName": "WORKSTATION",
                "ObjectName":        path,
                "Accesses":          access_mask,
                "ProcessName":       "C:\\Windows\\explorer.exe",
            }
        }

    def _generate_xml(
        self, username: str, path: str, action: str, obj_type: str, access: str, ts: datetime
    ) -> str:
        """Generate XML for the Raw Event Viewer."""
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.000000000Z")
        return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{{54849625-5478-4994-A5BA-3E3B0328C30D}}"/>
    <EventID>4663</EventID>
    <Version>1</Version>
    <Level>0</Level>
    <Task>12800</Task>
    <Opcode>0</Opcode>
    <Keywords>0x8020000000000000</Keywords>
    <TimeCreated SystemTime="{ts_str}"/>
    <EventRecordID>100500</EventRecordID>
    <Correlation/>
    <Execution ProcessID="4" ThreadID="8"/>
    <Channel>Security</Channel>
    <Computer>LOCAL-WORKSTATION</Computer>
    <Security/>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-12345678-12345678-12345678-1001</Data>
    <Data Name="SubjectUserName">{username}</Data>
    <Data Name="SubjectDomainName">WORKSTATION</Data>
    <Data Name="SubjectLogonId">0x3f5c2</Data>
    <Data Name="ObjectServer">Security</Data>
    <Data Name="ObjectType">{obj_type}</Data>
    <Data Name="ObjectName">{path}</Data>
    <Data Name="HandleId">0x7bc</Data>
    <Data Name="AccessList">{action}</Data>
    <Data Name="Accesses">{access}</Data>
    <Data Name="ProcessId">0x1a4</Data>
    <Data Name="ProcessName">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>
<!-- [PYTHON FILE SYSTEM OBSERVER EVENT] -->"""
