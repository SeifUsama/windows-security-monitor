"""
app/collectors/base_collector.py
---------------------------------
Abstract base class for all log collectors.

Defines the CollectionResult dataclass and the BaseCollector interface.
All collectors must implement collect() and return a CollectionResult.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


@dataclass
class CollectionResult:
    """
    Returned by every collector.

    Attributes:
        events:        List of normalized event dicts ready for DB insertion.
        access_denied: True if the log source rejected the read attempt.
        unavailable:   True if the log source doesn't exist on this machine.
        error_message: Human-readable status for the UI status bar.
        source_name:   Name of the log source (e.g. "Security", "Firewall").
    """
    events:        List[Dict[str, Any]] = field(default_factory=list)
    access_denied: bool                 = False
    unavailable:   bool                 = False
    error_message: Optional[str]        = None
    source_name:   str                  = "Unknown"

    @property
    def ok(self) -> bool:
        """True if the collection succeeded with at least no errors."""
        return not self.access_denied and not self.unavailable

    @property
    def status_text(self) -> str:
        """Short status string for display in the UI."""
        if self.access_denied:
            return f"⚠️ {self.source_name}: Access Denied — Administrator privileges may be required for full visibility."
        if self.unavailable:
            return f"ℹ️ {self.source_name}: Unavailable (logging may be disabled)."
        return f"✅ {self.source_name}: OK ({len(self.events)} new events)"


class BaseCollector(ABC):
    """
    Abstract base class for log collectors.

    Subclasses implement:
        collect(since_timestamp) -> CollectionResult

    The `since_timestamp` parameter implements incremental collection —
    only events after this timestamp should be returned.
    """

    def __init__(self, source_name: str):
        self.source_name = source_name

    @abstractmethod
    def collect(self, since_timestamp: Optional[str] = None) -> CollectionResult:
        """
        Collect log events.

        Args:
            since_timestamp: ISO 8601 string. If provided, only return events
                             after this timestamp (incremental mode).
        
        Returns:
            CollectionResult with events and status information.
        """
        ...

    def _make_result(
        self,
        events: List[Dict[str, Any]],
        access_denied: bool = False,
        unavailable: bool = False,
        error_message: Optional[str] = None,
    ) -> CollectionResult:
        return CollectionResult(
            events=events,
            access_denied=access_denied,
            unavailable=unavailable,
            error_message=error_message,
            source_name=self.source_name,
        )
