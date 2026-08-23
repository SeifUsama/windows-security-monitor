"""
app/demo_loader.py
-------------------
Demo Mode loader.

Loads synthetic events from demo_data/scenarios.py through the
SAME pipeline as real Windows events:

  Synthetic NormalizedEvent dicts
         |
         v
  DatabaseManager.insert_event()
         |
         v
  DetectionEngine.analyze()
         |
         v
  CorrelationEngine.process()
         |
         v
  Incidents stored in DB

The detection engine and correlation engine have NO knowledge that
these are demo events — they analyze the event fields exactly as
they would for real events.

Call load_demo() to populate the DB with demo data.
Call clear_demo() to remove all demo data.
"""

from typing import List, Dict, Any, Optional
from configparser import ConfigParser

from app.database.db_manager import DatabaseManager
from app.detection.engine import DetectionEngine
from app.correlation.correlator import CorrelationEngine
from app.collectors.firewall_log import FirewallLogCollector
from demo_data.scenarios import get_demo_events
from app.utils.logger import log


class DemoLoader:
    """
    Manages the Demo Mode lifecycle.
    
    1. Loads synthetic events into the database
    2. Runs the detection engine on them
    3. Runs the correlation engine
    4. Demo events and incidents are stored with is_demo=True
    """

    def __init__(self, db: DatabaseManager, config: ConfigParser):
        self.db = db
        self.config = config

    def load_demo(self) -> Dict[str, int]:
        """
        Load demo data through the full pipeline.
        
        Returns a dict with counts:
          {"events": N, "incidents": M}
        """
        log.info("Loading demo data...")

        # 1. Clear any existing demo data
        self.db.clear_demo_data()

        # 2. Get synthetic events
        demo_events = get_demo_events()

        # 3. Separate firewall events (source_log="DEMO" but have destination_port)
        #    Port scan rule needs source_log="Firewall" for filtering
        #    For demo purposes, we temporarily tag firewall-type events
        firewall_events = [e for e in demo_events if e.get("destination_port") is not None]
        other_events    = [e for e in demo_events if e.get("destination_port") is None]

        # Mark firewall demo events with source_log="Firewall" so the port scan rule picks them up
        for ev in firewall_events:
            ev["source_log"] = "Firewall"
            ev["is_demo"] = True

        all_events = other_events + firewall_events

        # 4. Insert events into DB and get their IDs
        db_ids = self.db.insert_events_bulk(all_events)
        log.info("Demo: inserted %d events", len(db_ids))

        # Attach DB IDs back to event dicts (needed for incident_events linking)
        for ev, db_id in zip(all_events, db_ids):
            ev["id"] = db_id

        # 5. Run detection engine — same engine as real data
        firewall_available = any(ev.get("destination_port") is not None for ev in all_events)
        engine = DetectionEngine(self.config, firewall_available=firewall_available)
        raw_incidents = engine.analyze(all_events)
        log.info("Demo: detection engine found %d raw incidents", len(raw_incidents))

        # 6. Run correlation engine
        correlator = CorrelationEngine(self.db)
        incident_ids = correlator.process(raw_incidents, all_events)
        log.info("Demo: correlation engine saved %d incidents", len(incident_ids))

        return {
            "events":    len(db_ids),
            "incidents": len(incident_ids),
        }

    def is_demo_loaded(self) -> bool:
        """Check if demo data is currently in the database."""
        rows = self.db.query_events({"is_demo": True}, limit=1)
        return len(rows) > 0

    def clear_demo(self) -> None:
        """Remove all demo data from the database."""
        self.db.clear_demo_data()
        log.info("Demo data cleared")
