"""Quick demo pipeline test."""
import sys
sys.path.insert(0, ".")
from configparser import ConfigParser
from app.database.db_manager import DatabaseManager
from app.demo_loader import DemoLoader
import os

config = ConfigParser()
config.read_dict({
    "monitoring": {"interval_seconds": "30", "max_events_per_cycle": "500"},
    "detection": {
        "brute_force_threshold": "5",
        "brute_force_window_seconds": "60",
        "port_scan_threshold": "10",
        "port_scan_window_seconds": "30",
    },
    "database": {"db_path": "test_demo.db"},
})

db = DatabaseManager("test_demo.db")
db.initialize()

loader = DemoLoader(db, config)
result = loader.load_demo()
print(f"Demo loaded: {result}")
print()

incidents = db.get_incidents()
for inc in incidents:
    d = dict(inc)
    print(f"Incident #{d['id']}: {d['attack_type']} | Severity: {d['severity']} | User: {d['username']} | Rule: {d['detection_rule']}")

if incidents:
    print()
    print("--- Detection Reason (first incident) ---")
    print(dict(incidents[0])["detection_reason"][:600])

db.close()
os.remove("test_demo.db")
print("\nDEMO PIPELINE TEST: PASSED")
