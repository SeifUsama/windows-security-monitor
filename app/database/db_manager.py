"""
app/database/db_manager.py
--------------------------
SQLite database manager for the Windows Security Monitor.

Handles:
  - Schema creation and migration
  - Event insertion and querying
  - Incident CRUD operations
  - Incremental collection checkpoints
  - Parameterized queries throughout (no SQL injection)
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

from app.utils.logger import log

# ---------------------------------------------------------------------------
# SQL Schema
# ---------------------------------------------------------------------------
SCHEMA_SQL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp           TEXT NOT NULL,
    source_log          TEXT NOT NULL,
    event_id            INTEGER,
    level               TEXT,
    username            TEXT,
    source_ip           TEXT,
    destination_ip      TEXT,
    source_port         INTEGER,
    destination_port    INTEGER,
    protocol            TEXT,
    message             TEXT,
    severity            TEXT DEFAULT 'INFO',
    description         TEXT,
    raw_xml             TEXT,
    is_demo             INTEGER DEFAULT 0,
    computer            TEXT,
    logon_type          TEXT,
    created_at          TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_event_id    ON events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_source_log  ON events(source_log);
CREATE INDEX IF NOT EXISTS idx_events_username    ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_source_ip   ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON events(severity);
CREATE INDEX IF NOT EXISTS idx_events_is_demo     ON events(is_demo);

CREATE TABLE IF NOT EXISTS incidents (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type      TEXT NOT NULL,
    severity         TEXT NOT NULL,
    status           TEXT DEFAULT 'NEW',
    source_ip        TEXT,
    username         TEXT,
    first_seen       TEXT NOT NULL,
    last_seen        TEXT NOT NULL,
    description      TEXT,
    detection_rule   TEXT,
    detection_reason TEXT,
    mitre_tactic     TEXT,
    mitre_technique  TEXT,
    event_count      INTEGER DEFAULT 0,
    is_demo          INTEGER DEFAULT 0,
    created_at       TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_incidents_severity    ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status      ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_attack_type ON incidents(attack_type);
CREATE INDEX IF NOT EXISTS idx_incidents_is_demo     ON incidents(is_demo);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_id  INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    event_id     INTEGER NOT NULL REFERENCES events(id)    ON DELETE CASCADE,
    PRIMARY KEY (incident_id, event_id)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    source              TEXT PRIMARY KEY,
    last_timestamp      TEXT,
    last_record_number  INTEGER
);
"""


class DatabaseManager:
    """
    Central database manager.
    
    Usage:
        db = DatabaseManager("security_monitor.db")
        db.initialize()
        event_id = db.insert_event({...})
    """

    def __init__(self, db_path: str = "security_monitor.db"):
        self.db_path = Path(db_path)
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    def get_connection(self) -> sqlite3.Connection:
        """Return a thread-local connection (row_factory = sqlite3.Row)."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def initialize(self) -> None:
        """Create tables and indexes if they don't exist."""
        try:
            conn = self.get_connection()
            conn.executescript(SCHEMA_SQL)
            conn.commit()
            
            # Migration to add MITRE ATT&CK columns if they don't exist in the existing db file
            try:
                cursor = conn.execute("PRAGMA table_info(incidents)")
                columns = [row["name"] for row in cursor.fetchall()]
                if "mitre_tactic" not in columns:
                    conn.execute("ALTER TABLE incidents ADD COLUMN mitre_tactic TEXT")
                if "mitre_technique" not in columns:
                    conn.execute("ALTER TABLE incidents ADD COLUMN mitre_technique TEXT")
                conn.commit()
            except sqlite3.Error as e:
                log.warning("Database migration for MITRE ATT&CK columns skipped/failed: %s", e)
                
            log.info("Database initialized at %s", self.db_path)
        except sqlite3.Error as e:
            log.error("Failed to initialize database: %s", e)
            raise

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Event operations
    # ------------------------------------------------------------------

    def insert_event(self, event: Dict[str, Any]) -> int:
        """
        Insert a normalized event dict and return its row ID.
        
        Expected keys match the 'events' table columns.
        Silently converts datetime objects to ISO strings.
        """
        ts = event.get("timestamp")
        if isinstance(ts, datetime):
            ts = ts.isoformat()

        sql = """
            INSERT INTO events
                (timestamp, source_log, event_id, level, username, source_ip,
                 destination_ip, source_port, destination_port, protocol,
                 message, severity, description, raw_xml, is_demo, computer, logon_type)
            VALUES
                (:timestamp, :source_log, :event_id, :level, :username, :source_ip,
                 :destination_ip, :source_port, :destination_port, :protocol,
                 :message, :severity, :description, :raw_xml, :is_demo, :computer, :logon_type)
        """
        params = {
            "timestamp":       ts,
            "source_log":      event.get("source_log", "Unknown"),
            "event_id":        event.get("event_id"),
            "level":           event.get("level"),
            "username":        event.get("username"),
            "source_ip":       event.get("source_ip"),
            "destination_ip":  event.get("destination_ip"),
            "source_port":     event.get("source_port"),
            "destination_port":event.get("destination_port"),
            "protocol":        event.get("protocol"),
            "message":         event.get("message"),
            "severity":        event.get("severity", "INFO"),
            "description":     event.get("description"),
            "raw_xml":         event.get("raw_xml"),
            "is_demo":         1 if event.get("is_demo") else 0,
            "computer":        event.get("computer"),
            "logon_type":      event.get("logon_type"),
        }
        try:
            conn = self.get_connection()
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid
        except sqlite3.Error as e:
            log.error("insert_event failed: %s", e)
            return -1

    def insert_events_bulk(self, events: List[Dict[str, Any]]) -> List[int]:
        """Insert multiple events efficiently. Returns list of row IDs."""
        ids = []
        for ev in events:
            row_id = self.insert_event(ev)
            if row_id > 0:
                ids.append(row_id)
        return ids

    def query_events(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 1000,
        offset: int = 0,
        order_by: str = "timestamp DESC",
    ) -> List[sqlite3.Row]:
        """
        Query events with optional filters.
        
        Supported filter keys:
            source_log, event_id, severity, username, source_ip,
            is_demo, keyword (searches message + description),
            from_time (ISO str), to_time (ISO str)
        """
        conditions = []
        params: Dict[str, Any] = {}

        if filters:
            if "source_log" in filters and filters["source_log"]:
                conditions.append("source_log = :source_log")
                params["source_log"] = filters["source_log"]
            if "event_id" in filters and filters["event_id"] is not None:
                conditions.append("event_id = :event_id")
                params["event_id"] = filters["event_id"]
            if "severity" in filters and filters["severity"]:
                conditions.append("severity = :severity")
                params["severity"] = filters["severity"]
            if "username" in filters and filters["username"]:
                conditions.append("username LIKE :username")
                params["username"] = f"%{filters['username']}%"
            if "source_ip" in filters and filters["source_ip"]:
                conditions.append("source_ip LIKE :source_ip")
                params["source_ip"] = f"%{filters['source_ip']}%"
            if "is_demo" in filters:
                conditions.append("is_demo = :is_demo")
                params["is_demo"] = 1 if filters["is_demo"] else 0
            if "keyword" in filters and filters["keyword"]:
                conditions.append("(message LIKE :kw OR description LIKE :kw)")
                params["kw"] = f"%{filters['keyword']}%"
            if "from_time" in filters and filters["from_time"]:
                conditions.append("timestamp >= :from_time")
                params["from_time"] = filters["from_time"]
            if "to_time" in filters and filters["to_time"]:
                conditions.append("timestamp <= :to_time")
                params["to_time"] = filters["to_time"]

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT * FROM events
            {where}
            ORDER BY {order_by}
            LIMIT :limit OFFSET :offset
        """
        params["limit"] = limit
        params["offset"] = offset

        try:
            conn = self.get_connection()
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error as e:
            log.error("query_events failed: %s", e)
            return []

    def get_event_by_id(self, event_id: int) -> Optional[sqlite3.Row]:
        """Fetch a single event row by its DB ID."""
        try:
            conn = self.get_connection()
            return conn.execute("SELECT * FROM events WHERE id = ?", (event_id,)).fetchone()
        except sqlite3.Error as e:
            log.error("get_event_by_id failed: %s", e)
            return None

    def count_events(self, filters: Optional[Dict[str, Any]] = None) -> int:
        """Return count of events matching the given filters."""
        rows = self.query_events(filters, limit=1_000_000)
        return len(rows)

    # ------------------------------------------------------------------
    # Incident operations
    # ------------------------------------------------------------------

    def insert_incident(self, incident: Dict[str, Any]) -> int:
        """Insert an incident and return its row ID."""
        def _ts(v):
            return v.isoformat() if isinstance(v, datetime) else v

        sql = """
            INSERT INTO incidents
                (attack_type, severity, status, source_ip, username,
                 first_seen, last_seen, description, detection_rule,
                 detection_reason, mitre_tactic, mitre_technique, event_count, is_demo)
            VALUES
                (:attack_type, :severity, :status, :source_ip, :username,
                 :first_seen, :last_seen, :description, :detection_rule,
                 :detection_reason, :mitre_tactic, :mitre_technique, :event_count, :is_demo)
        """
        params = {
            "attack_type":      incident.get("attack_type", "UNKNOWN"),
            "severity":         incident.get("severity", "INFO"),
            "status":           incident.get("status", "NEW"),
            "source_ip":        incident.get("source_ip"),
            "username":         incident.get("username"),
            "first_seen":       _ts(incident.get("first_seen")),
            "last_seen":        _ts(incident.get("last_seen")),
            "description":      incident.get("description"),
            "detection_rule":   incident.get("detection_rule"),
            "detection_reason": incident.get("detection_reason"),
            "mitre_tactic":     incident.get("mitre_tactic"),
            "mitre_technique":  incident.get("mitre_technique"),
            "event_count":      incident.get("event_count", 0),
            "is_demo":          1 if incident.get("is_demo") else 0,
        }
        try:
            conn = self.get_connection()
            cur = conn.execute(sql, params)
            conn.commit()
            return cur.lastrowid
        except sqlite3.Error as e:
            log.error("insert_incident failed: %s", e)
            return -1

    def link_event_to_incident(self, incident_id: int, event_id: int) -> None:
        """Create an association between an incident and an event."""
        try:
            conn = self.get_connection()
            conn.execute(
                "INSERT OR IGNORE INTO incident_events (incident_id, event_id) VALUES (?, ?)",
                (incident_id, event_id),
            )
            conn.commit()
        except sqlite3.Error as e:
            log.error("link_event_to_incident failed: %s", e)

    def get_incidents(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 200,
    ) -> List[sqlite3.Row]:
        """Query incidents with optional filters."""
        conditions = []
        params: Dict[str, Any] = {}

        if filters:
            if "status" in filters and filters["status"]:
                conditions.append("status = :status")
                params["status"] = filters["status"]
            if "severity" in filters and filters["severity"]:
                conditions.append("severity = :severity")
                params["severity"] = filters["severity"]
            if "attack_type" in filters and filters["attack_type"]:
                conditions.append("attack_type = :attack_type")
                params["attack_type"] = filters["attack_type"]
            if "is_demo" in filters:
                conditions.append("is_demo = :is_demo")
                params["is_demo"] = 1 if filters["is_demo"] else 0
            if "username" in filters and filters["username"]:
                conditions.append("username LIKE :username")
                params["username"] = f"%{filters['username']}%"
            if "source_ip" in filters and filters["source_ip"]:
                conditions.append("source_ip LIKE :source_ip")
                params["source_ip"] = f"%{filters['source_ip']}%"

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        sql = f"""
            SELECT * FROM incidents
            {where}
            ORDER BY last_seen DESC
            LIMIT :limit
        """
        params["limit"] = limit

        try:
            conn = self.get_connection()
            return conn.execute(sql, params).fetchall()
        except sqlite3.Error as e:
            log.error("get_incidents failed: %s", e)
            return []

    def get_incident_by_id(self, incident_id: int) -> Optional[sqlite3.Row]:
        try:
            conn = self.get_connection()
            return conn.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,)).fetchone()
        except sqlite3.Error as e:
            log.error("get_incident_by_id: %s", e)
            return None

    def get_incident_events(self, incident_id: int) -> List[sqlite3.Row]:
        """Return all events associated with a given incident, ordered by timestamp."""
        sql = """
            SELECT e.* FROM events e
            INNER JOIN incident_events ie ON ie.event_id = e.id
            WHERE ie.incident_id = ?
            ORDER BY e.timestamp ASC
        """
        try:
            conn = self.get_connection()
            return conn.execute(sql, (incident_id,)).fetchall()
        except sqlite3.Error as e:
            log.error("get_incident_events failed: %s", e)
            return []

    def update_incident_status(self, incident_id: int, new_status: str) -> None:
        """Update the status of an incident (e.g. INVESTIGATING, FALSE_POSITIVE, CLOSED)."""
        try:
            conn = self.get_connection()
            conn.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (new_status, incident_id),
            )
            conn.commit()
        except sqlite3.Error as e:
            log.error("update_incident_status failed: %s", e)

    # ------------------------------------------------------------------
    # Checkpoint operations (for incremental collection)
    # ------------------------------------------------------------------

    def get_checkpoint(self, source: str) -> Tuple[Optional[str], Optional[int]]:
        """
        Return (last_timestamp, last_record_number) for a log source.
        Returns (None, None) if no checkpoint exists yet.
        """
        try:
            conn = self.get_connection()
            row = conn.execute(
                "SELECT last_timestamp, last_record_number FROM checkpoints WHERE source = ?",
                (source,),
            ).fetchone()
            if row:
                return row["last_timestamp"], row["last_record_number"]
        except sqlite3.Error as e:
            log.error("get_checkpoint failed: %s", e)
        return None, None

    def update_checkpoint(
        self,
        source: str,
        last_timestamp: Optional[str],
        last_record_number: Optional[int] = None,
    ) -> None:
        """Upsert a checkpoint for a log source."""
        try:
            conn = self.get_connection()
            conn.execute(
                """
                INSERT INTO checkpoints (source, last_timestamp, last_record_number)
                VALUES (?, ?, ?)
                ON CONFLICT(source) DO UPDATE SET
                    last_timestamp     = excluded.last_timestamp,
                    last_record_number = excluded.last_record_number
                """,
                (source, last_timestamp, last_record_number),
            )
            conn.commit()
        except sqlite3.Error as e:
            log.error("update_checkpoint failed: %s", e)

    # ------------------------------------------------------------------
    # Statistics helpers
    # ------------------------------------------------------------------

    def get_statistics(self) -> Dict[str, Any]:
        """Return a dict of dashboard statistics."""
        conn = self.get_connection()
        stats: Dict[str, Any] = {}

        def scalar(sql: str, params=()) -> int:
            row = conn.execute(sql, params).fetchone()
            return row[0] if row and row[0] is not None else 0

        stats["total_events"]         = scalar("SELECT COUNT(*) FROM events WHERE is_demo = 0")
        stats["total_demo_events"]    = scalar("SELECT COUNT(*) FROM events WHERE is_demo = 1")
        stats["failed_logins"]        = scalar("SELECT COUNT(*) FROM events WHERE event_id = 4625 AND is_demo = 0")
        stats["successful_logins"]    = scalar("SELECT COUNT(*) FROM events WHERE event_id = 4624 AND is_demo = 0")
        stats["suspicious_events"]    = scalar("SELECT COUNT(*) FROM events WHERE severity IN ('HIGH','CRITICAL') AND is_demo = 0")
        stats["total_incidents"]      = scalar("SELECT COUNT(*) FROM incidents WHERE is_demo = 0")
        stats["active_incidents"]     = scalar("SELECT COUNT(*) FROM incidents WHERE status = 'NEW' AND is_demo = 0")
        stats["high_critical_incidents"] = scalar(
            "SELECT COUNT(*) FROM incidents WHERE severity IN ('HIGH','CRITICAL') AND is_demo = 0"
        )

        from datetime import timedelta
        now = datetime.utcnow()
        one_hour_ago = (now - timedelta(hours=1)).isoformat()
        one_day_ago  = (now - timedelta(days=1)).isoformat()
        stats["events_last_hour"] = scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND is_demo = 0", (one_hour_ago,)
        )
        stats["events_last_day"] = scalar(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ? AND is_demo = 0", (one_day_ago,)
        )

        # Same stats for demo
        stats["demo_failed_logins"]     = scalar("SELECT COUNT(*) FROM events WHERE event_id = 4625 AND is_demo = 1")
        stats["demo_successful_logins"] = scalar("SELECT COUNT(*) FROM events WHERE event_id = 4624 AND is_demo = 1")
        stats["demo_incidents"]         = scalar("SELECT COUNT(*) FROM incidents WHERE is_demo = 1")
        stats["demo_high_critical"]     = scalar(
            "SELECT COUNT(*) FROM incidents WHERE severity IN ('HIGH','CRITICAL') AND is_demo = 1"
        )

        return stats

    def get_events_over_time(self, hours: int = 24, is_demo: bool = False) -> List[Dict[str, Any]]:
        """Return event counts grouped by hour for the past N hours."""
        from datetime import timedelta
        now = datetime.utcnow()
        cutoff = (now - timedelta(hours=hours)).isoformat()
        sql = """
            SELECT strftime('%Y-%m-%d %H:00', timestamp) AS hour, COUNT(*) AS count
            FROM events
            WHERE timestamp >= ? AND is_demo = ?
            GROUP BY hour
            ORDER BY hour ASC
        """
        try:
            conn = self.get_connection()
            rows = conn.execute(sql, (cutoff, 1 if is_demo else 0)).fetchall()
            return [{"hour": r["hour"], "count": r["count"]} for r in rows]
        except sqlite3.Error as e:
            log.error("get_events_over_time: %s", e)
            return []

    def get_severity_distribution(self, is_demo: bool = False) -> Dict[str, int]:
        """Return count per severity level."""
        sql = "SELECT severity, COUNT(*) AS count FROM events WHERE is_demo = ? GROUP BY severity"
        try:
            conn = self.get_connection()
            rows = conn.execute(sql, (1 if is_demo else 0,)).fetchall()
            return {r["severity"]: r["count"] for r in rows}
        except sqlite3.Error as e:
            log.error("get_severity_distribution: %s", e)
            return {}

    def get_source_distribution(self, is_demo: bool = False) -> Dict[str, int]:
        """Return count per log source."""
        sql = "SELECT source_log, COUNT(*) AS count FROM events WHERE is_demo = ? GROUP BY source_log"
        try:
            conn = self.get_connection()
            rows = conn.execute(sql, (1 if is_demo else 0,)).fetchall()
            return {r["source_log"]: r["count"] for r in rows}
        except sqlite3.Error as e:
            log.error("get_source_distribution: %s", e)
            return {}

    def get_top_source_ips(self, limit: int = 10, is_demo: bool = False) -> List[Dict[str, Any]]:
        """Return top N source IPs by event count."""
        sql = """
            SELECT source_ip, COUNT(*) AS count
            FROM events
            WHERE source_ip IS NOT NULL AND is_demo = ?
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT ?
        """
        try:
            conn = self.get_connection()
            rows = conn.execute(sql, (1 if is_demo else 0, limit)).fetchall()
            return [{"ip": r["source_ip"], "count": r["count"]} for r in rows]
        except sqlite3.Error as e:
            log.error("get_top_source_ips: %s", e)
            return []

    def get_top_usernames(self, limit: int = 10, is_demo: bool = False) -> List[Dict[str, Any]]:
        """Return top N usernames targeted by failed logins."""
        sql = """
            SELECT username, COUNT(*) AS count
            FROM events
            WHERE event_id = 4625 AND username IS NOT NULL AND is_demo = ?
            GROUP BY username
            ORDER BY count DESC
            LIMIT ?
        """
        try:
            conn = self.get_connection()
            rows = conn.execute(sql, (1 if is_demo else 0, limit)).fetchall()
            return [{"username": r["username"], "count": r["count"]} for r in rows]
        except sqlite3.Error as e:
            log.error("get_top_usernames: %s", e)
            return []

    def clear_demo_data(self) -> None:
        """Remove all demo events and incidents from the database."""
        try:
            conn = self.get_connection()
            # Delete demo incident_events links
            conn.execute("""
                DELETE FROM incident_events WHERE incident_id IN
                (SELECT id FROM incidents WHERE is_demo = 1)
            """)
            conn.execute("DELETE FROM incidents WHERE is_demo = 1")
            conn.execute("DELETE FROM events WHERE is_demo = 1")
            conn.commit()
            log.info("Demo data cleared from database")
        except sqlite3.Error as e:
            log.error("clear_demo_data failed: %s", e)

    def clear_all_data(self) -> None:
        """Remove all events, incidents, links, and checkpoints from the database."""
        try:
            conn = self.get_connection()
            conn.execute("DELETE FROM incident_events")
            conn.execute("DELETE FROM incidents")
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM checkpoints")
            conn.commit()
            log.info("All records and checkpoints cleared from database")
        except sqlite3.Error as e:
            log.error("clear_all_data failed: %s", e)
