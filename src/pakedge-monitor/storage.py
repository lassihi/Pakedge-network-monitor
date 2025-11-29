import sqlite3
import json
from datetime import datetime, timedelta


class Storage:
    def __init__(self, db_path: str) -> None:
        self.db_path = db_path
        self.connect = sqlite3.connect(self.db_path)
        self._init_tables()

    def _init_tables(self) -> None:
        c = self.connect.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            mac TEXT PRIMARY KEY,
            ip TEXT NULL,
            hostname TEXT,
            first_seen TEXT,
            last_seen TEXT,
            active TEXT
        );
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS leases (
            id INTEGER PRIMARY KEY,
            mac TEXT,
            ip TEXT,
            hostname TEXT,
            expires TEXT,
            first_seen TEXT,
            end_time TEXT,
            active TEXT,
            UNIQUE(mac, ip, expires)
        );
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS connections (
            source TEXT,
            source_port INTEGER,
            destination TEXT,
            destination_port INTEGER,
            start_time TEXT,
            end_time TEXT,
            bytes INTEGER,
            packets INTEGER,
            protocol TEXT,
            active INTEGER,
            UNIQUE(source, source_port, destination, destination_port)
        );
        """)

        c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            type TEXT,
            source TEXT,
            details TEXT,
            time TEXT
        );
        """)

        self.connect.commit()

    def upsert_devices(self, mac: str, ip: str, hostname: str, first_seen: str, last_seen: str, active=True) -> None:
        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()
        c.execute("""
        INSERT INTO devices (mac, ip, hostname, first_seen, last_seen, active)
        VALUES(?,?,?,?,?,?)
        ON CONFLICT(mac) DO UPDATE SET
            ip=excluded.ip,
            hostname=excluded.hostname,
            first_seen=excluded.first_seen,
            last_seen=excluded.last_seen,
            active=excluded.active;
        """, (mac, ip, hostname, first_seen, last_seen, int(active)))
        self.connect.commit()

    def insert_leases(self, leases: list) -> None:
        if not leases:
            return

        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()
        mapped_leases = []
        for l in leases:
            mapped_leases.append({
                "mac": l["mac"],
                "ip": l["ip"],
                "hostname": l.get("hostname"),
                "first_seen": l["ts"],
                "expires": l["expires"],
                "end_time": l["end_time"],
                "active": int(l["active"])
            })

        c.executemany("""
        INSERT INTO leases (mac, ip, hostname, first_seen, expires, end_time, active)
        VALUES (:mac, :ip, :hostname, :first_seen, :expires, :end_time, :active)
        ON CONFLICT(mac, ip, expires) DO UPDATE SET
            hostname = COALESCE(excluded.hostname, hostname),
            first_seen = excluded.first_seen,
            end_time = excluded.end_time,
            active = excluded.active""", mapped_leases)

        self.connect.commit()

    def insert_connections(self, connections: list) -> None:
        if not connections:
            return

        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()
        mapped_connections = []

        for con in connections:
            if isinstance(c, dict):
                mapped_connections.append({
                    "source": con["source"],
                    "source_port": con["source_port"],
                    "destination": con["destination"],
                    "destination_port": con["destination_port"],
                    "start_time": con.get("start_time"),
                    "end_time": con.get("end_time"),
                    "bytes": con.get("bytes", 0),
                    "packets": con.get("packets", 0),
                    "protocol": con["protocol"],
                    "active": int(con.get("active", True)),
                })
            else:
                mapped_connections.append({
                    "source": con.source,
                    "source_port": con.source_port,
                    "destination": con.destination,
                    "destination_port": con.destination_port,
                    "start_time": con.start_time,
                    "end_time": con.end_time,
                    "bytes": con.bytes,
                    "packets": con.packets,
                    "protocol": con.protocol,
                    "active": int(getattr(con, "active", True)),
                })

        c.executemany("""
        INSERT INTO connections (
            source, source_port, destination, destination_port,
            start_time, end_time, bytes, packets, protocol, active
        )
        VALUES (
            :source, :source_port, :destination, :destination_port,
            :start_time, :end_time, :bytes, :packets, :protocol, :active
        )
        ON CONFLICT(source, source_port, destination, destination_port)
        DO UPDATE SET
            bytes = excluded.bytes,
            packets = excluded.packets,
            end_time = excluded.end_time,
            active = excluded.active;
        """, mapped_connections)

        self.connect.commit()

    def set_all_inactive(self, table: str) -> None:
        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()

        allowed = {"devices", "leases", "connections"}
        if table not in allowed:
            raise ValueError(f"Invalid table name: {table}")

        c.execute(f"UPDATE {table} SET active = 0 WHERE active = 1")

        self.connect.commit()

    def insert_alerts(self, alerts: list) -> None:
        if not alerts:
            return

        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()

        mapped_alerts = []
        for a in alerts:
            mapped_alerts.append({
                "type": a["type"],
                "source": a["source"],
                "details": json.dumps(a["details"], ensure_ascii=False),
                "time": a["time"]
            })

        c.executemany("""
        INSERT INTO alerts (type, source, details, time)
        VALUES (:type, :source, :details, :time)
        """, mapped_alerts)

        self.connect.commit()

    def close_connection(self) -> None:
        if self.connect:
            self.connect.close()
            self.connect = None

    def cleanup_connections(self, days=9) -> None:
        cutoff = (datetime.now() - timedelta(days=days)).isoformat()

        if self.connect is None:
            self.connect = sqlite3.connect(self.db_path)

        c = self.connect.cursor()
        c.execute(
            "DELETE FROM connections WHERE active = 0 AND end_time < ?", (cutoff,))
        deleted = c.rowcount

        self.connect.commit()

    def query_select(self, sql: str, params=()) -> list:
        if not sql.strip().lower().startswith("select"):
            raise ValueError("Only SELECT statements are allowed")
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            rows = c.execute(sql, params).fetchall()
            return rows
        finally:
            conn.close()

    def get_schema(self) -> list:
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            tables = c.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
            schema = []
            for (table_name,) in tables:
                if table_name.startswith("sqlite_"):
                    continue
                columns = c.execute(
                    f"PRAGMA table_info({table_name})").fetchall()
                schema.append((table_name, columns))
            return schema
        finally:
            conn.close()

    def get_devices(self) -> list:
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            rows = c.execute(
                """
                SELECT hostname, ip, mac
                FROM devices
                WHERE active = 1
                ORDER BY ip ASC
                """
            ).fetchall()
            return rows
        finally:
            conn.close()

    def get_alerts(self) -> list:
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            rows = c.execute(
                """
                SELECT type, source, time
                FROM alerts
                ORDER BY time DESC
                """
            ).fetchall()
            return rows
        finally:
            conn.close()

    def get_active_connections_from_ip(self, ip: str) -> list:
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            rows = c.execute(
                """
                SELECT destination, destination_port, start_time, protocol
                FROM connections
                WHERE active = 1 AND source = ?
                ORDER BY start_time DESC
                """,
                (ip,)
            ).fetchall()
            return rows
        finally:
            conn.close()

    def get_leases(self) -> list:
        conn = sqlite3.connect(self.db_path)
        try:
            c = conn.cursor()
            rows = c.execute(
                """
                SELECT hostname, ip, mac, expires
                FROM leases
                WHERE active = 1
                ORDER BY expires DESC
                """
            ).fetchall()
            return rows
        finally:
            conn.close()