# =========================================================
# DATABASE MODULE
# CLOUD SECURITY LOG ANALYZER
# STEP 21 — PERFORMANCE OPTIMIZATION
# =========================================================

import sqlite3
import os


# =========================================================
# DATABASE PATH
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATABASE_DIR = os.path.join(
    BASE_DIR,
    "database"
)

DB_PATH = os.path.join(
    DATABASE_DIR,
    "security_events.db"
)


# =========================================================
# CREATE DATABASE DIRECTORY
# =========================================================

os.makedirs(
    DATABASE_DIR,
    exist_ok=True
)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10
    )

    conn.row_factory = sqlite3.Row

    return conn


# =========================================================
# DATABASE INITIALIZATION
# =========================================================

def setup_database():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            severity TEXT,

            event TEXT,

            message TEXT,

            ip_address TEXT,

            username TEXT,

            timestamp TEXT,

            created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP

        )
    """)

    conn.commit()

    conn.close()

    create_indexes()


# =========================================================
# PERFORMANCE INDEXES
# =========================================================

def create_indexes():

    conn = get_connection()

    cursor = conn.cursor()

    # -----------------------------------------------------
    # SEVERITY INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_severity
        ON events(severity)
    """)

    # -----------------------------------------------------
    # IP ADDRESS INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_ip
        ON events(ip_address)
    """)

    # -----------------------------------------------------
    # USERNAME INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_username
        ON events(username)
    """)

    # -----------------------------------------------------
    # TIMESTAMP INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_timestamp
        ON events(timestamp)
    """)

    # -----------------------------------------------------
    # EVENT TYPE INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_event
        ON events(event)
    """)

    # -----------------------------------------------------
    # CREATED AT INDEX
    # -----------------------------------------------------

    cursor.execute("""
        CREATE INDEX IF NOT EXISTS
        idx_events_created_at
        ON events(created_at)
    """)

    conn.commit()

    conn.close()


# =========================================================
# SAVE SECURITY EVENT
# =========================================================

def save_event(
    severity,
    event,
    message,
    ip_address="Unknown",
    username="Unknown",
    timestamp="Unknown"
):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO events (

            severity,
            event,
            message,
            ip_address,
            username,
            timestamp

        )

        VALUES (?, ?, ?, ?, ?, ?)
        """,

        (
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp
        )
    )

    conn.commit()

    conn.close()


# =========================================================
# GET ALL EVENTS
# =========================================================

def get_events():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp,
            created_at

        FROM events

        ORDER BY id DESC
        """
    )

    events = cursor.fetchall()

    conn.close()

    return events


# =========================================================
# GET RECENT EVENTS
# =========================================================

def get_recent_events(limit=100):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp,
            created_at

        FROM events

        ORDER BY id DESC

        LIMIT ?
        """,

        (limit,)
    )

    events = cursor.fetchall()

    conn.close()

    return events


# =========================================================
# GET EVENTS BY SEVERITY
# =========================================================

def get_events_by_severity(severity):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp,
            created_at

        FROM events

        WHERE severity = ?

        ORDER BY id DESC
        """,

        (severity,)
    )

    events = cursor.fetchall()

    conn.close()

    return events


# =========================================================
# GET EVENTS BY IP
# =========================================================

def get_events_by_ip(ip_address):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp,
            created_at

        FROM events

        WHERE ip_address = ?

        ORDER BY id DESC
        """,

        (ip_address,)
    )

    events = cursor.fetchall()

    conn.close()

    return events


# =========================================================
# GET EVENTS BY USERNAME
# =========================================================

def get_events_by_username(username):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            id,
            severity,
            event,
            message,
            ip_address,
            username,
            timestamp,
            created_at

        FROM events

        WHERE username = ?

        ORDER BY id DESC
        """,

        (username,)
    )

    events = cursor.fetchall()

    conn.close()

    return events


# =========================================================
# COUNT EVENTS
# =========================================================

def count_events():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        """
    )

    result = cursor.fetchone()

    conn.close()

    return result[0]


# =========================================================
# COUNT EVENTS BY SEVERITY
# =========================================================

def count_by_severity(severity):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT COUNT(*)
        FROM events
        WHERE severity = ?
        """,

        (severity,)
    )

    result = cursor.fetchone()

    conn.close()

    return result[0]


# =========================================================
# DATABASE STATISTICS
# =========================================================

def get_database_statistics():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            COUNT(*) AS total_events,

            SUM(
                CASE
                    WHEN severity = 'CRITICAL'
                    THEN 1
                    ELSE 0
                END
            ) AS critical_events,

            SUM(
                CASE
                    WHEN severity = 'HIGH'
                    THEN 1
                    ELSE 0
                END
            ) AS high_events,

            SUM(
                CASE
                    WHEN severity = 'MEDIUM'
                    THEN 1
                    ELSE 0
                END
            ) AS medium_events,

            SUM(
                CASE
                    WHEN severity = 'LOW'
                    THEN 1
                    ELSE 0
                END
            ) AS low_events

        FROM events
        """
    )

    result = cursor.fetchone()

    conn.close()

    return dict(result)


# =========================================================
# DELETE OLD EVENTS
# =========================================================

def delete_old_events(days=30):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        DELETE FROM events

        WHERE created_at <
        datetime(
            'now',
            ?
        )
        """,

        (
            f"-{int(days)} days",
        )
    )

    deleted = cursor.rowcount

    conn.commit()

    conn.close()

    return deleted


# =========================================================
# DATABASE OPTIMIZATION
# =========================================================

def optimize_database():

    conn = get_connection()

    cursor = conn.cursor()

    # Update SQLite query planner statistics
    cursor.execute(
        "ANALYZE"
    )

    # Reclaim unused database space
    cursor.execute(
        "VACUUM"
    )

    conn.commit()

    conn.close()


# =========================================================
# VERIFY INDEXES
# =========================================================

def get_indexes():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT
            name

        FROM sqlite_master

        WHERE type = 'index'

        AND tbl_name = 'events'

        ORDER BY name
        """
    )

    indexes = [
        row["name"]
        for row in cursor.fetchall()
    ]

    conn.close()

    return indexes


# =========================================================
# INITIALIZE DATABASE
# =========================================================

setup_database()


# =========================================================
# MAIN TEST
# =========================================================

if __name__ == "__main__":

    print(
        "Database:",
        DB_PATH
    )

    print(
        "Total events:",
        count_events()
    )

    print(
        "Indexes:"
    )

    for index in get_indexes():

        print(
            " -",
            index
        )

    print(
        "Database performance module OK"
    )
