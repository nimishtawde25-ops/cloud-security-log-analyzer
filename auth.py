import os
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash


DATABASE = "database/security_events.db"


# =========================================================
# CREATE USERS TABLE
# =========================================================

def init_users_table():

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    connection.commit()
    connection.close()


# =========================================================
# CREATE USER
# =========================================================

def create_user(username, password):

    connection = sqlite3.connect(DATABASE)

    cursor = connection.cursor()

    password_hash = generate_password_hash(password)

    try:

        cursor.execute(
            """
            INSERT INTO users
            (username, password_hash)
            VALUES (?, ?)
            """,
            (
                username,
                password_hash
            )
        )

        connection.commit()

        print(
            "[AUTH] User created successfully."
        )

        return True

    except sqlite3.IntegrityError:

        print(
            "[AUTH] Username already exists."
        )

        return False

    finally:

        connection.close()


# =========================================================
# VERIFY LOGIN
# =========================================================

def verify_user(username, password):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()


    if user is None:

        return False


    return check_password_hash(
        user["password_hash"],
        password
    )


# =========================================================
# GET USER
# =========================================================

def get_user(username):

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    cursor = connection.cursor()

    cursor.execute(
        """
        SELECT id, username, created_at
        FROM users
        WHERE username = ?
        """,
        (username,)
    )

    user = cursor.fetchone()

    connection.close()

    return user
