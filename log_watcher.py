import os
import time

from analyzer.log_analyzer import analyze_log
from database.database import save_event


# =========================================================
# CONFIGURATION
# =========================================================

LOG_FILE = "logs/sample.log"

CHECK_INTERVAL = 1


# =========================================================
# PROCESS SECURITY EVENT
# =========================================================

def process_line(line):
    """
    Analyze one newly-added log line and save
    detected security events into SQLite.
    """

    line = line.strip()

    if not line:
        return

    print()
    print("=" * 60)
    print("NEW LOG ENTRY")
    print("=" * 60)
    print(line)

    try:
        results = analyze_log(line)

    except Exception as error:
        print()
        print("[ERROR] Analyzer failed:")
        print(error)
        return

    if not results:
        print("[INFO] No security event detected.")
        return

    for result in results:

        severity = result.get(
            "severity",
            "LOW"
        )

        event = result.get(
            "event",
            "Unknown Event"
        )

        message = result.get(
            "message",
            line
        )

        ip_address = result.get(
            "ip_address",
            "Unknown"
        )

        username = result.get(
            "username",
            "Unknown"
        )

        timestamp = result.get(
            "timestamp",
            "Unknown"
        )


        # -------------------------------------------------
        # SECURITY EVENT
        # -------------------------------------------------

        print()
        print("[SECURITY EVENT DETECTED]")

        print(
            f"Severity   : {severity}"
        )

        print(
            f"Event      : {event}"
        )

        print(
            f"IP Address : {ip_address}"
        )

        print(
            f"Username   : {username}"
        )

        print(
            f"Timestamp  : {timestamp}"
        )


        # -------------------------------------------------
        # HIGH SEVERITY ALERT
        # -------------------------------------------------

        if severity.upper() == "HIGH":

            print()
            print("🚨" + "=" * 56)
            print("🚨 CRITICAL SECURITY ALERT")
            print("🚨 HIGH-SEVERITY EVENT DETECTED")
            print("🚨" + "=" * 56)

            print(
                f"🚨 Event      : {event}"
            )

            print(
                f"🚨 IP Address : {ip_address}"
            )

            print(
                f"🚨 Username   : {username}"
            )

            print("🚨" + "=" * 56)
            print()


        # -------------------------------------------------
        # SAVE EVENT TO DATABASE
        # -------------------------------------------------

        try:

            saved = save_event(
                severity,
                event,
                message,
                ip_address,
                username,
                timestamp
            )

            if saved is False:

                print(
                    "[DATABASE] Duplicate event ignored."
                )

            else:

                print(
                    "[DATABASE] Event processed successfully."
                )

        except Exception as error:

            print()
            print(
                "[ERROR] Database save failed:"
            )

            print(error)


# =========================================================
# GET INITIAL FILE POSITION
# =========================================================

def get_start_position():

    """
    Start watching from the current end of the file.

    Existing old log entries are not processed again
    when the watcher starts.
    """

    try:

        return os.path.getsize(LOG_FILE)

    except FileNotFoundError:

        return 0


# =========================================================
# LOG WATCHER
# =========================================================

def watch_log():

    print()
    print("=" * 60)
    print("CLOUD SECURITY LOG WATCHER")
    print("=" * 60)

    print(
        f"Watching: {LOG_FILE}"
    )

    print(
        f"Check interval: {CHECK_INTERVAL} second(s)"
    )

    print()
    print(
        "Waiting for new log entries..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print("=" * 60)


    position = get_start_position()


    while True:

        try:

            # -------------------------------------------------
            # CHECK FILE EXISTS
            # -------------------------------------------------

            if not os.path.exists(LOG_FILE):

                print(
                    f"[WARNING] Log file not found: {LOG_FILE}"
                )

                time.sleep(
                    CHECK_INTERVAL
                )

                continue


            # -------------------------------------------------
            # GET CURRENT FILE SIZE
            # -------------------------------------------------

            current_size = os.path.getsize(
                LOG_FILE
            )


            # -------------------------------------------------
            # FILE WAS RESET OR TRUNCATED
            # -------------------------------------------------

            if current_size < position:

                print()
                print(
                    "[INFO] Log file was reset."
                )

                position = 0


            # -------------------------------------------------
            # NEW LOG DATA
            # -------------------------------------------------

            if current_size > position:

                with open(
                    LOG_FILE,
                    "r",
                    encoding="utf-8",
                    errors="ignore"
                ) as log_file:

                    log_file.seek(position)

                    new_data = log_file.read()

                    position = log_file.tell()


                # -------------------------------------------------
                # PROCESS NEW LINES
                # -------------------------------------------------

                lines = new_data.splitlines()


                for line in lines:

                    process_line(line)


            # -------------------------------------------------
            # WAIT BEFORE NEXT CHECK
            # -------------------------------------------------

            time.sleep(
                CHECK_INTERVAL
            )


        except KeyboardInterrupt:

            print()
            print()

            print(
                "Log watcher stopped."
            )

            break


        except Exception as error:

            print()
            print(
                "[ERROR] Watcher error:"
            )

            print(error)

            time.sleep(
                CHECK_INTERVAL
            )


# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":

    watch_log()
