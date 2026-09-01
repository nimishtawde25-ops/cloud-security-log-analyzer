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
# PROCESS ONE LOG LINE
# =========================================================

def process_line(line):

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


        try:

            save_event(
                severity,
                event,
                message,
                ip_address,
                username,
                timestamp
            )

            print(
                "[DATABASE] Event saved."
            )

        except Exception as error:

            print(
                "[DATABASE ERROR]"
            )

            print(error)


# =========================================================
# REAL-TIME MONITOR
# =========================================================

def monitor_log():

    print("=" * 60)
    print("CLOUD SECURITY REAL-TIME LOG MONITOR")
    print("=" * 60)

    print(
        f"Monitoring: {LOG_FILE}"
    )

    print(
        f"Check interval: {CHECK_INTERVAL} second(s)"
    )

    print(
        "Waiting for new log entries..."
    )

    print(
        "Press Ctrl+C to stop."
    )

    print("=" * 60)


    # -----------------------------------------------------
    # CHECK LOG FILE
    # -----------------------------------------------------

    if not os.path.exists(LOG_FILE):

        print()
        print(
            f"[ERROR] Log file not found: {LOG_FILE}"
        )

        return


    # -----------------------------------------------------
    # OPEN FILE
    # -----------------------------------------------------

    try:

        with open(
            LOG_FILE,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as logfile:

            # Start at the end of the file.
            # Existing entries are not processed again.

            logfile.seek(
                0,
                os.SEEK_END
            )


            while True:

                line = logfile.readline()


                # -------------------------------------------------
                # NEW LINE FOUND
                # -------------------------------------------------

                if line:

                    process_line(line)

                    continue


                # -------------------------------------------------
                # NO NEW LINE
                # -------------------------------------------------

                time.sleep(
                    CHECK_INTERVAL
                )


                # -------------------------------------------------
                # HANDLE LOG ROTATION / TRUNCATION
                # -------------------------------------------------

                try:

                    current_position = logfile.tell()

                    file_size = os.path.getsize(
                        LOG_FILE
                    )


                    if file_size < current_position:

                        print()
                        print(
                            "[INFO] Log file was reset or rotated."
                        )

                        logfile.seek(
                            0,
                            os.SEEK_SET
                        )

                except OSError:

                    pass


    except KeyboardInterrupt:

        print()
        print()
        print(
            "[MONITOR] Stopped by user."
        )


    except OSError as error:

        print()
        print(
            "[ERROR] Unable to monitor log file."
        )

        print(error)


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    monitor_log()
