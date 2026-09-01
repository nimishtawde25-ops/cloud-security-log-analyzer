# =========================================================
# NOTIFICATION ENGINE
# =========================================================

from notifications.config import (
    CONSOLE_NOTIFICATIONS,
    should_notify
)


# =========================================================
# NOTIFICATION MEMORY
# =========================================================

# Keeps track of alerts already notified during the
# current application run.

_notified_alerts = set()


# =========================================================
# CREATE ALERT IDENTIFIER
# =========================================================

def get_alert_identifier(alert):

    return (
        str(alert.get("severity", ""))
        + "|"
        + str(alert.get("type", ""))
        + "|"
        + str(alert.get("message", ""))
        + "|"
        + str(alert.get("ip_address", ""))
        + "|"
        + str(alert.get("username", ""))
        + "|"
        + str(alert.get("timestamp", ""))
    )


# =========================================================
# CONSOLE NOTIFICATION
# =========================================================

def send_console_notification(alert):

    print()
    print("=" * 60)
    print("🚨 SECURITY NOTIFICATION")
    print("=" * 60)

    print(
        f"Severity   : {alert.get('severity', 'UNKNOWN')}"
    )

    print(
        f"Alert Type : {alert.get('type', 'SECURITY_ALERT')}"
    )

    print(
        f"Message    : {alert.get('message', 'Unknown alert')}"
    )

    print(
        f"IP Address : {alert.get('ip_address', 'Unknown')}"
    )

    print(
        f"Username   : {alert.get('username', 'Unknown')}"
    )

    print(
        f"Risk Score : {alert.get('risk_score', 0)}"
    )

    print(
        f"Risk Level : {alert.get('risk_level', 'UNKNOWN')}"
    )

    print("=" * 60)
    print()


# =========================================================
# SEND SINGLE NOTIFICATION
# =========================================================

def send_notification(alert):

    if not isinstance(alert, dict):

        return False


    severity = alert.get(
        "severity",
        "LOW"
    )


    # -----------------------------------------------------
    # CHECK SEVERITY
    # -----------------------------------------------------

    if not should_notify(
        severity
    ):

        return False


    # -----------------------------------------------------
    # CREATE UNIQUE IDENTIFIER
    # -----------------------------------------------------

    alert_id = get_alert_identifier(
        alert
    )


    # -----------------------------------------------------
    # DUPLICATE CHECK
    # -----------------------------------------------------

    if alert_id in _notified_alerts:

        return False


    # -----------------------------------------------------
    # SEND CONSOLE NOTIFICATION
    # -----------------------------------------------------

    if CONSOLE_NOTIFICATIONS:

        send_console_notification(
            alert
        )

        _notified_alerts.add(
            alert_id
        )

        return True


    return False


# =========================================================
# SEND MULTIPLE NOTIFICATIONS
# =========================================================

def send_notifications(alerts):

    if not alerts:

        return 0


    notification_count = 0


    for alert in alerts:

        if send_notification(
            alert
        ):

            notification_count += 1


    return notification_count


# =========================================================
# CLEAR NOTIFICATION MEMORY
# =========================================================

def clear_notification_memory():

    _notified_alerts.clear()
