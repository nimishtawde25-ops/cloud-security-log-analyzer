# =========================================================
# NOTIFICATION CONFIGURATION
# =========================================================

NOTIFICATIONS_ENABLED = True

# Minimum severity that can trigger a notification.
#
# LOW
# MEDIUM
# HIGH
# CRITICAL

MINIMUM_SEVERITY = "HIGH"


# Console notifications are useful during the
# development/testing stage.

CONSOLE_NOTIFICATIONS = True


# Email is disabled for now.
# We will configure it safely in the next part.

EMAIL_NOTIFICATIONS = False


# =========================================================
# SEVERITY PRIORITY
# =========================================================

SEVERITY_PRIORITY = {

    "LOW": 1,

    "MEDIUM": 2,

    "HIGH": 3,

    "CRITICAL": 4

}


# =========================================================
# CHECK WHETHER NOTIFICATION IS REQUIRED
# =========================================================

def should_notify(severity):

    if not NOTIFICATIONS_ENABLED:

        return False


    severity = str(
        severity
    ).upper()


    minimum = str(
        MINIMUM_SEVERITY
    ).upper()


    current_priority = (
        SEVERITY_PRIORITY.get(
            severity,
            0
        )
    )


    minimum_priority = (
        SEVERITY_PRIORITY.get(
            minimum,
            3
        )
    )


    return (
        current_priority
        >=
        minimum_priority
    )
