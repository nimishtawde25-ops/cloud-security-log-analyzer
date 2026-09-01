from flask import (
    Flask,
    render_template,
    request,
    redirect,
    Response,
    session
)

from werkzeug.utils import secure_filename
from flask_talisman import Talisman

from analyzer.log_analyzer import (
    analyze_log,
    analyze_suspicious_ips,
    detect_brute_force,
    generate_alerts,
    classify_incidents,
    generate_correlated_threats
)

from database.database import (
    save_event,
    get_events
)

import csv
import io
import os


# =========================================================
# APPLICATION
# =========================================================

app = Flask(__name__)


# =========================================================
# FLASK SECURITY CONFIGURATION
# =========================================================

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "development-secret-change-me"
)

app.config.update(

    # Session security
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    # Local development uses HTTP
    SESSION_COOKIE_SECURE=False,

    # Maximum uploaded file size = 5 MB
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,

    # Disable unnecessary browser caching
    SEND_FILE_MAX_AGE_DEFAULT=0
)


# =========================================================
# SECURITY HEADERS
# =========================================================

Talisman(
    app,

    # Do NOT force HTTPS on local development
    force_https=False,

    # Keep compatible with the existing templates
    content_security_policy=False
)


# =========================================================
# LOGIN CONFIGURATION
# =========================================================

USERNAME = os.environ.get(
    "APP_USERNAME",
    "admin"
)

PASSWORD = os.environ.get(
    "APP_PASSWORD",
    "admin123"
)


# =========================================================
# ALLOWED LOG FILE TYPES
# =========================================================

ALLOWED_EXTENSIONS = {
    ".log",
    ".txt"
}


# =========================================================
# LOGIN CHECK
# =========================================================

def login_required():

    return session.get(
        "logged_in",
        False
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if login_required():

        return redirect("/")

    error = None

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if (
            username == USERNAME
            and
            password == PASSWORD
        ):

            session["logged_in"] = True

            return redirect("/")

        error = "Invalid username or password"

    return render_template(
        "login.html",
        error=error
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")


# =========================================================
# DASHBOARD
# =========================================================

@app.route(
    "/",
    methods=["GET", "POST"]
)
def index():

    # -----------------------------------------------------
    # AUTHENTICATION
    # -----------------------------------------------------

    if not login_required():

        return redirect("/login")


    # =====================================================
    # LOG FILE UPLOAD
    # =====================================================

    if request.method == "POST":

        uploaded_file = request.files.get(
            "log_file"
        )

        if (
            uploaded_file
            and
            uploaded_file.filename
        ):

            # -------------------------------------------------
            # SECURE FILENAME
            # -------------------------------------------------

            safe_filename = secure_filename(
                uploaded_file.filename
            )

            if not safe_filename:

                return redirect("/")


            # -------------------------------------------------
            # FILE EXTENSION CHECK
            # -------------------------------------------------

            extension = os.path.splitext(
                safe_filename
            )[1].lower()

            if extension not in ALLOWED_EXTENSIONS:

                return redirect("/")


            # -------------------------------------------------
            # READ LOG FILE
            # -------------------------------------------------

            try:

                log_data = uploaded_file.read().decode(
                    "utf-8",
                    errors="ignore"
                )


                # -------------------------------------------------
                # ANALYZE LOG
                # -------------------------------------------------

                results = analyze_log(
                    log_data
                )


                # -------------------------------------------------
                # SAVE EVENTS
                # -------------------------------------------------

                for result in results:

                    save_event(

                        result.get(
                            "severity",
                            "LOW"
                        ),

                        result.get(
                            "event",
                            "Unknown"
                        ),

                        result.get(
                            "message",
                            ""
                        ),

                        result.get(
                            "ip_address",
                            "Unknown"
                        ),

                        result.get(
                            "username",
                            "Unknown"
                        ),

                        result.get(
                            "timestamp",
                            "Unknown"
                        )

                    )


            except Exception as error:

                print(
                    "Log upload error:",
                    error
                )


            return redirect("/")


    # =====================================================
    # GET DATABASE EVENTS
    # =====================================================

    try:

        raw_events = get_events()

        events = [
            dict(event)
            for event in raw_events
        ]

    except Exception as error:

        print(
            "Database error:",
            error
        )

        events = []


    # =====================================================
    # BRUTE FORCE DETECTION
    # =====================================================

    try:

        brute_force_alerts = detect_brute_force(
            events
        )

    except Exception as error:

        print(
            "Brute force error:",
            error
        )

        brute_force_alerts = []


    # =====================================================
    # ADVANCED ALERT GENERATION
    # =====================================================

    try:

        advanced_alerts = generate_alerts(
            events
        )

    except Exception as error:

        print(
            "Advanced alert error:",
            error
        )

        advanced_alerts = []


    # =====================================================
    # INCIDENT CLASSIFICATION
    # =====================================================

    try:

        classified_alerts = classify_incidents(
            advanced_alerts
        )

    except Exception as error:

        print(
            "Classification error:",
            error
        )

        classified_alerts = []


    # =====================================================
    # THREAT CORRELATION
    # =====================================================

    try:

        correlated_alerts = generate_correlated_threats(
            events
        )

    except Exception as error:

        print(
            "Correlation error:",
            error
        )

        correlated_alerts = []


    # =====================================================
    # COMBINE ALERTS
    # =====================================================

    alerts = []

    alerts.extend(
        classified_alerts
    )

    alerts.extend(
        correlated_alerts
    )


    # =====================================================
    # ADD BRUTE FORCE ALERTS
    # =====================================================

    for alert in brute_force_alerts:

        duplicate = any(

            existing.get("type")
            ==
            alert.get("type")

            and

            existing.get("ip_address")
            ==
            alert.get("ip_address")

            for existing in alerts

        )

        if not duplicate:

            alerts.append(
                alert
            )


    # =====================================================
    # SUSPICIOUS IP ANALYSIS
    # =====================================================

    try:

        suspicious_ips = analyze_suspicious_ips(
            events
        )

    except Exception as error:

        print(
            "Suspicious IP error:",
            error
        )

        suspicious_ips = {}


    # =====================================================
    # FILTERS
    # =====================================================

    severity_filter = request.args.get(
        "severity",
        ""
    ).strip().upper()

    event_filter = request.args.get(
        "event",
        ""
    ).strip().lower()

    ip_filter = request.args.get(
        "ip",
        ""
    ).strip()


    filtered_events = []


    for event in events:

        # -------------------------------------------------
        # SEVERITY FILTER
        # -------------------------------------------------

        if severity_filter:

            event_severity = str(
                event.get(
                    "severity",
                    ""
                )
            ).upper()

            if event_severity != severity_filter:

                continue


        # -------------------------------------------------
        # EVENT FILTER
        # -------------------------------------------------

        if event_filter:

            event_name = str(
                event.get(
                    "event",
                    ""
                )
            ).lower()

            if event_filter not in event_name:

                continue


        # -------------------------------------------------
        # IP FILTER
        # -------------------------------------------------

        if ip_filter:

            event_ip = str(
                event.get(
                    "ip_address",
                    ""
                )
            )

            if ip_filter not in event_ip:

                continue


        filtered_events.append(
            event
        )


    # =====================================================
    # ALERT STATISTICS
    # =====================================================

    total_alerts = len(
        alerts
    )


    critical_alerts = sum(

        1

        for alert in alerts

        if str(
            alert.get(
                "severity",
                ""
            )
        ).upper()
        == "CRITICAL"

    )


    high_alerts = sum(

        1

        for alert in alerts

        if str(
            alert.get(
                "severity",
                ""
            )
        ).upper()
        == "HIGH"

    )


    medium_alerts = sum(

        1

        for alert in alerts

        if str(
            alert.get(
                "severity",
                ""
            )
        ).upper()
        == "MEDIUM"

    )


    low_alerts = sum(

        1

        for alert in alerts

        if str(
            alert.get(
                "severity",
                ""
            )
        ).upper()
        == "LOW"

    )


    # =====================================================
    # EVENT STATISTICS
    # =====================================================

    total_events = len(
        events
    )


    critical_events = sum(

        1

        for event in events

        if str(
            event.get(
                "severity",
                ""
            )
        ).upper()
        == "CRITICAL"

    )


    high_events = sum(

        1

        for event in events

        if str(
            event.get(
                "severity",
                ""
            )
        ).upper()
        == "HIGH"

    )


    medium_events = sum(

        1

        for event in events

        if str(
            event.get(
                "severity",
                ""
            )
        ).upper()
        == "MEDIUM"

    )


    low_events = sum(

        1

        for event in events

        if str(
            event.get(
                "severity",
                ""
            )
        ).upper()
        == "LOW"

    )


    # =====================================================
    # EVENT TYPE COUNTS
    # =====================================================

    failed_logins = sum(

        1

        for event in events

        if "failed login"
        in str(
            event.get(
                "event",
                ""
            )
        ).lower()

    )


    unauthorized_events = sum(

        1

        for event in events

        if "unauthorized"
        in str(
            event.get(
                "event",
                ""
            )
        ).lower()

    )


    permission_denied = sum(

        1

        for event in events

        if "permission denied"
        in str(
            event.get(
                "event",
                ""
            )
        ).lower()

    )


    successful_logins = sum(

        1

        for event in events

        if (
            "successful login"
            in str(
                event.get(
                    "event",
                    ""
                )
            ).lower()
        )

        or

        (
            "logged in successfully"
            in str(
                event.get(
                    "message",
                    ""
                )
            ).lower()
        )

    )


    # =====================================================
    # UNIQUE IP COUNT
    # =====================================================

    unique_ips = set(

        str(
            event.get(
                "ip_address",
                ""
            )
        )

        for event in events

        if event.get(
            "ip_address"
        )

    )


    unique_ip_count = len(
        unique_ips
    )


    # =====================================================
    # HIGH RISK IP COUNT
    # =====================================================

    high_risk_ips = 0


    if isinstance(
        suspicious_ips,
        dict
    ):

        high_risk_ips = sum(

            1

            for score
            in suspicious_ips.values()

            if isinstance(
                score,
                (int, float)
            )

            and score >= 6

        )


    # =====================================================
    # INCIDENT TYPE COUNTS
    # =====================================================

    incident_types = {}


    for alert in alerts:

        incident_type = alert.get(

            "incident_type",

            alert.get(
                "type",
                "UNKNOWN"
            )

        )

        incident_types[
            incident_type
        ] = (

            incident_types.get(
                incident_type,
                0
            )

            + 1

        )


    # =====================================================
    # SORT ALERTS BY RISK
    # =====================================================

    alerts.sort(

        key=lambda alert:

        int(
            alert.get(
                "risk_score",
                0
            )
            or
            0
        ),

        reverse=True

    )


    # =====================================================
    # RENDER DASHBOARD
    # =====================================================

    return render_template(

        "index.html",

        # -------------------------------------------------
        # EVENTS
        # -------------------------------------------------

        events=filtered_events,

        all_events=events,

        total_events=total_events,

        critical_events=critical_events,

        high_events=high_events,

        medium_events=medium_events,

        low_events=low_events,


        # -------------------------------------------------
        # ALERTS
        # -------------------------------------------------

        alerts=alerts,

        total_alerts=total_alerts,

        critical_alerts=critical_alerts,

        high_alerts=high_alerts,

        medium_alerts=medium_alerts,

        low_alerts=low_alerts,


        # -------------------------------------------------
        # DETECTION RESULTS
        # -------------------------------------------------

        brute_force_alerts=brute_force_alerts,

        classified_alerts=classified_alerts,

        correlated_alerts=correlated_alerts,

        suspicious_ips=suspicious_ips,

        incident_types=incident_types,


        # -------------------------------------------------
        # EVENT TYPE STATISTICS
        # -------------------------------------------------

        failed_logins=failed_logins,

        unauthorized_events=unauthorized_events,

        permission_denied=permission_denied,

        successful_logins=successful_logins,


        # -------------------------------------------------
        # IP STATISTICS
        # -------------------------------------------------

        unique_ip_count=unique_ip_count,

        high_risk_ips=high_risk_ips,


        # -------------------------------------------------
        # FILTER VALUES
        # -------------------------------------------------

        severity_filter=severity_filter,

        event_filter=event_filter,

        ip_filter=ip_filter

    )


# =========================================================
# CSV EXPORT
# =========================================================

@app.route("/export")
def export_csv():

    if not login_required():

        return redirect("/login")


    try:

        raw_events = get_events()

        events = [
            dict(event)
            for event in raw_events
        ]

    except Exception:

        events = []


    output = io.StringIO()

    writer = csv.writer(
        output
    )


    writer.writerow([

        "ID",
        "Severity",
        "Event",
        "Message",
        "IP Address",
        "Username",
        "Timestamp",
        "Created At"

    ])


    for event in events:

        writer.writerow([

            event.get(
                "id",
                ""
            ),

            event.get(
                "severity",
                ""
            ),

            event.get(
                "event",
                ""
            ),

            event.get(
                "message",
                ""
            ),

            event.get(
                "ip_address",
                ""
            ),

            event.get(
                "username",
                ""
            ),

            event.get(
                "timestamp",
                ""
            ),

            event.get(
                "created_at",
                ""
            )

        ])


    response = Response(

        output.getvalue(),

        mimetype="text/csv"

    )


    response.headers[
        "Content-Disposition"
    ] = (
        "attachment; "
        "filename=security_events.csv"
    )


    return response


# =========================================================
# HEALTH CHECK
# =========================================================

@app.route("/health")
def health():

    return {

        "status": "online",

        "service":
            "Cloud Security Log Analyzer"

    }


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(

        host="127.0.0.1",

        port=5000,

        debug=True

    )
