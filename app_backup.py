from flask import Flask, render_template, request, redirect, Response

from analyzer.log_analyzer import (
    analyze_log,
    analyze_suspicious_ips,
    detect_brute_force
)

from database.database import (
    save_event,
    get_events
)

import csv
import io


app = Flask(__name__)


# =========================================================
# DASHBOARD
# =========================================================

@app.route("/", methods=["GET", "POST"])
def index():

    # -----------------------------------------------------
    # LOG FILE UPLOAD
    # -----------------------------------------------------

    if request.method == "POST":

        uploaded_file = request.files.get("log_file")

        if uploaded_file and uploaded_file.filename:

            log_data = uploaded_file.read().decode(
                "utf-8",
                errors="ignore"
            )

            results = analyze_log(log_data)

            for result in results:

                save_event(
                    result["severity"],
                    result["event"],
                    result["message"],
                    result.get("ip_address", "Unknown"),
                    result.get("username", "Unknown"),
                    result.get("timestamp", "Unknown")
                )

            return redirect("/")


    # -----------------------------------------------------
    # GET EVENTS
    # -----------------------------------------------------

    events = get_events()

    events = [
        dict(event)
        for event in events
    ]


    # -----------------------------------------------------
    # BRUTE FORCE ALERTS
    # -----------------------------------------------------

    alerts = detect_brute_force(events)


    # -----------------------------------------------------
    # FILTERS
    # -----------------------------------------------------

    severity_filter = request.args.get(
        "severity",
        ""
    )

    event_filter = request.args.get(
        "event",
        ""
    )

    ip_filter = request.args.get(
        "ip",
        ""
    )


    filtered_events = []


    for event in events:

        if severity_filter:

            if event["severity"] != severity_filter:
                continue


        if event_filter:

            if event["event"] != event_filter:
                continue


        if ip_filter:

            ip_address = str(
                event["ip_address"]
            )

            if ip_filter.lower() not in ip_address.lower():
                continue


        filtered_events.append(event)


    # -----------------------------------------------------
    # SECURITY STATISTICS
    # -----------------------------------------------------

    total_events = len(events)


    high_events = sum(
        1
        for event in events
        if event["severity"] == "HIGH"
    )


    medium_events = sum(
        1
        for event in events
        if event["severity"] == "MEDIUM"
    )


    low_events = sum(
        1
        for event in events
        if event["severity"] == "LOW"
    )


    failed_logins = sum(
        1
        for event in events
        if event["event"] == "Failed Login"
    )


    # -----------------------------------------------------
    # SEVERITY CHART
    # -----------------------------------------------------

    severity_counts = {

        "HIGH": high_events,

        "MEDIUM": medium_events,

        "LOW": low_events

    }


    # -----------------------------------------------------
    # EVENT TYPE COUNTS
    # -----------------------------------------------------

    event_counts = {}


    for event in events:

        event_name = event["event"]

        if event_name not in event_counts:

            event_counts[event_name] = 0


        event_counts[event_name] += 1


    # -----------------------------------------------------
    # SECURITY TIMELINE
    # -----------------------------------------------------

    timeline_counts = {}


    for event in events:

        timestamp = str(
            event["timestamp"]
        )

        timeline_key = timestamp[:16]


        if timeline_key not in timeline_counts:

            timeline_counts[timeline_key] = 0


        timeline_counts[timeline_key] += 1


    # Sort timeline chronologically

    timeline_counts = dict(
        sorted(
            timeline_counts.items()
        )
    )


    # -----------------------------------------------------
    # SUSPICIOUS IP ADDRESSES
    # -----------------------------------------------------

    suspicious_ips = analyze_suspicious_ips(
        events
    )


    if suspicious_ips:

        top_suspicious_ip = max(
            suspicious_ips,
            key=suspicious_ips.get
        )

        top_suspicious_count = suspicious_ips[
            top_suspicious_ip
        ]

    else:

        top_suspicious_ip = "None"

        top_suspicious_count = 0


    # -----------------------------------------------------
    # RECENT ALERT HISTORY
    # -----------------------------------------------------

    alert_history = [

        event

        for event in events

        if event["severity"] == "HIGH"

    ][:10]


    # -----------------------------------------------------
    # EVENT TYPES
    # -----------------------------------------------------

    event_types = sorted(
        event_counts.keys()
    )


    # -----------------------------------------------------
    # RENDER DASHBOARD
    # -----------------------------------------------------

    return render_template(
        "index.html",

        results=filtered_events,

        alerts=alerts,

        alert_history=alert_history,

        total_events=total_events,

        high_events=high_events,

        medium_events=medium_events,

        low_events=low_events,

        failed_logins=failed_logins,

        severity_counts=severity_counts,

        event_counts=event_counts,

        event_types=event_types,

        timeline_counts=timeline_counts,

        suspicious_ips=suspicious_ips,

        top_suspicious_ip=top_suspicious_ip,

        top_suspicious_count=top_suspicious_count,

        severity_filter=severity_filter,

        event_filter=event_filter,

        ip_filter=ip_filter
    )


# =========================================================
# CSV EXPORT
# =========================================================

@app.route("/export")
def export_csv():

    events = get_events()


    output = io.StringIO()


    writer = csv.writer(output)


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

            event["id"],

            event["severity"],

            event["event"],

            event["message"],

            event["ip_address"],

            event["username"],

            event["timestamp"],

            event["created_at"]

        ])


    response = Response(
        output.getvalue(),
        mimetype="text/csv"
    )


    response.headers[
        "Content-Disposition"
    ] = "attachment; filename=security_report.csv"


    return response


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
