from analyzer.log_analyzer import analyze_log, detect_brute_force
from database.database import save_event


log_data = """
2026-08-22 20:00:01 Failed login username=admin from 192.168.1.50
2026-08-22 20:00:05 Failed login username=admin from 192.168.1.50
2026-08-22 20:00:09 Failed login username=admin from 192.168.1.50
"""


# -------------------------
# Analyze log
# -------------------------

results = analyze_log(log_data)

print("\nDetected Security Events:")
print("-------------------------")

for result in results:

    print(
        f"[{result['severity']}] "
        f"{result['event']} | "
        f"IP: {result['ip_address']} | "
        f"User: {result['username']}"
    )


# -------------------------
# Brute-force detection
# -------------------------

alerts = detect_brute_force(results)

print("\nSecurity Alerts:")
print("----------------")

if alerts:

    for alert in alerts:

        print(
            f"[{alert['severity']}] "
            f"{alert['alert_type']} | "
            f"IP: {alert['ip_address']} | "
            f"Attempts: {alert['failed_attempts']}"
        )

        print(
            f"Message: {alert['message']}"
        )

else:

    print("No brute-force activity detected.")


# -------------------------
# Database test
# -------------------------

print("\nDatabase Test:")
print("--------------")

for result in results:

    save_event(
        result["severity"],
        result["event"],
        result["message"],
        result["ip_address"],
        result["username"],
        result["timestamp"]
    )

    print(
        f"Saved: {result['event']} "
        f"from {result['ip_address']}"
    )


print("\nTest completed successfully.")
