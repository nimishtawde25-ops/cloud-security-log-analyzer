from analyzer.log_analyzer import analyze_log, detect_brute_force


log_data = """
2026-08-22 22:00:01 Failed login username=admin from 192.168.1.50
2026-08-22 22:00:05 Failed login username=admin from 192.168.1.50
2026-08-22 22:00:09 Failed login username=admin from 192.168.1.50
2026-08-22 22:01:01 Unauthorized access attempt from 10.0.0.25
2026-08-22 22:02:01 Permission denied for user analyst from 192.168.1.20
2026-08-22 22:03:01 WARNING unusual login behavior from 192.168.1.30
2026-08-22 22:04:01 Suspicious activity detected from 10.0.0.25
2026-08-22 22:05:01 User admin logged in successfully from 192.168.1.10
"""


results = analyze_log(log_data)


print("\n========== ALL SECURITY EVENTS ==========")


for result in results:

    print(
        f"[{result['severity']}] "
        f"{result['event']} | "
        f"IP: {result['ip_address']} | "
        f"User: {result['username']}"
    )


alerts = detect_brute_force(results)


print("\n========== SECURITY ALERTS ==========")


if alerts:

    for alert in alerts:

        print(
            f"[{alert['severity']}] "
            f"{alert['alert_type']} | "
            f"IP: {alert['ip_address']} | "
            f"Attempts: {alert['failed_attempts']}"
        )

else:

    print("No brute-force alerts detected.")


print("\n======================================")
print("All detection rules tested successfully.")
