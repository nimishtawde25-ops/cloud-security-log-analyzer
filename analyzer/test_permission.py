from analyzer.log_analyzer import analyze_log


log_data = """
2026-08-22 21:10:01 Permission denied for user admin from 192.168.1.20
2026-08-22 21:10:05 Permission denied while accessing /etc/shadow from 10.0.0.25
"""


results = analyze_log(log_data)


print("\nPermission Denied Test")
print("----------------------")


for result in results:

    print(
        f"[{result['severity']}] "
        f"{result['event']} | "
        f"IP: {result['ip_address']}"
    )


print("\nTest completed successfully.")
