from analyzer.log_analyzer import analyze_log


log_data = """
2026-08-22 21:00:01 Unauthorized access attempt from 10.0.0.25
2026-08-22 21:00:05 User attempted unauthorized access to /admin
"""


results = analyze_log(log_data)

print("\nUnauthorized Access Test")
print("------------------------")

for result in results:

    print(
        f"[{result['severity']}] "
        f"{result['event']} | "
        f"IP: {result['ip_address']}"
    )

print("\nTest completed successfully.")
