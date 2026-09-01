from analyzer.log_analyzer import analyze_log


log_data = """
2026-08-22 21:20:01 WARNING unusual login behavior from 192.168.1.30
2026-08-22 21:20:05 Suspicious activity detected from 10.0.0.25
"""


results = analyze_log(log_data)


print("\nSecurity Events Test")
print("--------------------")


for result in results:

    print(
        f"[{result['severity']}] "
        f"{result['event']} | "
        f"IP: {result['ip_address']}"
    )


print("\nTest completed successfully.")
