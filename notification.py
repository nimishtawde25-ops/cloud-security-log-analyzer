from datetime import datetime


def send_notification(alert):
    """
    Process a security alert notification.

    This initial notification engine writes notifications
    to the terminal. Later, Step 17.2 will add email/security
    notification integration.
    """

    alert_type = alert.get("alert_type", "Unknown Alert")
    severity = alert.get("severity", "UNKNOWN")
    message = alert.get("message", "No message")
    ip_address = alert.get("ip_address", "Unknown")
    username = alert.get("username", "Unknown")
    risk_score = alert.get("risk_score", 0)
    risk_level = alert.get("risk_level", "UNKNOWN")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "=" * 60)
    print("SECURITY NOTIFICATION")
    print("=" * 60)
    print(f"Time:        {timestamp}")
    print(f"Alert Type:  {alert_type}")
    print(f"Severity:    {severity}")
    print(f"Risk Score:  {risk_score}")
    print(f"Risk Level:  {risk_level}")
    print(f"IP Address:  {ip_address}")
    print(f"Username:    {username}")
    print(f"Message:     {message}")
    print("=" * 60)


def notify_alerts(alerts):
    """
    Send notifications for a list of security alerts.
    """

    if not alerts:
        return

    for alert in alerts:
        send_notification(alert)
