# =========================================================
# CLOUD SECURITY LOG ANALYZER
# STEP 18.6 - THREAT CORRELATION
# =========================================================

import re
from collections import defaultdict
from datetime import datetime, timedelta


# =========================================================
# THREAT SCORE
# =========================================================

def calculate_risk_score(event, message=""):

    event_text = str(event).lower()
    message_text = str(message).lower()

    score = 0

    if "failed login" in event_text:
        score += 25

    elif "unauthorized" in event_text:
        score += 45

    elif "permission denied" in event_text:
        score += 30

    elif "suspicious" in event_text:
        score += 40

    elif "brute force" in event_text:
        score += 70

    elif "privilege escalation" in event_text:
        score += 65

    elif "attack pattern" in event_text:
        score += 70

    elif "successful login" in event_text:
        score += 5

    if "failed login" in message_text:
        score += 15

    if "multiple login attempts" in message_text:
        score += 25

    if "unauthorized access" in message_text:
        score += 30

    if "permission denied" in message_text:
        score += 20

    if "privilege escalation" in message_text:
        score += 40

    if "sudo" in message_text:
        score += 20

    if "root" in message_text:
        score += 20

    if "brute force" in message_text:
        score += 40

    if "attack" in message_text:
        score += 30

    return min(score, 100)


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(score):

    score = int(score)

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


# =========================================================
# SEVERITY
# =========================================================

def severity_from_score(score):

    level = get_risk_level(score)

    if level == "CRITICAL":
        return "CRITICAL"

    if level == "HIGH":
        return "HIGH"

    if level == "MEDIUM":
        return "MEDIUM"

    return "LOW"


# =========================================================
# IP EXTRACTION
# =========================================================

def extract_ip(message):

    match = re.search(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        str(message)
    )

    if match:
        return match.group(0)

    return "Unknown"


# =========================================================
# USERNAME EXTRACTION
# =========================================================

def extract_username(message):

    message = str(message)

    patterns = [

        r"user\s+([A-Za-z0-9_.-]+)",

        r"user=([A-Za-z0-9_.-]+)",

        r"for\s+user\s+([A-Za-z0-9_.-]+)",

        r"username\s+([A-Za-z0-9_.-]+)",

        r"account\s+([A-Za-z0-9_.-]+)"

    ]

    for pattern in patterns:

        match = re.search(
            pattern,
            message,
            re.IGNORECASE
        )

        if match:
            return match.group(1)

    return "Unknown"


# =========================================================
# TIMESTAMP EXTRACTION
# =========================================================

def extract_timestamp(message):

    match = re.search(

        r"\b\d{4}-\d{2}-\d{2}"
        r"\s+\d{2}:\d{2}:\d{2}\b",

        str(message)

    )

    if match:
        return match.group(0)

    return "Unknown"


# =========================================================
# TIMESTAMP PARSER
# =========================================================

def parse_timestamp(timestamp):

    try:

        return datetime.strptime(
            timestamp,
            "%Y-%m-%d %H:%M:%S"
        )

    except (
        ValueError,
        TypeError
    ):

        return None


# =========================================================
# IPV4 VALIDATION
# =========================================================

def is_valid_ipv4(ip_address):

    if not ip_address:
        return False

    parts = str(
        ip_address
    ).split(".")

    if len(parts) != 4:
        return False

    try:

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    except ValueError:

        return False


# =========================================================
# PRIVATE IP
# =========================================================

def is_private_ip(ip_address):

    if not is_valid_ipv4(
        ip_address
    ):
        return False

    first, second, _, _ = map(
        int,
        ip_address.split(".")
    )

    if first == 10:
        return True

    if (
        first == 172
        and
        16 <= second <= 31
    ):
        return True

    if (
        first == 192
        and
        second == 168
    ):
        return True

    return False


# =========================================================
# SPECIAL IP
# =========================================================

def is_special_ip(ip_address):

    if not is_valid_ipv4(
        ip_address
    ):
        return True

    first, second, third, fourth = map(
        int,
        ip_address.split(".")
    )

    if first == 127:
        return True

    if (
        first == 169
        and
        second == 254
    ):
        return True

    if (
        first == 0
        and
        second == 0
        and
        third == 0
        and
        fourth == 0
    ):
        return True

    return False


# =========================================================
# ATTACK PATTERNS
# =========================================================

ATTACK_PATTERNS = {

    "SQL_INJECTION": [

        r"\bunion\s+select\b",

        r"\bselect\s+.*\s+from\b",

        r"\bor\s+1\s*=\s*1\b",

        r"\band\s+1\s*=\s*1\b",

        r"\bdrop\s+table\b",

        r"\binsert\s+into\b",

        r"\bdelete\s+from\b",

        r"\bupdate\s+.*\s+set\b",

        r"'\s*or\s*'1'\s*=\s*'1"

    ],

    "COMMAND_INJECTION": [

        r";\s*(whoami|id|uname|cat|ls|pwd)\b",

        r"\|\s*(whoami|id|uname|cat|ls|pwd)\b",

        r"\$\([^)]*\)",

        r"`[^`]+`",

        r"\b(?:cmd|command)\s*=",

        r"\b(?:exec|system|popen)\s*\("

    ],

    "PATH_TRAVERSAL": [

        r"\.\./",

        r"\.\.\\",

        r"%2e%2e%2f",

        r"%2e%2e/",

        r"/etc/passwd",

        r"/etc/shadow",

        r"boot\.ini"

    ],

    "XSS": [

        r"<script\b",

        r"</script>",

        r"javascript\s*:",

        r"onerror\s*=",

        r"onload\s*=",

        r"<iframe\b",

        r"<svg\b.*onload"

    ],

    "SUSPICIOUS_SCANNING": [

        r"\bnmap\b",

        r"\bmasscan\b",

        r"\bnikto\b",

        r"\bgobuster\b",

        r"\bdirbuster\b",

        r"\bport\s+scan\b",

        r"\bport\s+scanning\b",

        r"\bnetwork\s+scan\b",

        r"\bservice\s+enumeration\b"

    ]

}


# =========================================================
# DETECT ATTACK PATTERNS
# =========================================================

def detect_attack_patterns(message):

    text = str(message)

    detected = []

    for attack_type, patterns in (
        ATTACK_PATTERNS.items()
    ):

        for pattern in patterns:

            try:

                if re.search(
                    pattern,
                    text,
                    re.IGNORECASE
                ):

                    detected.append({

                        "type":
                            attack_type,

                        "pattern":
                            pattern

                    })

                    break

            except re.error:

                continue

    return detected


# =========================================================
# ATTACK RISK
# =========================================================

def calculate_attack_risk(
    attack_type
):

    scores = {

        "SQL_INJECTION": 85,

        "COMMAND_INJECTION": 90,

        "PATH_TRAVERSAL": 80,

        "XSS": 70,

        "SUSPICIOUS_SCANNING": 55

    }

    return scores.get(
        attack_type,
        60
    )


# =========================================================
# EVENT DETECTION
# =========================================================

def detect_event(message):

    text = str(
        message
    ).lower()

    if detect_attack_patterns(
        message
    ):

        return "Attack Pattern"

    privilege_patterns = [

        "privilege escalation",

        "privilege escalated",

        "root access",

        "root privileges",

        "became root",

        "uid=0",

        "euid=0",

        "sudo access",

        "unauthorized sudo",

        "unauthorized root"

    ]

    for pattern in privilege_patterns:

        if pattern in text:

            return "Privilege Escalation"

    if "brute force" in text:

        return "Brute Force"

    if (
        "failed login" in text
        or
        "login failed" in text
    ):

        return "Failed Login"

    if (
        "unauthorized" in text
        or
        "unauthorised" in text
    ):

        return "Unauthorized Access"

    if "permission denied" in text:

        return "Permission Denied"

    if "suspicious" in text:

        return "Suspicious Activity"

    if (
        "logged in successfully" in text
        or
        "login successful" in text
        or
        "successful login" in text
    ):

        return "Successful Login"

    if "warning" in text:

        return "Warning"

    return "Unknown Event"


# =========================================================
# ANALYZE LOG
# =========================================================

def analyze_log(log_data):

    results = []

    if not log_data:
        return results

    lines = str(
        log_data
    ).splitlines()

    for line in lines:

        line = line.strip()

        if not line:
            continue

        event = detect_event(
            line
        )

        if event == "Unknown Event":
            continue

        ip_address = extract_ip(
            line
        )

        username = extract_username(
            line
        )

        timestamp = extract_timestamp(
            line
        )

        risk_score = calculate_risk_score(
            event,
            line
        )

        attack_patterns = (
            detect_attack_patterns(
                line
            )
        )

        if attack_patterns:

            risk_score = max(

                risk_score,

                calculate_attack_risk(
                    attack_patterns[0][
                        "type"
                    ]
                )

            )

        risk_level = get_risk_level(
            risk_score
        )

        severity = severity_from_score(
            risk_score
        )

        if event == "Successful Login":

            severity = "LOW"

        results.append({

            "severity":
                severity,

            "event":
                event,

            "message":
                line,

            "ip_address":
                ip_address,

            "username":
                username,

            "timestamp":
                timestamp,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level

        })

    return results


# =========================================================
# SUSPICIOUS IP ANALYSIS
# =========================================================

def analyze_suspicious_ips(events):

    suspicious_ips = defaultdict(
        int
    )

    for event in events:

        ip_address = event.get(
            "ip_address",
            "Unknown"
        )

        if not is_valid_ipv4(
            ip_address
        ):
            continue

        event_name = str(
            event.get(
                "event",
                ""
            )
        ).lower()

        severity = str(
            event.get(
                "severity",
                ""
            )
        ).upper()

        if severity == "CRITICAL":

            suspicious_ips[
                ip_address
            ] += 4

        elif severity == "HIGH":

            suspicious_ips[
                ip_address
            ] += 3

        elif "attack pattern" in event_name:

            suspicious_ips[
                ip_address
            ] += 4

        elif "unauthorized" in event_name:

            suspicious_ips[
                ip_address
            ] += 3

        elif "privilege" in event_name:

            suspicious_ips[
                ip_address
            ] += 4

        elif "brute force" in event_name:

            suspicious_ips[
                ip_address
            ] += 4

        elif "suspicious" in event_name:

            suspicious_ips[
                ip_address
            ] += 2

    return dict(
        suspicious_ips
    )


# =========================================================
# IP INTELLIGENCE
# =========================================================

def get_ip_intelligence(events):

    intelligence = []

    unique_ips = set(

        event.get(
            "ip_address",
            "Unknown"
        )

        for event in events

    )

    for ip_address in unique_ips:

        if not is_valid_ipv4(
            ip_address
        ):
            continue

        ip_events = [

            event

            for event in events

            if event.get(
                "ip_address"
            ) == ip_address

        ]

        score = 0

        for event in ip_events:

            event_name = str(
                event.get(
                    "event",
                    ""
                )
            ).lower()

            if "failed login" in event_name:
                score += 5

            if "unauthorized" in event_name:
                score += 15

            if "permission denied" in event_name:
                score += 10

            if "privilege" in event_name:
                score += 25

            if "brute force" in event_name:
                score += 30

            if "attack pattern" in event_name:
                score += 30

            if "suspicious" in event_name:
                score += 20

            if str(
                event.get(
                    "severity",
                    ""
                )
            ).upper() == "CRITICAL":

                score += 20

        score = min(
            score,
            100
        )

        intelligence.append({

            "ip_address":
                ip_address,

            "risk_score":
                score,

            "risk_level":
                get_risk_level(
                    score
                ),

            "private":
                is_private_ip(
                    ip_address
                ),

            "special":
                is_special_ip(
                    ip_address
                ),

            "event_count":
                len(ip_events)

        })

    intelligence.sort(

        key=lambda item:
            item["risk_score"],

        reverse=True

    )

    return intelligence


# =========================================================
# BRUTE FORCE DETECTION
# =========================================================

def detect_brute_force(
    events,
    threshold=5,
    window_minutes=10
):

    failed_by_ip = defaultdict(
        list
    )

    failed_by_user = defaultdict(
        list
    )

    for event in events:

        event_name = str(
            event.get(
                "event",
                ""
            )
        ).lower()

        if "failed login" not in event_name:
            continue

        ip_address = event.get(
            "ip_address",
            "Unknown"
        )

        username = event.get(
            "username",
            "Unknown"
        )

        timestamp = event.get(
            "timestamp",
            "Unknown"
        )

        parsed_time = parse_timestamp(
            timestamp
        )

        record = {

            "ip_address":
                ip_address,

            "username":
                username,

            "timestamp":
                timestamp,

            "datetime":
                parsed_time

        }

        if ip_address != "Unknown":

            failed_by_ip[
                ip_address
            ].append(record)

        if username != "Unknown":

            failed_by_user[
                username
            ].append(record)

    alerts = []

    for ip_address, attempts in (
        failed_by_ip.items()
    ):

        attempts.sort(

            key=lambda x:
                x["datetime"]
                if x["datetime"]
                else datetime.min

        )

        for index in range(
            len(attempts)
        ):

            current = attempts[
                index
            ]

            current_time = current[
                "datetime"
            ]

            if current_time is None:
                continue

            window_start = (
                current_time
                -
                timedelta(
                    minutes=window_minutes
                )
            )

            window_attempts = [

                attempt

                for attempt in attempts

                if (
                    attempt["datetime"]
                    is not None

                    and

                    window_start
                    <=
                    attempt["datetime"]
                    <=
                    current_time
                )

            ]

            count = len(
                window_attempts
            )

            if count >= threshold:

                risk_score = min(

                    70
                    +
                    (
                        count
                        -
                        threshold
                    )
                    * 5,

                    100

                )

                alerts.append({

                    "severity":
                        severity_from_score(
                            risk_score
                        ),

                    "type":
                        "BRUTE_FORCE",

                    "message":
                        f"Detected {count} "
                        f"failed login attempts "
                        f"from {ip_address} "
                        f"within "
                        f"{window_minutes} "
                        f"minutes.",

                    "ip_address":
                        ip_address,

                    "username":
                        current[
                            "username"
                        ],

                    "attempts":
                        count,

                    "window_minutes":
                        window_minutes,

                    "risk_score":
                        risk_score,

                    "risk_level":
                        get_risk_level(
                            risk_score
                        ),

                    "timestamp":
                        current[
                            "timestamp"
                        ]

                })

                break

    for username, attempts in (
        failed_by_user.items()
    ):

        attempts.sort(

            key=lambda x:
                x["datetime"]
                if x["datetime"]
                else datetime.min

        )

        for index in range(
            len(attempts)
        ):

            current = attempts[
                index
            ]

            current_time = current[
                "datetime"
            ]

            if current_time is None:
                continue

            window_start = (
                current_time
                -
                timedelta(
                    minutes=window_minutes
                )
            )

            window_attempts = [

                attempt

                for attempt in attempts

                if (
                    attempt["datetime"]
                    is not None

                    and

                    window_start
                    <=
                    attempt["datetime"]
                    <=
                    current_time
                )

            ]

            count = len(
                window_attempts
            )

            if count >= threshold:

                source_ips = set(

                    attempt[
                        "ip_address"
                    ]

                    for attempt
                    in window_attempts

                )

                risk_score = min(

                    75
                    +
                    (
                        count
                        -
                        threshold
                    )
                    * 5,

                    100

                )

                alerts.append({

                    "severity":
                        severity_from_score(
                            risk_score
                        ),

                    "type":
                        "ACCOUNT_BRUTE_FORCE",

                    "message":
                        f"Detected {count} "
                        f"failed login attempts "
                        f"targeting user "
                        f"'{username}' within "
                        f"{window_minutes} "
                        f"minutes.",

                    "ip_address":
                        ", ".join(
                            sorted(
                                source_ips
                            )
                        ),

                    "username":
                        username,

                    "attempts":
                        count,

                    "window_minutes":
                        window_minutes,

                    "risk_score":
                        risk_score,

                    "risk_level":
                        get_risk_level(
                            risk_score
                        ),

                    "timestamp":
                        current[
                            "timestamp"
                        ]

                })

                break

    return alerts


# =========================================================
# PRIVILEGE ESCALATION
# =========================================================

def detect_privilege_escalation(events):

    alerts = []

    privilege_keywords = [

        "privilege escalation",

        "privilege escalated",

        "root access",

        "root privileges",

        "became root",

        "uid=0",

        "euid=0",

        "sudo",

        "unauthorized root",

        "unauthorized sudo"

    ]

    for event in events:

        message = str(
            event.get(
                "message",
                ""
            )
        ).lower()

        event_name = str(
            event.get(
                "event",
                ""
            )
        ).lower()

        matched_keyword = None

        for keyword in privilege_keywords:

            if (
                keyword in message
                or
                keyword in event_name
            ):

                matched_keyword = keyword

                break

        if not matched_keyword:
            continue

        risk_score = 80

        if "unauthorized" in message:
            risk_score += 10

        if "root" in message:
            risk_score += 5

        if "sudo" in message:
            risk_score += 5

        risk_score = min(
            risk_score,
            100
        )

        alerts.append({

            "severity":
                severity_from_score(
                    risk_score
                ),

            "type":
                "PRIVILEGE_ESCALATION",

            "message":
                event.get(
                    "message",
                    "Potential privilege escalation detected."
                ),

            "ip_address":
                event.get(
                    "ip_address",
                    "Unknown"
                ),

            "username":
                event.get(
                    "username",
                    "Unknown"
                ),

            "risk_score":
                risk_score,

            "risk_level":
                get_risk_level(
                    risk_score
                ),

            "matched_pattern":
                matched_keyword,

            "timestamp":
                event.get(
                    "timestamp",
                    "Unknown"
                )

        })

    return alerts


# =========================================================
# ATTACK ALERTS
# =========================================================

def detect_attack_alerts(events):

    alerts = []

    for event in events:

        message = event.get(
            "message",
            ""
        )

        detected_patterns = (
            detect_attack_patterns(
                message
            )
        )

        for detected in (
            detected_patterns
        ):

            attack_type = detected[
                "type"
            ]

            risk_score = (
                calculate_attack_risk(
                    attack_type
                )
            )

            alerts.append({

                "severity":
                    severity_from_score(
                        risk_score
                    ),

                "type":
                    attack_type,

                "message":
                    f"Potential "
                    f"{attack_type.replace('_', ' ').title()} "
                    f"pattern detected.",

                "ip_address":
                    event.get(
                        "ip_address",
                        "Unknown"
                    ),

                "username":
                    event.get(
                        "username",
                        "Unknown"
                    ),

                "risk_score":
                    risk_score,

                "risk_level":
                    get_risk_level(
                        risk_score
                    ),

                "matched_pattern":
                    detected[
                        "pattern"
                    ],

                "timestamp":
                    event.get(
                        "timestamp",
                        "Unknown"
                    )

            })

    return alerts


# =========================================================
# THREAT CORRELATION
# =========================================================

def correlate_threats(
    events,
    window_minutes=15
):

    groups = defaultdict(
        list
    )

    # -----------------------------------------------------
    # GROUP EVENTS BY IP
    # -----------------------------------------------------

    for event in events:

        ip_address = event.get(
            "ip_address",
            "Unknown"
        )

        if not is_valid_ipv4(
            ip_address
        ):
            continue

        timestamp = parse_timestamp(
            event.get(
                "timestamp",
                "Unknown"
            )
        )

        groups[
            ip_address
        ].append({

            "event":
                event.get(
                    "event",
                    ""
                ),

            "severity":
                event.get(
                    "severity",
                    ""
                ),

            "message":
                event.get(
                    "message",
                    ""
                ),

            "timestamp":
                timestamp,

            "username":
                event.get(
                    "username",
                    "Unknown"
                )

        })

    correlated_alerts = []

    # -----------------------------------------------------
    # ANALYZE EACH IP
    # -----------------------------------------------------

    for ip_address, ip_events in (
        groups.items()
    ):

        ip_events.sort(

            key=lambda x:
                x["timestamp"]
                if x["timestamp"]
                else datetime.min

        )

        if not ip_events:
            continue

        for index in range(
            len(ip_events)
        ):

            current = ip_events[
                index
            ]

            current_time = current[
                "timestamp"
            ]

            if current_time is None:
                continue

            window_start = (
                current_time
                -
                timedelta(
                    minutes=window_minutes
                )
            )

            related_events = [

                event

                for event in ip_events

                if (
                    event["timestamp"]
                    is not None

                    and

                    window_start
                    <=
                    event["timestamp"]
                    <=
                    current_time
                )

            ]

            event_types = set(

                str(
                    event["event"]
                ).lower()

                for event
                in related_events

            )

            # -------------------------------------------------
            # COUNT THREAT CATEGORIES
            # -------------------------------------------------

            failed_login = any(

                "failed login"
                in event_type

                for event_type
                in event_types

            )

            unauthorized = any(

                "unauthorized"
                in event_type

                for event_type
                in event_types

            )

            privilege = any(

                "privilege"
                in event_type

                for event_type
                in event_types

            )

            brute_force = any(

                "brute force"
                in event_type

                for event_type
                in event_types

            )

            attack_pattern = any(

                "attack pattern"
                in event_type

                for event_type
                in event_types

            )

            suspicious = any(

                "suspicious"
                in event_type

                for event_type
                in event_types

            )

            permission_denied = any(

                "permission denied"
                in event_type

                for event_type
                in event_types

            )

            category_count = sum([

                failed_login,

                unauthorized,

                privilege,

                brute_force,

                attack_pattern,

                suspicious,

                permission_denied

            ])

            # -------------------------------------------------
            # REQUIRE MULTIPLE RELATED SIGNALS
            # -------------------------------------------------

            if category_count < 2:
                continue

            # -------------------------------------------------
            # CORRELATION SCORE
            # -------------------------------------------------

            risk_score = min(

                40
                +
                category_count * 10
                +
                len(related_events) * 5,

                100

            )

            # Extra weight for dangerous combinations

            if brute_force and privilege:
                risk_score += 20

            if attack_pattern and privilege:
                risk_score += 20

            if unauthorized and privilege:
                risk_score += 15

            if brute_force and attack_pattern:
                risk_score += 15

            risk_score = min(
                risk_score,
                100
            )

            # -------------------------------------------------
            # EVENT SUMMARY
            # -------------------------------------------------

            summary = ", ".join(

                sorted(
                    event_types
                )

            )

            usernames = set(

                event["username"]

                for event
                in related_events

                if event["username"]
                != "Unknown"

            )

            correlated_alerts.append({

                "severity":
                    severity_from_score(
                        risk_score
                    ),

                "type":
                    "CORRELATED_THREAT",

                "message":
                    f"Multiple related security "
                    f"events detected from "
                    f"{ip_address}: "
                    f"{summary}",

                "ip_address":
                    ip_address,

                "username":
                    ", ".join(
                        sorted(
                            usernames
                        )
                    )
                    if usernames
                    else "Unknown",

                "event_count":
                    len(
                        related_events
                    ),

                "risk_score":
                    risk_score,

                "risk_level":
                    get_risk_level(
                        risk_score
                    ),

                "timestamp":
                    current[
                        "timestamp"
                    ].strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

            })

            # One correlation alert per IP window
            break

    return correlated_alerts


# =========================================================
# ADVANCED ALERT GENERATOR
# =========================================================

def generate_alerts(events):

    alerts = []

    # -----------------------------------------------------
    # HIGH / CRITICAL EVENTS
    # -----------------------------------------------------

    for event in events:

        severity = str(
            event.get(
                "severity",
                "LOW"
            )
        ).upper()

        if severity not in (
            "HIGH",
            "CRITICAL"
        ):
            continue

        risk_score = event.get(
            "risk_score"
        )

        if risk_score is None:

            risk_score = calculate_risk_score(

                event.get(
                    "event",
                    ""
                ),

                event.get(
                    "message",
                    ""
                )

            )

        alerts.append({

            "severity":
                severity,

            "type":
                event.get(
                    "event",
                    "SECURITY_ALERT"
                ),

            "message":
                event.get(
                    "message",
                    "Security event detected."
                ),

            "ip_address":
                event.get(
                    "ip_address",
                    "Unknown"
                ),

            "username":
                event.get(
                    "username",
                    "Unknown"
                ),

            "risk_score":
                risk_score,

            "risk_level":
                get_risk_level(
                    risk_score
                ),

            "timestamp":
                event.get(
                    "timestamp",
                    "Unknown"
                )

        })

    # -----------------------------------------------------
    # BRUTE FORCE
    # -----------------------------------------------------

    alerts.extend(
        detect_brute_force(
            events
        )
    )

    # -----------------------------------------------------
    # PRIVILEGE ESCALATION
    # -----------------------------------------------------

    alerts.extend(
        detect_privilege_escalation(
            events
        )
    )

    # -----------------------------------------------------
    # ATTACK PATTERNS
    # -----------------------------------------------------

    alerts.extend(
        detect_attack_alerts(
            events
        )
    )

    # -----------------------------------------------------
    # THREAT CORRELATION
    # -----------------------------------------------------

    alerts.extend(
        correlate_threats(
            events
        )
    )

    return alerts
# =========================================================
# STEP 18.7
# AUTOMATED INCIDENT CLASSIFICATION
# =========================================================

def classify_incident(alert):

    alert_type = str(
        alert.get("type", "")
    ).upper()

    message = str(
        alert.get("message", "")
    ).lower()

    risk_score = int(
        alert.get("risk_score", 0) or 0
    )

    # -----------------------------------------------------
    # ACCOUNT COMPROMISE
    # -----------------------------------------------------

    if (
        "BRUTE_FORCE" in alert_type
        or "ACCOUNT_BRUTE_FORCE" in alert_type
        or "FAILED LOGIN" in alert_type
    ):
        incident_type = "ACCOUNT_COMPROMISE"

    # -----------------------------------------------------
    # PRIVILEGE ESCALATION
    # -----------------------------------------------------

    elif (
        "PRIVILEGE" in alert_type
        or "ROOT" in message
        or "SUDO" in message
    ):
        incident_type = "PRIVILEGE_ESCALATION"

    # -----------------------------------------------------
    # WEB APPLICATION ATTACK
    # -----------------------------------------------------

    elif (
        "SQL_INJECTION" in alert_type
        or "XSS" in alert_type
        or "PATH_TRAVERSAL" in alert_type
    ):
        incident_type = "WEB_APPLICATION_ATTACK"

    # -----------------------------------------------------
    # COMMAND EXECUTION
    # -----------------------------------------------------

    elif "COMMAND_INJECTION" in alert_type:

        incident_type = "COMMAND_EXECUTION"

    # -----------------------------------------------------
    # RECONNAISSANCE
    # -----------------------------------------------------

    elif (
        "SCANNING" in alert_type
        or "SCAN" in message
        or "ENUMERATION" in message
    ):
        incident_type = "RECONNAISSANCE"

    # -----------------------------------------------------
    # UNAUTHORIZED ACCESS
    # -----------------------------------------------------

    elif "UNAUTHORIZED" in alert_type:

        incident_type = "UNAUTHORIZED_ACCESS"

    # -----------------------------------------------------
    # CORRELATED THREAT
    # -----------------------------------------------------

    elif "CORRELATED" in alert_type:

        incident_type = "MULTI_STAGE_ATTACK"

    # -----------------------------------------------------
    # GENERIC SECURITY INCIDENT
    # -----------------------------------------------------

    else:

        incident_type = "SECURITY_INCIDENT"

    # -----------------------------------------------------
    # CONFIDENCE
    # -----------------------------------------------------

    if risk_score >= 85:

        confidence = "VERY_HIGH"

    elif risk_score >= 70:

        confidence = "HIGH"

    elif risk_score >= 50:

        confidence = "MEDIUM"

    else:

        confidence = "LOW"

    # -----------------------------------------------------
    # PRIORITY
    # -----------------------------------------------------

    if risk_score >= 85:

        priority = "P1"

    elif risk_score >= 70:

        priority = "P2"

    elif risk_score >= 50:

        priority = "P3"

    else:

        priority = "P4"

    return {

        "incident_type":
            incident_type,

        "confidence":
            confidence,

        "priority":
            priority,

        "risk_score":
            risk_score

    }


# =========================================================
# CLASSIFY ALL INCIDENTS
# =========================================================

def classify_incidents(alerts):

    classified = []

    for alert in alerts:

        classification = classify_incident(
            alert
        )

        classified_alert = dict(
            alert
        )

        classified_alert.update(
            classification
        )

        classified.append(
            classified_alert
        )

    return classified


# =========================================================
# INCIDENT SUMMARY
# =========================================================

def incident_summary(alerts):

    summary = defaultdict(int)

    for alert in alerts:

        classification = classify_incident(
            alert
        )

        incident_type = classification[
            "incident_type"
        ]

        summary[
            incident_type
        ] += 1

    return dict(summary)
# =========================================================
# STEP 18.8
# ADVANCED THREAT CORRELATION
# =========================================================

def advanced_threat_correlation(
    events,
    window_minutes=15
):
    """
    Correlates multiple security events
    from the same IP address.
    """

    grouped = defaultdict(list)

    # -----------------------------------------------------
    # GROUP EVENTS BY IP
    # -----------------------------------------------------

    for event in events:

        ip_address = event.get(
            "ip_address",
            "Unknown"
        )

        if not is_valid_ipv4(ip_address):
            continue

        timestamp = parse_timestamp(
            event.get(
                "timestamp",
                "Unknown"
            )
        )

        grouped[ip_address].append({

            "event": event.get(
                "event",
                "Unknown"
            ),

            "message": event.get(
                "message",
                ""
            ),

            "username": event.get(
                "username",
                "Unknown"
            ),

            "severity": event.get(
                "severity",
                "LOW"
            ),

            "risk_score": int(
                event.get(
                    "risk_score",
                    0
                ) or 0
            ),

            "timestamp": timestamp

        })

    correlated = []

    # -----------------------------------------------------
    # ANALYZE EACH IP
    # -----------------------------------------------------

    for ip_address, ip_events in grouped.items():

        ip_events.sort(
            key=lambda x:
                x["timestamp"]
                if x["timestamp"]
                else datetime.min
        )

        if len(ip_events) < 2:
            continue

        # -------------------------------------------------
        # SLIDING WINDOW
        # -------------------------------------------------

        for index, current in enumerate(ip_events):

            current_time = current["timestamp"]

            if current_time is None:
                continue

            window_start = (
                current_time
                -
                timedelta(
                    minutes=window_minutes
                )
            )

            related = [

                item

                for item in ip_events

                if (
                    item["timestamp"]
                    is not None

                    and

                    window_start
                    <=
                    item["timestamp"]
                    <=
                    current_time
                )

            ]

            if len(related) < 2:
                continue

            # -------------------------------------------------
            # UNIQUE EVENT TYPES
            # -------------------------------------------------

            event_types = set(

                str(
                    item["event"]
                ).upper()

                for item in related

            )

            # -------------------------------------------------
            # UNIQUE USERS
            # -------------------------------------------------

            usernames = set(

                item["username"]

                for item in related

                if item["username"]
                != "Unknown"

            )

            # -------------------------------------------------
            # DETECT ATTACK CATEGORIES
            # -------------------------------------------------

            failed_login = any(

                "FAILED LOGIN"
                in event_type

                for event_type
                in event_types

            )

            unauthorized = any(

                "UNAUTHORIZED"
                in event_type

                for event_type
                in event_types

            )

            privilege = any(

                "PRIVILEGE"
                in event_type

                for event_type
                in event_types

            )

            brute_force = any(

                "BRUTE FORCE"
                in event_type

                for event_type
                in event_types

            )

            attack_pattern = any(

                "ATTACK PATTERN"
                in event_type

                for event_type
                in event_types

            )

            permission_denied = any(

                "PERMISSION DENIED"
                in event_type

                for event_type
                in event_types

            )

            suspicious = any(

                "SUSPICIOUS"
                in event_type

                for event_type
                in event_types

            )

            # -------------------------------------------------
            # NUMBER OF SECURITY SIGNALS
            # -------------------------------------------------

            signals = sum([

                failed_login,

                unauthorized,

                privilege,

                brute_force,

                attack_pattern,

                permission_denied,

                suspicious

            ])

            # -------------------------------------------------
            # MULTI-USER ATTACK
            # -------------------------------------------------

            multi_user_attack = (
                len(usernames) >= 2
            )

            # -------------------------------------------------
            # BASE SCORE
            # -------------------------------------------------

            score = 30

            score += signals * 8

            score += min(
                len(related) * 4,
                20
            )

            # Multiple usernames indicate broader targeting
            if multi_user_attack:

                score += 15

            # Dangerous combinations
            if (
                brute_force
                and
                unauthorized
            ):

                score += 15

            if (
                brute_force
                and
                privilege
            ):

                score += 20

            if (
                attack_pattern
                and
                privilege
            ):

                score += 20

            if (
                unauthorized
                and
                privilege
            ):

                score += 15

            if (
                failed_login
                and
                attack_pattern
            ):

                score += 15

            score = min(
                score,
                100
            )

            # -------------------------------------------------
            # ATTACK STAGE
            # -------------------------------------------------

            if (
                attack_pattern
                and
                privilege
            ):

                attack_stage = (
                    "EXPLOITATION_TO_PRIVILEGE_ESCALATION"
                )

            elif (
                failed_login
                and
                brute_force
            ):

                attack_stage = (
                    "CREDENTIAL_ATTACK"
                )

            elif attack_pattern:

                attack_stage = (
                    "EXPLOITATION"
                )

            elif unauthorized:

                attack_stage = (
                    "UNAUTHORIZED_ACCESS"
                )

            elif suspicious:

                attack_stage = (
                    "RECONNAISSANCE"
                )

            else:

                attack_stage = (
                    "MULTI_EVENT_ACTIVITY"
                )

            # -------------------------------------------------
            # CONFIDENCE
            # -------------------------------------------------

            if signals >= 5:

                confidence = "VERY_HIGH"

            elif signals >= 4:

                confidence = "HIGH"

            elif signals >= 3:

                confidence = "MEDIUM"

            else:

                confidence = "LOW"

            # -------------------------------------------------
            # CLASSIFICATION
            # -------------------------------------------------

            if (
                attack_pattern
                and
                privilege
            ):

                incident_type = (
                    "MULTI_STAGE_ATTACK"
                )

            elif multi_user_attack:

                incident_type = (
                    "MULTI_ACCOUNT_ATTACK"
                )

            elif brute_force:

                incident_type = (
                    "CREDENTIAL_ATTACK"
                )

            elif attack_pattern:

                incident_type = (
                    "APPLICATION_ATTACK"
                )

            elif unauthorized:

                incident_type = (
                    "UNAUTHORIZED_ACTIVITY"
                )

            else:

                incident_type = (
                    "CORRELATED_SECURITY_ACTIVITY"
                )

            # -------------------------------------------------
            # BUILD ALERT
            # -------------------------------------------------

            correlated.append({

                "severity":
                    severity_from_score(
                        score
                    ),

                "type":
                    "ADVANCED_CORRELATED_THREAT",

                "incident_type":
                    incident_type,

                "attack_stage":
                    attack_stage,

                "confidence":
                    confidence,

                "message":
                    (
                        f"Correlated {len(related)} "
                        f"security events from "
                        f"{ip_address} within "
                        f"{window_minutes} minutes."
                    ),

                "ip_address":
                    ip_address,

                "username":
                    ", ".join(
                        sorted(
                            usernames
                        )
                    )
                    if usernames
                    else "Unknown",

                "event_count":
                    len(related),

                "event_types":
                    sorted(
                        event_types
                    ),

                "risk_score":
                    score,

                "risk_level":
                    get_risk_level(
                        score
                    ),

                "timestamp":
                    current_time.strftime(
                        "%Y-%m-%d %H:%M:%S"
                    )

            })

            # -------------------------------------------------
            # ONE ALERT PER IP
            # -------------------------------------------------

            break

    return correlated


# =========================================================
# MERGE DUPLICATE ALERTS
# =========================================================

def merge_correlated_alerts(alerts):

    merged = {}

    for alert in alerts:

        ip_address = alert.get(
            "ip_address",
            "Unknown"
        )

        alert_type = alert.get(
            "type",
            "UNKNOWN"
        )

        key = (
            ip_address,
            alert_type
        )

        if key not in merged:

            merged[key] = dict(
                alert
            )

            continue

        existing = merged[key]

        # Keep highest risk score
        existing_score = int(
            existing.get(
                "risk_score",
                0
            ) or 0
        )

        new_score = int(
            alert.get(
                "risk_score",
                0
            ) or 0
        )

        if new_score > existing_score:

            existing[
                "risk_score"
            ] = new_score

            existing[
                "risk_level"
            ] = get_risk_level(
                new_score
            )

            existing[
                "severity"
            ] = severity_from_score(
                new_score
            )

        # Combine event count
        existing[
            "event_count"
        ] = (

            int(
                existing.get(
                    "event_count",
                    0
                )
            )

            +

            int(
                alert.get(
                    "event_count",
                    0
                )
            )

        )

        # Combine usernames
        old_users = set(

            str(
                existing.get(
                    "username",
                    ""
                )
            ).split(", ")

        )

        new_users = set(

            str(
                alert.get(
                    "username",
                    ""
                )
            ).split(", ")

        )

        users = (

            old_users
            |
            new_users

        )

        users.discard("")
        users.discard("Unknown")

        existing[
            "username"
        ] = (

            ", ".join(
                sorted(users)
            )
            if users
            else "Unknown"

        )

    return list(
        merged.values()
    )


# =========================================================
# COMPLETE ADVANCED CORRELATION
# =========================================================

def generate_correlated_threats(events):

    correlated = advanced_threat_correlation(
        events
    )

    correlated = merge_correlated_alerts(
        correlated
    )

    correlated.sort(

        key=lambda alert:
            int(
                alert.get(
                    "risk_score",
                    0
                ) or 0
            ),

        reverse=True

    )

    return correlated
# =========================================================
# STEP 18.10
# ADVANCED THREAT DETECTION
# FINAL INTEGRATION
# =========================================================

def advanced_threat_detection(events):
    """
    Final advanced threat detection engine.

    Combines:
        - Brute-force activity
        - Suspicious IP activity
        - Unauthorized access
        - Permission denied
        - Attack patterns
        - Multi-user targeting
        - Risk escalation
        - Threat correlation
    """

    if not events:
        return []

    threats = []

    # -----------------------------------------------------
    # GROUP EVENTS BY IP
    # -----------------------------------------------------

    ip_activity = defaultdict(list)

    for event in events:

        ip = str(
            event.get(
                "ip_address",
                "Unknown"
            )
        )

        if ip == "Unknown":
            continue

        ip_activity[ip].append(event)

    # -----------------------------------------------------
    # ANALYZE EACH IP
    # -----------------------------------------------------

    for ip, ip_events in ip_activity.items():

        failed_logins = 0
        unauthorized = 0
        permission_denied = 0
        suspicious = 0
        attack_patterns = 0

        usernames = set()
        event_names = set()

        # -------------------------------------------------
        # INSPECT EVENTS
        # -------------------------------------------------

        for event in ip_events:

            event_name = str(
                event.get(
                    "event",
                    ""
                )
            ).lower()

            message = str(
                event.get(
                    "message",
                    ""
                )
            ).lower()

            event_names.add(
                event_name
            )

            username = event.get(
                "username",
                "Unknown"
            )

            if username not in (
                "",
                None,
                "Unknown"
            ):

                usernames.add(
                    str(username)
                )

            # ---------------------------------------------
            # FAILED LOGIN
            # ---------------------------------------------

            if (
                "failed login"
                in event_name
                or
                "login failed"
                in message
            ):

                failed_logins += 1

            # ---------------------------------------------
            # UNAUTHORIZED
            # ---------------------------------------------

            if (
                "unauthorized"
                in event_name
                or
                "unauthorized"
                in message
            ):

                unauthorized += 1

            # ---------------------------------------------
            # PERMISSION DENIED
            # ---------------------------------------------

            if (
                "permission denied"
                in event_name
                or
                "permission denied"
                in message
            ):

                permission_denied += 1

            # ---------------------------------------------
            # SUSPICIOUS
            # ---------------------------------------------

            if (
                "suspicious"
                in event_name
                or
                "suspicious"
                in message
            ):

                suspicious += 1

            # ---------------------------------------------
            # ATTACK PATTERNS
            # ---------------------------------------------

            attack_keywords = [

                "sql injection",
                "command injection",
                "path traversal",
                "cross site scripting",
                "xss",
                "port scan",
                "scanning",
                "enumeration",
                "exploit",
                "payload"

            ]

            if any(
                keyword in message
                for keyword in attack_keywords
            ):

                attack_patterns += 1

        # -------------------------------------------------
        # RISK SCORE
        # -------------------------------------------------

        risk_score = 0

        risk_score += min(
            failed_logins * 8,
            40
        )

        risk_score += min(
            unauthorized * 15,
            30
        )

        risk_score += min(
            permission_denied * 8,
            20
        )

        risk_score += min(
            suspicious * 8,
            20
        )

        risk_score += min(
            attack_patterns * 15,
            30
        )

        # Multiple usernames = possible credential spraying
        if len(usernames) >= 2:

            risk_score += 15

        # Repeated failures = brute-force indicator
        if failed_logins >= 5:

            risk_score += 20

        # Combined suspicious activity
        if (
            failed_logins > 0
            and
            unauthorized > 0
        ):

            risk_score += 20

        # Attack + privilege-like activity
        if (
            attack_patterns > 0
            and
            permission_denied > 0
        ):

            risk_score += 15

        risk_score = min(
            risk_score,
            100
        )

        # -------------------------------------------------
        # IGNORE LOW-SIGNAL IPS
        # -------------------------------------------------

        if risk_score < 30:
            continue

        # -------------------------------------------------
        # INCIDENT TYPE
        # -------------------------------------------------

        if (
            failed_logins >= 5
            and
            len(usernames) >= 2
        ):

            incident_type = (
                "CREDENTIAL_SPRAYING"
            )

        elif failed_logins >= 5:

            incident_type = (
                "BRUTE_FORCE_ATTACK"
            )

        elif (
            attack_patterns > 0
            and
            unauthorized > 0
        ):

            incident_type = (
                "APPLICATION_INTRUSION"
            )

        elif attack_patterns > 0:

            incident_type = (
                "ATTACK_PATTERN"
            )

        elif unauthorized > 0:

            incident_type = (
                "UNAUTHORIZED_ACCESS"
            )

        elif permission_denied > 0:

            incident_type = (
                "ACCESS_VIOLATION"
            )

        else:

            incident_type = (
                "SUSPICIOUS_ACTIVITY"
            )

        # -------------------------------------------------
        # SEVERITY
        # -------------------------------------------------

        severity = severity_from_score(
            risk_score
        )

        # -------------------------------------------------
        # RISK LEVEL
        # -------------------------------------------------

        risk_level = get_risk_level(
            risk_score
        )

        # -------------------------------------------------
        # CONFIDENCE
        # -------------------------------------------------

        signal_count = sum([

            failed_logins > 0,
            unauthorized > 0,
            permission_denied > 0,
            suspicious > 0,
            attack_patterns > 0

        ])

        if signal_count >= 4:

            confidence = "VERY_HIGH"

        elif signal_count >= 3:

            confidence = "HIGH"

        elif signal_count >= 2:

            confidence = "MEDIUM"

        else:

            confidence = "LOW"

        # -------------------------------------------------
        # PRIORITY
        # -------------------------------------------------

        if risk_score >= 85:

            priority = "P1"

        elif risk_score >= 70:

            priority = "P2"

        elif risk_score >= 50:

            priority = "P3"

        else:

            priority = "P4"

        # -------------------------------------------------
        # ATTACK STAGE
        # -------------------------------------------------

        if (
            failed_logins > 0
            and
            unauthorized > 0
            and
            attack_patterns > 0
        ):

            attack_stage = (
                "CREDENTIAL_ACCESS_TO_EXPLOITATION"
            )

        elif failed_logins > 0:

            attack_stage = (
                "CREDENTIAL_ACCESS"
            )

        elif attack_patterns > 0:

            attack_stage = (
                "EXPLOITATION"
            )

        elif unauthorized > 0:

            attack_stage = (
                "INITIAL_ACCESS"
            )

        elif suspicious > 0:

            attack_stage = (
                "RECONNAISSANCE"
            )

        else:

            attack_stage = (
                "UNKNOWN"
            )

        # -------------------------------------------------
        # MESSAGE
        # -------------------------------------------------

        message = (

            f"Advanced threat detected from "
            f"{ip}. "

            f"Observed {len(ip_events)} event(s), "

            f"{failed_logins} failed login(s), "

            f"{unauthorized} unauthorized "
            f"event(s), "

            f"{permission_denied} permission "
            f"denied event(s), "

            f"and {attack_patterns} attack "
            f"pattern(s)."

        )

        # -------------------------------------------------
        # CREATE THREAT
        # -------------------------------------------------

        threats.append({

            "severity":
                severity,

            "type":
                "ADVANCED_THREAT",

            "incident_type":
                incident_type,

            "attack_stage":
                attack_stage,

            "confidence":
                confidence,

            "priority":
                priority,

            "message":
                message,

            "ip_address":
                ip,

            "username":
                ", ".join(
                    sorted(
                        usernames
                    )
                )
                if usernames
                else "Unknown",

            "event_count":
                len(ip_events),

            "failed_logins":
                failed_logins,

            "unauthorized_events":
                unauthorized,

            "permission_denied":
                permission_denied,

            "suspicious_events":
                suspicious,

            "attack_patterns":
                attack_patterns,

            "risk_score":
                risk_score,

            "risk_level":
                risk_level,

            "timestamp":
                (
                    ip_events[-1].get(
                        "timestamp",
                        "Unknown"
                    )
                )

        })

    # -----------------------------------------------------
    # SORT BY RISK
    # -----------------------------------------------------

    threats.sort(

        key=lambda threat:

        int(
            threat.get(
                "risk_score",
                0
            )
            or
            0
        ),

        reverse=True

    )

    return threats


# =========================================================
# FINAL THREAT REPORT
# =========================================================

def generate_threat_report(events):

    threats = advanced_threat_detection(
        events
    )

    report = {

        "total_threats":
            len(threats),

        "critical":
            0,

        "high":
            0,

        "medium":
            0,

        "low":
            0,

        "threats":
            threats

    }

    for threat in threats:

        severity = str(
            threat.get(
                "severity",
                "LOW"
            )
        ).lower()

        if severity in report:

            report[
                severity
            ] += 1

    # -----------------------------------------------------
    # OVERALL RISK
    # -----------------------------------------------------

    if not threats:

        report[
            "overall_risk"
        ] = "LOW"

    else:

        highest_score = max(

            int(
                threat.get(
                    "risk_score",
                    0
                )
                or
                0
            )

            for threat in threats

        )

        report[
            "highest_risk_score"
        ] = highest_score

        report[
            "overall_risk"
        ] = get_risk_level(
            highest_score
        )

    return report


# =========================================================
# FINAL DETECTION SUMMARY
# =========================================================

def get_detection_summary(events):

    report = generate_threat_report(
        events
    )

    threats = report.get(
        "threats",
        []
    )

    incident_counts = {}

    for threat in threats:

        incident_type = threat.get(
            "incident_type",
            "UNKNOWN"
        )

        incident_counts[
            incident_type
        ] = (

            incident_counts.get(
                incident_type,
                0
            )
            + 1

        )

    return {

        "total_threats":
            report.get(
                "total_threats",
                0
            ),

        "overall_risk":
            report.get(
                "overall_risk",
                "LOW"
            ),

        "highest_risk_score":
            report.get(
                "highest_risk_score",
                0
            ),

        "critical":
            report.get(
                "critical",
                0
            ),

        "high":
            report.get(
                "high",
                0
            ),

        "medium":
            report.get(
                "medium",
                0
            ),

        "low":
            report.get(
                "low",
                0
            ),

        "incident_counts":
            incident_counts

    }
