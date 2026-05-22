import re
import urllib.parse
from datetime import datetime

# Threat rules database
SUSPICIOUS_PATHS = [
    r'/admin', r'/wp-admin', r'/wp-login\.php', r'/\.env', r'/config', 
    r'/etc/passwd', r'/boot\.ini', r'/phpinfo\.php', r'/shell', r'/cmd\.exe',
    r'/\.git', r'/backup', r'/db_backup', r'/composer\.lock', r'/package-lock\.json',
    r'/jenkins', r'/phpmyadmin'
]

ATTACK_SIGNATURES = {
    "SQL Injection": r"(UNION\s+SELECT|SELECT\s+.*\s+FROM|UNION\s+ALL\s+SELECT|INSERT\s+INTO|OR\s+1\s*=\s*1|[\'\"]\s*OR\s*[\'\"]1[\'\"]\s*=\s*[\'\"]1)",
    "Directory Traversal / LFI": r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%252e\%252e\%252f)",
    "Cross-Site Scripting (XSS)": r"(<script.*?>|javascript:|onload=|<img\s+src\s*=\s*[\'\"]?javascript:)",
    "Command Injection": r"(;|&&|\|\|)\s*(cat|ls|pwd|whoami|id|wget|curl|netcat|nc|sh|bash|powershell|cmd)\s"
}

class SecurityRuleEngine:
    def __init__(self):
        # Cache for historical tracking (in-memory) to detect brute-force & flooding
        # In production, this would use Redis.
        self.ip_request_history = {}  # ip -> list of timestamps
        self.ip_failed_logins = {}    # ip -> list of timestamps

    def analyze_log_record(self, record: dict) -> dict:
        """Runs the rule engine over a single parsed log record and updates telemetry.
        
        Returns:
            dict containing:
                is_threat: bool
                threat_type: str (e.g. 'Normal', 'SQL Injection', 'Brute Force', etc.)
                severity: str ('Low', 'Medium', 'High', 'Critical')
                score: float (0.0 to 1.0)
                details: str
        """
        ip = record.get("ip")
        # URL decode query parameters (unquote twice to handle double url encoding)
        raw_url = record.get("url", "")
        url = urllib.parse.unquote(urllib.parse.unquote(raw_url))
        status = record.get("status", 200)
        method = record.get("method", "GET")
        
        # Parse timestamp
        now = datetime.now()
        
        # Track history for flooding
        if ip not in self.ip_request_history:
            self.ip_request_history[ip] = []
        self.ip_request_history[ip].append(now)
        
        # Clean history (only keep past 10 seconds for flooding)
        self.ip_request_history[ip] = [t for t in self.ip_request_history[ip] if (now - t).total_seconds() <= 10]
        
        # Track failed logins for brute-force (specifically POST /login or /wp-login with 401/403 status)
        is_login_attempt = "login" in url.lower() or "auth" in url.lower()
        is_failed = status in [401, 403]
        if is_login_attempt and is_failed:
            if ip not in self.ip_failed_logins:
                self.ip_failed_logins[ip] = []
            self.ip_failed_logins[ip].append(now)
        
        # Clean failed login history (keep past 60 seconds)
        if ip in self.ip_failed_logins:
            self.ip_failed_logins[ip] = [t for t in self.ip_failed_logins[ip] if (now - t).total_seconds() <= 60]

        # 1. FLOODING (DDoS) Check
        if len(self.ip_request_history[ip]) > 30:  # > 30 requests in 10 seconds
            return {
                "is_threat": True,
                "threat_type": "DDoS Attempt / Flooding",
                "severity": "High",
                "score": 0.85,
                "details": f"IP requested {len(self.ip_request_history[ip])} resources in 10 seconds."
            }

        # 2. BRUTE-FORCE Check
        if ip in self.ip_failed_logins and len(self.ip_failed_logins[ip]) >= 5:
            return {
                "is_threat": True,
                "threat_type": "Brute Force Attack",
                "severity": "Critical",
                "score": 0.95,
                "details": f"Detected {len(self.ip_failed_logins[ip])} failed login attempts in under 60 seconds."
            }

        # 3. CRITICAL SIGNATURE MATCHING (SQLi, XSS, etc.)
        for attack_name, regex in ATTACK_SIGNATURES.items():
            if re.search(regex, url, re.IGNORECASE):
                # Critical payload injection
                return {
                    "is_threat": True,
                    "threat_type": attack_name,
                    "severity": "Critical",
                    "score": 0.98,
                    "details": f"Exploit pattern detected in request query path: {url}"
                }

        # 4. SUSPICIOUS ENDPOINT SCANNING
        for path_regex in SUSPICIOUS_PATHS:
            if re.search(path_regex, url, re.IGNORECASE):
                # Privilege or configuration file sniffing
                severity = "High" if status == 200 else "Medium"
                score = 0.75 if status == 200 else 0.50
                return {
                    "is_threat": True,
                    "threat_type": "Web Scanner / Reconnaissance",
                    "severity": severity,
                    "score": score,
                    "details": f"Scanned restricted or sensitive endpoint '{url}' resulting in HTTP {status}."
                }

        # 5. PRIVILEGED ACCESS ALERT
        if ("/root" in url or "/admin/secure" in url or "/secret" in url) and status == 200:
            return {
                "is_threat": True,
                "threat_type": "Unauthorized Privilege Access",
                "severity": "High",
                "score": 0.80,
                "details": "Successful access to sensitive, restricted admin directory."
            }

        # 6. ANOMALOUS STATUS CODE SPARK (404/500 spikes)
        if status == 404:
            return {
                "is_threat": False,
                "threat_type": "Normal (404 Not Found)",
                "severity": "Low",
                "score": 0.15,
                "details": f"Requested resources not found: {url}"
            }
        elif status == 500:
            return {
                "is_threat": True,
                "threat_type": "Server Application Error",
                "severity": "Medium",
                "score": 0.40,
                "details": "Server responded with HTTP 500. Could indicate SQL syntax crashes or system failure."
            }

        # Normal Traffic
        return {
            "is_threat": False,
            "threat_type": "Normal",
            "severity": "Low",
            "score": 0.02,
            "details": "Normal HTTP request flow."
        }
