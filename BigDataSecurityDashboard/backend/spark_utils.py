import os
import re
import random
import time
from datetime import datetime
from typing import Dict, Any, List, Optional

# Re-use GEO_PROFILES for geographic information and malicious/benign labeling
GEO_PROFILES = [
    # Malicious/Suspicious IPs
    {"ip": "185.220.101.5", "country": "United States", "city": "Washington", "lat": 47.75, "lon": -120.74, "is_malicious": True},
    {"ip": "82.102.23.45", "country": "Russia", "city": "Moscow", "lat": 55.75, "lon": 37.61, "is_malicious": True},
    {"ip": "103.22.200.41", "country": "North Korea", "city": "Pyongyang", "lat": 39.03, "lon": 125.76, "is_malicious": True},
    {"ip": "198.51.100.12", "country": "China", "city": "Beijing", "lat": 39.90, "lon": 116.40, "is_malicious": True},
    {"ip": "91.220.43.12", "country": "Ukraine", "city": "Kyiv", "lat": 50.45, "lon": 30.52, "is_malicious": True},
    {"ip": "190.12.87.54", "country": "Brazil", "city": "Sao Paulo", "lat": -23.55, "lon": -46.63, "is_malicious": True},
    {"ip": "89.248.167.15", "country": "Netherlands", "city": "Amsterdam", "lat": 52.36, "lon": 4.90, "is_malicious": True},
    # Normal/User IPs
    {"ip": "122.164.48.9", "country": "India", "city": "Chennai", "lat": 13.08, "lon": 80.27, "is_malicious": False},
    {"ip": "203.0.113.88", "country": "Australia", "city": "Sydney", "lat": -33.86, "lon": 151.20, "is_malicious": False},
    {"ip": "81.108.20.11", "country": "United Kingdom", "city": "London", "lat": 51.50, "lon": -0.12, "is_malicious": False},
    {"ip": "192.168.1.15", "country": "Local", "city": "Localhost", "lat": 37.77, "lon": -122.41, "is_malicious": False},
    {"ip": "10.0.0.4", "country": "Internal", "city": "Intranet", "lat": 37.77, "lon": -122.41, "is_malicious": False}
]

APACHE_PATHS = [
    "/index.html", "/about.html", "/contact.html", "/products/items",
    "/js/main.js", "/css/styles.css", "/images/logo.png", "/favicon.ico",
    "/api/v1/status", "/api/v1/metrics", "/blog/posts"
]

APACHE_EXPLOITS = [
    {"url": "/api/users?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users--", "method": "GET", "status": 500, "type": "SQL Injection"},
    {"url": "/login?user=admin%27%20OR%201=1--", "method": "POST", "status": 200, "type": "SQL Injection"},
    {"url": "/static/../../etc/passwd", "method": "GET", "status": 400, "type": "Directory Traversal"},
    {"url": "/files/download?file=..%2f..%2f..%2fwindows%2fwin.ini", "method": "GET", "status": 400, "type": "Directory Traversal"},
    {"url": "/api/ping?host=127.0.0.1;%20whoami", "method": "GET", "status": 500, "type": "Command Injection"},
    {"url": "/cgi-bin/test.sh?cmd=cat%20/etc/hosts", "method": "GET", "status": 500, "type": "Command Injection"},
    {"url": "/wp-login.php", "method": "GET", "status": 404, "type": "Web Scanner / Recon"},
    {"url": "/admin", "method": "GET", "status": 401, "type": "Web Scanner / Recon"},
    {"url": "/.env", "method": "GET", "status": 404, "type": "Web Scanner / Recon"},
    {"url": "/phpmyadmin/index.php", "method": "GET", "status": 404, "type": "Web Scanner / Recon"}
]

HDFS_PATHS = [
    "/user/hdfs/data/analytics", "/user/hive/warehouse", "/tmp/spark-events", 
    "/system/yarn/logs", "/user/admin/workspace", "/user/root/setup.sh"
]

K8S_PODS = [
    "auth-service-pod-x92", "frontend-gateway-j12", "payment-api-h88", 
    "spark-executor-001", "database-proxy-z45", "nginx-ingress-controller"
]

CLOUD_SERVICES = [
    {"service": "ec2.amazonaws.com", "method": "DescribeInstances"},
    {"service": "s3.amazonaws.com", "method": "GetObject"},
    {"service": "iam.amazonaws.com", "method": "CreateUser"},
    {"service": "sts.amazonaws.com", "method": "AssumeRole"},
    {"service": "rds.amazonaws.com", "method": "DescribeDBInstances"}
]

ANDROID_TAGS = [
    "ActivityManager", "PackageManager", "LogcatService", "MalwareDetector", 
    "VpnConnection", "AuthManager", "NetworkStats"
]

def generate_mock_log_line(log_type: str, scenario: str = None) -> Dict[str, Any]:
    """Generates a raw string representation and dictionary meta of simulated logs based on type and scenario."""
    log_type = log_type.lower()
    if not scenario:
        scenario = random.choices(["normal", "exploit"], weights=[0.8, 0.2])[0]
        
    now = datetime.now()
    geo = random.choice(GEO_PROFILES)
    if scenario == "exploit" or geo["is_malicious"]:
        geo = random.choice([p for p in GEO_PROFILES if p["is_malicious"]])
    else:
        geo = random.choice([p for p in GEO_PROFILES if not p["is_malicious"]])
        
    ip = geo["ip"]
    country = geo["country"]
    city = geo["city"]
    
    if log_type == "apache":
        # 127.0.0.1 - - [21/May/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024
        ts_str = now.strftime("%d/%b/%Y:%H:%M:%S +0000")
        if scenario == "exploit":
            exploit = random.choice(APACHE_EXPLOITS)
            method = exploit["method"]
            url = exploit["url"]
            status = exploit["status"]
            threat_type = exploit["type"]
            severity = "High Threat" if status == 500 else "Suspicious"
        else:
            method = random.choice(["GET", "GET", "POST", "PUT"])
            url = random.choice(APACHE_PATHS)
            status = random.choice([200, 200, 200, 304, 404])
            threat_type = "Normal"
            severity = "Normal"
            
        size = random.randint(100, 50000) if status == 200 else random.randint(0, 1500)
        line = f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"'
        
        return {
            "line": line,
            "parsed": {
                "timestamp": ts_str,
                "ip": ip,
                "method": method,
                "url": url,
                "status": status,
                "size": size,
                "log_type": "Apache",
                "threat_type": threat_type,
                "threat_severity": severity,
                "prediction": "Anomaly" if scenario == "exploit" else "Normal",
                "anomaly_score": 0.85 if scenario == "exploit" else 0.04,
                "country": country,
                "city": city
            }
        }
        
    elif log_type == "hdfs":
        # 2026-05-21 21:00:01 192.168.1.50 INFO dfs.FSNamesystem: Allowed access to /user/hdfs/data
        ts_str = now.strftime("%Y-%m-%d %H:%M:%S")
        method = "HDFS_OP"
        
        if scenario == "exploit":
            sev_level = "ERROR"
            path = random.choice(HDFS_PATHS)
            msg = f"Unauthorized access denied to {path}"
            status = 403
            threat_type = "Unauthorized DFS Access"
            severity = "High Threat"
        else:
            sev_level = "INFO"
            path = random.choice(HDFS_PATHS)
            msg = f"Allowed access to {path}"
            status = 200
            threat_type = "Normal"
            severity = "Normal"
            
        line = f"{ts_str} {ip} {sev_level} dfs.FSNamesystem: {msg}"
        return {
            "line": line,
            "parsed": {
                "timestamp": ts_str,
                "ip": ip,
                "method": method,
                "url": path,
                "status": status,
                "size": random.randint(500, 10000),
                "log_type": "HDFS",
                "threat_type": threat_type,
                "threat_severity": severity,
                "prediction": "Anomaly" if scenario == "exploit" else "Normal",
                "anomaly_score": 0.90 if scenario == "exploit" else 0.05,
                "country": country,
                "city": city
            }
        }
        
    elif log_type == "kubernetes":
        # 2026-05-21T21:05:00Z WARN pod-auth-service 10.244.0.12 User service-admin failed login
        ts_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        pod = random.choice(K8S_PODS)
        method = "K8S_REQ"
        
        if scenario == "exploit":
            sev_level = "ERROR"
            msg = f"User system-admin attempted exploit: pod overflow warning"
            status = 401
            threat_type = "Pod Privilege Abuse"
            severity = "Critical"
        else:
            sev_level = "INFO"
            msg = f"Pod health-check responsive on ingress gateway"
            status = 200
            threat_type = "Normal"
            severity = "Normal"
            
        line = f"{ts_str} {sev_level} {pod} {ip} {msg}"
        return {
            "line": line,
            "parsed": {
                "timestamp": ts_str,
                "ip": ip,
                "method": method,
                "url": f"/pods/{pod}",
                "status": status,
                "size": random.randint(100, 2048),
                "log_type": "Kubernetes",
                "threat_type": threat_type,
                "threat_severity": severity,
                "prediction": "Anomaly" if scenario == "exploit" else "Normal",
                "anomaly_score": 0.94 if scenario == "exploit" else 0.03,
                "country": country,
                "city": city
            }
        }
        
    elif log_type == "cloudtrail":
        # 2026-05-21T21:10:00Z 198.51.100.41 DescribeInstances AccessDenied ec2.amazonaws.com
        ts_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        cloud_svc = random.choice(CLOUD_SERVICES)
        method = cloud_svc["method"]
        url = cloud_svc["service"]
        
        if scenario == "exploit":
            status_str = "AccessDenied"
            status = 403
            threat_type = "Cloud IAM Abuse"
            severity = "Critical"
        else:
            status_str = "Success"
            status = 200
            threat_type = "Normal"
            severity = "Normal"
            
        line = f"{ts_str} {ip} {method} {status_str} {url}"
        return {
            "line": line,
            "parsed": {
                "timestamp": ts_str,
                "ip": ip,
                "method": method,
                "url": url,
                "status": status,
                "size": random.randint(100, 800),
                "log_type": "CloudTrail",
                "threat_type": threat_type,
                "threat_severity": severity,
                "prediction": "Anomaly" if scenario == "exploit" else "Normal",
                "anomaly_score": 0.96 if scenario == "exploit" else 0.02,
                "country": country,
                "city": city
            }
        }
        
    elif log_type == "android":
        # 05-21 21:12:00.123 D LogcatService( 1200) IP 122.164.48.9 Exploit attempted
        ts_str = now.strftime("%m-%d %H:%M:%S.%f")[:-3]
        tag = random.choice(ANDROID_TAGS)
        pid = random.randint(1000, 9999)
        
        if scenario == "exploit":
            priority = "F"
            msg = "Exploit attempted: buffer overflow detected in network daemon"
            status = 500
            threat_type = "Logcat Malware Warning"
            severity = "High Threat"
        else:
            priority = "I"
            msg = f"Network socket opened successfully to route API payload"
            status = 200
            threat_type = "Normal"
            severity = "Normal"
            
        line = f"{ts_str} {priority} {tag}( {pid}) IP {ip} {msg}"
        return {
            "line": line,
            "parsed": {
                "timestamp": f"{now.year}-{ts_str}",
                "ip": ip,
                "method": f"ANDROID_{priority}",
                "url": f"/app/{tag}",
                "status": status,
                "size": random.randint(50, 450),
                "log_type": "Android",
                "threat_type": threat_type,
                "threat_severity": severity,
                "prediction": "Anomaly" if scenario == "exploit" else "Normal",
                "anomaly_score": 0.89 if scenario == "exploit" else 0.05,
                "country": country,
                "city": city
            }
        }
        
    # Standard Fallback
    return generate_mock_log_line("apache", scenario)
