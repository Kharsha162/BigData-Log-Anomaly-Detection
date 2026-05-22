import os
import random
import time
from datetime import datetime

# Geographic profiles for simulated IPs
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

NORMAL_PATHS = [
    "/index.html", "/about.html", "/contact.html", "/products/items",
    "/js/main.js", "/css/styles.css", "/images/logo.png", "/favicon.ico",
    "/api/v1/status", "/api/v1/metrics", "/blog/posts"
]

MALICIOUS_ACTIONS = [
    # SQL Injections
    {"url": "/api/users?id=1%20UNION%20SELECT%20NULL,username,password%20FROM%20users--", "method": "GET", "status": 500, "type": "SQL Injection"},
    {"url": "/login?user=admin%27%20OR%201=1--", "method": "POST", "status": 200, "type": "SQL Injection"},
    # Directory Traversals
    {"url": "/static/../../etc/passwd", "method": "GET", "status": 400, "type": "Directory Traversal / LFI"},
    {"url": "/files/download?file=..%2f..%2f..%2fwindows%2fwin.ini", "method": "GET", "status": 400, "type": "Directory Traversal / LFI"},
    # Command Injections
    {"url": "/api/ping?host=127.0.0.1;%20whoami", "method": "GET", "status": 500, "type": "Command Injection"},
    {"url": "/cgi-bin/test.sh?cmd=cat%20/etc/hosts", "method": "GET", "status": 500, "type": "Command Injection"},
    # Web Scanners / Recon
    {"url": "/wp-login.php", "method": "GET", "status": 404, "type": "Web Scanner / Reconnaissance"},
    {"url": "/admin", "method": "GET", "status": 401, "type": "Web Scanner / Reconnaissance"},
    {"url": "/.env", "method": "GET", "status": 404, "type": "Web Scanner / Reconnaissance"},
    {"url": "/phpmyadmin/index.php", "method": "GET", "status": 404, "type": "Web Scanner / Reconnaissance"}
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
]

def generate_apache_log_line(timestamp=None, geo_profile=None, scenario=None):
    """Generates a single Apache Common/Combined formatted log string and returns metadata.
    
    scenarios: 'normal', 'brute_force', 'ddos', 'exploit', None (random)
    """
    if not timestamp:
        timestamp = datetime.now()
    
    ts_str = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
    
    # Pick IP
    if not geo_profile:
        if scenario in ['brute_force', 'ddos', 'exploit']:
            # Pick a malicious IP
            geo_profile = random.choice([p for p in GEO_PROFILES if p["is_malicious"]])
        else:
            # Pick normal IP 80% of time, malicious 20%
            if random.random() < 0.8:
                geo_profile = random.choice([p for p in GEO_PROFILES if not p["is_malicious"]])
            else:
                geo_profile = random.choice([p for p in GEO_PROFILES if p["is_malicious"]])
                
    ip = geo_profile["ip"]
    user_agent = random.choice(USER_AGENTS)
    
    # Pick request
    if scenario == 'exploit':
        action = random.choice(MALICIOUS_ACTIONS)
        url = action["url"]
        method = action["method"]
        status = action["status"]
        threat_type = action["type"]
    elif scenario == 'brute_force':
        url = "/api/v1/auth/login"
        method = "POST"
        status = 401
        threat_type = "Brute Force Attack"
    elif scenario == 'ddos':
        url = "/index.html"
        method = "GET"
        status = 200
        threat_type = "DDoS Attempt / Flooding"
    else:
        # Default Random Selection
        if geo_profile["is_malicious"] and random.random() < 0.5:
            # Malicious IP attempts exploit
            action = random.choice(MALICIOUS_ACTIONS)
            url = action["url"]
            method = action["method"]
            status = action["status"]
            threat_type = action["type"]
        else:
            # Normal Request
            url = random.choice(NORMAL_PATHS)
            method = random.choice(["GET", "GET", "GET", "POST", "PUT"])
            status = random.choice([200, 200, 200, 200, 304, 404])
            threat_type = "Normal"
            
    size = random.randint(100, 25000) if status == 200 else random.randint(0, 1500)
    
    # Combine to Apache Combined Format:
    # 127.0.0.1 - - [21/May/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024 "referrer" "user_agent"
    log_line = f'{ip} - - [{ts_str}] "{method} {url} HTTP/1.1" {status} {size} "-" "{user_agent}"'
    
    return {
        "line": log_line,
        "metadata": {
            "timestamp": timestamp.isoformat(),
            "ip": ip,
            "country": geo_profile["country"],
            "city": geo_profile["city"],
            "lat": geo_profile["lat"],
            "lon": geo_profile["lon"],
            "method": method,
            "url": url,
            "status": status,
            "size": size,
            "threat_type": threat_type,
            "is_anomaly": geo_profile["is_malicious"] or status in [401, 403, 500] or threat_type != "Normal"
        }
    }

def create_initial_log_file(dest_path: str, count: int = 5000):
    """Creates a raw file populated with historical Apache logs to act as the initial dataset."""
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
    
    print(f"Generating {count} mock access logs in {dest_path}...")
    start_time = time.time() - (count * 10)  # Spread logs over the past few hours
    
    records = []
    # Seed brute-force scenario
    bf_profile = [p for p in GEO_PROFILES if p["ip"] == "82.102.23.45"][0]
    # Seed DDoS scenario
    ddos_profile = [p for p in GEO_PROFILES if p["ip"] == "185.220.101.5"][0]
    
    with open(dest_path, 'w', encoding='utf-8') as f:
        for i in range(count):
            curr_time = datetime.fromtimestamp(start_time + (i * 10))
            
            # Inject structured attacks at specific locations
            if 1000 < i < 1010:
                res = generate_apache_log_line(curr_time, bf_profile, 'brute_force')
            elif 2500 < i < 2550:
                res = generate_apache_log_line(curr_time, ddos_profile, 'ddos')
            elif i % 15 == 0:
                res = generate_apache_log_line(curr_time, scenario='exploit')
            else:
                res = generate_apache_log_line(curr_time)
                
            f.write(res["line"] + "\n")
            records.append(res["metadata"])
            
    print(f"Log generation finished in {time.time() - start_time:.2f} seconds.")
    return records
