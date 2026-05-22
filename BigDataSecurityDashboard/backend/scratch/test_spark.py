import requests
import sys
import os

os.environ['NO_PROXY'] = '127.0.0.1,localhost'

base_url = "http://127.0.0.1:8000/api"

print("--- Log in to acquire JWT token ---")
try:
    r = requests.post(f"{base_url}/auth/login", json={"username": "admin", "password": "admin123"})
    if r.status_code != 200:
        print("Login failed:", r.text)
        sys.exit(1)
    
    token = r.json().get("access_token")
    headers = {"Authorization": f"Bearer {token}"}
    print("Login success. Token acquired.")
except Exception as e:
    print("Connection error:", e)
    sys.exit(1)

print("\n--- Testing Spark Metrics Endpoint: GET /spark/metrics ---")
try:
    r = requests.get(f"{base_url}/spark/metrics", headers=headers)
    print("Metrics Status:", r.status_code)
    if r.status_code == 200:
        print("Metrics Payload:", r.json())
    else:
        print("Metrics Error:", r.text)
except Exception as e:
    print("Error calling metrics:", e)

print("\n--- Testing Spark Analyze Endpoint (Default Historical): POST /spark/analyze ---")
try:
    # Notice we can pass empty strings for filters, but let's see what form fields spark_routes expects.
    # From spark_routes.py:
    # file: Optional[UploadFile] = File(None)
    # log_type: str = Form("apache")
    # partitions: int = Form(4)
    # classifier: str = Form("isolation_forest")
    # etc.
    data = {
        "log_type": "apache",
        "partitions": "4",
        "classifier": "isolation_forest",
        "search_ip": "",
        "search_url": "",
        "severity_filter": "",
        "threat_type_filter": "",
        "time_range": "all"
    }
    r = requests.post(f"{base_url}/spark/analyze", data=data, headers=headers)
    print("Analyze Status:", r.status_code)
    if r.status_code == 200:
        res = r.json()
        print("Analyze Metadata:", res.get("metadata"))
        print("Analyze Records Count:", len(res.get("records", [])))
        print("Analyze Aggregations Keys:", res.get("aggregations", {}).keys())
        print("Sample Aggregations:", {k: v[:2] if isinstance(v, list) else v for k, v in res.get("aggregations", {}).items()})
    else:
        print("Analyze Error:", r.text)
except Exception as e:
    print("Error calling analyze:", e)

print("\n--- Testing Spark Simulation Endpoint: POST /spark/simulate ---")
try:
    data = {
        "log_type": "apache",
        "record_count": "10"
    }
    r = requests.post(f"{base_url}/spark/simulate", data=data, headers=headers)
    print("Simulate Status:", r.status_code)
    if r.status_code == 200:
        res = r.json()
        print("Simulate Metadata:", res.get("metadata"))
        print("Simulate Records Count:", len(res.get("records", [])))
        print("Simulate Aggregations Keys:", res.get("aggregations", {}).keys())
    else:
        print("Simulate Error:", r.text)
except Exception as e:
    print("Error calling simulate:", e)
