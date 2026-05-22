import os
import shutil
import random
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import APIRouter, Depends, Query, UploadFile, File, HTTPException, status
from pydantic import BaseModel, Field
from routes.auth import get_current_user
from services.state import app_state, DATA_DIR
from utils.log_generator import GEO_PROFILES, generate_apache_log_line, MALICIOUS_ACTIONS

router = APIRouter(prefix="", tags=["Advanced GeoMap Threat Intelligence"])

# Helper function to geolocate IP addresses deterministically
def geolocate_ip(ip_str: str) -> dict:
    # 1. First search in local preset profiles
    for profile in GEO_PROFILES:
        if profile["ip"] == ip_str:
            return {
                "country": profile["country"],
                "city": profile["city"],
                "latitude": profile["lat"],
                "longitude": profile["lon"],
                "isp": "CyberSafe Autonomous System" if profile["is_malicious"] else "Local Loop ISP"
            }
            
    # 2. Fallback to deterministic global coordinate pool
    h = int(hashlib.md5(ip_str.encode("utf-8")).hexdigest(), 16)
    
    GLOBAL_GEO_POOL = [
        {"country": "United States", "city": "San Francisco", "lat": 37.7749, "lon": -122.4194, "isp": "Cloudflare Hub"},
        {"country": "Germany", "city": "Frankfurt", "lat": 50.1109, "lon": 8.6821, "isp": "Deutsche Telekom AG"},
        {"country": "Japan", "city": "Tokyo", "lat": 35.6762, "lon": 139.6503, "isp": "NTT Global Network"},
        {"country": "Canada", "city": "Toronto", "lat": 43.6532, "lon": -79.3832, "isp": "Rogers Cable Network"},
        {"country": "France", "city": "Paris", "lat": 48.8566, "lon": 2.3522, "isp": "Orange S.A. Transit"},
        {"country": "Singapore", "city": "Singapore", "lat": 1.3521, "lon": 103.8198, "isp": "Singtel Infrastructure"},
        {"country": "South Africa", "city": "Cape Town", "lat": -33.9249, "lon": 18.4241, "isp": "Telkom SA Core"},
        {"country": "Netherlands", "city": "Rotterdam", "lat": 51.9244, "lon": 4.4777, "isp": "KPN Telecom"},
        {"country": "China", "city": "Beijing", "lat": 39.9042, "lon": 116.4074, "isp": "China Telecom"},
        {"country": "India", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777, "isp": "Reliance Jio Backbone"},
        {"country": "Brazil", "city": "Sao Paulo", "lat": -23.5505, "lon": -46.6333, "isp": "Claro Transit Gateway"},
        {"country": "Russia", "city": "Saint Petersburg", "lat": 59.9343, "lon": 30.3351, "isp": "Rostelecom Core"},
        {"country": "Australia", "city": "Sydney", "lat": -33.8688, "lon": 151.2093, "isp": "Telstra Communications"}
    ]
    
    geo = GLOBAL_GEO_POOL[h % len(GLOBAL_GEO_POOL)]
    # Add slight coordinate jitter so markers do not stack perfectly at the exact same point
    lat_jitter = ((h % 200) - 100) * 0.005
    lon_jitter = (((h >> 4) % 200) - 100) * 0.005
    
    return {
        "country": geo["country"],
        "city": geo["city"],
        "latitude": round(geo["lat"] + lat_jitter, 4),
        "longitude": round(geo["lon"] + lon_jitter, 4),
        "isp": geo["isp"]
    }

class GeoMapThreatRecord(BaseModel):
    timestamp: str
    ip: str
    country: str
    city: str
    isp: str
    latitude: float
    longitude: float
    threat_severity: str
    threat_type: str
    method: str
    url: str
    status: int
    size: int
    prediction: str
    anomaly_score: float

class CountryCount(BaseModel):
    country: str
    count: int
    percentage: float
    severity_distribution: Dict[str, int]

@router.get("/geomap-threats", response_model=List[GeoMapThreatRecord])
async def get_geomap_threats(
    current_user: str = Depends(get_current_user),
    ip: Optional[str] = Query(None, description="Filter by IP address"),
    url: Optional[str] = Query(None, description="Filter by URL string"),
    severity: Optional[str] = Query(None, description="Filter by Threat Severity (Normal, Suspicious, High Threat, Critical)"),
    country: Optional[str] = Query(None, description="Filter by Country name"),
    time_range: Optional[str] = Query(None, description="Filter by Time Range (e.g. 1h, 24h, 7d)")
):
    """Retrieves all anomaly and security threat logs mapped to coordinates and populated with full geo context."""
    db = app_state.logs_db
    records = []
    
    # 1. Map logs_db to our GeoMapThreatRecord format
    for log in db:
        # Resolve threat severity values for colors requested
        # Green -> Normal, Orange -> Suspicious, Red -> High Threat, Purple -> Critical
        sev = log.get("threat_severity", "Low")
        sev_mapped = "Normal"
        if sev == "Medium":
            sev_mapped = "Suspicious"
        elif sev == "High":
            sev_mapped = "High Threat"
        elif sev == "Critical":
            sev_mapped = "Critical"
            
        # Parse timestamp
        log_time_str = log.get("timestamp", "")
        
        # Calculate full geolocation & ISP details
        geo = geolocate_ip(log.get("ip", ""))
        
        rec = {
            "timestamp": log_time_str,
            "ip": log.get("ip", ""),
            "country": geo["country"],
            "city": geo["city"],
            "isp": geo["isp"],
            "latitude": geo["latitude"],
            "longitude": geo["longitude"],
            "threat_severity": sev_mapped,
            "threat_type": log.get("threat_type", "Normal"),
            "method": log.get("method", "GET"),
            "url": log.get("url", ""),
            "status": log.get("status", 200),
            "size": log.get("size", 0),
            "prediction": log.get("prediction", "Normal"),
            "anomaly_score": log.get("probability_score", 0.0)
        }
        records.append(rec)
        
    # 2. Filter matching criteria
    filtered = records.copy()
    
    if ip:
        filtered = [r for r in filtered if ip.lower() in r["ip"].lower()]
        
    if url:
        filtered = [r for r in filtered if url.lower() in r["url"].lower()]
        
    if severity:
        filtered = [r for r in filtered if r["threat_severity"].lower() == severity.lower()]
        
    if country:
        filtered = [r for r in filtered if r["country"].lower() == country.lower()]
        
    if time_range:
        now = datetime.now()
        delta = timedelta(days=365) # default long range
        if time_range == "1h":
            delta = timedelta(hours=1)
        elif time_range == "24h":
            delta = timedelta(hours=24)
        elif time_range == "7d":
            delta = timedelta(days=7)
            
        time_limit = now - delta
        
        parsed_filtered = []
        for r in filtered:
            try:
                # Try parsing standard isoformat or Apache format
                t_parsed = None
                try:
                    t_parsed = datetime.fromisoformat(r["timestamp"])
                except:
                    # Apache timestamp parsing fallback e.g. 21/May/2026:10:00:00 +0000
                    clean_ts = r["timestamp"].split(" ")[0]
                    t_parsed = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
                
                if t_parsed and t_parsed >= time_limit:
                    parsed_filtered.append(r)
            except Exception as e:
                # If timestamp parsing fails, keep it to be safe
                parsed_filtered.append(r)
        filtered = parsed_filtered
        
    return filtered

@router.get("/top-countries", response_model=List[CountryCount])
async def get_top_countries(current_user: str = Depends(get_current_user)):
    """Aggregates security threat locations and returns metrics on top attacking nations."""
    db = app_state.logs_db
    anomalies = [log for log in db if log.get("prediction") == "Anomaly"]
    
    country_counts = {}
    total_anomalies = len(anomalies)
    
    for log in anomalies:
        geo = geolocate_ip(log.get("ip", ""))
        c_name = geo["country"]
        
        sev = log.get("threat_severity", "Low")
        sev_mapped = "Normal"
        if sev == "Medium":
            sev_mapped = "Suspicious"
        elif sev == "High":
            sev_mapped = "High Threat"
        elif sev == "Critical":
            sev_mapped = "Critical"
            
        if c_name not in country_counts:
            country_counts[c_name] = {
                "count": 0,
                "severities": {"Normal": 0, "Suspicious": 0, "High Threat": 0, "Critical": 0}
            }
        
        country_counts[c_name]["count"] += 1
        country_counts[c_name]["severities"][sev_mapped] += 1
        
    sorted_countries = sorted(country_counts.items(), key=lambda x: x[1]["count"], reverse=True)
    
    result = []
    for c_name, meta in sorted_countries[:10]: # Top 10 countries
        pct = round((meta["count"] / total_anomalies) * 100, 2) if total_anomalies > 0 else 0.0
        result.append(CountryCount(
            country=c_name,
            count=meta["count"],
            percentage=pct,
            severity_distribution=meta["severities"]
        ))
        
    return result

class IpSearchResponse(BaseModel):
    ip: str
    latitude: float
    longitude: float
    threat_severity: str
    country: str
    count: int
    timestamp: str

@router.get("/search-ip/{ip}", response_model=IpSearchResponse)
async def search_ip_details(
    ip: str,
    current_user: str = Depends(get_current_user)
):
    """Searches active security records for a specific IP address and returns consolidated investigation intelligence."""
    db = app_state.logs_db
    
    # Filter records by IP
    matches = [log for log in db if log.get("ip") == ip]
    
    # Calculate geo
    geo = geolocate_ip(ip)
    
    if not matches:
        return IpSearchResponse(
            ip=ip,
            latitude=geo["latitude"],
            longitude=geo["longitude"],
            threat_severity="Normal",
            country=geo["country"],
            count=0,
            timestamp=datetime.now().isoformat()
        )
        
    count = len(matches)
    recent = matches[0]
    
    sev = recent.get("threat_severity", "Low")
    sev_mapped = "Normal"
    if sev == "Medium":
        sev_mapped = "Suspicious"
    elif sev == "High":
        sev_mapped = "High Threat"
    elif sev == "Critical":
        sev_mapped = "Critical"
        
    return IpSearchResponse(
        ip=ip,
        latitude=geo["latitude"],
        longitude=geo["longitude"],
        threat_severity=sev_mapped,
        country=geo["country"],
        count=count,
        timestamp=recent.get("timestamp", datetime.now().isoformat())
    )

@router.get("/live-attacks", response_model=List[GeoMapThreatRecord])
async def get_live_attacks(
    count: int = Query(5, ge=1, le=50),
    current_user: str = Depends(get_current_user)
):
    """Generates and returns highly realistic simulated attacks to feed real-time canvas overlays."""
    attacks = []
    
    # Selection of malicious profile templates
    ip_templates = [
        {"ip": "185.220.101.5", "type": "SQL Injection"},
        {"ip": "82.102.23.45", "type": "Directory Traversal / LFI"},
        {"ip": "103.22.200.41", "type": "DDoS Attempt / Flooding"},
        {"ip": "198.51.100.12", "type": "Command Injection"},
        {"ip": "91.220.43.12", "type": "Brute Force Attack"},
        {"ip": "190.12.87.54", "type": "Zero-Day Exploit Scan"},
        {"ip": "89.248.167.15", "type": "Buffer Overflow Attempt"}
    ]
    
    for _ in range(count):
        tmpl = random.choice(ip_templates)
        geo = geolocate_ip(tmpl["ip"])
        
        # Inject randomized details
        methods = ["GET", "POST", "PUT", "DELETE"]
        status_codes = [400, 401, 403, 404, 500, 503]
        severities = ["Suspicious", "High Threat", "Critical"]
        predictions = ["Anomaly"]
        
        action = random.choice(MALICIOUS_ACTIONS)
        
        rec = GeoMapThreatRecord(
            timestamp=datetime.now().isoformat(),
            ip=tmpl["ip"],
            country=geo["country"],
            city=geo["city"],
            isp=geo["isp"],
            latitude=geo["latitude"],
            longitude=geo["longitude"],
            threat_severity=random.choice(severities),
            threat_type=tmpl["type"],
            method=random.choice(methods),
            url=action["url"],
            status=random.choice(status_codes),
            size=random.randint(200, 4000),
            prediction=random.choice(predictions),
            anomaly_score=round(random.uniform(0.65, 0.99), 4)
        )
        attacks.append(rec)
        
    return attacks

@router.post("/process-log-map")
async def process_log_map(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Processes uploaded custom log files, geolocates entries, evaluates ML models, and injects into memory."""
    if not file.filename.endswith(('.log', '.txt', '.csv')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported format. Please upload standard Apache .log, .txt or .csv text files."
        )
        
    upload_dir = os.path.join(DATA_DIR, "uploaded_logs")
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, f"map_{file.filename}")
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        proc_res = app_state.spark_processor.process_logs(temp_path)
        df = proc_res["data"]
        records = df.to_dict('records')
        
        log_lines = []
        for r in records:
            line = f'{r["ip"]} - - [{r["timestamp"]}] "{r["method"]} {r["url"]} {r["protocol"]}" {r["status"]} {r["size"]} "-" "-"'
            log_lines.append(line)
            
        if not log_lines:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="File parsing resulted in empty records. Verify log schemas match standard combined specifications."
            )
            
        predictions, scores = app_state.ml_detector.predict_bulk(log_lines)
        new_count = 0
        
        for idx, r in enumerate(records):
            rule_res = app_state.rule_engine.analyze_log_record(r)
            is_anomaly = predictions[idx] == -1
            ml_score = scores[idx]
            
            prediction = "Anomaly" if (is_anomaly or rule_res["is_threat"]) else "Normal"
            rule_severity = rule_res["severity"]
            if prediction == "Anomaly" and rule_severity == "Low":
                rule_severity = "High" if ml_score >= 0.7 else "Medium"
            severity = rule_severity if prediction == "Anomaly" else "Low"
            threat_type = rule_res["threat_type"] if rule_res["is_threat"] else ("ML Anomaly" if is_anomaly else "Normal")
            
            geo = geolocate_ip(r["ip"])
            
            enriched = {
                "timestamp": str(r["timestamp"]),
                "ip": r["ip"],
                "method": r["method"],
                "url": r["url"],
                "status": r["status"],
                "size": r["size"],
                "threat_severity": severity,
                "prediction": prediction,
                "probability_score": round(ml_score, 4),
                "threat_type": threat_type,
                "details": rule_res["details"],
                "country": geo["country"],
                "city": geo["city"],
                "latitude": geo["latitude"],
                "longitude": geo["longitude"]
            }
            
            app_state.logs_db.insert(0, enriched)
            new_count += 1
            
        while len(app_state.logs_db) > 10000:
            app_state.logs_db.pop()
            
        # Append contents to global raw log file for Spark persistence
        with open(os.path.join(DATA_DIR, "raw_logs", "apache_access.log"), "a", encoding="utf-8") as raw_f:
            with open(temp_path, "r", encoding="utf-8", errors="ignore") as temp_f:
                raw_f.write(temp_f.read() + "\n")
                
        os.remove(temp_path)
        
        return {
            "status": "success",
            "message": f"Successfully parsed and mapped {new_count} records into the active database.",
            "engine": proc_res["engine"],
            "partitions": proc_res["partition_count"]
        }
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Mapping pipeline failed to compile: {str(e)}"
        )
