import os
import shutil
from fastapi import APIRouter, Depends, UploadFile, File, Query, HTTPException, status
from typing import Optional, List
from models.schemas import LogRecord, LogListResponse, DashboardStats
from services.state import app_state, DATA_DIR
from routes.auth import get_current_user

router = APIRouter(tags=["Logs & Security Metrics"])

@router.get("/stats", response_model=DashboardStats)
async def get_dashboard_statistics(current_user: str = Depends(get_current_user)):
    """Computes and returns real-time SOC metrics for the dashboard KPI cards."""
    db = app_state.logs_db
    total_logs = len(db)
    
    anomalies = [log for log in db if log["prediction"] == "Anomaly"]
    total_anomalies = len(anomalies)
    
    failed_requests = len([log for log in db if log["status"] >= 400])
    high_severity_alerts = len([log for log in db if log["threat_severity"] in ["High", "Critical"]])
    
    detection_rate = round((total_anomalies / total_logs) * 100, 2) if total_logs > 0 else 0.0
    
    # Calculate unique threat countries & suspicious IPs
    threat_countries = len(set(log["country"] for log in anomalies if log["country"] not in ["Unknown", "Local", "Internal"]))
    suspicious_ips = len(set(log["ip"] for log in anomalies))
    
    spark_jobs = app_state.spark_processor.batch_count
    
    system_status = "SECURE"
    if high_severity_alerts > 20:
        system_status = "CRITICAL"
    elif high_severity_alerts > 5:
        system_status = "WARNING"
        
    return {
        "total_logs": total_logs,
        "total_anomalies": total_anomalies,
        "failed_requests": failed_requests,
        "high_severity_alerts": high_severity_alerts,
        "detection_rate": detection_rate,
        "spark_jobs_processed": spark_jobs,
        "threat_countries": threat_countries,
        "suspicious_ips": suspicious_ips,
        "system_status": system_status
    }

@router.get("/logs", response_model=LogListResponse)
async def get_logs(
    current_user: str = Depends(get_current_user),
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=500),
    search: Optional[str] = None,
    ip: Optional[str] = None,
    status_code: Optional[int] = None,
    severity: Optional[str] = None,
    prediction: Optional[str] = None
):
    """Retrieves logs with comprehensive filtering, sorting (newest first), and pagination."""
    filtered_logs = app_state.logs_db.copy()
    
    # Apply filters
    if search:
        search_lower = search.lower()
        filtered_logs = [
            log for log in filtered_logs
            if search_lower in log["ip"].lower() or search_lower in log["url"].lower() or search_lower in log["threat_type"].lower()
        ]
        
    if ip:
        filtered_logs = [log for log in filtered_logs if log["ip"] == ip]
        
    if status_code:
        filtered_logs = [log for log in filtered_logs if log["status"] == status_code]
        
    if severity:
        filtered_logs = [log for log in filtered_logs if log["threat_severity"].lower() == severity.lower()]
        
    if prediction:
        filtered_logs = [log for log in filtered_logs if log["prediction"].lower() == prediction.lower()]

    total_filtered = len(filtered_logs)
    
    # Paginate
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_logs = filtered_logs[start_idx:end_idx]
    
    # Cast to LogRecord schema model
    logs_out = []
    for log in paginated_logs:
        logs_out.append(LogRecord(
            timestamp=log["timestamp"],
            ip=log["ip"],
            method=log["method"],
            url=log["url"],
            status=log["status"],
            size=log["size"],
            threat_severity=log["threat_severity"],
            prediction=log["prediction"],
            probability_score=log["probability_score"],
            country=log["country"],
            city=log["city"],
            latitude=log["latitude"],
            longitude=log["longitude"]
        ))
        
    return {
        "total": len(app_state.logs_db),
        "filtered_count": total_filtered,
        "logs": logs_out
    }

@router.get("/threats", response_model=List[LogRecord])
async def get_threats(current_user: str = Depends(get_current_user), limit: int = Query(100, ge=1, le=1000)):
    """Returns the most recent security threats detected by ML and signature rules."""
    anomalies = [log for log in app_state.logs_db if log["prediction"] == "Anomaly"]
    limited = anomalies[:limit]
    
    return [
        LogRecord(
            timestamp=l["timestamp"],
            ip=l["ip"],
            method=l["method"],
            url=l["url"],
            status=l["status"],
            size=l["size"],
            threat_severity=l["threat_severity"],
            prediction=l["prediction"],
            probability_score=l["probability_score"],
            country=l["country"],
            city=l["city"],
            latitude=l["latitude"],
            longitude=l["longitude"]
        ) for l in limited
    ]

@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    current_user: str = Depends(get_current_user)
):
    """Handles upload of raw logs, saves them, runs parsing + ML detection, and updates the cache."""
    if not file.filename.endswith(('.log', '.txt', '.csv')):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file format. Please upload a .log, .txt or .csv log file."
        )
        
    # Write file to temporary storage location
    upload_dir = os.path.join(DATA_DIR, "uploaded_logs")
    os.makedirs(upload_dir, exist_ok=True)
    temp_path = os.path.join(upload_dir, file.filename)
    
    with open(temp_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
        
    try:
        # Parse uploaded file
        proc_res = app_state.spark_processor.process_logs(temp_path)
        df = proc_res["data"]
        
        # Load records and parse them
        records = df.to_dict('records')
        new_count = 0
        
        # Reconstruct lines for ML Predictor
        log_lines = []
        for r in records:
            line = f'{r["ip"]} - - [{r["timestamp"]}] "{r["method"]} {r["url"]} {r["protocol"]}" {r["status"]} {r["size"]} "-" "-"'
            log_lines.append(line)
            
        if not log_lines:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No valid Apache Combined logs found in the uploaded file."
            )
            
        predictions, scores = app_state.ml_detector.predict_bulk(log_lines)
        
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
            
            from utils.log_generator import GEO_PROFILES
            geo = next((p for p in GEO_PROFILES if p["ip"] == r["ip"]), {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0})
            
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
                "latitude": geo["lat"],
                "longitude": geo["lon"]
            }
            
            # Prepend to memory store
            app_state.logs_db.insert(0, enriched)
            new_count += 1
            
        # Clean up database size limits
        while len(app_state.logs_db) > 10000:
            app_state.logs_db.pop()
            
        # Append contents to global raw log file for Spark persistence
        with open(os.path.join(DATA_DIR, "raw_logs", "apache_access.log"), "a", encoding="utf-8") as raw_f:
            with open(temp_path, "r", encoding="utf-8", errors="ignore") as temp_f:
                raw_f.write(temp_f.read() + "\n")
                
        # Clean up temp file
        os.remove(temp_path)
        
        return {
            "status": "success",
            "message": f"Successfully parsed and analyzed {new_count} logs from {file.filename}.",
            "engine_used": proc_res["engine"],
            "partitions": proc_res["partition_count"]
        }
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred while parsing the file: {str(e)}"
        )

@router.post("/generate-mock")
async def generate_mock_logs(
    count: int = Query(50, ge=1, le=1000),
    scenario: Optional[str] = Query(None, description="Choices: normal, brute_force, ddos, exploit"),
    current_user: str = Depends(get_current_user)
):
    """Force-generates custom mock log entries for simulation, appending them immediately."""
    from utils.log_generator import generate_apache_log_line
    
    generated = []
    for _ in range(count):
        res = generate_apache_log_line(scenario=scenario)
        enriched = app_state.add_log_line(res["line"])
        if enriched:
            generated.append(enriched)
            
    return {
        "status": "success",
        "message": f"Generated {len(generated)} logs matching scenario '{scenario or 'Random'}'.",
        "logs": generated[:10]  # Return sample
    }
