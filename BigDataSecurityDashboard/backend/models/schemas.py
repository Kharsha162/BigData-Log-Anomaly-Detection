from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class UserLogin(BaseModel):
    username: str = Field(..., example="admin")
    password: str = Field(..., example="security101")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class LogRecord(BaseModel):
    timestamp: str
    ip: str
    method: str
    url: str
    status: int
    size: int
    threat_severity: str = "Low"
    prediction: str = "Normal"
    probability_score: float = 0.0
    country: str = "Unknown"
    city: str = "Unknown"
    latitude: float = 0.0
    longitude: float = 0.0

class LogListResponse(BaseModel):
    total: int
    filtered_count: int
    logs: List[LogRecord]

class AnomalySummary(BaseModel):
    total_logs: int
    total_anomalies: int
    anomaly_rate: float
    high_severity_alerts: int
    critical_severity_alerts: int

class SinglePredictRequest(BaseModel):
    log_line: str = Field(..., example='185.220.101.5 - - [21/May/2026:10:00:00 +0000] "GET /wp-login.php HTTP/1.1" 404 128')
    classifier: Optional[str] = "isolation_forest"

class SinglePredictResponse(BaseModel):
    log_line: str
    prediction: str  # "Anomaly" or "Normal"
    anomaly_score: float
    threat_severity: str
    threat_type: str
    details: str
    all_predictions: Optional[Dict[str, Any]] = None

class SparkEngineMetrics(BaseModel):
    engine_type: str
    active_workers: int
    memory_used_gb: float
    total_memory_gb: float
    cpu_utilization_pct: float
    total_jobs_run: int
    uptime_sec: int
    is_fallback: bool

class DashboardStats(BaseModel):
    total_logs: int
    total_anomalies: int
    failed_requests: int
    high_severity_alerts: int
    detection_rate: float
    spark_jobs_processed: int
    threat_countries: int
    suspicious_ips: int
    system_status: str
