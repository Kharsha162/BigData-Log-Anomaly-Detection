from fastapi import APIRouter, Depends, HTTPException, status, Query
from models.schemas import SinglePredictRequest, SinglePredictResponse, AnomalySummary
from services.state import app_state, RAW_LOG_PATH
from routes.auth import get_current_user
import os

router = APIRouter(prefix="/predict", tags=["Machine Learning Anomaly Detection"])

@router.post("", response_model=SinglePredictResponse)
async def predict_single_log(
    payload: SinglePredictRequest,
    current_user: str = Depends(get_current_user)
):
    """Predicts threat vectors and anomaly score for a single raw Apache combined log line."""
    line = payload.log_line
    
    # 1. Parse line
    parsed = app_state.spark_processor.parse_log_line_regex(line)
    if not parsed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Log line could not be parsed. Verify format matches Apache Common/Combined Log pattern."
        )
        
    # 2. Run rule analyzer
    rule_res = app_state.rule_engine.analyze_log_record(parsed)
    
    # 3. Run ML
    classifier = payload.classifier or "isolation_forest"
    pred, score = app_state.ml_detector.predict(line, classifier=classifier)
    
    is_anomaly = pred == -1
    prediction_str = "Anomaly" if (is_anomaly or rule_res["is_threat"]) else "Normal"
    
    rule_severity = rule_res["severity"]
    if prediction_str == "Anomaly" and rule_severity == "Low":
        rule_severity = "High" if score >= 0.7 else "Medium"
    severity = rule_severity if prediction_str == "Anomaly" else "Low"
    
    threat_type = rule_res["threat_type"] if rule_res["is_threat"] else (f"ML Anomaly ({classifier})" if is_anomaly else "Normal")
    
    # Run all classifiers for deep auditing and comparison
    all_preds = app_state.ml_detector.predict_all_classifiers(line)
    
    return {
        "log_line": line,
        "prediction": prediction_str,
        "anomaly_score": round(score, 4),
        "threat_severity": severity,
        "threat_type": threat_type,
        "details": rule_res["details"],
        "all_predictions": all_preds
    }

@router.get("/summary", response_model=AnomalySummary)
async def get_anomaly_summary(current_user: str = Depends(get_current_user)):
    """Aggregates machine learning metrics, identifying total threat counts and rates."""
    db = app_state.logs_db
    total = len(db)
    
    anomalies = [log for log in db if log["prediction"] == "Anomaly"]
    total_anoms = len(anomalies)
    
    rate = round((total_anoms / total) * 100, 2) if total > 0 else 0.0
    
    high = len([l for l in anomalies if l["threat_severity"] == "High"])
    critical = len([l for l in anomalies if l["threat_severity"] == "Critical"])
    
    return {
        "total_logs": total,
        "total_anomalies": total_anoms,
        "anomaly_rate": rate,
        "high_severity_alerts": high,
        "critical_severity_alerts": critical
    }

@router.post("/retrain")
async def retrain_anomaly_model(current_user: str = Depends(get_current_user)):
    """Triggers the ML engine to retrain its TF-IDF + Isolation Forest model using all records from the raw log files."""
    if not os.path.exists(RAW_LOG_PATH):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Raw logs access file is missing. Seed logs or upload files first."
        )
        
    try:
        # Load raw lines from disk
        lines = []
        with open(RAW_LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                stripped = line.strip()
                if stripped:
                    lines.append(stripped)
                    
        if len(lines) < 10:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Not enough logs available on disk to run retraining. Require at least 10 entries."
            )
            
        # Fit new models
        app_state.ml_detector.train(lines)
        
        # Re-initialize dataset so scores update
        app_state.initialize_dataset()
        
        return {
            "status": "success",
            "message": f"Successfully retrained ML model on {len(lines)} log lines. In-memory data refreshed.",
            "contamination_rate": 0.1
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to complete model training: {str(e)}"
        )
