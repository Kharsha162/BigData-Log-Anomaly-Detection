import os
import shutil
from fastapi import APIRouter, Depends, UploadFile, File, Form, Query, HTTPException, status
from fastapi.responses import Response, JSONResponse
from typing import Optional, List

from routes.auth import get_current_user
from services.state import app_state, DATA_DIR, RAW_LOG_PATH
from models.schemas import SparkEngineMetrics
from spark_engine import spark_engine
from spark_services import spark_service

router = APIRouter(prefix="/spark", tags=["Apache Spark Data Processor"])

@router.get("/metrics", response_model=SparkEngineMetrics)
def get_spark_engine_metrics(current_user: str = Depends(get_current_user)):
    """Exposes cluster performance metrics, partition statistics, and CPU/Memory telemetries."""
    try:
        # Get live telemetry from our singleton engine
        stats = spark_engine.get_cluster_metrics()
        return SparkEngineMetrics(
            engine_type=stats["engine_type"],
            active_workers=stats["active_workers"],
            memory_used_gb=stats["memory_used_gb"],
            total_memory_gb=stats["total_memory_gb"],
            cpu_utilization_pct=stats["cpu_utilization_pct"],
            total_jobs_run=stats["total_jobs_run"],
            uptime_sec=stats["uptime_sec"],
            is_fallback=stats["is_fallback"]
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to fetch Spark telemetry: {str(e)}"
        )

@router.post("/analyze")
def analyze_logs(
    file: Optional[UploadFile] = File(None),
    log_type: str = Form("apache"),
    partitions: int = Form(4),
    classifier: str = Form("isolation_forest"),
    search_ip: str = Form(""),
    search_url: str = Form(""),
    status_code: Optional[int] = Form(None),
    severity_filter: str = Form(""),
    threat_type_filter: str = Form(""),
    time_range: str = Form("all"),
    current_user: str = Depends(get_current_user)
):
    """Parses uploaded log files (or fallback historical logs) using Apache Spark and applies ML classification."""
    target_file = None
    is_temp = False
    
    try:
        # 1. Handle File Upload if present
        if file is not None:
            upload_dir = os.path.join(DATA_DIR, "spark_uploads")
            os.makedirs(upload_dir, exist_ok=True)
            target_file = os.path.join(upload_dir, file.filename)
            
            with open(target_file, "wb") as buffer:
                shutil.copyfileobj(file.file, buffer)
            is_temp = True
        else:
            # Fall back to existing raw logs
            target_file = RAW_LOG_PATH
            if not os.path.exists(target_file):
                # If no raw logs exist, bootstrap a small file
                os.makedirs(os.path.dirname(target_file), exist_ok=True)
                from utils.log_generator import create_initial_log_file
                create_initial_log_file(target_file, count=500)
                
        # 2. Run Spark/Pandas pipeline with filters & ML enrichment
        results = spark_service.process_and_enrich_logs(
            file_path=target_file,
            log_type=log_type,
            partitions=partitions,
            classifier=classifier,
            search_ip=search_ip,
            search_url=search_url,
            status_code=status_code,
            severity_filter=severity_filter,
            threat_type_filter=threat_type_filter,
            time_range=time_range
        )
        
        # Clean up temporary uploaded file
        if is_temp and target_file and os.path.exists(target_file):
            os.remove(target_file)
            
        return results
        
    except Exception as e:
        if is_temp and target_file and os.path.exists(target_file):
            os.remove(target_file)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Spark Analytics Engine failed to execute: {str(e)}"
        )

@router.post("/simulate")
def trigger_live_simulation(
    log_type: str = Form("apache"),
    record_count: int = Form(25),
    current_user: str = Depends(get_current_user)
):
    """Trigger a real-time micro-batch processing simulation of streamed security events."""
    try:
        results = spark_service.generate_live_simulation_batch(log_type, record_count)
        return results
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Live Spark simulation failed: {str(e)}"
        )

@router.post("/export/csv")
def export_spark_csv(
    records: List[dict],
    current_user: str = Depends(get_current_user)
):
    """Exports processed Spark logs into an offline download-ready CSV payload."""
    try:
        csv_data = spark_service.export_csv(records)
        return Response(
            content=csv_data,
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=spark_processed_logs.csv"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CSV export failed: {str(e)}"
        )

@router.post("/export/json")
def export_spark_json(
    records: List[dict],
    current_user: str = Depends(get_current_user)
):
    """Exports processed Spark logs into a structural JSON dataset representation."""
    try:
        json_data = spark_service.export_json(records)
        return Response(
            content=json_data,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=spark_processed_logs.json"}
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"JSON export failed: {str(e)}"
        )
