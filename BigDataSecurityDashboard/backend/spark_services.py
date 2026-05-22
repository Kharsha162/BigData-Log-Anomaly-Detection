import os
import time
import json
import csv
import random
import pandas as pd
from datetime import datetime
from typing import List, Dict, Any, Optional

from spark_engine import spark_engine
from spark_utils import GEO_PROFILES, generate_mock_log_line

class SparkSecurityService:
    def __init__(self):
        self.simulation_active = False
        self.simulated_logs: List[Dict[str, Any]] = []
        self.batch_id_counter = 1
        
    def get_ml_detector(self):
        """Loads and returns the ML detector from global app state dynamically to avoid circular dependencies."""
        try:
            from services.state import app_state
            return app_state.ml_detector
        except Exception as e:
            print(f"[Spark Service] Dynamic import of app_state failed: {e}. Instantiating local ML detector.")
            from services.ml_service import MLAnomalyDetector
            return MLAnomalyDetector()

    def process_and_enrich_logs(
        self, 
        file_path: str, 
        log_type: str, 
        partitions: int = 4, 
        classifier: str = "isolation_forest",
        search_ip: str = "",
        search_url: str = "",
        status_code: Optional[int] = None,
        severity_filter: str = "",
        threat_type_filter: str = "",
        time_range: str = "all"
    ) -> Dict[str, Any]:
        """Runs the distributed Spark/Pandas pipeline, feeds elements to ML classifiers, and filters outputs."""
        start_time = time.time()
        
        # 1. Spark Ingestion & Schema Transformations (already includes ML anomaly detection & Geolocation)
        parsed_records = spark_engine.parse_logs_pyspark(file_path, log_type, partitions)
        
        # 2. Add batch_id to all records and keep all coordinates/telemetry
        enriched_records = []
        for r in parsed_records:
            enriched_records.append({
                "timestamp": r["timestamp"],
                "ip": r["ip"],
                "method": r["method"],
                "url": r["url"],
                "status": r["status"],
                "size": r["size"],
                "log_type": r.get("log_type", "Apache"),
                "threat_type": r.get("threat_type", "Normal"),
                "threat_severity": r.get("threat_severity", "Normal"),
                "prediction": r.get("prediction", "Normal"),
                "anomaly_score": r.get("anomaly_score", 0.05),
                "country": r.get("country", "Unknown"),
                "city": r.get("city", "Unknown"),
                "latitude": float(r.get("latitude", 0.0)),
                "longitude": float(r.get("longitude", 0.0)),
                "isp": r.get("isp", "Local Loop ISP"),
                "batch_id": f"RDD-0{self.batch_id_counter}",
                "all_classifiers": r.get("all_classifiers", {})
            })
            
        self.batch_id_counter += 1
        
        # 3. Apply Spark Filtering Engine
        filtered_records = []
        now_dt = datetime.now()
        
        for rec in enriched_records:
            # IP filter
            if search_ip and search_ip.lower() not in rec["ip"].lower():
                continue
            # Endpoint filter
            if search_url and search_url.lower() not in rec["url"].lower():
                continue
            # Status code filter
            if status_code is not None and rec["status"] != status_code:
                continue
            # Severity filter
            if severity_filter and severity_filter.lower() != rec["threat_severity"].lower():
                continue
            # Attack type filter
            if threat_type_filter and threat_type_filter.lower() not in rec["threat_type"].lower():
                continue
            # Time range filter
            if time_range != "all":
                try:
                    # Clean HDFS / K8s date for parsing
                    t_str = rec["timestamp"]
                    if "T" in t_str:
                        rec_dt = datetime.strptime(t_str.split(".")[0].replace("Z", ""), "%Y-%m-%dT%H:%M:%S")
                    elif len(t_str) == 19:
                        rec_dt = datetime.strptime(t_str, "%Y-%m-%d %H:%M:%S")
                    else:
                        # Fallback
                        rec_dt = now_dt
                        
                    delta = now_dt - rec_dt
                    if time_range == "1h" and delta.total_seconds() > 3600:
                        continue
                    elif time_range == "6h" and delta.total_seconds() > 21600:
                        continue
                    elif time_range == "24h" and delta.total_seconds() > 86400:
                        continue
                except Exception:
                    pass # Ignore if timestamp parse error
                    
            filtered_records.append(rec)
            
        # 4. Generate Spark Aggregations & Metrics
        aggregations = spark_engine.aggregate_metrics(filtered_records)
        duration = time.time() - start_time
        
        # Compile processing speed
        proc_speed = int(len(parsed_records) / duration) if duration > 0 else len(parsed_records)
        
        return {
            "metadata": {
                "records_processed": len(parsed_records),
                "records_filtered": len(filtered_records),
                "execution_time_sec": round(duration, 3),
                "processing_speed_lps": proc_speed,
                "partitions": partitions,
                "batch_id": f"RDD-0{self.batch_id_counter - 1}",
                "engine_type": "Apache Spark (Native)" if not spark_engine.is_fallback else "Pandas Emulated Spark"
            },
            "records": filtered_records,
            "aggregations": aggregations
        }

    def generate_live_simulation_batch(self, log_type: str, record_count: int = 25) -> Dict[str, Any]:
        """Simulates real-time log ingestion and passes through the active processor."""
        temp_log_path = os.path.join(os.path.dirname(__file__), "..", "data", "temp_simulation.log")
        os.makedirs(os.path.dirname(temp_log_path), exist_ok=True)
        
        # 1. Generate live logs
        sim_raw_lines = []
        sim_meta_records = []
        for _ in range(record_count):
            scenario = random.choices(["normal", "exploit"], weights=[0.85, 0.15])[0]
            sim_item = generate_mock_log_line(log_type, scenario)
            sim_raw_lines.append(sim_item["line"])
            sim_meta_records.append(sim_item["parsed"])
            
        # 2. Write to temp file for Spark session ingestion simulation
        with open(temp_log_path, "w", encoding="utf-8") as f:
            f.write("\n".join(sim_raw_lines) + "\n")
            
        # 3. Process logs
        res = self.process_and_enrich_logs(temp_log_path, log_type, partitions=2)
        
        # Remove temp file
        if os.path.exists(temp_log_path):
            try:
                os.remove(temp_log_path)
            except Exception:
                pass
                
        # Save to local cache of live feeds
        self.simulated_logs.extend(res["records"])
        if len(self.simulated_logs) > 500:
            # Evict old logs to keep clean memory footprint
            self.simulated_logs = self.simulated_logs[-500:]
            
        return res

    def export_csv(self, records: List[dict]) -> str:
        """Formats Spark data into standard CSV file output string."""
        if not records:
            return "ip,timestamp,method,url,status,size,log_type,threat_severity,prediction,anomaly_score,country,city\n"
            
        keys = ["ip", "timestamp", "method", "url", "status", "size", "log_type", "threat_severity", "prediction", "anomaly_score", "country", "city", "batch_id"]
        
        import io
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=keys, extrasaction="ignore")
        writer.writeheader()
        for r in records:
            writer.writerow(r)
        return output.getvalue()

    def export_json(self, records: List[dict]) -> str:
        """Formats Spark data into JSON file output string."""
        return json.dumps(records, indent=2)

# Global singleton
spark_service = SparkSecurityService()
