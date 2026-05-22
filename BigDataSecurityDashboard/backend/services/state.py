import os
import pandas as pd
from datetime import datetime
from services.ml_service import MLAnomalyDetector
from services.spark_service import SparkSecurityProcessor
from utils.security_analyzer import SecurityRuleEngine
from utils.log_generator import create_initial_log_file, GEO_PROFILES, generate_apache_log_line

# Define project directories
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "data"))
RAW_LOG_PATH = os.path.join(DATA_DIR, "raw_logs", "apache_access.log")
PROCESSED_CSV_PATH = os.path.join(DATA_DIR, "processed_logs.csv")

class AppState:
    def __init__(self):
        # Instantiate services
        self.ml_detector = MLAnomalyDetector()
        self.spark_processor = SparkSecurityProcessor()
        self.rule_engine = SecurityRuleEngine()
        
        # Shared database of logs
        self.logs_db = []
        
        # Bootstrap default dataset
        self.initialize_dataset()

    def initialize_dataset(self):
        """Generates initial logs if none exist, processes them with Spark/Pandas, and loads them into memory."""
        os.makedirs(os.path.join(DATA_DIR, "raw_logs"), exist_ok=True)
        
        # 1. Seed raw log file if it doesn't exist
        if not os.path.exists(RAW_LOG_PATH):
            print("No raw log file detected. Seeding 2500 logs...")
            create_initial_log_file(RAW_LOG_PATH, count=2500)
        else:
            print("Found existing raw log file at:", RAW_LOG_PATH)
            
        # 2. Process logs using Spark or Pandas Fallback
        print("Parsing and cleaning raw logs...")
        proc_result = self.spark_processor.process_logs(RAW_LOG_PATH)
        df = proc_result["data"]
        
        # 3. Enrich logs with Rule-Engine & ML predictions
        print("Enriching logs with ML anomaly scores and threat classifications...")
        enriched_records = []
        
        # Convert df to records
        records = df.to_dict('records')
        
        # Extract log lines for ML bulk prediction
        log_lines = []
        for r in records:
            # Reconstruct log line for ML TF-IDF matching
            line = f'{r["ip"]} - - [{r["timestamp"]}] "{r["method"]} {r["url"]} {r["protocol"]}" {r["status"]} {r["size"]} "-" "-"'
            log_lines.append(line)
            
        # Predict anomalies in bulk for startup speed
        predictions, scores = self.ml_detector.predict_bulk(log_lines)
        
        for idx, r in enumerate(records):
            # Run rule-based analysis
            rule_res = self.rule_engine.analyze_log_record(r)
            
            # Combine rules + ML
            is_anomaly = predictions[idx] == -1
            ml_score = scores[idx]
            
            # Determine overall prediction & severity
            prediction = "Anomaly" if (is_anomaly or rule_res["is_threat"]) else "Normal"
            
            # Map rule severity
            rule_severity = rule_res["severity"]
            if prediction == "Anomaly" and rule_severity == "Low":
                # Elevated if ML flags it but rules missed it
                rule_severity = "Medium" if ml_score < 0.7 else "High"
                
            severity = rule_severity if prediction == "Anomaly" else "Low"
            threat_type = rule_res["threat_type"] if rule_res["is_threat"] else ("ML Anomaly" if is_anomaly else "Normal")
            
            # Retrieve lat/lon
            geo = next((p for p in GEO_PROFILES if p["ip"] == r["ip"]), {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0})
            
            enriched_records.append({
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
            })
            
        self.logs_db = enriched_records
        
        # Save enriched logs to processed CSV
        pd.DataFrame(enriched_records).to_csv(PROCESSED_CSV_PATH, index=False)
        print(f"Dataset initialization complete. Loaded {len(self.logs_db)} enriched logs.")

    def add_log_line(self, line: str):
        """Parses, enriches, and appends a single log line to our active database."""
        parsed = self.spark_processor.parse_log_line_regex(line)
        if not parsed:
            return None
            
        # Run Rule Engine
        rule_res = self.rule_engine.analyze_log_record(parsed)
        
        # Run ML Predictor
        pred, ml_score = self.ml_detector.predict(line)
        
        is_anomaly = pred == -1
        prediction = "Anomaly" if (is_anomaly or rule_res["is_threat"]) else "Normal"
        
        # Determine Severity
        rule_severity = rule_res["severity"]
        if prediction == "Anomaly" and rule_severity == "Low":
            rule_severity = "High" if ml_score >= 0.7 else "Medium"
        severity = rule_severity if prediction == "Anomaly" else "Low"
        
        threat_type = rule_res["threat_type"] if rule_res["is_threat"] else ("ML Anomaly" if is_anomaly else "Normal")
        
        # Geo lookup
        geo = next((p for p in GEO_PROFILES if p["ip"] == parsed["ip"]), {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0})
        
        enriched = {
            "timestamp": datetime.now().isoformat(),
            "ip": parsed["ip"],
            "method": parsed["method"],
            "url": parsed["url"],
            "status": parsed["status"],
            "size": parsed["size"],
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
        
        # Append to head of database (newest first)
        self.logs_db.insert(0, enriched)
        
        # Keep database size bounded in memory to prevent leak
        if len(self.logs_db) > 10000:
            self.logs_db.pop()
            
        return enriched

# Instantiate the global state
app_state = AppState()
