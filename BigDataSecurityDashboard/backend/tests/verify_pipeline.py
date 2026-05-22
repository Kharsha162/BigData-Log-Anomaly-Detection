import os
import sys

# Append parent directory to sys.path so we can import services
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from services.ml_service import MLAnomalyDetector
from services.spark_service import SparkSecurityProcessor
from utils.security_analyzer import SecurityRuleEngine
from utils.log_generator import generate_apache_log_line

def run_tests():
    print("==================================================")
    print("         SECOPS PIPELINE VERIFICATION              ")
    print("==================================================")
    
    # 1. Test Rule Engine
    print("\n[+] Testing Security Rule Engine...")
    engine = SecurityRuleEngine()
    
    sqli_record = {
        "ip": "185.220.101.5",
        "url": "/api/users?id=1%20UNION%20SELECT%2520username",
        "method": "GET",
        "status": 500
    }
    res_sqli = engine.analyze_log_record(sqli_record)
    assert res_sqli["is_threat"] == True
    assert res_sqli["threat_type"] == "SQL Injection"
    assert res_sqli["severity"] == "Critical"
    print("    - SQL Injection signature check: PASSED")

    brute_force_record = {
        "ip": "82.102.23.45",
        "url": "/wp-login.php",
        "method": "GET",
        "status": 404
    }
    res_recon = engine.analyze_log_record(brute_force_record)
    assert res_recon["is_threat"] == True
    assert "Scanner" in res_recon["threat_type"]
    print("    - Sensitive path scanning check: PASSED")
    
    # 2. Test ML Detector
    print("\n[+] Testing Machine Learning Anomaly Detector...")
    detector = MLAnomalyDetector()
    
    # Run test prediction on a normal log line
    normal_line = '127.0.0.1 - - [21/May/2026:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla"'
    pred, score = detector.predict(normal_line)
    print(f"    - Normal log prediction: Verdict={pred} (1=Normal, -1=Anomaly), Score={score:.4f}")
    assert isinstance(score, float)
    
    # Run test prediction on a suspicious log line
    exploit_line = '185.220.101.5 - - [21/May/2026:10:00:00 +0000] "GET /etc/passwd HTTP/1.1" 400 128 "-" "Mozilla"'
    pred_expl, score_expl = detector.predict(exploit_line)
    print(f"    - Exploit log prediction: Verdict={pred_expl}, Score={score_expl:.4f}")
    assert score_expl > score
    print("    - Anomaly score escalation: PASSED")
    
    # 3. Test Spark Engine Fallback
    print("\n[+] Testing Spark Parsing Engine (Pandas Fallback)...")
    processor = SparkSecurityProcessor()
    
    # Write a temporary log file
    temp_log_path = "temp_test_access.log"
    with open(temp_log_path, 'w') as f:
        for _ in range(50):
            res = generate_apache_log_line()
            f.write(res["line"] + "\n")
            
    try:
        proc_res = processor.process_logs(temp_log_path)
        print(f"    - Active Engine: {proc_res['engine']}")
        print(f"    - Ingested Logs: {proc_res['total_logs']}")
        print(f"    - Created Partitions: {proc_res['partition_count']}")
        print(f"    - HTTP Status Distribution: {proc_res['status_distribution']}")
        assert proc_res["total_logs"] == 50
        print("    - Spark aggregation metrics: PASSED")
    finally:
        if os.path.exists(temp_log_path):
            os.remove(temp_log_path)

    print("\n==================================================")
    print("      ALL PIPELINE INTEGRATION TESTS PASSED       ")
    print("==================================================")

if __name__ == "__main__":
    run_tests()
