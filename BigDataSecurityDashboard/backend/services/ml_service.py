import os
import joblib
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import IsolationForest, RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression

# Paths to save ML artifacts
MODEL_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "model"))
MODEL_PATH = os.path.join(MODEL_DIR, "apache_log_model.pkl") # Isolation Forest
RF_MODEL_PATH = os.path.join(MODEL_DIR, "random_forest_model.pkl")
LR_MODEL_PATH = os.path.join(MODEL_DIR, "logistic_regression_model.pkl")
GB_MODEL_PATH = os.path.join(MODEL_DIR, "gradient_boosting_model.pkl")
VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.pkl")

# Regex to parse log lines inside training for label building (avoiding circular dependency)
LOG_REGEX = r'^(\S+) \S+ \S+ \[([\w:/]+\s[+\-]\d{4})\] "(\S+)\s+(\S+)\s+(\S+)" (\d{3}) (\d+|-)'

class MLAnomalyDetector:
    def __init__(self):
        self.model = None          # Isolation Forest
        self.rf_model = None       # Random Forest
        self.lr_model = None       # Logistic Regression
        self.gb_model = None       # Gradient Boosting
        self.vectorizer = None
        os.makedirs(MODEL_DIR, exist_ok=True)
        self.load_model()

    def load_model(self):
        """Loads models and vectorizer from disk, or initializes default ones if missing."""
        try:
            if (os.path.exists(MODEL_PATH) and 
                os.path.exists(RF_MODEL_PATH) and 
                os.path.exists(LR_MODEL_PATH) and 
                os.path.exists(GB_MODEL_PATH) and 
                os.path.exists(VECTORIZER_PATH)):
                self.model = joblib.load(MODEL_PATH)
                self.rf_model = joblib.load(RF_MODEL_PATH)
                self.lr_model = joblib.load(LR_MODEL_PATH)
                self.gb_model = joblib.load(GB_MODEL_PATH)
                self.vectorizer = joblib.load(VECTORIZER_PATH)
                print("All ML models loaded successfully from disk.")
            else:
                print("One or more ML models not found. Bootstrapping default models...")
                self.bootstrap_model()
        except Exception as e:
            print(f"Error loading models: {e}. Re-bootstrapping...")
            self.bootstrap_model()

    def bootstrap_model(self):
        """Fits starter models on mock log data to prevent cold-start failures."""
        # Simple sample logs: mix of normal and suspicious actions
        sample_logs = [
            '127.0.0.1 - - [21/May/2026:10:00:01 +0000] "GET /index.html HTTP/1.1" 200 1024',
            '127.0.0.1 - - [21/May/2026:10:00:02 +0000] "GET /style.css HTTP/1.1" 200 4096',
            '127.0.0.1 - - [21/May/2026:10:00:03 +0000] "GET /js/app.js HTTP/1.1" 200 8192',
            '192.168.1.10 - - [21/May/2026:10:01:05 +0000] "POST /login HTTP/1.1" 200 512',
            '192.168.1.10 - - [21/May/2026:10:02:10 +0000] "POST /login HTTP/1.1" 401 256',
            '192.168.1.10 - - [21/May/2026:10:02:12 +0000] "POST /login HTTP/1.1" 401 256',
            # Anomalies/attacks
            '185.220.101.5 - - [21/May/2026:10:03:00 +0000] "GET /admin HTTP/1.1" 404 128',
            '185.220.101.5 - - [21/May/2026:10:03:15 +0000] "GET /wp-login.php HTTP/1.1" 404 128',
            '185.220.101.5 - - [21/May/2026:10:04:00 +0000] "GET /etc/passwd HTTP/1.1" 400 512',
            '185.220.101.5 - - [21/May/2026:10:04:30 +0000] "GET /index.php?id=1%27%20UNION%20SELECT%20NULL,username,password%20FROM%20users-- HTTP/1.1" 500 2048',
        ]
        self.train(sample_logs)

    def train(self, log_lines):
        """Trains the TF-IDF Vectorizer and all 4 models: Isolation Forest, Random Forest, Logistic Regression, and Gradient Boosting."""
        if not log_lines:
            raise ValueError("Cannot train ML model on empty log data.")

        # 1. Vectorization
        self.vectorizer = TfidfVectorizer(
            analyzer='word',
            token_pattern=r'(?u)\b\w+\b',
            ngram_range=(1, 2),
            max_features=1000
        )
        x_tfidf = self.vectorizer.fit_transform(log_lines)

        # 2. Get training labels (y) using the security rule engine (avoiding circular dependency)
        from utils.security_analyzer import SecurityRuleEngine
        rule_engine = SecurityRuleEngine()
        
        y = []
        for line in log_lines:
            match = re.match(LOG_REGEX, line)
            if match:
                parsed = {
                    "ip": match.group(1),
                    "timestamp": match.group(2),
                    "method": match.group(3),
                    "url": match.group(4),
                    "protocol": match.group(5),
                    "status": int(match.group(6)),
                    "size": 0 if match.group(7) == '-' else int(match.group(7))
                }
                rule_res = rule_engine.analyze_log_record(parsed)
                y.append(1 if rule_res["is_threat"] else 0)
            else:
                y.append(0)
                
        y = np.array(y)

        # 3. Train Isolation Forest (Unsupervised/Semi-supervised)
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(x_tfidf)

        # 4. Train Random Forest (Supervised)
        self.rf_model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            n_jobs=-1
        )
        self.rf_model.fit(x_tfidf, y)

        # 5. Train Logistic Regression (Supervised)
        self.lr_model = LogisticRegression(
            max_iter=1000,
            random_state=42
        )
        self.lr_model.fit(x_tfidf, y)

        # 6. Train Gradient Boosting Classifier (Supervised)
        self.gb_model = GradientBoostingClassifier(
            n_estimators=100,
            random_state=42
        )
        self.gb_model.fit(x_tfidf, y)

        # Save all models to disk
        joblib.dump(self.model, MODEL_PATH)
        joblib.dump(self.rf_model, RF_MODEL_PATH)
        joblib.dump(self.lr_model, LR_MODEL_PATH)
        joblib.dump(self.gb_model, GB_MODEL_PATH)
        joblib.dump(self.vectorizer, VECTORIZER_PATH)
        print("All 4 ML models trained and saved successfully.")

    def predict(self, log_line: str, classifier: str = "isolation_forest"):
        """Predicts if a log line is an anomaly using the chosen classifier.
        
        Returns:
            prediction: int (1 for normal, -1 for anomaly)
            score: float (normalized anomaly score between 0 and 1, where higher means more anomalous)
        """
        if not self.model or not self.vectorizer:
            self.load_model()

        try:
            x_tfidf = self.vectorizer.transform([log_line])
            
            c_lower = classifier.lower().replace(" ", "_")
            
            if c_lower == "isolation_forest":
                prediction = self.model.predict(x_tfidf)[0]  # 1 or -1
                raw_score = self.model.decision_function(x_tfidf)[0]
                score = 1.0 / (1.0 + np.exp(raw_score * 10))  # Sigmoid scaling
                
            elif c_lower == "random_forest":
                prob = self.rf_model.predict_proba(x_tfidf)[0][1]
                prediction = -1 if prob >= 0.5 else 1
                score = float(prob)
                
            elif c_lower == "logistic_regression":
                prob = self.lr_model.predict_proba(x_tfidf)[0][1]
                prediction = -1 if prob >= 0.5 else 1
                score = float(prob)
                
            elif c_lower == "gradient_boosting":
                prob = self.gb_model.predict_proba(x_tfidf)[0][1]
                prediction = -1 if prob >= 0.5 else 1
                score = float(prob)
                
            else:
                # Default Isolation Forest
                prediction = self.model.predict(x_tfidf)[0]
                raw_score = self.model.decision_function(x_tfidf)[0]
                score = 1.0 / (1.0 + np.exp(raw_score * 10))

            return int(prediction), float(score)
        except Exception as e:
            print(f"Error predicting log line: {e}")
            return 1, 0.05

    def predict_all_classifiers(self, log_line: str):
        """Predicts using all 4 classifiers separately and returns their predictions and scores."""
        if not self.model or not self.vectorizer:
            self.load_model()
            
        try:
            x_tfidf = self.vectorizer.transform([log_line])
            results = {}
            
            # 1. Isolation Forest
            if_pred = self.model.predict(x_tfidf)[0]
            if_raw = self.model.decision_function(x_tfidf)[0]
            if_score = 1.0 / (1.0 + np.exp(if_raw * 10))
            results["isolation_forest"] = {
                "prediction": "Anomaly" if if_pred == -1 else "Normal",
                "score": float(if_score)
            }
            
            # 2. Random Forest
            rf_prob = self.rf_model.predict_proba(x_tfidf)[0][1]
            results["random_forest"] = {
                "prediction": "Anomaly" if rf_prob >= 0.5 else "Normal",
                "score": float(rf_prob)
            }
            
            # 3. Logistic Regression
            lr_prob = self.lr_model.predict_proba(x_tfidf)[0][1]
            results["logistic_regression"] = {
                "prediction": "Anomaly" if lr_prob >= 0.5 else "Normal",
                "score": float(lr_prob)
            }
            
            # 4. Gradient Boosting
            gb_prob = self.gb_model.predict_proba(x_tfidf)[0][1]
            results["gradient_boosting"] = {
                "prediction": "Anomaly" if gb_prob >= 0.5 else "Normal",
                "score": float(gb_prob)
            }
            
            return results
        except Exception as e:
            print(f"Error in multi-predict: {e}")
            return {
                "isolation_forest": {"prediction": "Normal", "score": 0.05},
                "random_forest": {"prediction": "Normal", "score": 0.05},
                "logistic_regression": {"prediction": "Normal", "score": 0.05},
                "gradient_boosting": {"prediction": "Normal", "score": 0.05}
            }

    def predict_all_classifiers_bulk(self, log_lines: list):
        """Predicts using all 4 classifiers separately for a list of log lines in bulk to optimize execution speed."""
        if not self.model or not self.vectorizer:
            self.load_model()
            
        if not log_lines:
            return []
            
        try:
            # 1. Bulk TF-IDF transformation - ONLY ONCE!
            x_tfidf = self.vectorizer.transform(log_lines)
            
            # 2. Isolation Forest predictions
            if_preds = self.model.predict(x_tfidf)
            if_raws = self.model.decision_function(x_tfidf)
            if_scores = 1.0 / (1.0 + np.exp(if_raws * 10))
            
            # 3. Random Forest predictions
            rf_probs = self.rf_model.predict_proba(x_tfidf)[:, 1]
            
            # 4. Logistic Regression predictions
            lr_probs = self.lr_model.predict_proba(x_tfidf)[:, 1]
            
            # 5. Gradient Boosting predictions
            gb_probs = self.gb_model.predict_proba(x_tfidf)[:, 1]
            
            # Compile results
            bulk_results = []
            for i in range(len(log_lines)):
                bulk_results.append({
                    "isolation_forest": {
                        "prediction": "Anomaly" if if_preds[i] == -1 else "Normal",
                        "score": float(if_scores[i])
                    },
                    "random_forest": {
                        "prediction": "Anomaly" if rf_probs[i] >= 0.5 else "Normal",
                        "score": float(rf_probs[i])
                    },
                    "logistic_regression": {
                        "prediction": "Anomaly" if lr_probs[i] >= 0.5 else "Normal",
                        "score": float(lr_probs[i])
                    },
                    "gradient_boosting": {
                        "prediction": "Anomaly" if gb_probs[i] >= 0.5 else "Normal",
                        "score": float(gb_probs[i])
                    }
                })
            return bulk_results
        except Exception as e:
            print(f"Error in bulk multi-predict: {e}")
            fallback_item = {
                "isolation_forest": {"prediction": "Normal", "score": 0.05},
                "random_forest": {"prediction": "Normal", "score": 0.05},
                "logistic_regression": {"prediction": "Normal", "score": 0.05},
                "gradient_boosting": {"prediction": "Normal", "score": 0.05}
            }
            return [fallback_item] * len(log_lines)

    def predict_bulk(self, log_lines: list):
        """Predicts anomalies for multiple log lines in bulk (default to Isolation Forest)."""
        if not self.model or not self.vectorizer:
            self.load_model()

        if not log_lines:
            return [], []

        try:
            x_tfidf = self.vectorizer.transform(log_lines)
            predictions = self.model.predict(x_tfidf)
            raw_scores = self.model.decision_function(x_tfidf)
            
            scores = 1.0 / (1.0 + np.exp(raw_scores * 10))
            return predictions.tolist(), scores.tolist()
        except Exception as e:
            print(f"Error predicting bulk logs: {e}")
            return [1] * len(log_lines), [0.05] * len(log_lines)
