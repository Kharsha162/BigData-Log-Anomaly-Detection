# Big Data Log Anomaly Detection & Security Analytics Platform

A production-style Security Operations Center (SOC) dashboard that processes large-scale web logs, utilizes machine learning (Isolation Forest + TF-IDF) to detect cyber threats in real time, and handles big data processing using Apache Spark (with automatic multi-threaded Pandas fallbacks).

---

## 🚀 Key Highlights & Tech Stack

### Frontend
- **ReactJS & Vite**: Blazing-fast development server and optimized production bundles.
- **Tailwind CSS**: Custom cyber-dark theme with glowing borders, neon badges, and glassmorphic layouts.
- **Recharts**: Modular plotting of threat timelines, log ratios, attack distributions, and network volumes.
- **React Leaflet**: Interactive global map displaying source attack vectors routing to local SOC datacenters.
- **Framer Motion**: Smooth entry transitions, active card hover alerts, and list animations.
- **Axios & WebSockets**: Automatic bearer tokens interceptors and real-time live log streams.

### Backend & ML
- **FastAPI & Uvicorn**: High-performance asynchronous API routers.
- **Apache Spark / PySpark**: Scalable RDD log parsers and processing metric aggregators.
- **Pandas**: Local multi-threaded fallback system to simulate Spark configurations seamlessly on developer machines.
- **Scikit-Learn**: TF-IDF text feature vectorization and Isolation Forest unsupervised anomaly detection.
- **JWT Authentication**: Secured operator portals (Default: `admin` / `admin123`).

---

## 📁 Complete Folder Structure

```
BigDataSecurityDashboard/
│
├── frontend/
│   ├── package.json           # Frontend script triggers & library configurations
│   ├── tailwind.config.js     # Custom cyber-dark neon color theme configuration
│   ├── postcss.config.js      # PostCSS directives for Tailwind compilation
│   ├── index.html             # Main entry HTML template equipped with SEO metadata
│   └── src/
│       ├── main.jsx           # Mounts the React application in StrictMode
│       ├── index.css          # Injects Tailwind directives, Leaflet canvas overlays, and animations
│       ├── App.jsx            # Core application router with JWT authorization guards
│       ├── components/
│       │   ├── Sidebar.jsx    # Collapsible sidebar with navigation items and logout actions
│       │   ├── Header.jsx     # Synchronized telemetry clock, system status, and profiles
│       │   └── ProtectedRoute.jsx # JWT local token validation route handler
│       ├── pages/
│       │   ├── Dashboard.jsx  # SOC Command Room: real-time graphs and streaming alert tables
│       │   ├── ApacheLogs.jsx # Logs inspector: query bars, parameters, CSV downloads, and uploader
│       │   ├── ThreatIntel.jsx# Exploit database matching signatures and top attacker IP files
│       │   ├── SparkAnalytics.jsx # Cluster metrics console: active workers, memory graphs, and jobs
│       │   ├── AnomalyDetection.jsx # ML testing playground: RETRAIN controls and log prediction sandbox
│       │   ├── AttackMap.jsx  # Interactive map plotting threat coordinates and vector routes
│       │   ├── Reports.jsx    # Compliance generator: print-ready PDF and summary audits
│       │   └── Settings.jsx   # Stream delay parameters and forced red-team scenario triggers
│       ├── charts/
│       │   ├── ThreatTimeline.jsx # Recharts Area: rolling anomaly indicators
│       │   ├── AnomalyBarChart.jsx # Recharts Bar: attack vector categorizations
│       │   ├── DistributionPieChart.jsx # Recharts Pie: normal vs anomaly counts
│       │   └── TrafficAreaChart.jsx # Recharts Area: total log request frequency
│       └── services/
│           └── api.js         # Axios HTTP services with JWT interceptors
│
├── backend/
│   ├── main.py                # Initializes FastAPI, CORS, and registers WebSocket feeds
│   ├── requirements.txt       # Python package dependencies
│   ├── routes/
│   │   ├── auth.py            # Administrative token generation and verification
│   │   ├── logs.py            # Log retrieval, parameters search, and multipart upload
│   │   ├── predict.py         # Sandbox prediction models and Retrain loops
│   │   └── spark.py           # Spark cluster telemetry telemetry endpoints
│   ├── models/
│   │   └── schemas.py         # Pydantic input models and validation schemas
│   ├── services/
│   │   ├── state.py           # In-memory log database cache and service managers
│   │   ├── ml_service.py      # TF-IDF Vectorizer + Isolation Forest handler
│   │   └── spark_service.py   # PySpark parser engine with local Pandas fallbacks
│   └── utils/
│       ├── log_generator.py   # Seeding utility and real-time scenario log generator
│       └── security_analyzer.py # Cyber signature scanners, brute-force trackers, and DDOS checkers
│
├── model/
│   ├── apache_log_model.pkl   # Serialized Isolation Forest model binary
│   └── tfidf_vectorizer.pkl   # Serialized TF-IDF text feature vectorizer
│
├── data/
│   ├── raw_logs/              # Folder housing original raw log text files
│   └── processed_logs.csv     # Extracted and enriched security logs database
│
└── README.md                  # System manual and documentation
```

---

## 🛠️ Installation & Getting Started

### Prerequisites
- **Python**: v3.9+ (Pip package manager)
- **NodeJS**: v18+ (NPM package manager)
- *(Optional)* Java JDK 8/11 and Apache Spark (if you wish to test native Spark clustering). If not configured, the system gracefully uses the Pandas engine.

---

### Step 1: Backend Setup
1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   # On Windows (PowerShell):
   .\venv\Scripts\Activate.ps1
   # On Linux/macOS:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the FastAPI server using Uvicorn:
   ```bash
   python main.py
   ```
   *The backend will boot on `http://localhost:8000`. On first start, it will automatically generate 2,500 mock log entries, fit the ML classifier, and cache them, meaning the dashboard is fully populated instantly.*

---

### Step 2: Frontend Setup
1. Open a new terminal window and navigate to the frontend directory:
   ```bash
   cd frontend
   ```
2. Install npm packages:
   ```bash
   npm install
   ```
3. Start the local Vite development server:
   ```bash
   npm run dev
   ```
   *The frontend will boot on `http://localhost:5173`.*

---

## 🔐 Credentials for Testing
- **URL**: `http://localhost:5173/login`
- **Username**: `admin`
- **Password**: `admin123`

---

## 🖥️ System Architecture & Workflow

1. **Log Simulation & Ingestion**: The system continuously generates Apache Combined Log format lines. A WebSocket broadcast system pushes new logs to all connected dashboards.
2. **Rule-Based Threat Verification**: Before machine learning execution, logs pass through a rule engine (`security_analyzer.py`). This performs pattern matches (signatures for SQLi, Cross-site scripting, directory path traversal), monitors IP request rates (DDoS detection), and checks login limits (brute-force detection).
3. **ML Classification Pipeline**: The line is sent to the Machine Learning model (`ml_service.py`). It applies TF-IDF vectorization to convert raw text into numerical features and passes it to an Isolation Forest anomaly classifier. The anomaly decision function is normalized into an anomaly probability percentage.
4. **Spark Analysis**: The Spark Processing Service (`spark_service.py`) aggregates log properties, tracks request quantities, parses common patterns, and calculates execution performance. It falls back to multi-threaded Pandas calculation if PySpark is not present.
5. **Interactive Mapping**: Geographic IP lookups map threat source coordinates (latitude/longitude) and render them on Leaflet Maps (`AttackMap.jsx`). The frontend draws animated vectors from the source countries directly to a mock center in India.

---

## 🔍 Troubleshooting Guide

### 1. Leaflet map renders as scattered grey boxes or fails to align tiles
- **Fix**: Verify that you are connected to the Internet (leaflet maps fetch tiles dynamically from CartoDB servers) and check that `import 'leaflet/dist/leaflet.css';` is present in `AttackMap.jsx`.

### 2. Vite throws "react-router-dom" or package import errors
- **Fix**: Clean node_modules cache and reinstall:
  ```bash
  rm -rf node_modules package-lock.json
  npm install
  ```

### 3. PySpark complains about JAVA_HOME or spark-submit variables on Windows
- **Fix**: You don't need to manually configure environment variables! The backend `spark_service.py` is configured with safety try-catch wrappers. It will automatically log a message indicating fallback mode and activate the Pandas processor.

### 4. JWT Validation returns "401 Unauthorized" or CORS blocks calls
- **Fix**: Check that the FastAPI server is running. If CORS blocks persist, ensure that Uvicorn is serving on `localhost:8000` and the React client makes calls to `http://localhost:8000/api` (as configured in `api.js`).

---

## 🎓 Interview & Viva Explanation Guide

### Q1: Why did you choose Isolation Forest for Anomaly Detection?
*Answer*: Isolation Forest is an unsupervised ensemble learning algorithm specifically designed to detect anomalies in high-dimensional space. Unlike traditional classifiers that train on balanced classes, Isolation Forest isolates anomalous items by randomly partitioning feature paths. Because anomalies are sparse and distinct, they require fewer splits to isolate (closer to the root of the trees), resulting in fast execution and high accuracy without needing labeled attack sets.

### Q2: What is the purpose of combining TF-IDF with Isolation Forest?
*Answer*: Web server log lines are unstructured textual strings. To feed them to a mathematical classifier, we must convert them into numerical arrays. Term Frequency-Inverse Document Frequency (TF-IDF) scores words or patterns based on their frequency in a single log line relative to the entire log file. This highlights rare directories, uncommon query parameters, and malicious command injections (e.g., `UNION SELECT`), making them easily identifiable to the Isolation Forest model.

### Q3: How does your Spark Service fallback work?
*Answer*: In production big-data infrastructures, PySpark runs on distributed yarn clusters to parse gigabytes of streaming logs. However, establishing local Spark nodes on developer laptops often fails due to missing Java variables. To make the project production-ready yet beginner-friendly, we coded an interface wrapper. If Spark is unavailable, it processes the raw data using Pandas, utilizing multi-threaded vector operations to perform identical parsing and metrics calculations.

---

## 📝 Resume-Ready Project Description

**Title**: Big Data Log Anomaly Detection & Security Analytics Platform
**Role**: Senior Full-Stack Security & ML Engineer
- Designed and built a Security Operations Center (SOC) dashboard utilizing **ReactJS**, **FastAPI**, **Apache Spark**, and **Scikit-learn** to process web access logs, identify intrusion vectors, and display visual analytics in real time.
- Implemented an unsupervised Machine Learning pipeline using **TF-IDF Vectorization** and **Isolation Forest** to classify log line anomalies with an adjustable contamination rate, achieving automated threat score normalization.
- Crafted a rule-based correlation engine to flag DDoS request spikes, multi-attempt authentication brute-force scans, SQL Injections, and Directory Traversals.
- Designed a hybrid PySpark data processing service that parses Apache Combined logs, aggregates statuses, and calculates cluster performance telemetry, featuring a seamless Pandas execution fallback engine.
- Configured visual dashboard components including an interactive geographic Leaflet attack map with custom SVG glow markers, 4 responsive Recharts plotting panes, real-time WebSocket feeds, and printing stylesheet compliance reports.
