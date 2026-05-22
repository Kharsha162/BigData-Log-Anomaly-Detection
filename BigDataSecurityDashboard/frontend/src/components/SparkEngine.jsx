import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { sparkApi } from '../services/api';

import SparkSidebar from './SparkSidebar';
import SparkFilters from './SparkFilters';
import SparkMetrics from './SparkMetrics';
import SparkCharts from './SparkCharts';
import SparkThreatTable from './SparkThreatTable';
import SparkSimulation from './SparkSimulation';

const SparkEngine = () => {
  // 1. Spark Engine State
  const [metrics, setMetrics] = useState({
    engine_type: "Pandas Emulated Spark Engine",
    active_workers: 4,
    memory_used_gb: 1.2,
    total_memory_gb: 8.0,
    cpu_utilization_pct: 12.5,
    total_jobs_run: 12,
    uptime_sec: 250,
    is_fallback: true
  });
  
  const [batchMeta, setBatchMeta] = useState({
    records_processed: 500,
    records_filtered: 500,
    execution_time_sec: 0.125,
    processing_speed_lps: 4000,
    partitions: 4,
    batch_id: "RDD-012",
    engine_type: "Pandas Emulated Spark Engine"
  });

  const [records, setRecords] = useState([]);
  const [aggregations, setAggregations] = useState({
    top_attackers: [],
    status_counts: [],
    request_trends: [],
    anomaly_counts: { Normal: 0, Anomaly: 0 },
    endpoint_analytics: [],
    severity_distribution: { Normal: 0, Suspicious: 0, "High Threat": 0, Critical: 0 }
  });

  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");
  
  // 2. User Configuration Settings
  const [logType, setLogType] = useState('apache');
  const [partitions, setPartitions] = useState(4);
  const [classifier, setClassifier] = useState('isolation_forest');
  const [uploadFileObj, setUploadFileObj] = useState(null);

  // 3. User Filter Inputs
  const [searchIp, setSearchIp] = useState('');
  const [searchUrl, setSearchUrl] = useState('');
  const [statusCode, setStatusCode] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [timeRange, setTimeRange] = useState('all');

  // 4. Live Simulation Streams
  const [simulationActive, setSimulationActive] = useState(false);
  const [simulatedLines, setSimulatedLines] = useState([]);

  // Fetch cluster metrics
  const fetchClusterMetrics = async () => {
    try {
      const data = await sparkApi.getMetrics();
      setMetrics(data);
    } catch (err) {
      console.warn("Failed to fetch spark metrics from backend, using current values:", err);
    }
  };

  // Run the core ingestion and analysis pipeline
  const runSparkAnalysis = async () => {
    setLoading(true);
    setErrorMsg("");
    
    try {
      const formData = new FormData();
      if (uploadFileObj) {
        formData.append('file', uploadFileObj);
      }
      formData.append('log_type', logType);
      formData.append('partitions', partitions);
      formData.append('classifier', classifier);
      
      formData.append('search_ip', searchIp);
      formData.append('search_url', searchUrl);
      if (statusCode) {
        formData.append('status_code', statusCode);
      }
      formData.append('severity_filter', severityFilter);
      formData.append('time_range', timeRange);

      const response = await sparkApi.analyzeLogs(formData);
      
      setBatchMeta(response.metadata);
      setRecords(response.records);
      setAggregations(response.aggregations);
      fetchClusterMetrics(); // Update job count
    } catch (err) {
      console.error("Spark execution pipeline failed:", err);
      setErrorMsg("Failed to run Spark distributed processing. Check backend connection.");
      // Seed high quality mock data so user is not blocked
      bootstrapMockDataset();
    } finally {
      setLoading(false);
    }
  };

  // Handle live simulation iteration
  const triggerSimulationStep = async () => {
    try {
      const formData = new FormData();
      formData.append('log_type', logType);
      formData.append('record_count', 15);
      
      const response = await sparkApi.simulateLogs(formData);
      
      // Update tables with new results
      setBatchMeta(response.metadata);
      setRecords(prev => {
        const combined = [...response.records, ...prev];
        return combined.slice(0, 300); // Caps memory footprint
      });
      
      // Update charts & aggregates
      setAggregations(response.aggregations);
      
      // Append raw lines to simulated console
      const newConsoleLines = response.records.map(rec => {
        let line = "";
        if (logType === 'apache') {
          line = `${rec.ip} - - [${rec.timestamp}] "GET ${rec.url} HTTP/1.1" ${rec.status} ${rec.size}`;
        } else if (logType === 'hdfs') {
          line = `${rec.timestamp} ${rec.ip} INFO dfs.FSNamesystem: Access ${rec.url}`;
        } else {
          line = `${rec.timestamp} ${rec.ip} Android [PID 4501]: Request ${rec.url}`;
        }
        return {
          line,
          parsed: rec
        };
      });
      
      setSimulatedLines(prev => {
        const combined = [...prev, ...newConsoleLines];
        return combined.slice(-100); // Cap scrolling line count
      });
      
      fetchClusterMetrics();
    } catch (err) {
      console.warn("Live Spark simulation failed, running client-side mock step:", err);
      executeClientMockStep();
    }
  };

  // Bootstrapping mock dataset if server is disconnected
  const bootstrapMockDataset = () => {
    const mockRecords = [];
    const ips = ["185.220.101.5", "82.102.23.45", "122.164.48.9", "203.0.113.88", "192.168.1.15"];
    const endpoints = ["/api/v1/auth/login", "/wp-login.php", "/static/../../etc/passwd", "/index.html", "/js/app.js"];
    const severities = ["Normal", "Suspicious", "High Threat", "Critical"];
    
    for (let i = 0; i < 200; i++) {
      const isAnom = Math.random() < 0.15;
      const ip = isAnom ? ips[Math.floor(Math.random() * 2)] : ips[Math.floor(Math.random() * 3) + 2];
      const url = isAnom ? endpoints[Math.floor(Math.random() * 3)] : endpoints[Math.floor(Math.random() * 2) + 3];
      const status = isAnom ? (Math.random() < 0.5 ? 401 : 500) : 200;
      const severity = isAnom ? severities[Math.floor(Math.random() * 3) + 1] : "Normal";
      
      const country = ip === "185.220.101.5" ? "United States" : (ip === "82.102.23.45" ? "Russia" : (ip === "122.164.48.9" ? "India" : (ip === "203.0.113.88" ? "Australia" : "Local")));
      const city = ip === "185.220.101.5" ? "Washington" : (ip === "82.102.23.45" ? "Moscow" : (ip === "122.164.48.9" ? "Chennai" : (ip === "203.0.113.88" ? "Sydney" : "Localhost")));
      const latitude = ip === "185.220.101.5" ? 47.75 : (ip === "82.102.23.45" ? 55.75 : (ip === "122.164.48.9" ? 13.08 : (ip === "203.0.113.88" ? -33.86 : 37.77)));
      const longitude = ip === "185.220.101.5" ? -120.74 : (ip === "82.102.23.45" ? 37.61 : (ip === "122.164.48.9" ? 80.27 : (ip === "203.0.113.88" ? 151.20 : -122.41)));
      const isp = isAnom ? "CyberSafe Autonomous System" : "Local Loop ISP";

      mockRecords.push({
        timestamp: new Date(Date.now() - (i * 15000)).toISOString().replace('T', ' ').substring(0, 19),
        ip,
        method: "GET",
        url,
        status,
        size: Math.floor(Math.random() * 4000) + 120,
        log_type: logType.toUpperCase(),
        threat_type: isAnom ? "Exploit Attempt" : "Normal",
        threat_severity: severity,
        prediction: isAnom ? "Anomaly" : "Normal",
        anomaly_score: isAnom ? 0.88 : 0.04,
        country,
        city,
        latitude,
        longitude,
        isp,
        batch_id: `RDD-012`
      });
    }


    setRecords(mockRecords);
    
    // Recalculate aggregates
    const severityCount = { Normal: 0, Suspicious: 0, "High Threat": 0, Critical: 0 };
    const anomCount = { Normal: 0, Anomaly: 0 };
    
    mockRecords.forEach(r => {
      severityCount[r.threat_severity] = (severityCount[r.threat_severity] || 0) + 1;
      anomCount[r.prediction] = (anomCount[r.prediction] || 0) + 1;
    });

    setAggregations({
      top_attackers: [
        { ip: "185.220.101.5", count: 24 },
        { ip: "82.102.23.45", count: 18 }
      ],
      status_counts: [
        { status: 200, count: 164 },
        { status: 401, count: 20 },
        { status: 500, count: 16 }
      ],
      request_trends: [
        { time: "22:00", count: 45 },
        { time: "22:15", count: 68 },
        { time: "22:30", count: 52 },
        { time: "22:45", count: 85 }
      ],
      anomaly_counts: anomCount,
      endpoint_analytics: [
        { endpoint: "/wp-login.php", count: 18 },
        { endpoint: "/index.html", count: 145 },
        { endpoint: "/static/../../etc/passwd", count: 12 }
      ],
      severity_distribution: severityCount
    });
  };

  const executeClientMockStep = () => {
    const isAnom = Math.random() < 0.15;
    const ip = isAnom ? "82.102.23.45" : "122.164.48.9";
    const url = isAnom ? "/wp-login.php" : "/index.html";
    const status = isAnom ? 401 : 200;
    const severity = isAnom ? "High Threat" : "Normal";
    const ts = new Date().toISOString().replace('T', ' ').substring(0, 19);
    
    const country = isAnom ? "Russia" : "India";
    const city = isAnom ? "Moscow" : "Chennai";
    const latitude = isAnom ? 55.75 : 13.08;
    const longitude = isAnom ? 37.61 : 80.27;
    const isp = isAnom ? "CyberSafe Autonomous System" : "Local Loop ISP";

    const record = {
      timestamp: ts,
      ip,
      method: isAnom ? "POST" : "GET",
      url,
      status,
      size: isAnom ? 400 : 2500,
      log_type: logType.toUpperCase(),
      threat_type: isAnom ? "Brute force attempts" : "Normal",
      threat_severity: severity,
      prediction: isAnom ? "Anomaly" : "Normal",
      anomaly_score: isAnom ? 0.92 : 0.05,
      country,
      city,
      latitude,
      longitude,
      isp,
      batch_id: "RDD-015"
    };

    setRecords(prev => [record, ...prev].slice(0, 200));
    setSimulatedLines(prev => [
      ...prev,
      {
        line: `${ip} - - [${ts}] "${isAnom ? 'POST' : 'GET'} ${url} HTTP/1.1" ${status} 200`,
        parsed: record
      }
    ].slice(-100));

    // Update Aggregates partially
    setAggregations(prev => {
      const activeAnoms = { ...prev.anomaly_counts };
      activeAnoms[record.prediction] += 1;
      
      const activeSevs = { ...prev.severity_distribution };
      activeSevs[record.threat_severity] += 1;

      return {
        ...prev,
        anomaly_counts: activeAnoms,
        severity_distribution: activeSevs
      };
    });
  };

  // Triggered on file upload click
  const handleUploadFile = (file) => {
    setUploadFileObj(file);
  };

  // Export handlers
  const handleExportCsv = async () => {
    try {
      const blob = await sparkApi.exportCSV(records);
      const url = window.URL.createObjectURL(new Blob([blob]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `spark_logs_export_${Date.now()}.csv`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("CSV Export failed", err);
    }
  };

  const handleExportJson = async () => {
    try {
      const blob = await sparkApi.exportJSON(records);
      const url = window.URL.createObjectURL(new Blob([blob]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `spark_logs_export_${Date.now()}.json`);
      document.body.appendChild(link);
      link.click();
      link.parentNode.removeChild(link);
    } catch (err) {
      console.error("JSON Export failed", err);
    }
  };

  // Clear query criteria
  const handleClearFilters = () => {
    setSearchIp('');
    setSearchUrl('');
    setStatusCode('');
    setSeverityFilter('');
    setTimeRange('all');
    runSparkAnalysis();
  };

  // Simulation Trigger Toggle
  const handleToggleSimulation = () => {
    setSimulationActive(!simulationActive);
  };

  // 5. Ingestion Hook Lifecycle
  useEffect(() => {
    runSparkAnalysis();
    fetchClusterMetrics();
    const metricsInterval = setInterval(fetchClusterMetrics, 8000);
    return () => clearInterval(metricsInterval);
  }, [logType, partitions, classifier, searchIp, searchUrl, statusCode, severityFilter, timeRange]);

  // Simulation loop trigger
  useEffect(() => {
    let loopId = null;
    if (simulationActive) {
      loopId = setInterval(triggerSimulationStep, 2500);
    }
    return () => {
      if (loopId) clearInterval(loopId);
    };
  }, [simulationActive, logType]);

  return (
    <div className="flex flex-col lg:flex-row gap-6 w-full items-start">
      
      {/* 1. Spark Settings Panel Sidebar */}
      <SparkSidebar
        onRunAnalysis={runSparkAnalysis}
        onToggleSimulation={handleToggleSimulation}
        simulationActive={simulationActive}
        loading={loading}
        logType={logType}
        setLogType={setLogType}
        partitions={partitions}
        setPartitions={setPartitions}
        classifier={classifier}
        setClassifier={setClassifier}
        onUploadFile={handleUploadFile}
      />

      {/* 2. Primary Metrics & Content Hub */}
      <div className="flex flex-1 flex-col gap-6 w-full min-w-0">
        
        {/* Error Notifications */}
        {errorMsg && (
          <div className="rounded-xl border border-red-500/25 bg-red-950/20 p-4 text-xs font-mono text-cyberRed">
            <span className="font-bold">CONNECTION ALERT:</span> {errorMsg} Bootstrapping client side simulation backup.
          </div>
        )}

        {/* Filters */}
        <SparkFilters
          searchIp={searchIp}
          setSearchIp={setSearchIp}
          searchUrl={searchUrl}
          setSearchUrl={setSearchUrl}
          statusCode={statusCode}
          setStatusCode={setStatusCode}
          severityFilter={severityFilter}
          setSeverityFilter={setSeverityFilter}
          timeRange={timeRange}
          setTimeRange={setTimeRange}
          onClearFilters={handleClearFilters}
          onExportCsv={handleExportCsv}
          onExportJson={handleExportJson}
          recordCount={records.length}
        />

        {/* KPI Spark Telemetry Metrics */}
        <SparkMetrics
          metrics={metrics}
          batchMeta={batchMeta}
          anomalyCount={aggregations.anomaly_counts.Anomaly || 0}
        />

        {/* Simulation CLI Console */}
        {simulationActive && (
          <SparkSimulation
            simulationActive={simulationActive}
            onToggleSimulation={handleToggleSimulation}
            simulatedLines={simulatedLines}
            logType={logType}
          />
        )}

        {/* Dynamic Analytics Charts */}
        <SparkCharts 
          aggregations={aggregations} 
        />

        {/* Tabular RDD Streams Console */}
        <SparkThreatTable 
          records={records} 
        />

      </div>

    </div>
  );
};

export default SparkEngine;
