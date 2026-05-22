import React, { useState } from 'react';
import { FiUploadCloud, FiCpu, FiPlay, FiStopCircle, FiDatabase, FiSettings, FiActivity } from 'react-icons/fi';

const SparkSidebar = ({ 
  onRunAnalysis, 
  onToggleSimulation, 
  simulationActive, 
  loading,
  logType,
  setLogType,
  partitions,
  setPartitions,
  classifier,
  setClassifier,
  onUploadFile 
}) => {
  const [dragActive, setDragActive] = useState(false);
  const [selectedFile, setSelectedFile] = useState(null);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setDragActive(true);
    } else if (e.type === "dragleave") {
      setDragActive(false);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      onUploadFile(file);
    }
  };

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setSelectedFile(file);
      onUploadFile(file);
    }
  };

  const logTypes = [
    { value: 'apache', label: 'Apache Access Logs' },
    { value: 'hdfs', label: 'HDFS File System' },
    { value: 'kubernetes', label: 'Kubernetes Cluster' },
    { value: 'cloudtrail', label: 'AWS CloudTrail Logs' },
    { value: 'android', label: 'Android Logcat Systems' }
  ];

  const partitionList = [1, 2, 4, 8];

  const classifiers = [
    { value: 'isolation_forest', label: 'Isolation Forest (ML)' },
    { value: 'random_forest', label: 'Random Forest (Supervised)' },
    { value: 'logistic_regression', label: 'Logistic Regression' },
    { value: 'gradient_boosting', label: 'Gradient Boosting (GBM)' }
  ];

  return (
    <div className="w-full lg:w-80 rounded-2xl border border-cardBorder bg-[#0C111D]/90 backdrop-blur-lg p-5 flex flex-col gap-6 shadow-xl transition-all duration-300">
      
      {/* Module Title */}
      <div className="flex items-center gap-2 border-b border-cardBorder/50 pb-3">
        <FiCpu className="text-cyberGreen text-xl animate-pulse" />
        <span className="font-mono text-xs uppercase tracking-widest text-gray-400 font-bold">Spark Orchestration</span>
      </div>

      {/* Log Type Selector */}
      <div className="flex flex-col gap-2">
        <label className="text-[10px] font-semibold font-mono uppercase tracking-widest text-gray-500">
          1. System Ingestion Schema
        </label>
        <select 
          value={logType}
          onChange={(e) => setLogType(e.target.value)}
          className="w-full bg-[#161B26] border border-cardBorder rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyberGreen font-mono"
        >
          {logTypes.map((t) => (
            <option key={t.value} value={t.value}>{t.label}</option>
          ))}
        </select>
      </div>

      {/* Drag & Drop File Upload */}
      <div className="flex flex-col gap-2">
        <label className="text-[10px] font-semibold font-mono uppercase tracking-widest text-gray-500">
          2. Upload Security Log Payload
        </label>
        
        <div 
          onDragEnter={handleDrag}
          onDragOver={handleDrag}
          onDragLeave={handleDrag}
          onDrop={handleDrop}
          className={`relative border-2 border-dashed rounded-xl p-5 flex flex-col items-center justify-center text-center cursor-pointer transition-all duration-300 ${
            dragActive 
              ? 'border-cyberGreen bg-cyberGreen/5' 
              : selectedFile 
                ? 'border-cyberBlue/60 bg-cyberBlue/5' 
                : 'border-cardBorder hover:border-cyberGreen/50 bg-[#161B26]/30'
          }`}
        >
          <input 
            type="file" 
            accept=".log,.txt,.csv"
            onChange={handleFileChange}
            className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          />
          <FiUploadCloud className={`text-3xl mb-2 ${selectedFile ? 'text-cyberBlue animate-bounce' : 'text-gray-500'}`} />
          <p className="text-[11px] text-gray-300 font-medium truncate max-w-full px-2">
            {selectedFile ? selectedFile.name : "Drag & drop log files here"}
          </p>
          <p className="text-[9px] text-gray-500 font-mono mt-1">
            Accepts: .log, .txt, .csv (Max 50MB)
          </p>
        </div>
      </div>

      {/* Spark Partition Setting */}
      <div className="flex flex-col gap-2">
        <label className="text-[10px] font-semibold font-mono uppercase tracking-widest text-gray-500 flex items-center justify-between">
          <span>3. Core Partitions</span>
          <span className="text-[9px] text-cyberGreen font-bold font-mono">Parallel Tasks</span>
        </label>
        <div className="grid grid-cols-4 gap-2">
          {partitionList.map((p) => (
            <button
              key={p}
              type="button"
              onClick={() => setPartitions(p)}
              className={`py-1.5 rounded-lg border text-xs font-mono transition-all duration-200 ${
                partitions === p
                  ? 'bg-cyberGreen/20 border-cyberGreen text-cyberGreen font-bold shadow-sm shadow-cyberGreen/20'
                  : 'bg-[#161B26] border-cardBorder text-gray-400 hover:border-gray-500'
              }`}
            >
              {p}
            </button>
          ))}
        </div>
      </div>

      {/* Classifier Select */}
      <div className="flex flex-col gap-2">
        <label className="text-[10px] font-semibold font-mono uppercase tracking-widest text-gray-500">
          4. ML Anomaly Classifier
        </label>
        <select
          value={classifier}
          onChange={(e) => setClassifier(e.target.value)}
          className="w-full bg-[#161B26] border border-cardBorder rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyberGreen font-mono"
        >
          {classifiers.map((c) => (
            <option key={c.value} value={c.value}>{c.label}</option>
          ))}
        </select>
      </div>

      {/* Controls */}
      <div className="flex flex-col gap-3 mt-2 pt-2 border-t border-cardBorder/50">
        <button
          type="button"
          onClick={onRunAnalysis}
          disabled={loading}
          className={`w-full py-3 rounded-xl border flex items-center justify-center gap-2 font-mono text-xs uppercase font-bold transition-all duration-300 ${
            loading
              ? 'bg-cardBorder/40 border-cardBorder/50 text-gray-500 cursor-not-allowed'
              : 'bg-cyberGreen text-darkBg border-cyberGreen hover:bg-transparent hover:text-cyberGreen hover:shadow-lg hover:shadow-cyberGreen/10'
          }`}
        >
          {loading ? (
            <>
              <span className="h-4 w-4 animate-spin rounded-full border-2 border-gray-600 border-t-white"></span>
              <span>Distributing...</span>
            </>
          ) : (
            <>
              <FiPlay className="text-sm fill-current" />
              <span>Run Spark Pipeline</span>
            </>
          )}
        </button>

        <button
          type="button"
          onClick={onToggleSimulation}
          className={`w-full py-2.5 rounded-xl border flex items-center justify-center gap-2 font-mono text-xs uppercase font-bold transition-all duration-300 ${
            simulationActive
              ? 'bg-cyberRed/20 border-cyberRed text-cyberRed hover:bg-cyberRed/30 shadow-md shadow-cyberRed/5'
              : 'bg-[#161B26] border-cardBorder text-gray-300 hover:border-cyberBlue hover:text-cyberBlue'
          }`}
        >
          {simulationActive ? (
            <>
              <FiStopCircle className="text-sm" />
              <span>Halt Simulator</span>
            </>
          ) : (
            <>
              <FiActivity className="text-sm animate-pulse" />
              <span>Live Simulation</span>
            </>
          )}
        </button>
      </div>

      {/* Spark Mini-Telemetry */}
      <div className="rounded-xl bg-[#161B26]/50 border border-cardBorder/40 p-3 mt-auto">
        <div className="flex items-center gap-1.5 text-[9px] font-semibold font-mono text-gray-500 uppercase tracking-widest mb-1.5">
          <FiDatabase className="text-[10px]" />
          <span>Active RDD Telemetry</span>
        </div>
        <div className="flex flex-col gap-1 text-[10px] font-mono text-gray-400">
          <div className="flex justify-between">
            <span>Core Allocation:</span>
            <span className="text-white font-bold">{partitions * 2} Threads</span>
          </div>
          <div className="flex justify-between">
            <span>Ingestion Pipeline:</span>
            <span className="text-cyberGreen font-bold uppercase">Ready</span>
          </div>
        </div>
      </div>
      
    </div>
  );
};

export default SparkSidebar;
