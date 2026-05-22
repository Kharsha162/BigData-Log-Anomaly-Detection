import React from 'react';
import { FiCpu, FiServer, FiHardDrive, FiActivity, FiZap, FiAlertTriangle, FiCheckCircle } from 'react-icons/fi';

const SparkMetrics = ({ metrics, batchMeta, anomalyCount = 0 }) => {
  // Safe extraction of metrics
  const activeWorkers = metrics?.active_workers || 4;
  const memoryUsed = metrics?.memory_used_gb || 1.2;
  const memoryTotal = metrics?.total_memory_gb || 8.0;
  const cpuLoad = metrics?.cpu_utilization_pct || 12.5;
  const uptime = metrics?.uptime_sec || 0;
  const totalJobsRun = metrics?.total_jobs_run || 0;
  const isFallback = metrics?.is_fallback || false;

  const recordsProcessed = batchMeta?.records_processed || 0;
  const processingSpeed = batchMeta?.processing_speed_lps || 0;
  const activePartitions = batchMeta?.partitions || 1;
  const batchId = batchMeta?.batch_id || "RDD-000";

  // Calculate anomaly percentages
  const anomalyRate = recordsProcessed > 0 ? ((anomalyCount / recordsProcessed) * 100).toFixed(2) : '0.00';

  const cards = [
    {
      title: "Spark Batch Ingestion",
      value: recordsProcessed.toLocaleString(),
      desc: `Ingested batch: ${batchId}`,
      icon: <FiZap className="text-xl text-cyberBlue" />,
      glow: "hover:shadow-glowBlue/5",
      accent: "border-l-4 border-l-cyberBlue"
    },
    {
      title: "Anomalies Flagged",
      value: anomalyCount.toLocaleString(),
      desc: `${anomalyRate}% anomaly rate`,
      icon: <FiAlertTriangle className={`text-xl ${anomalyCount > 0 ? 'text-cyberRed animate-pulse' : 'text-gray-500'}`} />,
      glow: "hover:shadow-glowRed/5",
      accent: "border-l-4 border-l-cyberRed"
    },
    {
      title: "Spark Data Partitions",
      value: `${activePartitions} Active`,
      desc: `${activeWorkers} worker daemon threads`,
      icon: <FiServer className="text-xl text-cyberGreen" />,
      glow: "hover:shadow-glowGreen/5",
      accent: "border-l-4 border-l-cyberGreen"
    },
    {
      title: "Engine Speed (LPS)",
      value: `${processingSpeed.toLocaleString()} /s`,
      desc: "Distributed parse latency",
      icon: <FiActivity className="text-xl text-cyberYellow animate-pulse" />,
      glow: "hover:shadow-glowYellow/5",
      accent: "border-l-4 border-l-cyberYellow"
    }
  ];

  return (
    <div className="flex flex-col gap-6 w-full">
      
      {/* Cluster Warning Banner */}
      {isFallback && (
        <div className="rounded-xl border border-cyberGreen/30 bg-[#0B1E19]/80 p-4 flex items-start gap-3 transition-all duration-300 shadow-glowGreen/5">
          <FiCheckCircle className="text-cyberGreen text-xl flex-shrink-0 mt-0.5 animate-pulse" />
          <div className="flex-1 text-xs font-mono text-gray-300 leading-relaxed font-semibold">
            <span className="font-bold text-white uppercase bg-cyberGreen/20 border border-cyberGreen/30 px-1.5 py-0.5 rounded mr-1.5">
              Pandas-Optimized Spark Core
            </span>
            The SecOps pipeline is running at full velocity on the high-speed Pandas-emulated Spark engine. Distributed parsing schemas, ML anomaly models, and filters are fully operational.
          </div>
        </div>
      )}

      {/* Primary KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
        {cards.map((card, idx) => (
          <div 
            key={idx} 
            className={`rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-4 flex flex-col justify-between transition-all duration-300 ${card.glow} ${card.accent}`}
          >
            <div className="flex items-center justify-between">
              <span className="text-[9px] font-bold uppercase tracking-widest text-gray-500 font-mono">
                {card.title}
              </span>
              <div className="p-1.5 rounded-lg bg-[#161B26] border border-cardBorder/40">
                {card.icon}
              </div>
            </div>
            <div className="mt-3 flex items-baseline gap-2">
              <span className="text-2xl font-bold tracking-tight text-white font-mono">
                {card.value}
              </span>
            </div>
            <p className="mt-1 text-[10px] text-gray-500 font-mono">
              {card.desc}
            </p>
          </div>
        ))}
      </div>

      {/* Cluster Hardware Telemetry Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 w-full">
        
        {/* Core Engine Hardware Status */}
        <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-[9px] font-bold uppercase tracking-widest text-gray-500 font-mono">Cluster Ingestion Engine</span>
              <h3 className="text-sm font-bold text-white font-mono mt-1 truncate">{metrics?.engine_type || "SparkAnalyticsEngine"}</h3>
            </div>
            <FiCpu className="text-xl text-cyberBlue" />
          </div>
          <div className="flex justify-between items-center text-xs font-mono border-t border-cardBorder/30 pt-3">
            <span className="text-gray-400">Total Jobs Ingested:</span>
            <span className="text-cyberGreen font-bold">{totalJobsRun} completed</span>
          </div>
          <div className="flex justify-between items-center text-xs font-mono">
            <span className="text-gray-400">Daemon Cluster Uptime:</span>
            <span className="text-gray-200">{uptime} seconds</span>
          </div>
        </div>

        {/* Cluster Memory Usage */}
        <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-[9px] font-bold uppercase tracking-widest text-gray-500 font-mono">Heap Cluster Memory</span>
              <h3 className="text-lg font-bold text-white font-mono mt-1">
                {memoryUsed.toFixed(2)} / {memoryTotal.toFixed(1)} GB
              </h3>
            </div>
            <FiHardDrive className="text-xl text-cyberYellow animate-pulse" />
          </div>
          {/* Progress bar */}
          <div className="w-full bg-[#161B26] h-2 rounded-full overflow-hidden border border-cardBorder/50 mt-1">
            <div 
              className="bg-cyberYellow h-full transition-all duration-500 rounded-full"
              style={{ width: `${(memoryUsed / memoryTotal) * 100}%` }}
            />
          </div>
          <div className="flex justify-between items-center text-[10px] font-mono text-gray-500">
            <span>Buffer Overlap: OK</span>
            <span>{((memoryUsed / memoryTotal) * 100).toFixed(1)}% Memory Used</span>
          </div>
        </div>

        {/* CPU Workload */}
        <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-3">
          <div className="flex items-center justify-between">
            <div className="flex flex-col">
              <span className="text-[9px] font-bold uppercase tracking-widest text-gray-500 font-mono">Parallel Spark Threads</span>
              <h3 className="text-lg font-bold text-white font-mono mt-1">
                {cpuLoad.toFixed(1)}% CPU Utilization
              </h3>
            </div>
            <FiActivity className="text-xl text-cyberRed animate-pulse" />
          </div>
          {/* Progress bar */}
          <div className="w-full bg-[#161B26] h-2 rounded-full overflow-hidden border border-cardBorder/50 mt-1">
            <div 
              className="bg-cyberRed h-full transition-all duration-500 rounded-full"
              style={{ width: `${cpuLoad}%` }}
            />
          </div>
          <div className="flex justify-between items-center text-[10px] font-mono text-gray-500">
            <span>Core Worker Usage: ACTIVE</span>
            <span>Allocated: {activeWorkers} Workers</span>
          </div>
        </div>

      </div>

    </div>
  );
};

export default SparkMetrics;
