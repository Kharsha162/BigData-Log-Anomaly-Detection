import React, { useEffect, useRef } from 'react';
import { FiTerminal, FiPlay, FiStopCircle, FiCheck, FiAlertTriangle } from 'react-icons/fi';

const SparkSimulation = ({ 
  simulationActive, 
  onToggleSimulation, 
  simulatedLines = [], 
  logType = 'apache' 
}) => {
  const terminalEndRef = useRef(null);

  useEffect(() => {
    // Scroll to bottom of terminal when new simulated lines are received
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [simulatedLines]);

  return (
    <div className="w-full rounded-2xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4 shadow-xl transition-all duration-300">
      
      {/* Title / Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-cardBorder/50 pb-3">
        <div className="flex items-center gap-2">
          <FiTerminal className="text-cyberGreen text-lg animate-pulse" />
          <h2 className="font-mono text-xs uppercase tracking-widest text-white font-bold">
            Real-Time Spark Stream Simulator Console
          </h2>
        </div>

        {/* Start / Stop */}
        <button
          type="button"
          onClick={onToggleSimulation}
          className={`flex items-center gap-1.5 px-4 py-1.5 rounded-lg border font-mono text-[10px] uppercase font-bold transition-all duration-200 ${
            simulationActive
              ? 'bg-cyberRed/20 border-cyberRed text-cyberRed hover:bg-cyberRed/30'
              : 'bg-cyberGreen/20 border-cyberGreen text-cyberGreen hover:bg-cyberGreen/30'
          }`}
        >
          {simulationActive ? (
            <>
              <FiStopCircle className="text-xs" />
              <span>Halt Simulator</span>
            </>
          ) : (
            <>
              <FiPlay className="text-xs" />
              <span>Start Simulator</span>
            </>
          )}
        </button>
      </div>

      {/* Terminal Display */}
      <div className="w-full bg-[#050811] rounded-xl border border-cardBorder p-4 h-64 overflow-y-auto font-mono text-[10px] text-cyberGreen leading-relaxed shadow-inner">
        
        {/* Terminal Header Info */}
        <div className="border-b border-cyberGreen/10 pb-2 mb-3 text-gray-500 flex justify-between">
          <span>SPARK_STREAM_DAEMON // SIMULATOR ACTIVE</span>
          <span className="uppercase text-cyberBlue">SCHEMA: {logType}</span>
        </div>

        {/* Log Tickers */}
        <div className="flex flex-col gap-1.5">
          {simulatedLines.length === 0 ? (
            <div className="text-gray-600 italic py-4">
              [SYSTEM] Log stream emulator idle. Press "Start Simulator" to begin streaming real-time security events...
            </div>
          ) : (
            simulatedLines.map((item, idx) => {
              const isAnomaly = item.parsed?.prediction === 'Anomaly';
              const logLine = item.line || '';

              return (
                <div 
                  key={idx} 
                  className={`flex flex-col sm:flex-row items-start gap-1 sm:gap-3 py-1 px-2 rounded transition-all duration-150 ${
                    isAnomaly 
                      ? 'bg-cyberRed/10 border-l-2 border-l-cyberRed text-cyberRed/90' 
                      : 'hover:bg-cardBorder/20 text-cyberGreen/90'
                  }`}
                >
                  {/* Status Indicator */}
                  <span className="flex-shrink-0 font-bold flex items-center gap-1 select-none">
                    {isAnomaly ? (
                      <span className="text-cyberRed flex items-center gap-0.5 font-bold uppercase bg-cyberRed/10 border border-cyberRed/20 px-1 rounded text-[8px]">
                        <FiAlertTriangle className="text-[9px] inline animate-pulse" /> ALERT
                      </span>
                    ) : (
                      <span className="text-cyberGreen flex items-center gap-0.5 font-bold uppercase bg-cyberGreen/10 border border-cyberGreen/20 px-1 rounded text-[8px]">
                        <FiCheck className="text-[9px] inline" /> INGEST
                      </span>
                    )}
                  </span>

                  {/* Log timestamp & content */}
                  <span className="text-gray-500 select-none">
                    {item.parsed?.timestamp ? `[${item.parsed.timestamp}]` : ''}
                  </span>
                  
                  <span className="break-all font-mono">
                    {logLine}
                  </span>
                </div>
              );
            })
          )}
          <div ref={terminalEndRef} />
        </div>
      </div>

      {/* Footer System Telemetry */}
      <div className="flex flex-wrap gap-4 text-[9px] font-mono text-gray-500 uppercase tracking-wider border-t border-cardBorder/30 pt-3">
        <div className="flex items-center gap-1">
          <span className="h-1.5 w-1.5 rounded-full bg-cyberGreen animate-ping" />
          <span>Ingest Thread: Ingestion active</span>
        </div>
        <div>
          <span>Stream Interval: 2.5 seconds</span>
        </div>
        <div>
          <span>Buffer Queue: {simulatedLines.length} / 500 records</span>
        </div>
      </div>
      
    </div>
  );
};

export default SparkSimulation;
