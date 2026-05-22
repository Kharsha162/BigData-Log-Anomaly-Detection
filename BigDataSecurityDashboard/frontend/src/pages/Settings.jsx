import React, { useState, useEffect, useRef } from 'react';
import { FiSliders, FiPlay, FiPause, FiZap, FiCpu, FiAlertOctagon } from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import { mlApi } from '../services/api';

const Settings = () => {
  const [streamSpeed, setStreamSpeed] = useState(2.0);
  const [isStreaming, setIsStreaming] = useState(true);
  const [retraining, setRetraining] = useState(false);
  const [trainStatus, setTrainStatus] = useState(null);
  
  const wsRef = useRef(null);

  useEffect(() => {
    // Establish temporary WebSocket socket to send control signals
    const socket = new WebSocket('ws://127.0.0.1:8000/ws/logs');
    wsRef.current = socket;

    socket.onopen = () => {
      console.log('Settings control socket established.');
      // Push current UI state to backend
      socket.send(JSON.stringify({ action: "set_interval", value: streamSpeed }));
      socket.send(JSON.stringify({ action: "toggle_stream", value: isStreaming }));
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleSpeedChange = (e) => {
    const val = parseFloat(e.target.value);
    setStreamSpeed(val);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: "set_interval",
        value: val
      }));
    }
  };

  const handleToggleStreaming = () => {
    const nextState = !isStreaming;
    setIsStreaming(nextState);
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: "toggle_stream",
        value: nextState
      }));
    }
  };

  const handleTriggerAttack = (scenario) => {
    if (wsRef.current && wsRef.current.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({
        action: "trigger_anomaly",
        scenario: scenario
      }));
    } else {
      alert("WebSocket connection is currently offline. Start FastAPI backend first.");
    }
  };

  const handleRetrain = async () => {
    setRetraining(true);
    setTrainStatus(null);
    try {
      const res = await mlApi.retrainModel();
      setTrainStatus(res.message);
    } catch {
      setTrainStatus("Retraining failed.");
    } finally {
      setRetraining(false);
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="SYSTEM CONTROLS & SECURITY PARAMETERS" />
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            
            {/* Live streaming controllers */}
            <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5 space-y-6">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                <FiSliders className="text-cyberGreen" />
                Live Log Simulator Streaming Config
              </h3>

              {/* Toggle stream */}
              <div className="flex items-center justify-between border-b border-cardBorder/40 pb-4">
                <div>
                  <span className="text-xs font-bold text-white block">Log Stream Simulator</span>
                  <span className="text-[10px] text-gray-500 font-mono mt-0.5">Toggle real-time log ingestion feeds</span>
                </div>
                <button
                  onClick={handleToggleStreaming}
                  className={`px-4 py-2 rounded text-xs font-bold font-mono flex items-center gap-2 border ${
                    isStreaming 
                      ? 'bg-cyberGreen/20 text-cyberGreen border-cyberGreen/30 shadow-glowGreen' 
                      : 'bg-cardBorder text-gray-400 border-cardBorder'
                  }`}
                >
                  {isStreaming ? <FiPause /> : <FiPlay />}
                  <span>{isStreaming ? 'STREAMING ACTIVE' : 'STREAMING PAUSED'}</span>
                </button>
              </div>

              {/* Interval slider */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <div>
                    <span className="font-bold text-white block">Ingestion Delay Interval</span>
                    <span className="text-[10px] text-gray-500 font-mono">Seconds between generated logs</span>
                  </div>
                  <span className="font-mono text-cyberBlue font-bold">{streamSpeed.toFixed(1)}s</span>
                </div>
                <input
                  type="range"
                  min="0.5"
                  max="5.0"
                  step="0.5"
                  value={streamSpeed}
                  onChange={handleSpeedChange}
                  disabled={!isStreaming}
                  className="w-full h-1 bg-cardBorder rounded-lg appearance-none cursor-pointer accent-cyberBlue disabled:opacity-35"
                />
              </div>
            </div>

            {/* Fire drills sandbox */}
            <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5 space-y-4">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                  <FiAlertOctagon className="text-cyberRed" />
                  Red-Team Intrusion Fire Drills
                </h3>
                <p className="text-xs text-gray-500 mt-1">
                  Injects simulated exploit lines directly into the live log stream cache to test dashboard alarms.
                </p>
              </div>

              <div className="grid grid-cols-3 gap-3 pt-2 font-mono text-[10px]">
                <button
                  onClick={() => handleTriggerAttack('exploit')}
                  className="rounded bg-red-950/20 text-cyberRed border border-cyberRed/30 py-3 font-semibold shadow-glowRed/5 hover:bg-red-950/40"
                >
                  TRIGGER SQLi
                </button>
                <button
                  onClick={() => handleTriggerAttack('ddos')}
                  className="rounded bg-yellow-950/20 text-cyberYellow border border-cyberYellow/30 py-3 font-semibold shadow-glowYellow/5 hover:bg-yellow-950/40"
                >
                  TRIGGER DDoS
                </button>
                <button
                  onClick={() => handleTriggerAttack('brute_force')}
                  className="rounded bg-blue-950/20 text-cyberBlue border border-cyberBlue/30 py-3 font-semibold shadow-glowBlue/5 hover:bg-blue-950/40"
                >
                  TRIGGER BRUTE FORCE
                </button>
              </div>
            </div>

            {/* ML pipeline maintenance */}
            <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5 space-y-4">
              <div>
                <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                  <FiCpu className="text-cyberBlue" />
                  Anomaly Detection Model Retraining
                </h3>
                <p className="text-xs text-gray-500 mt-1">
                  Instructs the backend to execute on-demand retraining of the Isolation Forest classifier.
                </p>
              </div>

              <div className="pt-2">
                {trainStatus && (
                  <div className="rounded bg-cardBorder p-3 text-xs font-mono text-gray-300 border border-cardBorder mb-3">
                    {trainStatus}
                  </div>
                )}
                <button
                  onClick={handleRetrain}
                  disabled={retraining}
                  className="rounded bg-cyberBlue text-darkBg px-5 py-2.5 text-xs font-bold uppercase shadow-glowBlue hover:bg-cyberBlue/90 disabled:opacity-50 flex items-center gap-2"
                >
                  {retraining && <span className="h-4 w-4 animate-spin rounded-full border-2 border-darkBg border-t-transparent"></span>}
                  <span>Retrain Model</span>
                </button>
              </div>
            </div>

          </div>
        </main>
      </div>
    </div>
  );
};

export default Settings;
