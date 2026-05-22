import React, { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { 
  FiShield, FiAlertTriangle, FiAlertOctagon, FiActivity, 
  FiCpu, FiGlobe, FiDatabase, FiSearch, FiRefreshCw 
} from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import ThreatTimeline from '../charts/ThreatTimeline';
import AnomalyBarChart from '../charts/AnomalyBarChart';
import DistributionPieChart from '../charts/DistributionPieChart';
import TrafficAreaChart from '../charts/TrafficAreaChart';
import { logsApi } from '../services/api';

const Dashboard = () => {
  // KPI Stats
  const [stats, setStats] = useState({
    total_logs: 0,
    total_anomalies: 0,
    failed_requests: 0,
    high_severity_alerts: 0,
    detection_rate: 0.0,
    spark_jobs_processed: 0,
    threat_countries: 0,
    suspicious_ips: 0,
  });

  const [loading, setLoading] = useState(true);
  const [liveLogs, setLiveLogs] = useState([]);
  
  // Chart datasets
  const [timelineData, setTimelineData] = useState([]);
  const [barData, setBarData] = useState([]);
  const [pieData, setPieData] = useState([]);
  const [trafficData, setTrafficData] = useState([]);

  const socketRef = useRef(null);

  // Fetch initial data
  const fetchData = async () => {
    try {
      const initialStats = await logsApi.getStats();
      setStats(initialStats);
      
      const historicalLogs = await logsApi.getLogs({ limit: 100 });
      setLiveLogs(historicalLogs.logs.slice(0, 15));
      
      // Process initial charts from historical data
      generateChartData(historicalLogs.logs);
      setLoading(false);
    } catch (err) {
      console.error("Error loading dashboard data:", err);
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();

    // Establish WebSocket Connection for real-time telemetry streaming
    const wsUrl = 'ws://127.0.0.1:8000/ws/logs';
    const socket = new WebSocket(wsUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      console.log('WebSocket stream connection established.');
    };

    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      if (message.type === 'log_entry') {
        const newLog = message.data;
        
        // 1. Prepend to live logs stream
        setLiveLogs(prev => [newLog, ...prev.slice(0, 14)]);
        
        // 2. Increment stats dynamically
        setStats(prev => {
          const total = prev.total_logs + 1;
          const isAnom = newLog.prediction === 'Anomaly';
          const failed = newLog.status >= 400 ? prev.failed_requests + 1 : prev.failed_requests;
          const anoms = isAnom ? prev.total_anomalies + 1 : prev.total_anomalies;
          const highAlerts = (isAnom && ['High', 'Critical'].includes(newLog.threat_severity)) 
            ? prev.high_severity_alerts + 1 
            : prev.high_severity_alerts;
            
          return {
            ...prev,
            total_logs: total,
            total_anomalies: anoms,
            failed_requests: failed,
            high_severity_alerts: highAlerts,
            detection_rate: parseFloat(((anoms / total) * 100).toFixed(2)),
          };
        });

        // 3. Dynamic sliding-window charts update
        updateChartsRealtime(newLog);
      }
    };

    socket.onclose = () => {
      console.log('WebSocket stream connection closed.');
    };

    return () => {
      socket.close();
    };
  }, []);

  const generateChartData = (logs) => {
    // Pie Chart
    const anomalies = logs.filter(l => l.prediction === 'Anomaly').length;
    const normal = logs.length - anomalies;
    setPieData([
      { name: 'Normal Traffic', value: normal },
      { name: 'Anomalies', value: anomalies }
    ]);

    // Bar Chart of attack types
    const types = {};
    logs.forEach(l => {
      if (l.prediction === 'Anomaly') {
        const type = l.url.includes('UNION') ? 'SQLi' :
                     l.url.includes('passwd') ? 'LFI' :
                     l.url.includes('login') ? 'BruteForce' : 'Scanner';
        types[type] = (types[type] || 0) + 1;
      }
    });
    setBarData(Object.keys(types).map(k => ({ name: k, value: types[k] })));

    // Timeline and Traffic Charts
    // Build hourly groupings
    const timelines = [];
    const traffics = [];
    const last10 = logs.slice(0, 10).reverse();
    
    last10.forEach((l, idx) => {
      timelines.push({
        timestamp: l.timestamp,
        threats: l.prediction === 'Anomaly' ? 1 : 0
      });
      traffics.push({
        timestamp: l.timestamp,
        count: 1
      });
    });

    setTimelineData(timelines);
    setTrafficData(traffics);
  };

  const updateChartsRealtime = (newLog) => {
    const timestamp = newLog.timestamp;

    // Update normal vs anomaly pie immutably
    setPieData(prev => {
      if (!prev || prev.length < 2) return prev;
      return [
        { ...prev[0], value: newLog.prediction !== 'Anomaly' ? prev[0].value + 1 : prev[0].value },
        { ...prev[1], value: newLog.prediction === 'Anomaly' ? prev[1].value + 1 : prev[1].value }
      ];
    });

    // Update attack type bar if anomaly immutably
    if (newLog.prediction === 'Anomaly') {
      const type = newLog.url.includes('UNION') ? 'SQLi' :
                   newLog.url.includes('passwd') ? 'LFI' :
                   newLog.url.includes('login') ? 'BruteForce' : 'Scanner';
      setBarData(prev => {
        const copy = prev.map(item => {
          if (item.name === type) {
            return { ...item, value: item.value + 1 };
          }
          return item;
        });
        const existing = copy.find(item => item.name === type);
        if (!existing) {
          copy.push({ name: type, value: 1 });
        }
        return copy;
      });
    }

    // Slide timeline window
    setTimelineData(prev => {
      const nextVal = newLog.prediction === 'Anomaly' ? 1 : 0;
      const copy = [...prev, { timestamp, threats: nextVal }];
      if (copy.length > 15) copy.shift();
      return copy;
    });

    // Slide traffic window
    setTrafficData(prev => {
      const copy = [...prev, { timestamp, count: 1 }];
      if (copy.length > 15) copy.shift();
      return copy;
    });
  };

  // Card Animation Config
  const containerVars = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.05 }
    }
  };

  const itemVars = {
    hidden: { opacity: 0, y: 15 },
    show: { opacity: 1, y: 0, transition: { type: 'spring', stiffness: 100 } }
  };

  const kpis = [
    { title: 'Total Logs', value: stats.total_logs.toLocaleString(), icon: <FiDatabase className="text-cyberBlue" />, glow: 'border-blue-900/30' },
    { title: 'Total Anomalies', value: stats.total_anomalies.toLocaleString(), icon: <FiAlertTriangle className="text-cyberRed" />, glow: 'border-red-900/30 shadow-glowRed/5' },
    { title: 'Failed Requests', value: stats.failed_requests.toLocaleString(), icon: <FiAlertOctagon className="text-cyberYellow" />, glow: 'border-yellow-900/30' },
    { title: 'High Severity Alerts', value: stats.high_severity_alerts.toLocaleString(), icon: <FiShield className="text-cyberRed" />, glow: 'border-red-900/40 shadow-glowRed/10' },
    { title: 'Detection Rate', value: `${stats.detection_rate}%`, icon: <FiActivity className="text-cyberGreen" />, glow: 'border-green-900/30' },
    { title: 'Spark Jobs Run', value: stats.spark_jobs_processed.toLocaleString(), icon: <FiCpu className="text-cyberBlue" />, glow: 'border-blue-900/30' },
    { title: 'Threat Countries', value: stats.threat_countries, icon: <FiGlobe className="text-cyberYellow" />, glow: 'border-yellow-900/30' },
    { title: 'Suspicious IPs', value: stats.suspicious_ips, icon: <FiSearch className="text-cyberGreen" />, glow: 'border-green-900/30' },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="OPERATION CENTRE OVERVIEW" />

        {/* Dashboard Content scroll pane */}
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          
          {loading ? (
            <div className="flex h-full items-center justify-center text-cyberGreen">
              <span className="h-8 w-8 animate-spin rounded-full border-4 border-cardBorder border-t-cyberGreen"></span>
            </div>
          ) : (
            <>
              {/* KPI Cards Grid */}
              <motion.div 
                variants={containerVars}
                initial="hidden"
                animate="show"
                className="grid grid-cols-2 md:grid-cols-4 gap-4"
              >
                {kpis.map((kpi, idx) => (
                  <motion.div
                    key={idx}
                    variants={itemVars}
                    className={`rounded-xl border bg-cardBg p-5 flex items-center justify-between transition-all ${kpi.glow}`}
                  >
                    <div>
                      <p className="text-[10px] uppercase tracking-wider text-gray-500 font-mono font-semibold">{kpi.title}</p>
                      <h3 className="mt-2 text-2xl font-bold text-white font-sans">{kpi.value}</h3>
                    </div>
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-cardBorder text-xl">
                      {kpi.icon}
                    </div>
                  </motion.div>
                ))}
              </motion.div>

              {/* Charts Panel Grid */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Timeline chart */}
                <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 p-5 glass-panel">
                  <h4 className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                    <span className="h-2 w-2 rounded-full bg-cyberRed animate-ping"></span>
                    Threat Timeline Anomaly Frequency
                  </h4>
                  <ThreatTimeline data={timelineData} />
                </div>

                {/* Traffic chart */}
                <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 p-5 glass-panel">
                  <h4 className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                    <FiActivity className="text-cyberBlue" />
                    Network Traffic Flow Volume (Requests / Sec)
                  </h4>
                  <TrafficAreaChart data={trafficData} />
                </div>

                {/* Attack Types Bar Chart */}
                <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 p-5 glass-panel">
                  <h4 className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                    <FiAlertTriangle className="text-cyberYellow" />
                    Classification of Cyberattacks (Scanners vs Exploit)
                  </h4>
                  <AnomalyBarChart data={barData} />
                </div>

                {/* Pie Distribution */}
                <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 p-5 glass-panel">
                  <h4 className="mb-4 text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                    <FiShield className="text-cyberGreen" />
                    Ingested Logs Classification Ratio
                  </h4>
                  <DistributionPieChart data={pieData} />
                </div>
              </div>

              {/* Real-time Streaming console */}
              <div className="rounded-xl border border-cardBorder bg-[#070A10] p-5">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                    <span className="h-2.5 w-2.5 bg-cyberGreen rounded-full animate-ping"></span>
                    Live Streaming SecOps Log Stream
                  </h4>
                  <span className="text-[10px] font-mono text-gray-600 bg-cardBorder px-2.5 py-1 rounded">
                    WebSocket Feed Status: CONNECTED
                  </span>
                </div>

                <div className="overflow-x-auto rounded-lg border border-cardBorder">
                  <table className="w-full text-left text-xs console-font">
                    <thead className="bg-cardBg text-gray-500 uppercase tracking-widest text-[10px] border-b border-cardBorder">
                      <tr>
                        <th className="py-3 px-4">Timestamp</th>
                        <th className="py-3 px-4">Origin IP</th>
                        <th className="py-3 px-4">Method</th>
                        <th className="py-3 px-4">URL</th>
                        <th className="py-3 px-4">HTTP</th>
                        <th className="py-3 px-4">Severity</th>
                        <th className="py-3 px-4 text-right">Verdict</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-cardBorder/40">
                      {liveLogs.map((log, idx) => {
                        const isAnom = log.prediction === 'Anomaly';
                        const severityColors = {
                          Low: 'text-gray-400',
                          Medium: 'text-cyberYellow',
                          High: 'text-cyberRed font-bold',
                          Critical: 'text-cyberRed font-bold animate-pulse',
                        };

                        return (
                          <motion.tr
                            key={idx}
                            initial={{ opacity: 0, x: -10 }}
                            animate={{ opacity: 1, x: 0 }}
                            className={`hover:bg-cardBg/30 ${isAnom ? 'bg-red-950/5' : ''}`}
                          >
                            <td className="py-2.5 px-4 text-gray-500">
                              {(() => {
                                const ts = log.timestamp;
                                if (typeof ts !== 'string') return 'Unknown';
                                return ts.includes('T') ? ts.split('T')[1]?.substring(0, 8) : ts;
                              })()}
                            </td>
                            <td className="py-2.5 px-4 font-semibold text-gray-300">{log.ip}</td>
                            <td className="py-2.5 px-4"><span className="text-cyberBlue">{log.method}</span></td>
                            <td className="py-2.5 px-4 text-gray-400 truncate max-w-xs">{log.url}</td>
                            <td className="py-2.5 px-4">
                              <span className={log.status >= 400 ? 'text-cyberRed' : 'text-cyberGreen'}>
                                {log.status}
                              </span>
                            </td>
                            <td className="py-2.5 px-4">
                              <span className={`text-[10px] uppercase font-mono ${severityColors[log.threat_severity] || 'text-gray-400'}`}>
                                {log.threat_severity}
                              </span>
                            </td>
                            <td className="py-2.5 px-4 text-right">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                isAnom ? 'bg-cyberRed/20 text-cyberRed border border-cyberRed/30' : 'bg-cyberGreen/20 text-cyberGreen border border-cyberGreen/30'
                              }`}>
                                {log.prediction}
                              </span>
                            </td>
                          </motion.tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </main>
      </div>
    </div>
  );
};

export default Dashboard;
