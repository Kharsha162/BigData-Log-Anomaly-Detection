import React, { useState, useEffect } from 'react';
import { 
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  BarChart, Bar, PieChart, Pie, Cell, Legend
} from 'recharts';
import { FiTrendingUp, FiGlobe, FiPieChart, FiAlertOctagon, FiZap, FiCpu, FiHardDrive, FiActivity, FiAlertCircle } from 'react-icons/fi';
import { sparkApi } from '../services/api';

const ThreatMapSidebar = ({ threats, selectedThreat }) => {
  const [activeTab, setActiveTab] = useState('timeline');
  const [sparkMetrics, setSparkMetrics] = useState(null);
  const [sparkLoading, setSparkLoading] = useState(true);

  useEffect(() => {
    if (selectedThreat) {
      setActiveTab('investigate');
    }
  }, [selectedThreat]);

  // Poll Spark metrics every 5 seconds for live analytics
  useEffect(() => {
    let active = true;
    const fetchSpark = async () => {
      try {
        const data = await sparkApi.getMetrics();
        if (active) {
          setSparkMetrics(data);
          setSparkLoading(false);
        }
      } catch (err) {
        console.error("Failed to load spark telemetry:", err);
      }
    };
    fetchSpark();
    const interval = setInterval(fetchSpark, 5000);
    return () => {
      active = false;
      clearInterval(interval);
    };
  }, []);

  // 1. Prepare Attack Timeline Data
  const getTimelineData = () => {
    const timelineCounts = {};
    threats.forEach(t => {
      // Extract hour e.g. 10:00
      let timeKey = "00:00";
      const ts = t.timestamp;
      if (typeof ts === 'string') {
        if (ts.includes('T')) {
          timeKey = ts.split('T')[1].substring(0, 5); // HH:MM
        } else if (ts.includes(':')) {
          const parts = ts.split(':');
          timeKey = `${parts[1]}:00`; // e.g. Oct 21/May/2026:10:00:00 -> 10:00
        }
      }
      timelineCounts[timeKey] = (timelineCounts[timeKey] || 0) + 1;
    });

    return Object.keys(timelineCounts)
      .sort()
      .map(key => ({
        time: key,
        count: timelineCounts[key]
      }))
      .slice(-12); // Show recent 12 data points
  };

  // 2. Prepare Top Attacker Countries Data
  const getCountriesData = () => {
    const countryCounts = {};
    threats.forEach(t => {
      if (t.country && t.country !== 'Unknown') {
        countryCounts[t.country] = (countryCounts[t.country] || 0) + 1;
      }
    });

    return Object.keys(countryCounts)
      .map(key => ({
        name: key,
        attacks: countryCounts[key]
      }))
      .sort((a, b) => b.attacks - a.attacks)
      .slice(0, 5); // Top 5
  };

  // 3. Prepare Threat Severity Distribution Data
  const getSeverityData = () => {
    const counts = { "Normal": 0, "Suspicious": 0, "High Threat": 0, "Critical": 0 };
    threats.forEach(t => {
      if (counts[t.threat_severity] !== undefined) {
        counts[t.threat_severity]++;
      } else {
        counts["Normal"]++;
      }
    });

    return Object.keys(counts).map(key => ({
      name: key,
      value: counts[key]
    })).filter(item => item.value > 0);
  };

  // 4. Prepare Status Code Data
  const getStatusCodeData = () => {
    const codeCounts = {};
    threats.forEach(t => {
      const code = t.status || 200;
      codeCounts[code] = (codeCounts[code] || 0) + 1;
    });

    return Object.keys(codeCounts).map(key => ({
      code: `HTTP ${key}`,
      count: codeCounts[key]
    })).sort((a, b) => b.count - a.count);
  };

  // Color mapping
  const SEVERITY_COLORS = {
    "Normal": "#10B981",       // Green
    "Suspicious": "#F59E0B",   // Orange
    "High Threat": "#EF4444",  // Red
    "Critical": "#8B5CF6"      // Purple
  };

  const chartTabs = [
    ...(selectedThreat ? [{ id: 'investigate', label: 'Investigate', icon: <FiActivity className="text-cyberBlue animate-pulse" /> }] : []),
    { id: 'timeline', label: 'Timeline', icon: <FiTrendingUp /> },
    { id: 'countries', label: 'Countries', icon: <FiGlobe /> },
    { id: 'severity', label: 'Severity', icon: <FiPieChart /> },
    { id: 'status', label: 'HTTP Codes', icon: <FiAlertOctagon /> },
    { id: 'spark', label: 'Spark', icon: <FiZap className="animate-pulse" /> }
  ];

  return (
    <div className="rounded-xl border border-cardBorder bg-[#0C111D]/90 backdrop-blur-md p-4 flex flex-col h-full min-h-[350px]">
      {/* Visual Navigation Tabs */}
      <div className="flex border-b border-cardBorder/40 pb-2 mb-4 justify-between">
        {chartTabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1 px-2 py-1.5 rounded text-[10px] font-bold font-mono uppercase transition ${
              activeTab === tab.id
                ? 'bg-cyberBlue/10 text-cyberBlue border border-cyberBlue/25'
                : 'text-gray-500 hover:text-white'
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Render Chart Panel */}
      <div className="flex-1 w-full min-h-[220px]">
        {activeTab === 'investigate' && selectedThreat && (
          <div className="h-full w-full flex flex-col justify-between font-mono text-xs">
            <div>
              <div className="flex items-center justify-between mb-3 border-b border-cardBorder/40 pb-2">
                <h4 className="text-[10px] font-bold uppercase tracking-wider text-cyberBlue flex items-center gap-1.5">
                  <FiActivity className="animate-pulse text-cyberRed text-xs" />
                  Live Host Investigation
                </h4>
                <span className="text-[9px] text-gray-500">
                  {selectedThreat.timestamp && typeof selectedThreat.timestamp === 'string'
                    ? (selectedThreat.timestamp.includes('T') ? selectedThreat.timestamp.split('T')[0] : selectedThreat.timestamp)
                    : 'Unknown Time'}
                </span>
              </div>

              <div className="space-y-3">
                <div className="bg-[#05070C] p-2.5 rounded-lg border border-cardBorder flex items-center justify-between">
                  <div>
                    <span className="text-[8px] text-gray-500 block uppercase font-bold">Investigated Host</span>
                    <span className="text-sm font-bold text-white tracking-wide">{selectedThreat.ip}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-[8px] text-gray-500 block uppercase font-bold">Country Origin</span>
                    <span className="text-xs font-bold text-cyberBlue flex items-center gap-1 justify-end">
                      <FiGlobe className="text-[10px]" />
                      {selectedThreat.country || 'Unknown'}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2.5">
                  <div className="bg-[#05070C] p-2 rounded border border-cardBorder">
                    <span className="text-[8px] text-gray-500 block uppercase font-bold">Threat Severity</span>
                    <span className={`text-[10px] font-bold block mt-0.5 uppercase ${
                      selectedThreat.threat_severity === 'Critical' ? 'text-purple-400' :
                      selectedThreat.threat_severity === 'High Threat' ? 'text-cyberRed' :
                      selectedThreat.threat_severity === 'Suspicious' ? 'text-cyberYellow' : 'text-cyberGreen'
                    }`}>
                      {selectedThreat.threat_severity || 'Normal'}
                    </span>
                  </div>
                  <div className="bg-[#05070C] p-2 rounded border border-cardBorder">
                    <span className="text-[8px] text-gray-500 block uppercase font-bold">Confidence Scale</span>
                    <span className="text-[10px] font-bold text-white block mt-0.5">
                      {(() => {
                        const score = parseFloat(selectedThreat.anomaly_score);
                        return (isNaN(score) ? 90.0 : score * 100).toFixed(1);
                      })()}%
                    </span>
                  </div>
                </div>

                <div className="bg-[#05070C] p-2.5 rounded border border-cardBorder space-y-1.5 text-[10px] text-gray-400">
                  <div className="flex justify-between border-b border-cardBorder/30 pb-1">
                    <span>Attack Signature:</span>
                    <span className="text-white font-bold max-w-[130px] truncate" title={selectedThreat.threat_type}>{selectedThreat.threat_type || 'Unknown'}</span>
                  </div>
                  <div className="flex justify-between border-b border-cardBorder/30 pb-1">
                    <span>ISP Transit Core:</span>
                    <span className="text-white font-bold max-w-[130px] truncate" title={selectedThreat.isp}>{selectedThreat.isp || 'Local Loop'}</span>
                  </div>
                  <div className="flex justify-between border-b border-cardBorder/30 pb-1">
                    <span>Location Lat/Lon:</span>
                    <span className="text-white font-bold">
                      {selectedThreat.latitude !== undefined && selectedThreat.latitude !== null && !isNaN(parseFloat(selectedThreat.latitude))
                        ? parseFloat(selectedThreat.latitude).toFixed(4)
                        : '0.0000'}
                      ,{' '}
                      {selectedThreat.longitude !== undefined && selectedThreat.longitude !== null && !isNaN(parseFloat(selectedThreat.longitude))
                        ? parseFloat(selectedThreat.longitude).toFixed(4)
                        : '0.0000'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span>City Node:</span>
                    <span className="text-white font-bold">{selectedThreat.city || 'Chennai Hub'}</span>
                  </div>
                </div>

                <div className="space-y-1">
                  <span className="text-[8px] text-gray-500 uppercase font-bold block">Audited Request Payload</span>
                  <div className="p-2 rounded bg-[#05070C] border border-cardBorder text-[9px] text-gray-400 overflow-x-auto select-all whitespace-nowrap scrollbar-none font-mono">
                    <span className="font-bold text-cyberBlue">{selectedThreat.method || 'GET'}</span> {selectedThreat.url || '/'}
                  </div>
                </div>
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-cardBorder/40 bg-cyberRed/5 border-dashed border p-2.5 rounded-lg flex items-center gap-2">
              <FiAlertCircle className="text-cyberRed text-lg animate-pulse shrink-0" />
              <div>
                <span className="text-[8px] text-cyberRed uppercase font-bold block">Automated Recommendation</span>
                <span className="text-[9px] text-gray-400 block leading-tight">
                  High-frequency anomalies detected. Recommend WAF edge blockage for AS Transit.
                </span>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'timeline' && (
          <div className="h-full w-full">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono mb-2">
              Anomaly Capture Timeline
            </h4>
            <div className="h-[200px] w-full text-xs">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={getTimelineData()} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorTimeline" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00E5FF" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00E5FF" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <YAxis stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#05070C', borderColor: '#1F2937', color: '#FFF', fontSize: 10, fontFamily: 'monospace' }}
                    labelStyle={{ color: '#00E5FF', fontWeight: 'bold' }}
                  />
                  <Area type="monotone" dataKey="count" stroke="#00E5FF" strokeWidth={2} fillOpacity={1} fill="url(#colorTimeline)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {activeTab === 'countries' && (
          <div className="h-full w-full">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono mb-2">
              Top Incident Geolocation Sources
            </h4>
            <div className="h-[200px] w-full text-xs">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={getCountriesData()} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <XAxis dataKey="name" stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <YAxis stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#05070C', borderColor: '#1F2937', color: '#FFF', fontSize: 10, fontFamily: 'monospace' }}
                    labelStyle={{ color: '#F59E0B', fontWeight: 'bold' }}
                    cursor={{ fill: '#1F2937', opacity: 0.2 }}
                  />
                  <Bar dataKey="attacks" fill="#F59E0B" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {activeTab === 'severity' && (
          <div className="h-full w-full">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono mb-2">
              Incident Risk Stratification
            </h4>
            <div className="h-[200px] w-full flex items-center justify-center">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={getSeverityData()}
                    cx="50%"
                    cy="45%"
                    innerRadius={45}
                    outerRadius={65}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {getSeverityData().map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={SEVERITY_COLORS[entry.name] || '#9CA3AF'} />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#05070C', borderColor: '#1F2937', color: '#FFF', fontSize: 10, fontFamily: 'monospace' }}
                  />
                  <Legend 
                    layout="horizontal" 
                    verticalAlign="bottom" 
                    align="center"
                    iconSize={8}
                    wrapperStyle={{ fontSize: 8, fontFamily: 'monospace', color: '#9CA3AF', paddingTop: 10 }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {activeTab === 'status' && (
          <div className="h-full w-full">
            <h4 className="text-[10px] font-bold uppercase tracking-wider text-gray-400 font-mono mb-2">
              HTTP Code Signature Profile
            </h4>
            <div className="h-[200px] w-full text-xs">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={getStatusCodeData()} margin={{ top: 10, right: 10, left: -25, bottom: 5 }}>
                  <XAxis dataKey="code" stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <YAxis stroke="#4B5563" tickLine={false} style={{ fontSize: 9, fontFamily: 'monospace' }} />
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#05070C', borderColor: '#1F2937', color: '#FFF', fontSize: 10, fontFamily: 'monospace' }}
                    labelStyle={{ color: '#EF4444', fontWeight: 'bold' }}
                    cursor={{ fill: '#1F2937', opacity: 0.2 }}
                  />
                  <Bar dataKey="count" fill="#EF4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}

        {activeTab === 'spark' && (
          <div className="h-full w-full flex flex-col justify-between">
            <div>
              <h4 className="text-[10px] font-bold uppercase tracking-wider text-cyberBlue font-mono mb-2 flex items-center gap-1">
                <FiZap />
                Spark Cluster RDD Telemetry
              </h4>
              
              {sparkLoading || !sparkMetrics ? (
                <div className="flex h-24 items-center justify-center text-cyberBlue">
                  <span className="h-5 w-5 animate-spin rounded-full border-2 border-cardBorder border-t-cyberBlue"></span>
                </div>
              ) : (
                <div className="space-y-3 font-mono text-[11px] text-gray-400">
                  <div className="bg-[#05070C] p-2 rounded border border-cardBorder">
                    <span className="text-[9px] text-gray-500 block uppercase">Processing Core Engine</span>
                    <span className="font-bold text-white uppercase">{sparkMetrics.engine_type}</span>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px]">
                      <span>CPU LOAD:</span>
                      <span className="text-cyberRed font-bold">{sparkMetrics.cpu_utilization_pct.toFixed(1)}%</span>
                    </div>
                    <div className="h-1.5 w-full bg-cardBorder rounded overflow-hidden">
                      <div className="h-full bg-cyberRed" style={{ width: `${sparkMetrics.cpu_utilization_pct}%` }}></div>
                    </div>
                  </div>

                  <div className="space-y-1">
                    <div className="flex justify-between text-[10px]">
                      <span>CLUSTER RAM:</span>
                      <span className="text-cyberYellow font-bold">{sparkMetrics.memory_used_gb.toFixed(1)} / {sparkMetrics.total_memory_gb.toFixed(1)} GB</span>
                    </div>
                    <div className="h-1.5 w-full bg-cardBorder rounded overflow-hidden">
                      <div className="h-full bg-cyberYellow" style={{ width: `${(sparkMetrics.memory_used_gb / sparkMetrics.total_memory_gb) * 100}%` }}></div>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[10px]">
                    <div className="bg-[#05070C] p-1.5 rounded border border-cardBorder">
                      <span className="text-gray-500 block uppercase">Workers</span>
                      <span className="font-bold text-white">{sparkMetrics.active_workers} Cores</span>
                    </div>
                    <div className="bg-[#05070C] p-1.5 rounded border border-cardBorder">
                      <span className="text-gray-500 block uppercase">Jobs Run</span>
                      <span className="font-bold text-white">{sparkMetrics.total_jobs_run} Batches</span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ThreatMapSidebar;
