import React from 'react';
import { 
  ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, 
  BarChart, Bar, Cell, PieChart, Pie, Legend 
} from 'recharts';

const SparkCharts = ({ aggregations }) => {
  // Safe extraction of aggregations
  const requestTrends = aggregations?.request_trends || [];
  const statusCounts = aggregations?.status_counts || [];
  const topAttackers = aggregations?.top_attackers || [];
  const endpointAnalytics = aggregations?.endpoint_analytics || [];
  const severityDistribution = aggregations?.severity_distribution || { Normal: 0, Suspicious: 0, "High Threat": 0, Critical: 0 };
  const anomalyCounts = aggregations?.anomaly_counts || { Normal: 0, Anomaly: 0 };

  // Theme Colors
  const colors = {
    cyberGreen: '#00F0FF', // Wait, let's look at the colors. In existing, cyberGreen is usually neon green like '#10B981', let's use standard hexes.
    cyan: '#06B6D4',
    green: '#10B981',
    yellow: '#F59E0B',
    red: '#EF4444',
    purple: '#8B5CF6',
    gray: '#6B7280'
  };

  const chartColors = {
    normal: '#10B981', // Green
    suspicious: '#F59E0B', // Yellow
    high: '#EF4444', // Red
    critical: '#8B5CF6' // Purple
  };

  // 1. Format Severity data for Pie Chart
  const severityData = [
    { name: 'Normal', value: severityDistribution.Normal || 0, color: chartColors.normal },
    { name: 'Suspicious', value: severityDistribution.Suspicious || 0, color: chartColors.suspicious },
    { name: 'High Threat', value: severityDistribution["High Threat"] || 0, color: chartColors.high },
    { name: 'Critical', value: severityDistribution.Critical || 0, color: chartColors.critical }
  ].filter(item => item.value > 0);

  // 2. Format Anomaly Trend Data
  const anomalyData = [
    { name: 'Normal', value: anomalyCounts.Normal || 0, color: '#10B981' },
    { name: 'Anomaly', value: anomalyCounts.Anomaly || 0, color: '#EF4444' }
  ];

  // 3. Format Status Code Data
  const statusData = statusCounts.map(item => ({
    name: String(item.status),
    count: item.count,
    color: item.status >= 400 ? '#EF4444' : '#10B981'
  }));

  // 4. Format Attacker Data
  const attackerData = topAttackers.map(item => ({
    ip: item.ip,
    count: item.count
  }));

  // 5. Format Endpoint Data
  const endpointData = endpointAnalytics.map(item => ({
    url: item.endpoint.length > 25 ? `${item.endpoint.substring(0, 25)}...` : item.endpoint,
    count: item.count
  }));

  // Custom tooltips
  const CustomTooltip = ({ active, payload }) => {
    if (active && payload && payload.length) {
      return (
        <div className="bg-[#0C111D] border border-cardBorder p-2.5 rounded-lg font-mono text-[10px] text-gray-300">
          <p className="text-white font-bold">{payload[0].name || payload[0].payload.ip || payload[0].payload.url || 'Log Count'}</p>
          <p className="mt-1 flex items-center gap-1">
            <span>Requests:</span>
            <span className="text-cyberGreen font-bold font-mono">{payload[0].value}</span>
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6 w-full">

      {/* Ingestion Timeline Chart */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          Spark Ingestion Timeline (Micro-Batches)
        </h3>
        <div className="w-full h-60 min-h-[240px]">
          {requestTrends.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
              Awaiting Spark pipeline ingestion...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={requestTrends} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorTrends" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#06B6D4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#4B5563" fontSize={9} tickLine={false} />
                <YAxis stroke="#4B5563" fontSize={9} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Area type="monotone" dataKey="count" stroke="#06B6D4" strokeWidth={1.5} fillOpacity={1} fill="url(#colorTrends)" />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Anomaly Breakdown Bar */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          ML Classifier Verdict Breakdown
        </h3>
        <div className="w-full h-60 min-h-[240px]">
          {anomalyData.every(item => item.value === 0) ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
              Awaiting Spark pipeline ingestion...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={anomalyData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#4B5563" fontSize={9} tickLine={false} />
                <YAxis stroke="#4B5563" fontSize={9} tickLine={false} />
                <Tooltip content={<CustomTooltip />} />
                <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                  {anomalyData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Threat Severity Pie/Donut Chart */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          SecOps Incident Severity Distribution
        </h3>
        <div className="w-full h-60 min-h-[240px] flex items-center justify-center">
          {severityData.length === 0 ? (
            <div className="text-xs font-mono text-gray-600">
              Awaiting Spark pipeline ingestion...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend 
                  verticalAlign="bottom" 
                  height={36} 
                  iconType="circle"
                  formatter={(value) => <span className="text-[10px] font-mono text-gray-400">{value}</span>}
                />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Top Attacker IP Address Chart */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          Top Attacker IPs (Spark Analyzed)
        </h3>
        <div className="w-full h-60 min-h-[240px]">
          {attackerData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
              No anomalies detected in active dataset.
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={attackerData} layout="vertical" margin={{ top: 10, right: 10, left: 15, bottom: 0 }}>
                <XAxis type="number" stroke="#4B5563" fontSize={9} tickLine={false} />
                <YAxis dataKey="ip" type="category" stroke="#4B5563" fontSize={9} tickLine={false} width={85} />
                <Tooltip />
                <Bar dataKey="count" fill="#EF4444" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* HTTP Status Code Distribution */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          Status Code Aggregation Frequency
        </h3>
        <div className="w-full h-60 min-h-[240px]">
          {statusData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
              Awaiting Spark pipeline ingestion...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={statusData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#4B5563" fontSize={9} tickLine={false} />
                <YAxis stroke="#4B5563" fontSize={9} tickLine={false} />
                <Tooltip />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {statusData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Requested Endpoints */}
      <div className="rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4">
        <h3 className="text-[10px] font-bold uppercase tracking-widest text-gray-500 font-mono">
          Resource URL Target Frequency
        </h3>
        <div className="w-full h-60 min-h-[240px]">
          {endpointData.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs font-mono text-gray-600">
              Awaiting Spark pipeline ingestion...
            </div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={endpointData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="url" stroke="#4B5563" fontSize={8} tickLine={false} interval={0} height={40} angle={-15} textAnchor="end" />
                <YAxis stroke="#4B5563" fontSize={9} tickLine={false} />
                <Tooltip />
                <Bar dataKey="count" fill="#8B5CF6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

    </div>
  );
};

export default SparkCharts;
