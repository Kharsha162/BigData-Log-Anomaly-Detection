import React from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const ThreatTimeline = ({ data }) => {
  // Format timestamps for display (e.g. HH:MM:SS)
  const formatData = data.map(item => {
    try {
      const timeStr = item.timestamp.split('T')[1]?.substring(0, 8) || item.timestamp;
      return {
        ...item,
        time: timeStr
      };
    } catch {
      return { ...item, time: item.timestamp };
    }
  });

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart
          data={formatData}
          margin={{ top: 10, right: 10, left: -20, bottom: 0 }}
        >
          <defs>
            <linearGradient id="colorThreat" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#FF3366" stopOpacity={0.4}/>
              <stop offset="95%" stopColor="#FF3366" stopOpacity={0}/>
            </linearGradient>
          </defs>
          <CartesianGrid strokeDasharray="3 3" stroke="#1F2A37" />
          <XAxis 
            dataKey="time" 
            stroke="#9CA3AF" 
            tick={{ fill: '#9CA3AF', fontSize: 10 }}
            dy={10}
          />
          <YAxis 
            stroke="#9CA3AF" 
            tick={{ fill: '#9CA3AF', fontSize: 10 }}
            dx={-5}
          />
          <Tooltip
            contentStyle={{ backgroundColor: '#0C111D', borderColor: '#1F2A37', borderRadius: '8px' }}
            labelStyle={{ color: '#E5E7EB', fontWeight: 'bold' }}
            itemStyle={{ color: '#FF3366' }}
          />
          <Area 
            type="monotone" 
            dataKey="threats" 
            stroke="#FF3366" 
            fillOpacity={1} 
            fill="url(#colorThreat)" 
            strokeWidth={2}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
};

export default ThreatTimeline;
