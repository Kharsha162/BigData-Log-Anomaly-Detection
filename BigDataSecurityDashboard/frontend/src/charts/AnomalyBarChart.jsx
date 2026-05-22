import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const AnomalyBarChart = ({ data }) => {
  // Pastel neon colors for bar categories
  const COLORS = ['#FF3366', '#FFCC00', '#33CCFF', '#00FF66', '#8B5CF6'];

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart
          data={data}
          margin={{ top: 10, right: 10, left: -20, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1F2A37" />
          <XAxis 
            dataKey="name" 
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
            itemStyle={{ color: '#00FF66' }}
          />
          <Bar dataKey="value" fill="#00FF66" radius={[4, 4, 0, 0]}>
            {data.map((entry, index) => (
              <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
};

export default AnomalyBarChart;
