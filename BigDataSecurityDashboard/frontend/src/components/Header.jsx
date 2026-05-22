import React, { useState, useEffect } from 'react';
import { FiClock, FiActivity, FiUser, FiBell } from 'react-icons/fi';
import { logsApi } from '../services/api';

const Header = ({ title }) => {
  const [time, setTime] = useState(new Date());
  const [sysStatus, setSysStatus] = useState({ label: 'SECURE', color: 'bg-cyberGreen' });

  // Dynamic Clock
  useEffect(() => {
    const timer = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  // Poll status occasionally to update header indicators
  useEffect(() => {
    const fetchStatus = async () => {
      try {
        const stats = await logsApi.getStats();
        if (stats.system_status === 'CRITICAL') {
          setSysStatus({ label: 'CRITICAL', color: 'bg-cyberRed animate-pulse' });
        } else if (stats.system_status === 'WARNING') {
          setSysStatus({ label: 'WARNING', color: 'bg-cyberYellow' });
        } else {
          setSysStatus({ label: 'SECURE', color: 'bg-cyberGreen' });
        }
      } catch (err) {
        console.error('Error fetching statistics for header:', err);
      }
    };
    
    fetchStatus();
    const interval = setInterval(fetchStatus, 15000); // 15 seconds
    return () => clearInterval(interval);
  }, []);

  const formatDate = (date) => {
    const pad = (num) => String(num).padStart(2, '0');
    const year = date.getFullYear();
    const month = pad(date.getMonth() + 1);
    const day = pad(date.getDate());
    const hours = pad(date.getHours());
    const minutes = pad(date.getMinutes());
    const seconds = pad(date.getSeconds());
    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  };

  return (
    <header className="flex h-16 w-full items-center justify-between border-b border-cardBorder bg-[#0C111D]/80 px-6 backdrop-blur-md z-10">
      {/* Title */}
      <div>
        <h1 className="text-xl font-bold tracking-tight text-white">{title || 'Dashboard'}</h1>
      </div>

      {/* Right Telemetry */}
      <div className="flex items-center gap-6 text-sm text-gray-400 font-mono">
        {/* Dynamic Clock */}
        <div className="flex items-center gap-2 bg-[#172033] px-3 py-1.5 rounded border border-cardBorder">
          <FiClock className="text-cyberBlue" />
          <span className="text-gray-200">{formatDate(time)}</span>
        </div>

        {/* Security Health status */}
        <div className="flex items-center gap-2 bg-[#172033] px-3 py-1.5 rounded border border-cardBorder">
          <FiActivity className="text-cyberGreen" />
          <span className="text-gray-300">SYSTEM:</span>
          <div className="flex items-center gap-1.5">
            <span className={`h-2.5 w-2.5 rounded-full ${sysStatus.color}`}></span>
            <span className="font-bold text-white text-xs">{sysStatus.label}</span>
          </div>
        </div>

        {/* User profile */}
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-full bg-cardBorder text-gray-200">
            <FiUser className="text-base text-cyberBlue" />
          </div>
          <div className="hidden flex-col md:flex">
            <span className="text-xs font-semibold text-white font-sans">SecOps Administrator</span>
            <span className="text-[10px] text-gray-500 uppercase font-mono">Role: ROOT</span>
          </div>
        </div>
      </div>
    </header>
  );
};

export default Header;
