import React, { useRef } from 'react';
import { FiSearch, FiSliders, FiDownload, FiPlay, FiSquare, FiUploadCloud } from 'react-icons/fi';

const ThreatFilters = ({
  filters,
  setFilters,
  countries,
  onUpload,
  uploading,
  simulationRunning,
  toggleSimulation,
  onExportCSV
}) => {
  const fileInputRef = useRef(null);

  const handleFilterChange = (key, value) => {
    setFilters(prev => ({
      ...prev,
      [key]: value
    }));
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      onUpload(file);
    }
  };

  return (
    <div className="rounded-xl border border-cardBorder bg-[#0C111D]/90 backdrop-blur-md p-5 space-y-4">
      {/* Header section with tools */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-cardBorder/40 pb-4">
        <h3 className="text-xs font-semibold uppercase tracking-wider text-white font-mono flex items-center gap-2">
          <FiSliders className="text-cyberGreen" />
          Filter Matrix & Control Center
        </h3>
        
        {/* Quick actions: CSV & Simulation Controls */}
        <div className="flex flex-wrap items-center gap-2">
          <button
            onClick={toggleSimulation}
            className={`px-3 py-1.5 rounded text-[11px] font-bold font-mono uppercase tracking-wider flex items-center gap-1.5 transition ${
              simulationRunning
                ? 'bg-cyberRed/20 text-cyberRed border border-cyberRed/30 hover:bg-cyberRed/30'
                : 'bg-cyberGreen/20 text-cyberGreen border border-cyberGreen/30 hover:bg-cyberGreen/30'
            }`}
          >
            {simulationRunning ? (
              <>
                <FiSquare className="text-xs animate-pulse" />
                <span>Stop Simulation</span>
              </>
            ) : (
              <>
                <FiPlay className="text-xs" />
                <span>Start Simulation</span>
              </>
            )}
          </button>

          <button
            onClick={onExportCSV}
            className="px-3 py-1.5 rounded bg-cardBorder text-gray-300 border border-cardBorder/60 hover:text-white hover:bg-cardBorder/80 text-[11px] font-mono flex items-center gap-1.5 transition"
          >
            <FiDownload className="text-xs" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Grid containing filters */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {/* 1. File Upload Box */}
        <div className="sm:col-span-2 lg:col-span-2">
          <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
            Log Ingestion Upload
          </label>
          <div 
            onClick={() => fileInputRef.current?.click()}
            className="group relative flex items-center justify-center border border-dashed border-cardBorder rounded-lg bg-[#05070C] p-3 text-center cursor-pointer hover:border-cyberGreen transition duration-200"
          >
            <input 
              type="file" 
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".log,.txt,.csv"
              className="hidden"
            />
            {uploading ? (
              <div className="flex items-center gap-2 text-cyberGreen font-mono text-[11px]">
                <span className="h-3 w-3 animate-spin rounded-full border border-t-transparent border-cyberGreen"></span>
                <span>Ingesting logs...</span>
              </div>
            ) : (
              <div className="flex items-center gap-2 text-gray-400 group-hover:text-cyberGreen font-mono text-[11px]">
                <FiUploadCloud className="text-lg group-hover:scale-110 transition duration-200 text-cyberBlue" />
                <span className="truncate">Upload Apache log file</span>
              </div>
            )}
          </div>
        </div>

        {/* 2. Attacker IP Search */}
        <div>
          <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
            Attacker IP Search
          </label>
          <div className="relative">
            <input
              type="text"
              value={filters.ip}
              onChange={(e) => handleFilterChange('ip', e.target.value)}
              placeholder="e.g. 185.220..."
              className="w-full pl-8 pr-3 py-1.5 rounded-lg border border-cardBorder bg-[#05070C] text-xs font-mono text-white placeholder-gray-700 outline-none focus:border-cyberGreen transition"
            />
            <FiSearch className="absolute left-2.5 top-2.5 text-gray-600 text-xs" />
          </div>
        </div>

        {/* 3. Attack URL Search */}
        <div>
          <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
            Attack URL Search
          </label>
          <div className="relative">
            <input
              type="text"
              value={filters.url}
              onChange={(e) => handleFilterChange('url', e.target.value)}
              placeholder="e.g. /etc/passwd"
              className="w-full pl-8 pr-3 py-1.5 rounded-lg border border-cardBorder bg-[#05070C] text-xs font-mono text-white placeholder-gray-700 outline-none focus:border-cyberGreen transition"
            />
            <FiSearch className="absolute left-2.5 top-2.5 text-gray-600 text-xs" />
          </div>
        </div>

        {/* 4. Threat Severity */}
        <div>
          <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
            Threat Severity
          </label>
          <select
            value={filters.severity}
            onChange={(e) => handleFilterChange('severity', e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg border border-cardBorder bg-[#05070C] text-xs font-mono text-white outline-none focus:border-cyberGreen cursor-pointer transition"
          >
            <option value="">All Severities</option>
            <option value="Normal">Normal (Green)</option>
            <option value="Suspicious">Suspicious (Orange)</option>
            <option value="High Threat">High Threat (Red)</option>
            <option value="Critical">Critical (Purple)</option>
          </select>
        </div>

        {/* 5. Country Dropdown */}
        <div>
          <label className="block text-[10px] uppercase font-mono tracking-wider text-gray-500 mb-1.5">
            Origin Country
          </label>
          <select
            value={filters.country}
            onChange={(e) => handleFilterChange('country', e.target.value)}
            className="w-full px-3 py-1.5 rounded-lg border border-cardBorder bg-[#05070C] text-xs font-mono text-white outline-none focus:border-cyberGreen cursor-pointer transition"
          >
            <option value="">All Countries</option>
            {countries.map((c, idx) => (
              <option key={idx} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
      </div>
      
      {/* 6. Time Range quick tabs */}
      <div className="flex items-center gap-3 pt-2 border-t border-cardBorder/20 text-xs font-mono">
        <span className="text-[10px] text-gray-500 uppercase font-semibold">Incident Timeframe:</span>
        <div className="flex gap-1.5">
          {[
            { id: '', name: 'All Time' },
            { id: '1h', name: 'Last 1 Hour' },
            { id: '24h', name: 'Last 24 Hours' },
            { id: '7d', name: 'Last 7 Days' }
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => handleFilterChange('time_range', t.id)}
              className={`px-2.5 py-1 rounded text-[10px] transition ${
                filters.time_range === t.id
                  ? 'bg-cyberGreen text-darkBg font-bold'
                  : 'bg-cardBorder/50 text-gray-400 hover:bg-cardBorder hover:text-white'
              }`}
            >
              {t.name}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ThreatFilters;
