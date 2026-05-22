import React from 'react';
import { FiSearch, FiSliders, FiDownload, FiTrash2 } from 'react-icons/fi';

const SparkFilters = ({
  searchIp,
  setSearchIp,
  searchUrl,
  setSearchUrl,
  statusCode,
  setStatusCode,
  severityFilter,
  setSeverityFilter,
  timeRange,
  setTimeRange,
  onClearFilters,
  onExportCsv,
  onExportJson,
  recordCount = 0
}) => {
  const statusCodes = [
    { value: '', label: 'All Status' },
    { value: '200', label: '200 OK' },
    { value: '304', label: '304 Not Modified' },
    { value: '400', label: '400 Bad Request' },
    { value: '401', label: '401 Unauthorized' },
    { value: '403', label: '403 Forbidden' },
    { value: '404', label: '404 Not Found' },
    { value: '500', label: '500 Server Error' }
  ];

  const severities = [
    { value: '', label: 'All Severities' },
    { value: 'Normal', label: 'Normal / Benign' },
    { value: 'Suspicious', label: 'Suspicious' },
    { value: 'High Threat', label: 'High Threat' },
    { value: 'Critical', label: 'Critical / Breach' }
  ];

  const timeRanges = [
    { value: 'all', label: 'All History' },
    { value: '1h', label: 'Past 1 Hr' },
    { value: '6h', label: 'Past 6 Hrs' },
    { value: '24h', label: 'Past 24 Hrs' }
  ];

  return (
    <div className="w-full rounded-2xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4 shadow-xl transition-all duration-300">
      
      {/* Top row: Section title & Exports */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 border-b border-cardBorder/50 pb-3">
        <div className="flex items-center gap-2">
          <FiSliders className="text-cyberBlue text-lg" />
          <h2 className="font-mono text-xs uppercase tracking-widest text-white font-bold">
            Real-Time Spark Filtering Engine
          </h2>
          <span className="bg-cyberBlue/10 border border-cyberBlue/20 text-cyberBlue font-mono text-[9px] px-2 py-0.5 rounded-full font-semibold">
            {recordCount.toLocaleString()} Records Active
          </span>
        </div>

        {/* Download Buttons */}
        <div className="flex items-center gap-2 self-end sm:self-auto">
          <button
            type="button"
            onClick={onExportCsv}
            disabled={recordCount === 0}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border font-mono text-[10px] uppercase font-bold transition-all duration-200 ${
              recordCount === 0
                ? 'bg-cardBorder/30 border-cardBorder/50 text-gray-600 cursor-not-allowed'
                : 'bg-cardBorder/40 border-cardBorder text-gray-300 hover:bg-cyberBlue hover:border-cyberBlue hover:text-darkBg'
            }`}
          >
            <FiDownload className="text-xs" />
            <span>CSV Report</span>
          </button>
          
          <button
            type="button"
            onClick={onExportJson}
            disabled={recordCount === 0}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg border font-mono text-[10px] uppercase font-bold transition-all duration-200 ${
              recordCount === 0
                ? 'bg-cardBorder/30 border-cardBorder/50 text-gray-600 cursor-not-allowed'
                : 'bg-cardBorder/40 border-cardBorder text-gray-300 hover:bg-cyberYellow hover:border-cyberYellow hover:text-darkBg'
            }`}
          >
            <FiDownload className="text-xs" />
            <span>JSON Payload</span>
          </button>
        </div>
      </div>

      {/* Main filter inputs grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-4 gap-4">
        
        {/* IP Search */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[9px] font-mono uppercase tracking-widest text-gray-500 font-semibold">
            Search Attacking IP
          </label>
          <div className="relative">
            <FiSearch className="absolute left-3 top-2.5 text-gray-500 text-xs" />
            <input
              type="text"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              placeholder="e.g. 185.220.101.5"
              className="w-full bg-[#161B26] border border-cardBorder rounded-lg pl-8 pr-3 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyberBlue font-mono"
            />
          </div>
        </div>

        {/* URL / Endpoint Search */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[9px] font-mono uppercase tracking-widest text-gray-500 font-semibold">
            Search Endpoint / Action
          </label>
          <div className="relative">
            <FiSearch className="absolute left-3 top-2.5 text-gray-500 text-xs" />
            <input
              type="text"
              value={searchUrl}
              onChange={(e) => setSearchUrl(e.target.value)}
              placeholder="e.g. wp-login.php"
              className="w-full bg-[#161B26] border border-cardBorder rounded-lg pl-8 pr-3 py-2 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyberBlue font-mono"
            />
          </div>
        </div>

        {/* Status Code Dropdown */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[9px] font-mono uppercase tracking-widest text-gray-500 font-semibold">
            Status Code
          </label>
          <select
            value={statusCode}
            onChange={(e) => setStatusCode(e.target.value)}
            className="w-full bg-[#161B26] border border-cardBorder rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyberBlue font-mono"
          >
            {statusCodes.map((sc) => (
              <option key={sc.value} value={sc.value}>{sc.label}</option>
            ))}
          </select>
        </div>

        {/* Threat Severity */}
        <div className="flex flex-col gap-1.5">
          <label className="text-[9px] font-mono uppercase tracking-widest text-gray-500 font-semibold">
            Incident Severity
          </label>
          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="w-full bg-[#161B26] border border-cardBorder rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyberBlue font-mono"
          >
            {severities.map((sev) => (
              <option key={sev.value} value={sev.value}>{sev.label}</option>
            ))}
          </select>
        </div>

      </div>

      {/* Time-Range and Clear Row */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 pt-2 mt-1 border-t border-cardBorder/30">
        
        {/* Time Tabs */}
        <div className="flex items-center gap-1 bg-[#161B26]/80 p-0.5 rounded-lg border border-cardBorder/50 w-full sm:w-auto">
          {timeRanges.map((tr) => (
            <button
              key={tr.value}
              type="button"
              onClick={() => setTimeRange(tr.value)}
              className={`flex-1 sm:flex-initial px-3 py-1 rounded-md text-[10px] font-mono font-semibold transition-all duration-200 ${
                timeRange === tr.value
                  ? 'bg-cyberBlue/20 text-cyberBlue border border-cyberBlue/30'
                  : 'text-gray-400 border border-transparent hover:text-white'
              }`}
            >
              {tr.label}
            </button>
          ))}
        </div>

        {/* Clear Filters */}
        <button
          type="button"
          onClick={onClearFilters}
          className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg border border-cardBorder/60 text-gray-400 hover:text-cyberRed hover:border-cyberRed/30 hover:bg-cyberRed/5 font-mono text-[10px] font-bold transition-all duration-200 self-end sm:self-auto"
        >
          <FiTrash2 className="text-xs" />
          <span>Clear Engine Query</span>
        </button>

      </div>
      
    </div>
  );
};

export default SparkFilters;
