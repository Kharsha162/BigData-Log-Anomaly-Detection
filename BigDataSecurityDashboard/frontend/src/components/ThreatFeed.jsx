import React from 'react';
import { FiRadio, FiCornerDownRight } from 'react-icons/fi';

const ThreatFeed = ({ threats, onSelectThreat }) => {
  const recentThreats = threats.slice(0, 15); // Show top 15 recent threats

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case 'Normal':
        return 'bg-cyberGreen/20 text-cyberGreen border-cyberGreen/30';
      case 'Suspicious':
        return 'bg-cyberYellow/20 text-cyberYellow border-cyberYellow/30';
      case 'High Threat':
        return 'bg-cyberRed/20 text-cyberRed border-cyberRed/30';
      case 'Critical':
        return 'bg-purple-500/20 text-purple-400 border-purple-500/30 animate-pulse';
      default:
        return 'bg-cardBorder text-gray-400 border-cardBorder/40';
    }
  };

  return (
    <div className="rounded-xl border border-cardBorder bg-[#0C111D]/90 backdrop-blur-md p-4 flex flex-col h-full">
      <h3 className="text-xs font-semibold uppercase tracking-wider text-white font-mono mb-3 flex items-center gap-2">
        <FiRadio className="text-cyberRed animate-pulse" />
        Live Attack Feed Ledger
      </h3>

      <div className="flex-1 overflow-y-auto space-y-2 max-h-[350px] pr-1 scrollbar-thin">
        {recentThreats.length === 0 ? (
          <div className="flex h-32 items-center justify-center text-xs font-mono text-gray-500">
            No incident packets captured.
          </div>
        ) : (
          recentThreats.map((threat, idx) => (
            <div
              key={idx}
              onClick={() => onSelectThreat(threat)}
              className="group p-2.5 rounded-lg border border-cardBorder/40 bg-[#05070C]/80 hover:bg-cardBorder/20 hover:border-cyberGreen/30 cursor-pointer transition duration-150 relative text-[11px] font-mono"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-bold text-cyberBlue hover:text-[#33CCFF] hover:underline cursor-pointer transition-colors duration-150 flex items-center gap-1.5">
                  <span className="h-1.5 w-1.5 rounded-full bg-cyberBlue animate-pulse inline-block"></span>
                  {threat.ip}
                </span>
                <span className={`px-1.5 py-0.5 rounded text-[8px] font-bold border uppercase tracking-wider ${getSeverityBadge(threat.threat_severity)}`}>
                  {threat.threat_severity}
                </span>
              </div>
              
              <div className="text-[10px] text-cyberBlue mb-1 font-semibold flex items-center gap-1">
                <FiCornerDownRight className="text-[9px] text-gray-600" />
                {threat.threat_type}
              </div>

              <div className="text-gray-500 truncate max-w-[220px]" title={threat.url}>
                {threat.method} {threat.url}
              </div>

              <div className="flex justify-between items-center text-[9px] text-gray-600 mt-1.5 pt-1.5 border-t border-cardBorder/20">
                <span>{threat.city}, {threat.country}</span>
                <span>
                  {(() => {
                    const ts = threat.timestamp;
                    if (typeof ts !== 'string') return 'Unknown';
                    if (ts.includes('T')) return ts.split('T')[1]?.substring(0, 8);
                    if (ts.includes(':')) {
                      const parts = ts.split(':');
                      return parts[1] && parts[2] ? `${parts[1]}:${parts[2]}` : ts;
                    }
                    return ts;
                  })()}
                </span>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default ThreatFeed;
