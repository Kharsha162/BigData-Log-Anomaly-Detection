import React from 'react';
import { FiActivity, FiAlertTriangle, FiGlobe, FiCpu } from 'react-icons/fi';

const ThreatStats = ({ threats }) => {
  const totalAttacks = threats.length;
  
  const highOrCritical = threats.filter(
    t => t.threat_severity === 'High Threat' || t.threat_severity === 'Critical'
  ).length;
  
  const criticalRatio = totalAttacks > 0 ? ((highOrCritical / totalAttacks) * 100).toFixed(1) : '0.0';
  
  const uniqueCountries = new Set(threats.map(t => t.country).filter(c => c && c !== 'Unknown')).size;
  const uniqueIPs = new Set(threats.map(t => t.ip)).size;

  // Posture logic
  let posture = "SECURE";
  let postureColor = "text-cyberGreen border-cyberGreen/25 shadow-glowGreen/5 bg-cyberGreen/5";
  if (highOrCritical > 15) {
    posture = "CRITICAL LIMIT";
    postureColor = "text-cyberRed border-cyberRed/25 shadow-glowRed/5 bg-cyberRed/5";
  } else if (highOrCritical > 5) {
    posture = "WARNING ESCALATION";
    postureColor = "text-cyberYellow border-cyberYellow/25 shadow-glowYellow/5 bg-cyberYellow/5";
  }

  const kpiData = [
    {
      title: "Total Tracked Incidents",
      value: totalAttacks.toLocaleString(),
      desc: "Aggregated attack lines",
      icon: <FiActivity className="text-xl text-cyberBlue" />,
      glow: "hover:shadow-glowBlue/5 focus-within:border-cyberBlue"
    },
    {
      title: "High & Critical Ratio",
      value: `${criticalRatio}%`,
      desc: `${highOrCritical} high-risk alerts`,
      icon: <FiAlertTriangle className="text-xl text-cyberRed animate-pulse" />,
      glow: "hover:shadow-glowRed/5 focus-within:border-cyberRed"
    },
    {
      title: "Attacking Countries",
      value: uniqueCountries,
      desc: `${uniqueIPs} malicious IPs`,
      icon: <FiGlobe className="text-xl text-cyberYellow" />,
      glow: "hover:shadow-glowYellow/5 focus-within:border-cyberYellow"
    },
    {
      title: "SOC Threat Posture",
      value: posture,
      desc: "Based on active high threats",
      icon: <FiCpu className="text-xl text-cyberGreen" />,
      glow: "hover:shadow-glowGreen/5 focus-within:border-cyberGreen",
      customClass: postureColor
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 w-full">
      {kpiData.map((kpi, idx) => (
        <div 
          key={idx} 
          className={`rounded-xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-4 transition-all duration-300 ${kpi.glow} ${kpi.customClass || ''}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500 font-mono">
              {kpi.title}
            </span>
            <div className="p-1.5 rounded-lg bg-cardBorder/30">
              {kpi.icon}
            </div>
          </div>
          <div className="mt-2 flex items-baseline gap-2">
            <span className="text-2xl font-bold tracking-tight text-white font-mono">
              {kpi.value}
            </span>
          </div>
          <p className="mt-1 text-[11px] text-gray-500 font-mono">
            {kpi.desc}
          </p>
        </div>
      ))}
    </div>
  );
};

export default ThreatStats;
