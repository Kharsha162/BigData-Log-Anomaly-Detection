import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { FiAlertOctagon, FiShield, FiGlobe, FiTerminal, FiSearch } from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import { logsApi } from '../services/api';

const ThreatIntel = () => {
  const [threats, setThreats] = useState([]);
  const [loading, setLoading] = useState(true);
  const [topActors, setTopActors] = useState([]);
  const [geoStats, setGeoStats] = useState([]);

  useEffect(() => {
    const fetchThreats = async () => {
      try {
        const res = await logsApi.getThreats(100);
        setThreats(res);
        
        // Aggregate top threat actors (IPs)
        const actors = {};
        const countries = {};
        
        res.forEach(log => {
          actors[log.ip] = (actors[log.ip] || 0) + 1;
          countries[log.country] = (countries[log.country] || 0) + 1;
        });

        // Convert to sorted lists
        const sortedActors = Object.keys(actors).map(ip => {
          const sample = res.find(l => l.ip === ip);
          return {
            ip,
            count: actors[ip],
            country: sample.country,
            severity: sample.threat_severity,
            details: sample.details || "Suspicious requests matching signature."
          };
        }).sort((a, b) => b.count - a.count).slice(0, 10);

        const sortedCountries = Object.keys(countries).map(cName => ({
          name: cName,
          count: countries[cName]
        })).sort((a,b) => b.count - a.count);

        setTopActors(sortedActors);
        setGeoStats(sortedCountries);
        setLoading(false);
      } catch (err) {
        console.error("Error loading threat intelligence:", err);
        setLoading(false);
      }
    };

    fetchThreats();
  }, []);

  const signatureDatabase = [
    { name: "SQL Injection", desc: "Attempts to inject SQL commands into application variables to extract databases.", pattern: "UNION SELECT / OR 1=1 / SELECT FROM" },
    { name: "Directory Traversal", desc: "Exploit attempts to traverse directory roots and access sensitive configurations.", pattern: "../ / ..\\ / %2e%2e%2f / etc/passwd" },
    { name: "Cross-Site Scripting (XSS)", desc: "Injects client-side scripting tags into URL requests or forms.", pattern: "<script> / javascript: / onload=" },
    { name: "Command Injection", desc: "Injects operating system command flags via query strings to run remote processes.", pattern: "&& whoami / ; curl / netcat / nc" },
    { name: "Brute Force Authentication", desc: "Rapid submission of authentication passwords targeting login endpoints.", pattern: "> 5 failed auths in under 60 seconds" },
  ];

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="THREAT INTELLIGENCE SECURITY CONSOLE" />
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {/* Signatures & Geo Overview */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Signature Database */}
            <div className="lg:col-span-2 rounded-xl border border-cardBorder bg-[#0C111D] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-4 flex items-center gap-2">
                <FiShield className="text-cyberGreen" />
                Active Exploit Signatures Database
              </h3>
              <div className="space-y-4">
                {signatureDatabase.map((sig, idx) => (
                  <div key={idx} className="p-4 rounded-lg bg-cardBg border border-cardBorder/60">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-bold text-white">{sig.name}</span>
                      <span className="font-mono text-[9px] bg-red-950/20 text-cyberRed border border-cyberRed/30 px-2 py-0.5 rounded font-semibold uppercase">
                        Active Monitoring
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mb-2">{sig.desc}</p>
                    <div className="font-mono text-[10px] bg-[#05070C] text-cyberGreen p-2 rounded border border-cardBorder">
                      Pattern: {sig.pattern}
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Threat Country Breakdown */}
            <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-4 flex items-center gap-2">
                <FiGlobe className="text-cyberYellow" />
                Attack Origins By Country
              </h3>
              {loading ? (
                <div className="flex h-40 items-center justify-center text-cyberGreen">
                  <span className="h-6 w-6 animate-spin rounded-full border-2 border-cardBorder border-t-cyberGreen"></span>
                </div>
              ) : (
                <div className="space-y-3">
                  {geoStats.map((geo, idx) => (
                    <div key={idx} className="flex items-center justify-between border-b border-cardBorder/40 pb-2 text-xs font-mono">
                      <span className="text-gray-300 flex items-center gap-2">
                        <span className="text-gray-500">#{idx+1}</span>
                        {geo.name}
                      </span>
                      <span className="text-cyberRed font-bold">{geo.count} events</span>
                    </div>
                  ))}
                  {geoStats.length === 0 && (
                    <p className="text-center text-xs text-gray-500 font-mono py-8">
                      No threat origin analytics available.
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Top Threat Actors List */}
          <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono mb-4 flex items-center gap-2">
              <FiAlertOctagon className="text-cyberRed" />
              Identified Threat Actors & Suspicious IPs
            </h3>

            <div className="overflow-x-auto rounded-lg border border-cardBorder">
              <table className="w-full text-left text-xs console-font">
                <thead className="bg-cardBg text-gray-500 uppercase tracking-widest text-[10px] border-b border-cardBorder">
                  <tr>
                    <th className="py-3 px-4">Threat Actor IP</th>
                    <th className="py-3 px-4">Country Origin</th>
                    <th className="py-3 px-4">Incidents Recorded</th>
                    <th className="py-3 px-4">Calculated Risk</th>
                    <th className="py-3 px-4">Last Detected Exploit Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cardBorder/40">
                  {loading ? (
                    <tr>
                      <td colSpan="5" className="py-8 text-center text-cyberGreen">
                        <span className="h-6 w-6 animate-spin rounded-full border-2 border-cardBorder border-t-cyberGreen inline-block"></span>
                      </td>
                    </tr>
                  ) : topActors.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="py-8 text-center text-gray-500 font-mono">
                        No active malicious indicators logged in database.
                      </td>
                    </tr>
                  ) : (
                    topActors.map((actor, idx) => (
                      <tr key={idx} className="hover:bg-cardBg/30">
                        <td className="py-3 px-4 font-bold text-cyberRed">{actor.ip}</td>
                        <td className="py-3 px-4 text-gray-300">{actor.country}</td>
                        <td className="py-3 px-4 text-white font-mono">{actor.count}</td>
                        <td className="py-3 px-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                            ['High', 'Critical'].includes(actor.severity)
                              ? 'bg-red-950/20 text-cyberRed border border-cyberRed/30'
                              : 'bg-yellow-950/20 text-cyberYellow border border-cyberYellow/30'
                          }`}>
                            {actor.severity} RISK
                          </span>
                        </td>
                        <td className="py-3 px-4 text-gray-400 font-mono text-[11px] truncate max-w-xs" title={actor.details}>
                          {actor.details}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ThreatIntel;
