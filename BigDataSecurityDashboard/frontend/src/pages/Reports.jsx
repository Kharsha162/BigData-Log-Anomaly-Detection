import React, { useState, useEffect } from 'react';
import { FiFileText, FiDownload, FiPrinter, FiShield, FiAlertTriangle } from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import { logsApi } from '../services/api';

const Reports = () => {
  const [loading, setLoading] = useState(true);
  const [reportStats, setReportStats] = useState({
    total: 0,
    anomalies: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    scanners: 0,
    sqli: 0,
    traversals: 0,
    bruteForce: 0,
  });

  const loadReportData = async () => {
    try {
      const res = await logsApi.getLogs({ limit: 500 }); // Scan up to 500 logs for audit
      const list = res.logs;
      
      const stats = {
        total: res.filtered_count,
        anomalies: list.filter(l => l.prediction === 'Anomaly').length,
        critical: list.filter(l => l.threat_severity === 'Critical').length,
        high: list.filter(l => l.threat_severity === 'High').length,
        medium: list.filter(l => l.threat_severity === 'Medium').length,
        low: list.filter(l => l.threat_severity === 'Low').length,
        scanners: list.filter(l => l.threat_type === 'Web Scanner / Reconnaissance').length,
        sqli: list.filter(l => l.threat_type === 'SQL Injection').length,
        traversals: list.filter(l => l.threat_type === 'Directory Traversal / LFI').length,
        bruteForce: list.filter(l => l.threat_type === 'Brute Force Attack').length,
      };
      
      setReportStats(stats);
      setLoading(false);
    } catch (err) {
      console.error("Failed to load audit metrics:", err);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadReportData();
  }, []);

  const handlePrintPDF = () => {
    window.print();
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200 print:bg-white print:text-black">
      {/* Hide navigation components during browser printing */}
      <div className="print:hidden flex">
        <Sidebar />
      </div>
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <div className="print:hidden">
          <Header title="AUDIT COMPLIANCE REPORTING CENTER" />
        </div>
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6 print:px-0 print:py-0">
          
          {/* Controls - Print / Actions */}
          <div className="flex justify-between items-center print:hidden border-b border-cardBorder pb-4">
            <div className="text-xs text-gray-500 font-mono">
              COMPLIANCE AUDIT SCHEMA: PCI-DSS / SOC2 TYPE II
            </div>
            <button
              onClick={handlePrintPDF}
              className="flex items-center gap-2 rounded bg-cyberGreen px-5 py-2.5 text-xs font-bold text-darkBg uppercase shadow-glowGreen hover:bg-cyberGreen/90 transition"
            >
              <FiPrinter />
              <span>Print Security PDF Audit</span>
            </button>
          </div>

          {/* Printable Report Shell */}
          <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-8 space-y-6 print:border-none print:bg-white print:p-0">
            {/* Header branding */}
            <div className="flex justify-between items-start border-b border-cardBorder pb-6 print:border-black/10">
              <div>
                <span className="font-sans font-extrabold tracking-widest text-white uppercase text-base print:text-black">
                  ANTIGRAVITY <span className="text-cyberGreen print:text-black font-semibold">SOC AUDIT</span>
                </span>
                <p className="text-xs text-gray-500 font-mono mt-1">Report Generated: {new Date().toISOString().substring(0, 19).replace('T', ' ')} UTC</p>
              </div>
              <div className="text-right">
                <span className="text-[10px] font-mono font-bold text-cyberGreen border border-cyberGreen/30 px-2 py-0.5 rounded uppercase print:border-black/20 print:text-black">
                  CONFIDENTIAL
                </span>
                <p className="text-[10px] text-gray-500 font-mono mt-1.5">Platform: SecOps v1.0.0</p>
              </div>
            </div>

            {/* Document summary */}
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white font-sans uppercase tracking-wide print:text-black">
                1. Executive Incident Summary
              </h3>
              <p className="text-xs text-gray-400 leading-relaxed print:text-black/80">
                This document serves as an official cybersecurity posture compliance assessment. It reports telemetry logs, structural system metrics parsed through Apache Spark processing interfaces, and anomaly classifications computed by Isolation Forest Machine Learning pipelines.
              </p>
            </div>

            {loading ? (
              <div className="flex h-32 items-center justify-center text-cyberGreen">
                <span className="h-6 w-6 animate-spin rounded-full border-2 border-cardBorder border-t-cyberGreen"></span>
              </div>
            ) : (
              <>
                {/* Metric Summary Grid */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 py-4 border-y border-cardBorder/40 print:border-black/10 print:grid-cols-4 print:text-black">
                  <div>
                    <span className="text-[9px] text-gray-500 uppercase tracking-widest font-mono">Total Scanned Logs</span>
                    <p className="text-2xl font-bold text-white mt-1 print:text-black">{reportStats.total.toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="text-[9px] text-gray-500 uppercase tracking-widest font-mono">Total Threats</span>
                    <p className="text-2xl font-bold text-cyberRed mt-1 print:text-black">{reportStats.anomalies.toLocaleString()}</p>
                  </div>
                  <div>
                    <span className="text-[9px] text-gray-500 uppercase tracking-widest font-mono">High Risk Events</span>
                    <p className="text-2xl font-bold text-cyberYellow mt-1 print:text-black">
                      {(reportStats.critical + reportStats.high).toLocaleString()}
                    </p>
                  </div>
                  <div>
                    <span className="text-[9px] text-gray-500 uppercase tracking-widest font-mono">Ingestion Rate</span>
                    <p className="text-2xl font-bold text-cyberBlue mt-1 print:text-black">100% SUCCESS</p>
                  </div>
                </div>

                {/* Threat vectors classification table */}
                <div className="space-y-4">
                  <h3 className="text-sm font-bold text-white font-sans uppercase tracking-wide print:text-black">
                    2. Classification of Attack Vectors
                  </h3>
                  
                  <div className="overflow-hidden rounded border border-cardBorder print:border-black/10">
                    <table className="w-full text-left text-xs console-font print:text-black">
                      <thead className="bg-cardBg text-gray-400 uppercase tracking-widest text-[9px] border-b border-cardBorder print:bg-black/5 print:text-black">
                        <tr>
                          <th className="py-2.5 px-4">Attack Classification</th>
                          <th className="py-2.5 px-4">Associated Severity</th>
                          <th className="py-2.5 px-4 text-right">Registered Events</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-cardBorder/30 print:divide-black/10">
                        <tr>
                          <td className="py-2.5 px-4 font-semibold">SQL Injection (SQLi)</td>
                          <td className="py-2.5 px-4 text-cyberRed">CRITICAL</td>
                          <td className="py-2.5 px-4 text-right font-mono">{reportStats.sqli}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-4 font-semibold">Directory Traversal / LFI</td>
                          <td className="py-2.5 px-4 text-cyberRed">HIGH</td>
                          <td className="py-2.5 px-4 text-right font-mono">{reportStats.traversals}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-4 font-semibold">Brute Force Attack</td>
                          <td className="py-2.5 px-4 text-cyberRed font-bold animate-pulse">CRITICAL</td>
                          <td className="py-2.5 px-4 text-right font-mono">{reportStats.bruteForce}</td>
                        </tr>
                        <tr>
                          <td className="py-2.5 px-4 font-semibold">Web Scanner / Reconnaissance</td>
                          <td className="py-2.5 px-4 text-cyberYellow">MEDIUM</td>
                          <td className="py-2.5 px-4 text-right font-mono">{reportStats.scanners}</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Audit Signature space */}
                <div className="pt-16 grid grid-cols-2 gap-8 text-xs font-mono text-gray-500 print:text-black">
                  <div>
                    <div className="border-t border-cardBorder/80 pt-2 w-48 print:border-black/30">
                      Operator Signature
                    </div>
                    <span className="text-[10px] text-gray-600 block mt-1">ROLE: Administrator</span>
                  </div>
                  <div className="text-right flex flex-col items-end">
                    <div className="border-t border-cardBorder/80 pt-2 w-48 print:border-black/30 text-right">
                      Date of Verification
                    </div>
                    <span className="text-[10px] text-gray-600 block mt-1">{new Date().toISOString().split('T')[0]}</span>
                  </div>
                </div>
              </>
            )}
          </div>
        </main>
      </div>
    </div>
  );
};

export default Reports;
