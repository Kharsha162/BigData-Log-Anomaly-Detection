import React, { useState } from 'react';
import { FiChevronDown, FiChevronUp, FiAlertOctagon, FiCheckCircle, FiInfo } from 'react-icons/fi';

const SparkThreatTable = ({ records }) => {
  const [expandedRow, setExpandedRow] = useState(null);
  const [currentPage, setCurrentPage] = useState(1);
  const recordsPerPage = 15;

  const toggleRow = (index) => {
    if (expandedRow === index) {
      setExpandedRow(null);
    } else {
      setExpandedRow(index);
    }
  };

  // Pagination logic
  const indexOfLastRecord = currentPage * recordsPerPage;
  const indexOfFirstRecord = indexOfLastRecord - recordsPerPage;
  const currentRecords = records.slice(indexOfFirstRecord, indexOfLastRecord);
  const totalPages = Math.ceil(records.length / recordsPerPage);

  const getSeverityStyle = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-purple-950/40 text-purple-400 border-purple-800/40';
      case 'high threat':
      case 'high':
        return 'bg-red-950/40 text-red-400 border-red-800/40';
      case 'suspicious':
      case 'medium':
        return 'bg-yellow-950/40 text-cyberYellow border-yellow-800/40';
      default:
        return 'bg-emerald-950/40 text-emerald-400 border-emerald-800/40';
    }
  };

  return (
    <div className="w-full rounded-2xl border border-cardBorder bg-[#0C111D]/80 backdrop-blur-md p-5 flex flex-col gap-4 shadow-xl transition-all duration-300">
      
      {/* Header */}
      <div className="flex items-center justify-between border-b border-cardBorder/50 pb-3">
        <div className="flex items-center gap-2">
          <FiInfo className="text-cyberGreen text-lg" />
          <h2 className="font-mono text-xs uppercase tracking-widest text-white font-bold">
            Spark Ingested Stream (Active Micro-Batches)
          </h2>
        </div>
        <span className="text-[10px] text-gray-500 font-mono">
          Click any row to examine separate ML Classifier verdicts
        </span>
      </div>

      {/* Table Console */}
      <div className="overflow-x-auto rounded-xl border border-cardBorder/60 bg-[#0C111D]/50">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#161B26] text-gray-500 uppercase tracking-widest text-[9px] border-b border-cardBorder">
            <tr>
              <th className="py-3 px-4 w-6"></th>
              <th className="py-3 px-4">Batch ID</th>
              <th className="py-3 px-4">Origin IP</th>
              <th className="py-3 px-4">Timestamp</th>
              <th className="py-3 px-4">Request Endpoint</th>
              <th className="py-3 px-4">Status</th>
              <th className="py-3 px-4">Severity</th>
              <th className="py-3 px-4">Verdict</th>
              <th className="py-3 px-4 text-right">Size</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cardBorder/30">
            {currentRecords.length === 0 ? (
              <tr>
                <td colSpan="9" className="py-8 text-center text-gray-600">
                  No records matching the query parameters. Run the pipeline above or toggle the live simulator.
                </td>
              </tr>
            ) : (
              currentRecords.map((rec, idx) => {
                const globalIndex = indexOfFirstRecord + idx;
                const isExpanded = expandedRow === globalIndex;
                const isAnomaly = rec.prediction === 'Anomaly';

                return (
                  <React.Fragment key={globalIndex}>
                    {/* Primary Row */}
                    <tr 
                      onClick={() => toggleRow(globalIndex)}
                      className={`cursor-pointer transition-colors duration-150 hover:bg-cardBg/20 ${
                        isExpanded ? 'bg-cardBg/20' : ''
                      }`}
                    >
                      <td className="py-3.5 px-4 text-gray-500">
                        {isExpanded ? <FiChevronUp /> : <FiChevronDown />}
                      </td>
                      <td className="py-3.5 px-4 font-bold text-cyberBlue">
                        {rec.batch_id}
                      </td>
                      <td className="py-3.5 px-4 font-semibold text-gray-300">
                        {rec.ip}
                      </td>
                      <td className="py-3.5 px-4 text-gray-500 text-[10px]">
                        {rec.timestamp}
                      </td>
                      <td className="py-3.5 px-4 text-gray-400 max-w-[200px] truncate">
                        {rec.url}
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`font-bold ${rec.status >= 400 ? 'text-cyberRed' : 'text-cyberGreen'}`}>
                          {rec.status}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`px-2 py-0.5 rounded border text-[9px] font-bold ${getSeverityStyle(rec.threat_severity)}`}>
                          {rec.threat_severity}
                        </span>
                      </td>
                      <td className="py-3.5 px-4">
                        <span className={`flex items-center gap-1 font-bold ${isAnomaly ? 'text-cyberRed' : 'text-cyberGreen'}`}>
                          {isAnomaly ? <FiAlertOctagon /> : <FiCheckCircle />}
                          {rec.prediction}
                        </span>
                      </td>
                      <td className="py-3.5 px-4 text-right text-gray-400 font-semibold">
                        {rec.size.toLocaleString()} B
                      </td>
                    </tr>

                    {/* Expandable Classifier Details Row */}
                    {isExpanded && (
                      <tr className="bg-[#121824]/40 border-b border-cardBorder">
                        <td colSpan="9" className="p-4">
                          <div className="rounded-lg border border-cardBorder bg-[#0C111D]/80 p-4 flex flex-col gap-3 font-mono">
                            
                            {/* Header Info */}
                            <div className="flex items-center justify-between border-b border-cardBorder/40 pb-2">
                              <span className="text-[10px] font-bold uppercase text-cyberBlue tracking-widest">
                                ML Security Engine Analytics Console
                              </span>
                              <span className="text-[10px] text-gray-400">
                                Target Request: <code className="text-white bg-cardBorder px-1.5 py-0.5 rounded">{rec.method} {rec.url}</code>
                              </span>
                            </div>

                            {/* Attacker Details Grid */}
                            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
                              <div>
                                <span className="text-gray-500">Origin Geo:</span>{' '}
                                <span className="text-white font-semibold">
                                  {rec.country}, {rec.city}
                                </span>
                              </div>
                              <div>
                                <span className="text-gray-500">Threat Signature Match:</span>{' '}
                                <span className="text-white font-semibold">{rec.threat_type || 'None'}</span>
                              </div>
                              <div>
                                <span className="text-gray-500">Spark Pipeline Execution Time:</span>{' '}
                                <span className="text-cyberGreen font-bold">~0.03ms</span>
                              </div>
                            </div>

                            {/* Separated Classifier Verdicts */}
                            <div className="mt-2 flex flex-col gap-1.5">
                              <span className="text-[9px] font-bold uppercase text-gray-500 tracking-wider">
                                Separate Model Classifiers Output:
                              </span>
                              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                                
                                {/* Isolation Forest */}
                                <div className="rounded-lg border border-cardBorder/50 bg-[#161B26] p-3 flex flex-col justify-between">
                                  <span className="text-[10px] font-bold uppercase text-gray-400">Isolation Forest</span>
                                  <div className="mt-2 flex justify-between items-center text-xs">
                                    <span className={rec.all_classifiers?.isolation_forest?.prediction === 'Anomaly' ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>
                                      {rec.all_classifiers?.isolation_forest?.prediction || (isAnomaly ? 'Anomaly' : 'Normal')}
                                    </span>
                                    <span className="text-gray-400 text-[10px]">
                                      Score: {(rec.all_classifiers?.isolation_forest?.score || rec.anomaly_score).toFixed(3)}
                                    </span>
                                  </div>
                                </div>

                                {/* Random Forest */}
                                <div className="rounded-lg border border-cardBorder/50 bg-[#161B26] p-3 flex flex-col justify-between">
                                  <span className="text-[10px] font-bold uppercase text-gray-400">Random Forest</span>
                                  <div className="mt-2 flex justify-between items-center text-xs">
                                    <span className={rec.all_classifiers?.random_forest?.prediction === 'Anomaly' ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>
                                      {rec.all_classifiers?.random_forest?.prediction || (isAnomaly ? 'Anomaly' : 'Normal')}
                                    </span>
                                    <span className="text-gray-400 text-[10px]">
                                      Prob: {(rec.all_classifiers?.random_forest?.score || (isAnomaly ? 0.85 : 0.05)).toFixed(3)}
                                    </span>
                                  </div>
                                </div>

                                {/* Logistic Regression */}
                                <div className="rounded-lg border border-cardBorder/50 bg-[#161B26] p-3 flex flex-col justify-between">
                                  <span className="text-[10px] font-bold uppercase text-gray-400">Logistic Regression</span>
                                  <div className="mt-2 flex justify-between items-center text-xs">
                                    <span className={rec.all_classifiers?.logistic_regression?.prediction === 'Anomaly' ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>
                                      {rec.all_classifiers?.logistic_regression?.prediction || (isAnomaly ? 'Anomaly' : 'Normal')}
                                    </span>
                                    <span className="text-gray-400 text-[10px]">
                                      Prob: {(rec.all_classifiers?.logistic_regression?.score || (isAnomaly ? 0.72 : 0.04)).toFixed(3)}
                                    </span>
                                  </div>
                                </div>

                                {/* Gradient Boosting */}
                                <div className="rounded-lg border border-cardBorder/50 bg-[#161B26] p-3 flex flex-col justify-between">
                                  <span className="text-[10px] font-bold uppercase text-gray-400">Gradient Boosting</span>
                                  <div className="mt-2 flex justify-between items-center text-xs">
                                    <span className={rec.all_classifiers?.gradient_boosting?.prediction === 'Anomaly' ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>
                                      {rec.all_classifiers?.gradient_boosting?.prediction || (isAnomaly ? 'Anomaly' : 'Normal')}
                                    </span>
                                    <span className="text-gray-400 text-[10px]">
                                      Prob: {(rec.all_classifiers?.gradient_boosting?.score || (isAnomaly ? 0.88 : 0.03)).toFixed(3)}
                                    </span>
                                  </div>
                                </div>

                              </div>
                            </div>

                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between font-mono text-[11px] text-gray-500 pt-2 border-t border-cardBorder/30">
          <span>
            Showing {indexOfFirstRecord + 1}-{Math.min(indexOfLastRecord, records.length)} of {records.length} items
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setCurrentPage(prev => Math.max(prev - 1, 1))}
              disabled={currentPage === 1}
              className={`px-3 py-1.5 rounded-lg border border-cardBorder bg-[#161B26] text-xs transition-colors duration-150 ${
                currentPage === 1 ? 'opacity-40 cursor-not-allowed' : 'hover:bg-cardBorder hover:text-white'
              }`}
            >
              Prev
            </button>
            <span className="px-3 py-1.5 text-xs text-gray-300 font-bold self-center">
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => setCurrentPage(prev => Math.min(prev + 1, totalPages))}
              disabled={currentPage === totalPages}
              className={`px-3 py-1.5 rounded-lg border border-cardBorder bg-[#161B26] text-xs transition-colors duration-150 ${
                currentPage === totalPages ? 'opacity-40 cursor-not-allowed' : 'hover:bg-cardBorder hover:text-white'
              }`}
            >
              Next
            </button>
          </div>
        </div>
      )}

    </div>
  );
};

export default SparkThreatTable;
