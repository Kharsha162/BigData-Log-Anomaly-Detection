import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { 
  FiSearch, FiFilter, FiDownload, FiUploadCloud, 
  FiCheckCircle, FiAlertCircle, FiTerminal, FiChevronLeft, FiChevronRight 
} from 'react-icons/fi';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import { logsApi } from '../services/api';

const ApacheLogs = () => {
  // Logs query state
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [totalPages, setTotalPages] = useState(1);
  const [totalCount, setTotalCount] = useState(0);
  
  // Filters
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [severityFilter, setSeverityFilter] = useState('');
  const [predictionFilter, setPredictionFilter] = useState('');
  
  // Upload log variables
  const [uploading, setUploading] = useState(false);
  const [uploadSuccess, setUploadSuccess] = useState(null);
  const [uploadError, setUploadError] = useState(null);

  // Load logs when filters change
  const loadLogs = async () => {
    setLoading(true);
    try {
      const params = {
        page,
        limit: 25,
        search: search || undefined,
        status_code: statusFilter ? parseInt(statusFilter) : undefined,
        severity: severityFilter || undefined,
        prediction: predictionFilter || undefined
      };
      const res = await logsApi.getLogs(params);
      setLogs(res.logs);
      setTotalCount(res.filtered_count);
      setTotalPages(Math.max(1, Math.ceil(res.filtered_count / 25)));
    } catch (err) {
      console.error("Failed to load logs:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadLogs();
  }, [page, statusFilter, severityFilter, predictionFilter]);

  const handleSearchSubmit = (e) => {
    e.preventDefault();
    setPage(1);
    loadLogs();
  };

  // CSV Export utility
  const handleExportCSV = () => {
    if (logs.length === 0) return;
    
    // Define headers
    const headers = ['Timestamp', 'IP Address', 'Method', 'URL', 'Status Code', 'Severity', 'Verdict', 'Probability Score', 'Country'];
    
    // Map log lines
    const rows = logs.map(l => [
      l.timestamp,
      l.ip,
      l.method,
      `"${l.url}"`,
      l.status,
      l.threat_severity,
      l.prediction,
      l.probability_score,
      l.country
    ]);
    
    const csvContent = [headers.join(','), ...rows.map(e => e.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.setAttribute("href", url);
    link.setAttribute("download", `SecOps_Logs_${new Date().toISOString().substring(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  // Upload trigger
  const handleFileUpload = async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    setUploading(true);
    setUploadSuccess(null);
    setUploadError(null);

    try {
      const res = await logsApi.uploadLogs(file);
      setUploadSuccess(res.message);
      setPage(1);
      loadLogs();
    } catch (err) {
      setUploadError(err.response?.data?.detail || "Failed to process the uploaded file.");
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="APACHE SECURITY LOG AUDITING" />
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6">
          {/* Controls: Search, Filters, Upload */}
          <div className="grid grid-cols-1 xl:grid-cols-4 gap-4">
            {/* Search Bar */}
            <form onSubmit={handleSearchSubmit} className="xl:col-span-2 flex gap-2">
              <div className="relative flex-1">
                <FiSearch className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Search by IP, URL Path, Threat Category..."
                  className="w-full rounded-lg border border-cardBorder bg-cardBg py-2.5 pl-10 pr-4 text-sm text-white placeholder-gray-600 outline-none transition focus:border-cyberGreen"
                />
              </div>
              <button
                type="submit"
                className="rounded-lg bg-cardBorder px-5 py-2.5 font-mono text-xs font-bold text-cyberGreen hover:bg-cardBorder/80 border border-cyberGreen/20 shadow-glowGreen/5"
              >
                QUERY
              </button>
            </form>

            {/* Quick Filters */}
            <div className="flex gap-2">
              {/* HTTP Status Code Filter */}
              <select
                value={statusFilter}
                onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                className="flex-1 rounded-lg border border-cardBorder bg-cardBg px-3 py-2 text-xs font-mono text-gray-300 outline-none focus:border-cyberGreen"
              >
                <option value="">STATUS (ALL)</option>
                <option value="200">200 OK</option>
                <option value="304">304 Redirect</option>
                <option value="400">400 Bad Req</option>
                <option value="401">401 Unauthorized</option>
                <option value="404">404 Not Found</option>
                <option value="500">500 Server Err</option>
              </select>

              {/* Severity Filter */}
              <select
                value={severityFilter}
                onChange={(e) => { setSeverityFilter(e.target.value); setPage(1); }}
                className="flex-1 rounded-lg border border-cardBorder bg-cardBg px-3 py-2 text-xs font-mono text-gray-300 outline-none focus:border-cyberGreen"
              >
                <option value="">SEVERITY (ALL)</option>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
              </select>

              {/* Verdict Filter */}
              <select
                value={predictionFilter}
                onChange={(e) => { setPredictionFilter(e.target.value); setPage(1); }}
                className="flex-1 rounded-lg border border-cardBorder bg-cardBg px-3 py-2 text-xs font-mono text-gray-300 outline-none focus:border-cyberGreen"
              >
                <option value="">VERDICT (ALL)</option>
                <option value="Normal">Normal</option>
                <option value="Anomaly">Anomaly</option>
              </select>
            </div>

            {/* Actions: CSV Export and Upload */}
            <div className="flex gap-2">
              <button
                onClick={handleExportCSV}
                className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-cardBorder text-gray-300 text-xs py-2 hover:bg-cardBorder/80 border border-cardBorder"
              >
                <FiDownload />
                <span>Export CSV</span>
              </button>

              <label className="flex-1 flex items-center justify-center gap-2 rounded-lg bg-cyberGreen text-darkBg text-xs font-bold py-2 cursor-pointer shadow-glowGreen hover:bg-cyberGreen/90">
                <FiUploadCloud />
                <span>Upload Logs</span>
                <input
                  type="file"
                  accept=".log,.txt,.csv"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </label>
            </div>
          </div>

          {/* Upload Status Alerts */}
          <AnimatePresence>
            {uploading && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="rounded-lg border border-cyberBlue/20 bg-cyberBlue/5 p-4 flex items-center gap-3 text-xs text-cyberBlue font-mono"
              >
                <span className="h-4 w-4 animate-spin rounded-full border-2 border-cyberBlue border-t-transparent"></span>
                Processing raw log vectors and triggering Spark pipelines...
              </motion.div>
            )}
            {uploadSuccess && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="rounded-lg border border-cyberGreen/20 bg-cyberGreen/5 p-4 flex items-center gap-3 text-xs text-cyberGreen font-mono"
              >
                <FiCheckCircle className="text-base" />
                {uploadSuccess}
              </motion.div>
            )}
            {uploadError && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                className="rounded-lg border border-cyberRed/20 bg-cyberRed/5 p-4 flex items-center gap-3 text-xs text-cyberRed font-mono"
              >
                <FiAlertCircle className="text-base" />
                {uploadError}
              </motion.div>
            )}
          </AnimatePresence>

          {/* Main Log Table */}
          <div className="rounded-xl border border-cardBorder bg-[#0C111D] p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-400 font-mono flex items-center gap-2">
                <FiTerminal className="text-cyberGreen" />
                Total Queries Matched: <span className="text-white font-bold">{totalCount}</span>
              </h3>
            </div>

            <div className="overflow-x-auto rounded-lg border border-cardBorder">
              <table className="w-full text-left text-xs console-font">
                <thead className="bg-cardBg text-gray-500 uppercase tracking-widest text-[10px] border-b border-cardBorder">
                  <tr>
                    <th className="py-3 px-4">Timestamp</th>
                    <th className="py-3 px-4">Origin IP</th>
                    <th className="py-3 px-4">Geo Origin</th>
                    <th className="py-3 px-4">Method</th>
                    <th className="py-3 px-4">URL</th>
                    <th className="py-3 px-4">Status</th>
                    <th className="py-3 px-4">Severity</th>
                    <th className="py-3 px-4">ML Score</th>
                    <th className="py-3 px-4 text-right">Verdict</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cardBorder/40">
                  {loading ? (
                    <tr>
                      <td colSpan="9" className="py-8 text-center text-cyberGreen">
                        <span className="h-6 w-6 animate-spin rounded-full border-2 border-cardBorder border-t-cyberGreen inline-block"></span>
                      </td>
                    </tr>
                  ) : logs.length === 0 ? (
                    <tr>
                      <td colSpan="9" className="py-8 text-center text-gray-500 font-mono">
                        No records found matching search queries or filters.
                      </td>
                    </tr>
                  ) : (
                    logs.map((log, idx) => {
                      const isAnom = log.prediction === 'Anomaly';
                      const severityColors = {
                        Low: 'text-gray-400',
                        Medium: 'text-cyberYellow',
                        High: 'text-cyberRed font-bold',
                        Critical: 'text-cyberRed font-bold animate-pulse',
                      };

                      return (
                        <tr key={idx} className={`hover:bg-cardBg/30 ${isAnom ? 'bg-red-950/5' : ''}`}>
                          <td className="py-3 px-4 text-gray-500 whitespace-nowrap">
                            {log.timestamp.includes('T') ? log.timestamp.replace('T', ' ').substring(0, 19) : log.timestamp.substring(0, 19)}
                          </td>
                          <td className="py-3 px-4 font-semibold text-gray-300">{log.ip}</td>
                          <td className="py-3 px-4 text-gray-400">{log.country || 'Local'}</td>
                          <td className="py-3 px-4"><span className="text-cyberBlue">{log.method}</span></td>
                          <td className="py-3 px-4 text-gray-400 truncate max-w-xs" title={log.url}>{log.url}</td>
                          <td className="py-3 px-4">
                            <span className={log.status >= 400 ? 'text-cyberRed' : 'text-cyberGreen'}>
                              {log.status}
                            </span>
                          </td>
                          <td className="py-3 px-4">
                            <span className={`text-[10px] uppercase font-mono ${severityColors[log.threat_severity] || 'text-gray-400'}`}>
                              {log.threat_severity}
                            </span>
                          </td>
                          <td className="py-3 px-4 text-gray-400">{(log.probability_score * 100).toFixed(1)}%</td>
                          <td className="py-3 px-4 text-right">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              isAnom ? 'bg-cyberRed/20 text-cyberRed border border-cyberRed/30' : 'bg-cyberGreen/20 text-cyberGreen border border-cyberGreen/30'
                            }`}>
                              {log.prediction}
                            </span>
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination controls */}
            <div className="flex items-center justify-between mt-4 text-xs font-mono text-gray-500">
              <span>Page {page} of {totalPages}</span>
              <div className="flex gap-2">
                <button
                  disabled={page <= 1}
                  onClick={() => setPage(page - 1)}
                  className="rounded bg-cardBg border border-cardBorder p-1.5 hover:text-white disabled:opacity-30 disabled:pointer-events-none"
                >
                  <FiChevronLeft className="text-base" />
                </button>
                <button
                  disabled={page >= totalPages}
                  onClick={() => setPage(page + 1)}
                  className="rounded bg-cardBg border border-cardBorder p-1.5 hover:text-white disabled:opacity-30 disabled:pointer-events-none"
                >
                  <FiChevronRight className="text-base" />
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default ApacheLogs;
