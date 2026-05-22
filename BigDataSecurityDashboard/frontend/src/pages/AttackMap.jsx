import React, { useState, useEffect } from 'react';
import Sidebar from '../components/Sidebar';
import Header from '../components/Header';
import ThreatStats from '../components/ThreatStats';
import ThreatFilters from '../components/ThreatFilters';
import GeoMap from '../components/GeoMap';
import ThreatMapSidebar from '../components/ThreatMapSidebar';
import ThreatFeed from '../components/ThreatFeed';
import { geomapApi } from '../services/api';

const AttackMap = () => {
  // Master states
  const [threatLogs, setThreatLogs] = useState([]);
  const [filteredThreats, setFilteredThreats] = useState([]);
  const [selectedThreat, setSelectedThreat] = useState(null);
  
  // Controls
  const [loading, setLoading] = useState(true);
  const [uploading, setUploading] = useState(false);
  const [simulationRunning, setSimulationRunning] = useState(false);
  
  // Filters state
  const [filters, setFilters] = useState({
    ip: '',
    url: '',
    severity: '',
    country: '',
    time_range: '' // '', '1h', '24h', '7d'
  });

  // Dynamic unique countries list
  const [countries, setCountries] = useState([]);

  // 1. Initial Load of threat coordinates from backend
  const loadThreats = async () => {
    try {
      const data = await geomapApi.getThreats(filters);
      setThreatLogs(data);
      setLoading(false);
    } catch (err) {
      console.error("Failed to load geomap threats:", err);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, [filters.time_range]); // Reload when timeframe changes to utilize backend database query speed

  // 2. Perform Client-Side filtering for quick visual updates on queries
  useEffect(() => {
    let result = threatLogs.copy ? threatLogs.copy() : [...threatLogs];

    if (filters.ip) {
      result = result.filter(r => r.ip.toLowerCase().includes(filters.ip.toLowerCase()));
    }
    
    if (filters.url) {
      result = result.filter(r => r.url.toLowerCase().includes(filters.url.toLowerCase()));
    }
    
    if (filters.severity) {
      result = result.filter(r => r.threat_severity.toLowerCase() === filters.severity.toLowerCase());
    }
    
    if (filters.country) {
      result = result.filter(r => r.country.toLowerCase() === filters.country.toLowerCase());
    }

    setFilteredThreats(result);

    // Extract unique countries list
    const uniqueCountries = [...new Set(threatLogs.map(t => t.country).filter(c => c && c !== 'Unknown'))].sort();
    setCountries(uniqueCountries);
  }, [threatLogs, filters.ip, filters.url, filters.severity, filters.country]);

  // 3. Real-Time simulation loop
  useEffect(() => {
    let interval = null;
    if (simulationRunning) {
      interval = setInterval(async () => {
        try {
          // Fetch 2 random new simulated attack logs from the server
          const newAttacks = await geomapApi.getLiveAttacks(2);
          
          setThreatLogs(prev => {
            // Merge and keep capped at 200 items in memory to prevent DOM overloading
            const merged = [...newAttacks, ...prev];
            return merged.slice(0, 200);
          });
        } catch (err) {
          console.error("Simulation retrieval error:", err);
        }
      }, 3500); // Trigger every 3.5 seconds
    } else {
      clearInterval(interval);
    }
    return () => clearInterval(interval);
  }, [simulationRunning]);

  // 4. File upload processor (Log Ingestion)
  const handleUpload = async (file) => {
    setUploading(true);
    try {
      const res = await geomapApi.processLogMap(file);
      alert(res.message || "Logs ingested and geolocated successfully.");
      // Reload active threat listing
      loadThreats();
    } catch (err) {
      console.error(err);
      alert(err.response?.data?.detail || "Log mapping failed. Verify file schema format matches Apache requirements.");
    } finally {
      setUploading(false);
    }
  };

  // 5. Select incident from ledger to focus map camera
  const handleSelectThreat = (threat) => {
    setSelectedThreat(threat);
  };

  // 6. CSV Export helper
  const handleExportCSV = () => {
    if (filteredThreats.length === 0) {
      alert("No data available to export.");
      return;
    }

    const headers = ["Timestamp", "IP Address", "Country", "City", "ISP", "Latitude", "Longitude", "Severity", "Attack Type", "Method", "URL", "Status Code", "Anomaly Score"];
    const rows = filteredThreats.map(t => [
      t.timestamp,
      t.ip,
      t.country,
      t.city,
      t.isp,
      t.latitude,
      t.longitude,
      t.threat_severity,
      t.threat_type,
      t.method,
      `"${t.url.replace(/"/g, '""')}"`,
      t.status,
      t.anomaly_score
    ]);

    const csvContent = "data:text/csv;charset=utf-8," 
      + [headers.join(","), ...rows.map(e => e.join(","))].join("\n");

    const encodedUri = encodeURI(csvContent);
    const link = document.createElement("a");
    link.setAttribute("href", encodedUri);
    link.setAttribute("download", `Threat_Map_Audit_${new Date().toISOString().slice(0,10)}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-darkBg text-gray-200">
      <Sidebar />
      
      <div className="flex flex-1 flex-col overflow-hidden">
        <Header title="ADVANCED THREAT INTEL GEOMAP MODULE" />
        
        <main className="flex-1 overflow-y-auto px-6 py-6 space-y-6 flex flex-col">
          {/* 1. Statistics Cards */}
          <ThreatStats threats={filteredThreats} />

          {/* 2. Advanced Control Policies (Upload, filters, CSV, simulation) */}
          <ThreatFilters
            filters={filters}
            setFilters={setFilters}
            countries={countries}
            onUpload={handleUpload}
            uploading={uploading}
            simulationRunning={simulationRunning}
            toggleSimulation={() => setSimulationRunning(!simulationRunning)}
            onExportCSV={handleExportCSV}
          />

          {/* 3. Main Dashboard Layout Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1 min-h-[480px]">
            {/* Map Canvas (Left / Col span 2) */}
            <div className="lg:col-span-2 h-full min-h-[450px]">
              {loading ? (
                <div className="w-full h-full rounded-xl border border-cardBorder bg-[#0C111D] flex items-center justify-center text-cyberGreen">
                  <span className="h-8 w-8 animate-spin rounded-full border-4 border-cardBorder border-t-cyberGreen"></span>
                </div>
              ) : (
                <GeoMap 
                  threats={filteredThreats} 
                  selectedThreat={selectedThreat} 
                  onSelectThreat={handleSelectThreat}
                />
              )}
            </div>

            {/* Sidebar Charts & Logs Feed (Right / Col span 1) */}
            <div className="space-y-6 flex flex-col h-full justify-between">
              {/* Recharts visualizations & Spark RDD telemetry */}
              <div className="flex-1">
                <ThreatMapSidebar threats={filteredThreats} selectedThreat={selectedThreat} />
              </div>
              
              {/* Live threat scrolling ledger */}
              <div className="h-[250px] lg:h-auto flex-1">
                <ThreatFeed 
                  threats={filteredThreats} 
                  onSelectThreat={handleSelectThreat} 
                />
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
};

export default AttackMap;
