import React, { useEffect, useState, useMemo, useRef } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline, CircleMarker, useMap } from 'react-leaflet';
import L from 'leaflet';
import { FiSearch, FiGlobe, FiClock, FiTarget, FiAlertCircle, FiTrash2 } from 'react-icons/fi';
import api from '../services/api';

// Reset Leaflet Default Icon prototype to fix Vite dynamic asset resolution crashes
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Central Target Node
const SERVER_NODE = { lat: 13.0827, lon: 80.2707, name: "Chennai SOC Mainframe Node" };

// Dynamic Map Controller to pan and zoom smoothly to selected IP nodes and open popups
const MapController = ({ selectedThreat, markerRefs }) => {
  const map = useMap();

  useEffect(() => {
    // Invalidate size on mount to force recalculation of bounds and resolve grey spaces
    const timer = setTimeout(() => {
      map.invalidateSize();
    }, 200);
    return () => clearTimeout(timer);
  }, [map]);

  useEffect(() => {
    if (selectedThreat) {
      const lat = parseFloat(selectedThreat.latitude);
      const lon = parseFloat(selectedThreat.longitude);
      if (!isNaN(lat) && !isNaN(lon)) {
        // Fly smoothly to location
        map.flyTo([lat, lon], 7, {
          animate: true,
          duration: 1.5
        });

        // Delay popup auto-opening to allow flyTo to complete beautifully
        const timer = setTimeout(() => {
          const marker = markerRefs.current[selectedThreat.ip];
          if (marker) {
            marker.openPopup();
          }
        }, 1600);
        return () => clearTimeout(timer);
      }
    }
  }, [selectedThreat, map, markerRefs]);

  return null;
};

// Custom Glowing HTML div icon generators for the severities, with support for count and selected states
const getAttackerIcon = (severity, count = 1, isSelected = false) => {
  let color = '#10B981'; // Green (Normal)
  if (severity === 'Suspicious') {
    color = '#F59E0B'; // Orange
  } else if (severity === 'High Threat') {
    color = '#EF4444'; // Red
  } else if (severity === 'Critical') {
    color = '#A78BFA'; // Purple
  }

  const pulseSize = isSelected ? 'h-10 w-10 border border-white/30' : 'h-6 w-6';
  const markerSize = isSelected ? 'h-5 w-5 border-2 scale-125' : 'h-3.5 w-3.5';
  const glowShadow = isSelected ? `shadow-[0_0_15px_${color}]` : '';

  const badgeHtml = count > 1 ? `
    <span class="absolute -top-2.5 -right-2.5 px-1 py-0.5 rounded-full text-[8px] font-bold bg-[#0C111D] border border-cardBorder text-white font-mono flex items-center justify-center min-w-[14px] h-[14px]">
      ${count}
    </span>
  ` : '';

  const html = `
    <div class="relative flex items-center justify-center transition-all duration-300">
      <div class="absolute ${pulseSize} rounded-full opacity-50 animate-ping" style="background-color: ${color};"></div>
      ${isSelected ? `<div class="absolute h-8 w-8 rounded-full border border-dashed border-white/40 animate-spin"></div>` : ''}
      <div class="${markerSize} rounded-full border border-white/80 shadow-lg ${glowShadow} flex items-center justify-center transition-all duration-300" style="background-color: ${color};">
        ${isSelected ? `<div class="h-1.5 w-1.5 bg-white rounded-full"></div>` : ''}
      </div>
      ${badgeHtml}
    </div>
  `;

  return L.divIcon({
    html: html,
    className: `custom-cyber-marker ${isSelected ? 'z-[9999]' : ''}`,
    iconSize: isSelected ? [36, 36] : [24, 24],
    iconAnchor: isSelected ? [18, 18] : [12, 12],
  });
};

const getTargetIcon = () => {
  const html = `
    <div class="relative flex items-center justify-center">
      <div class="absolute h-8 w-8 rounded-full opacity-30 bg-cyberGreen animate-ping"></div>
      <div class="h-5 w-5 bg-[#05070C] border-2 border-cyberGreen rounded-full flex items-center justify-center shadow-lg">
        <div class="h-2 w-2 bg-cyberGreen rounded-full shadow-glowGreen"></div>
      </div>
    </div>
  `;
  return L.divIcon({
    html: html,
    className: 'custom-target-marker',
    iconSize: [32, 32],
    iconAnchor: [16, 16],
  });
};

const GeoMap = ({ threats = [], selectedThreat, onSelectThreat }) => {
  // IP Search & Dropdown States
  const [searchQuery, setSearchQuery] = useState('');
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [localSelectedThreat, setLocalSelectedThreat] = useState(null);
  const [investigatedThreat, setInvestigatedThreat] = useState(null);
  
  const searchRef = useRef(null);
  const markerRefs = useRef({});

  const [recentSearches, setRecentSearches] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('recent_ip_searches') || '[]');
    } catch {
      return [];
    }
  });

  // Clear stale references on update if threats change
  useEffect(() => {
    markerRefs.current = {};
  }, [threats]);

  // Click outside listener to close dropdown
  useEffect(() => {
    const clickOutside = (e) => {
      if (searchRef.current && !searchRef.current.contains(e.target)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('mousedown', clickOutside);
    return () => document.removeEventListener('mousedown', clickOutside);
  }, []);

  // 1. Group overlapping threat markers by IP for native lag-free clustering
  const clusteredThreats = useMemo(() => {
    const groups = {};
    (threats || []).forEach(t => {
      if (!t || !t.ip) return;
      if (!groups[t.ip]) {
        groups[t.ip] = {
          ...t,
          count: 0,
          severity_distribution: { Normal: 0, Suspicious: 0, "High Threat": 0, Critical: 0 }
        };
      }
      groups[t.ip].count += 1;
      groups[t.ip].severity_distribution[t.threat_severity] = (groups[t.ip].severity_distribution[t.threat_severity] || 0) + 1;
      
      // Inherit the most severe threat scale for color logic
      const severitiesOrder = ['Normal', 'Suspicious', 'High Threat', 'Critical'];
      const currentOrder = severitiesOrder.indexOf(groups[t.ip].threat_severity);
      const newOrder = severitiesOrder.indexOf(t.threat_severity);
      if (newOrder > currentOrder) {
        groups[t.ip].threat_severity = t.threat_severity;
        groups[t.ip].threat_type = t.threat_type;
        groups[t.ip].timestamp = t.timestamp;
        groups[t.ip].method = t.method;
        groups[t.ip].url = t.url;
        groups[t.ip].status = t.status;
        groups[t.ip].anomaly_score = t.anomaly_score;
      }
    });
    return Object.values(groups);
  }, [threats]);

  // Combined threat pool including any newly backend-queried IP record
  const allRenderedThreats = useMemo(() => {
    const list = [...clusteredThreats];
    if (investigatedThreat && !list.some(t => t.ip === investigatedThreat.ip)) {
      list.unshift(investigatedThreat);
    }
    return list;
  }, [clusteredThreats, investigatedThreat]);

  // Generate unique IP list for suggestions matching typed query
  const ipSuggestions = useMemo(() => {
    if (!searchQuery) return [];
    const uniqueIPs = [...new Set(threats.map(t => t.ip).filter(Boolean))];
    return uniqueIPs
      .filter(ip => ip.toLowerCase().includes(searchQuery.toLowerCase()))
      .slice(0, 5);
  }, [threats, searchQuery]);

  // Unified select threat handler
  const handleSelectIP = async (ip) => {
    if (!ip) return;
    setSearchQuery(ip);
    setShowSuggestions(false);

    // Save to LocalStorage searches
    const updated = [ip, ...recentSearches.filter(x => x !== ip)].slice(0, 5);
    setRecentSearches(updated);
    localStorage.setItem('recent_ip_searches', JSON.stringify(updated));

    // Check if IP matches current threat pool
    const existing = allRenderedThreats.find(t => t.ip === ip);
    if (existing) {
      if (onSelectThreat) {
        onSelectThreat(existing);
      } else {
        setLocalSelectedThreat(existing);
      }
    } else {
      // Not in pool, query FastAPI backend search endpoint!
      try {
        const response = await api.get(`/search-ip/${ip}`);
        if (response && response.data) {
          const data = response.data;
          const enriched = {
            ip: data.ip,
            latitude: parseFloat(data.latitude),
            longitude: parseFloat(data.longitude),
            threat_severity: data.threat_severity || 'Normal',
            threat_type: 'IP INVESTIGATION INSTANCE',
            country: data.country || 'Unknown',
            city: 'Audited Node',
            isp: 'CyberSafe SecOps Transit',
            timestamp: data.timestamp || new Date().toISOString(),
            anomaly_score: 0.95,
            prediction: data.threat_severity !== 'Normal' ? 'Anomaly' : 'Normal',
            method: 'TRACE',
            url: `/search-ip/${data.ip}`,
            status: 200,
            size: 0
          };
          setInvestigatedThreat(enriched);
          if (onSelectThreat) {
            onSelectThreat(enriched);
          } else {
            setLocalSelectedThreat(enriched);
          }
        }
      } catch (err) {
        console.error("FastAPI IP query failed:", err);
      }
    }
  };

  const activeSelectedThreat = selectedThreat || localSelectedThreat;
  const isAnySelected = !!activeSelectedThreat;

  return (
    <div className="w-full h-full min-h-[480px] bg-[#05070C] relative rounded-xl overflow-hidden border border-cardBorder" style={{ height: '100%', minHeight: '480px' }}>
      
      {/* ── INTERACTIVE IP SEARCH HUD OVERLAY ── */}
      <div 
        ref={searchRef}
        className="absolute top-4 right-4 z-[1000] w-72 bg-[#0C111D]/95 backdrop-blur-md border border-cardBorder rounded-xl shadow-2xl p-3 font-mono border-t-2 border-t-cyberBlue/60 transition-all duration-300"
      >
        <div className="flex items-center justify-between mb-2">
          <span className="text-[10px] uppercase font-bold text-cyberBlue tracking-wider flex items-center gap-1.5">
            <span className="h-1.5 w-1.5 bg-cyberBlue rounded-full animate-ping"></span>
            IP Investigation HUD
          </span>
          {searchQuery && (
            <button 
              onClick={() => {
                setSearchQuery('');
                setLocalSelectedThreat(null);
                setInvestigatedThreat(null);
                if (onSelectThreat) onSelectThreat(null);
              }}
              className="text-[9px] text-gray-500 hover:text-cyberRed transition uppercase font-bold flex items-center gap-0.5"
            >
              <FiTrash2 /> Clear
            </button>
          )}
        </div>

        <div className="relative">
          <input
            type="text"
            placeholder="Search / Select IP Address..."
            value={searchQuery}
            onChange={(e) => {
              setSearchQuery(e.target.value);
              setShowSuggestions(true);
            }}
            onFocus={() => setShowSuggestions(true)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && searchQuery) {
                handleSelectIP(searchQuery);
              }
            }}
            className="w-full pl-8 pr-3 py-2 rounded-lg border border-cardBorder bg-[#05070C] text-[11px] text-white placeholder-gray-600 outline-none focus:border-cyberBlue focus:shadow-[0_0_8px_rgba(51,204,255,0.25)] transition duration-200"
          />
          <FiSearch className="absolute left-2.5 top-3 text-gray-600 text-xs" />
        </div>

        {/* Autocomplete Dropdown suggestions list */}
        {showSuggestions && (
          <div className="absolute left-0 right-0 mt-1.5 bg-[#0C111D] border border-cardBorder rounded-lg shadow-2xl overflow-hidden max-h-56 z-[1001] divide-y divide-cardBorder/30">
            {searchQuery && ipSuggestions.length > 0 && (
              <div className="py-1">
                <div className="text-[8px] uppercase tracking-wider text-gray-500 font-bold px-2.5 py-1">Threat Matches</div>
                {ipSuggestions.map((ip, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectIP(ip)}
                    className="px-2.5 py-1.5 hover:bg-cyberBlue/10 text-gray-300 hover:text-white cursor-pointer text-[11px] flex justify-between items-center transition"
                  >
                    <span className="font-semibold text-cyberBlue">{ip}</span>
                    <span className="text-[8px] px-1 bg-cyberBlue/20 text-cyberBlue rounded">Select</span>
                  </div>
                ))}
              </div>
            )}

            {searchQuery && !ipSuggestions.includes(searchQuery) && (
              <div
                onClick={() => handleSelectIP(searchQuery)}
                className="px-2.5 py-2 hover:bg-cyberBlue/10 text-cyberBlue hover:text-[#33CCFF] cursor-pointer text-[10px] flex items-center gap-1.5 transition font-semibold"
              >
                <FiGlobe className="animate-spin text-xs" />
                <span>Investigate Global IP: {searchQuery}</span>
              </div>
            )}

            {!searchQuery && threats.length > 0 && (
              <div className="py-1">
                <div className="text-[8px] uppercase tracking-wider text-gray-500 font-bold px-2.5 py-1 flex items-center gap-1">
                  <FiTarget className="text-cyberBlue" />
                  Quick Selection
                </div>
                {threats.slice(0, 5).map((t, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectIP(t.ip)}
                    className="px-2.5 py-1.5 hover:bg-cardBorder/40 text-gray-300 hover:text-white cursor-pointer text-[11px] flex justify-between items-center transition"
                  >
                    <span>{t.ip}</span>
                    <span className={`text-[8px] px-1 rounded font-mono ${
                      t.threat_severity === 'Critical' ? 'bg-purple-500/20 text-purple-400' :
                      t.threat_severity === 'High Threat' ? 'bg-cyberRed/20 text-cyberRed' :
                      'bg-cyberYellow/20 text-cyberYellow'
                    }`}>{t.threat_severity}</span>
                  </div>
                ))}
              </div>
            )}

            {!searchQuery && recentSearches.length > 0 && (
              <div className="py-1 border-t border-cardBorder/30">
                <div className="text-[8px] uppercase tracking-wider text-gray-500 font-bold px-2.5 py-1 flex items-center gap-1">
                  <FiClock className="text-gray-500" />
                  Recent Searches
                </div>
                {recentSearches.map((ip, idx) => (
                  <div
                    key={idx}
                    onClick={() => handleSelectIP(ip)}
                    className="px-2.5 py-1.5 hover:bg-cardBorder/40 text-gray-300 hover:text-white cursor-pointer text-[11px] flex justify-between items-center transition"
                  >
                    <span>{ip}</span>
                    <span className="text-[8px] text-gray-500">Audited</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>

      <MapContainer
        center={[20.0, 10.0]}
        zoom={2}
        className="w-full h-full"
        maxBounds={[[-90, -180], [90, 180]]}
        minZoom={1.8}
        zoomControl={true}
        style={{ width: '100%', height: '100%' }}
      >
        {/* Dynamic Map panning */}
        <MapController selectedThreat={activeSelectedThreat} markerRefs={markerRefs} />

        {/* CartoDB premium dark theme layer */}
        <TileLayer
          url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
          attribution='&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors &copy; <a href="https://carto.com/attributions">CARTO</a>'
        />

        {/* Target Server Center Node */}
        <Marker position={[SERVER_NODE.lat, SERVER_NODE.lon]} icon={getTargetIcon()}>
          <Popup className="cyber-popup font-mono text-xs">
            <div className="p-1">
              <span className="font-bold text-cyberGreen uppercase">{SERVER_NODE.name}</span>
              <p className="text-[10px] text-gray-400 mt-1">Status: SECURE / PROTECTED</p>
              <p className="text-[10px] text-gray-500">Position: {SERVER_NODE.lat}, {SERVER_NODE.lon}</p>
            </div>
          </Popup>
        </Marker>

        {/* Render threat nodes, vector lines, and range rings */}
        {allRenderedThreats.map((threat, idx) => {
          if (!threat) return null;
          
          const lat = parseFloat(threat.latitude);
          const lon = parseFloat(threat.longitude);
          if (isNaN(lat) || isNaN(lon)) return null;
          
          const sourcePos = [lat, lon];
          const destPos = [SERVER_NODE.lat, SERVER_NODE.lon];
          
          // Visual States based on Selection
          const isSelected = activeSelectedThreat && activeSelectedThreat.ip === threat.ip;
          const opacity = isAnySelected ? (isSelected ? 1.0 : 0.25) : 0.85;

          // Severity Color mapping
          let strokeColor = '#10B981'; // Green
          if (threat.threat_severity === 'Suspicious') {
            strokeColor = '#F59E0B'; // Orange
          } else if (threat.threat_severity === 'High Threat') {
            strokeColor = '#EF4444'; // Red
          } else if (threat.threat_severity === 'Critical') {
            strokeColor = '#A78BFA'; // Purple
          }

          // Active Glow Highlight state
          const vectorColor = isSelected ? '#33CCFF' : strokeColor;
          const vectorWeight = isSelected ? 3.0 : (threat.threat_severity === 'Critical' ? 1.5 : 1.1);
          const vectorOpacity = isAnySelected ? (isSelected ? 0.95 : 0.05) : 0.35;
          const pulseColor = isSelected ? '#33CCFF' : strokeColor;

          const isThreat = threat.threat_severity !== 'Normal' || isSelected;

          return (
            <React.Fragment key={`${threat.timestamp || idx}-${threat.ip || ''}-${idx}`}>
              {/* Clickable Attacker Node marker */}
              <Marker 
                position={sourcePos} 
                opacity={opacity}
                ref={el => {
                  if (el) {
                    markerRefs.current[threat.ip] = el;
                  }
                }}
                icon={getAttackerIcon(threat.threat_severity, threat.count || 1, isSelected)}
              >
                <Popup className="cyber-popup font-mono text-xs">
                  <div className="space-y-2 p-1 max-w-[240px]">
                    <div className="border-b border-cardBorder pb-1 flex justify-between items-center gap-2">
                      <span className="font-bold text-white uppercase truncate">IP: {threat.ip}</span>
                      <span className={`px-1 rounded text-[8px] font-bold ${
                        threat.prediction === 'Anomaly' ? 'bg-cyberRed/20 text-cyberRed border border-cyberRed/30' : 'bg-cyberGreen/20 text-cyberGreen border border-cyberGreen/30'
                      }`}>
                        {threat.prediction}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-x-2 gap-y-1 text-[10px] text-gray-400">
                      <div>
                        <span className="text-[8px] text-gray-600 block uppercase">Geo Origin</span>
                        <span className="font-bold text-gray-300 truncate block">{threat.city}, {threat.country}</span>
                      </div>
                      <div>
                        <span className="text-[8px] text-gray-600 block uppercase">ISP Core</span>
                        <span className="font-bold text-gray-300 truncate block">{threat.isp}</span>
                      </div>
                      <div>
                        <span className="text-[8px] text-gray-600 block uppercase">Attack Signature</span>
                        <span className="font-bold text-cyberBlue truncate block">{threat.threat_type}</span>
                      </div>
                      <div>
                        <span className="text-[8px] text-gray-600 block uppercase">Confidence Score</span>
                        <span className="font-bold text-white block">{(threat.anomaly_score * 100).toFixed(1)}%</span>
                      </div>
                    </div>

                    <div className="p-1 rounded bg-[#05070C] border border-cardBorder/60 text-[9px] text-gray-500 overflow-x-auto select-all whitespace-nowrap scrollbar-none">
                      <span className="font-bold text-white">{threat.method}</span> {threat.url}
                    </div>

                    <div className="flex justify-between items-center text-[9px] text-gray-600 border-t border-cardBorder/40 pt-1">
                      <span>Status: <span className={threat.status >= 400 ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>{threat.status}</span></span>
                      <span>
                        {threat.timestamp && typeof threat.timestamp === 'string'
                          ? (threat.timestamp.includes('T') ? threat.timestamp.split('T')[0] : threat.timestamp)
                          : 'Unknown'}
                      </span>
                    </div>
                  </div>
                </Popup>
              </Marker>

              {/* Threat Attack Vectors routing towards Chennai mainframe */}
              {isThreat && (
                <>
                  <Polyline
                    positions={[sourcePos, destPos]}
                    pathOptions={{
                      color: vectorColor,
                      weight: vectorWeight,
                      opacity: vectorOpacity,
                      dashArray: isSelected ? '0' : '3, 6'
                    }}
                  />

                  {/* Impact range overlay */}
                  <CircleMarker
                    center={sourcePos}
                    pathOptions={{
                      color: pulseColor,
                      fillColor: pulseColor,
                      fillOpacity: isSelected ? 0.12 : 0.04,
                      weight: isSelected ? 1 : 0,
                      radius: threat.threat_severity === 'Critical' ? 45 : (threat.threat_severity === 'High Threat' ? 30 : 15)
                    }}
                  />
                </>
              )}
            </React.Fragment>
          );
        })}
      </MapContainer>
    </div>
  );
};

export default GeoMap;
