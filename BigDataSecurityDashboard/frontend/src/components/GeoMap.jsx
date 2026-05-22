import React, { useEffect } from 'react';
import { MapContainer, TileLayer, Marker, Popup, Polyline, CircleMarker, useMap } from 'react-leaflet';
import L from 'leaflet';

// Reset Leaflet Default Icon prototype to fix Vite dynamic asset resolution crashes
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon-2x.png',
  iconUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-icon.png',
  shadowUrl: 'https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.7.1/images/marker-shadow.png',
});

// Central Target Node
const SERVER_NODE = { lat: 13.0827, lon: 80.2707, name: "Chennai SOC Mainframe Node" };

// Dynamic Map Controller to pan and zoom smoothly to selected IP nodes
const MapController = ({ selectedThreat }) => {
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
        map.setView([lat, lon], 5, {
          animate: true,
          duration: 1.2
        });
      }
    }
  }, [selectedThreat, map]);
  return null;
};

// Custom Glowing HTML div icon generators for the severities
const getAttackerIcon = (severity) => {
  let color = '#10B981'; // Green (Normal)
  if (severity === 'Suspicious') {
    color = '#F59E0B'; // Orange
  } else if (severity === 'High Threat') {
    color = '#EF4444'; // Red
  } else if (severity === 'Critical') {
    color = '#A78BFA'; // Purple
  }

  const html = `
    <div class="relative flex items-center justify-center">
      <div class="absolute h-5 w-5 rounded-full opacity-40 animate-ping" style="background-color: ${color};"></div>
      <div class="h-3 w-3 rounded-full border border-white shadow-lg" style="background-color: ${color};"></div>
    </div>
  `;

  return L.divIcon({
    html: html,
    className: 'custom-cyber-marker',
    iconSize: [24, 24],
    iconAnchor: [12, 12],
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

const GeoMap = ({ threats = [], selectedThreat }) => {
  return (
    <div className="w-full h-full min-h-[480px] bg-[#05070C] relative rounded-xl overflow-hidden border border-cardBorder" style={{ height: '100%', minHeight: '480px' }}>
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
        <MapController selectedThreat={selectedThreat} />

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

        {/* Dynamic Threat nodes, vector routing, and heat circles */}
        {(threats || []).map((threat, idx) => {
          if (!threat) return null;
          
          const lat = parseFloat(threat.latitude);
          const lon = parseFloat(threat.longitude);
          if (isNaN(lat) || isNaN(lon)) return null;
          
          const sourcePos = [lat, lon];
          const destPos = [SERVER_NODE.lat, SERVER_NODE.lon];
          
          // Mapping line colors matching severity scales
          let strokeColor = '#10B981'; // Green
          if (threat.threat_severity === 'Suspicious') {
            strokeColor = '#F59E0B'; // Orange
          } else if (threat.threat_severity === 'High Threat') {
            strokeColor = '#EF4444'; // Red
          } else if (threat.threat_severity === 'Critical') {
            strokeColor = '#A78BFA'; // Purple
          }

          const isThreat = threat.threat_severity !== 'Normal';

          return (
            <React.Fragment key={`${threat.timestamp || idx}-${threat.ip || ''}-${idx}`}>
              {/* Clickable Attacker Node marker */}
              <Marker position={sourcePos} icon={getAttackerIcon(threat.threat_severity)}>
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
                        <span className="text-[8px] text-gray-600 block uppercase">Score Confidence</span>
                        <span className="font-bold text-white block">{(threat.anomaly_score * 100).toFixed(1)}%</span>
                      </div>
                    </div>

                    <div className="p-1 rounded bg-[#05070C] border border-cardBorder/60 text-[9px] text-gray-500 overflow-x-auto select-all whitespace-nowrap scrollbar-none">
                      <span className="font-bold text-white">{threat.method}</span> {threat.url}
                    </div>

                    <div className="flex justify-between items-center text-[9px] text-gray-600 border-t border-cardBorder/40 pt-1">
                      <span>Status: <span className={threat.status >= 400 ? 'text-cyberRed font-bold' : 'text-cyberGreen font-bold'}>{threat.status}</span></span>
                      <span>{threat.timestamp.split('T')[0] || threat.timestamp}</span>
                    </div>
                  </div>
                </Popup>
              </Marker>

              {/* Threat Attack Vectors routing towards server */}
              {isThreat && (
                <>
                  <Polyline
                    positions={[sourcePos, destPos]}
                    pathOptions={{
                      color: strokeColor,
                      weight: threat.threat_severity === 'Critical' ? 1.5 : 1.1,
                      opacity: 0.35,
                      dashArray: '3, 6'
                    }}
                  />

                  {/* Impact heat overlay */}
                  <CircleMarker
                    center={sourcePos}
                    pathOptions={{
                      color: strokeColor,
                      fillColor: strokeColor,
                      fillOpacity: 0.04,
                      weight: 0,
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
