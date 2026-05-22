import React, { useState } from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { 
  FiShield, 
  FiTerminal, 
  FiAlertOctagon, 
  FiZap, 
  FiEye, 
  FiGlobe, 
  FiFileText, 
  FiSettings, 
  FiLogOut,
  FiMenu,
  FiX
} from 'react-icons/fi';
import { useAuth } from '../context/AuthContext';

const Sidebar = () => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const { logout } = useAuth();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const navItems = [
    { name: 'Operation Centre Overview', path: '/', icon: <FiShield className="text-lg" /> },
    { name: 'Log Analytics', path: '/logs', icon: <FiTerminal className="text-lg" /> },
    { name: 'Threat Intelligence', path: '/threat-intel', icon: <FiAlertOctagon className="text-lg" /> },
    { name: 'Spark Engines', path: '/spark', icon: <FiZap className="text-lg" /> },
    { name: 'ML Anomalies', path: '/ml', icon: <FiEye className="text-lg" /> },
    { name: 'Attack Geo Map', path: '/map', icon: <FiGlobe className="text-lg" /> },
    { name: 'Audit Reports', path: '/reports', icon: <FiFileText className="text-lg" /> },
    { name: 'Control Settings', path: '/settings', icon: <FiSettings className="text-lg" /> },
  ];

  return (
    <aside 
      className={`relative z-20 flex flex-col border-r border-cardBorder bg-[#0C111D] transition-all duration-300 ${
        collapsed ? 'w-20' : 'w-64'
      } h-screen select-none text-gray-400`}
    >
      {/* Sidebar Header */}
      <div className="flex h-16 items-center justify-between px-4 border-b border-cardBorder">
        {!collapsed && (
          <div className="flex items-center gap-2">
            <div className="h-2 w-2 rounded-full bg-cyberGreen animate-ping"></div>
            <span className="font-sans font-bold tracking-wider text-white uppercase text-xs">
              OPERATION CENTRE <span className="text-cyberGreen">OVERVIEW</span>
            </span>
          </div>
        )}
        {collapsed && (
          <div className="mx-auto flex h-8 w-8 items-center justify-center rounded-lg bg-cardBorder text-cyberGreen">
            <FiShield className="text-xl" />
          </div>
        )}
        <button 
          onClick={() => setCollapsed(!collapsed)}
          className="rounded-lg p-1 text-gray-500 hover:bg-cardBorder hover:text-white"
        >
          {collapsed ? <FiMenu className="text-lg" /> : <FiX className="text-lg" />}
        </button>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 space-y-1 py-4 px-2 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            className={({ isActive }) =>
              `flex items-center gap-4 rounded-lg px-3 py-3 text-sm font-medium transition-all duration-200 ${
                isActive
                  ? 'bg-gradient-to-r from-cardBorder to-transparent text-white border-l-2 border-cyberGreen shadow-glowGreen'
                  : 'hover:bg-cardBorder/40 hover:text-white'
              }`
            }
          >
            <div className="flex-shrink-0">{item.icon}</div>
            {!collapsed && <span className="truncate">{item.name}</span>}
          </NavLink>
        ))}
      </nav>

      {/* Footer / Logout */}
      <div className="p-2 border-t border-cardBorder">
        <button
          onClick={handleLogout}
          className="flex w-full items-center gap-4 rounded-lg px-3 py-3 text-sm font-medium transition-colors hover:bg-red-950/20 hover:text-cyberRed"
        >
          <FiLogOut className="text-lg flex-shrink-0" />
          {!collapsed && <span>System Logout</span>}
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
