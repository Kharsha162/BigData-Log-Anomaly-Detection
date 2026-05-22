import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';

const ProtectedRoute = ({ children }) => {
  const { isAuthenticated, loading } = useAuth();

  if (loading || isAuthenticated === null) {
    // Cyber-style loading spinner
    return (
      <div className="flex h-screen items-center justify-center bg-darkBg text-cyberGreen">
        <div className="relative">
          <div className="h-16 w-16 animate-spin rounded-full border-4 border-cardBorder border-t-cyberGreen"></div>
          <span className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 font-mono text-xs">SOC</span>
        </div>
      </div>
    );
  }

  return isAuthenticated ? children : <Navigate to="/login" replace />;
};

export default ProtectedRoute;
