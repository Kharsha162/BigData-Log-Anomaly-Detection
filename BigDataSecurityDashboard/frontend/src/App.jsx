import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';

// Pages
import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import ApacheLogs from './pages/ApacheLogs';
import ThreatIntel from './pages/ThreatIntel';
import SparkAnalytics from './pages/SparkAnalytics';
import AnomalyDetection from './pages/AnomalyDetection';
import AttackMap from './pages/AttackMap';
import Reports from './pages/Reports';
import Settings from './pages/Settings';

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
        {/* Auth Route */}
        <Route path="/login" element={<Login />} />

        {/* Protected Dashboard Views */}
        <Route path="/" element={
          <ProtectedRoute>
            <Dashboard />
          </ProtectedRoute>
        } />
        <Route path="/logs" element={
          <ProtectedRoute>
            <ApacheLogs />
          </ProtectedRoute>
        } />
        <Route path="/threat-intel" element={
          <ProtectedRoute>
            <ThreatIntel />
          </ProtectedRoute>
        } />
        <Route path="/spark" element={
          <ProtectedRoute>
            <SparkAnalytics />
          </ProtectedRoute>
        } />
        <Route path="/ml" element={
          <ProtectedRoute>
            <AnomalyDetection />
          </ProtectedRoute>
        } />
        <Route path="/map" element={
          <ProtectedRoute>
            <AttackMap />
          </ProtectedRoute>
        } />
        <Route path="/reports" element={
          <ProtectedRoute>
            <Reports />
          </ProtectedRoute>
        } />
        <Route path="/settings" element={
          <ProtectedRoute>
            <Settings />
          </ProtectedRoute>
        } />

        {/* Fallback redirect to Overview dashboard */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
      </AuthProvider>
    </BrowserRouter>
  );
}

export default App;
