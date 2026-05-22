import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { FiLock, FiUser, FiShield, FiAlertTriangle } from 'react-icons/fi';
import { useAuth } from '../context/AuthContext';

const Login = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const navigate = useNavigate();
  const { login, isAuthenticated } = useAuth();

  useEffect(() => {
    // Redirect if already authenticated
    if (isAuthenticated) {
      navigate('/');
    }
  }, [isAuthenticated, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      await login(username, password);
      navigate('/');
    } catch (err) {
      console.error(err);
      setError(err.response?.data?.detail || 'Authentication server connection failed.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-darkBg px-4 py-12 select-none overflow-hidden">
      {/* Background Matrix/Cyber grid lines */}
      <div className="absolute inset-0 cyber-grid opacity-30"></div>
      <div className="absolute -left-1/4 -top-1/4 h-[800px] w-[800px] rounded-full bg-cyberGreen/5 blur-[120px] animate-pulse-slow"></div>
      <div className="absolute -right-1/4 -bottom-1/4 h-[800px] w-[800px] rounded-full bg-cyberBlue/5 blur-[120px] animate-pulse-slow"></div>

      <motion.div
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.6, ease: 'easeOut' }}
        className="w-full max-w-md glass-panel rounded-2xl border border-cardBorder p-8 shadow-2xl relative z-10"
      >
        {/* Terminal Header Decoration */}
        <div className="absolute top-3 left-4 flex gap-1.5">
          <span className="h-3 w-3 rounded-full bg-cyberRed/40"></span>
          <span className="h-3 w-3 rounded-full bg-cyberYellow/40"></span>
          <span className="h-3 w-3 rounded-full bg-cyberGreen/40"></span>
        </div>

        <div className="flex flex-col items-center mb-8">
          <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-cardBorder text-cyberGreen border border-cyberGreen/30 shadow-glowGreen">
            <FiShield className="text-3xl" />
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white font-sans text-center">
            BIG DATA SECURITY DASHBOARD
          </h2>
          <p className="mt-2 text-xs text-gray-500 font-mono uppercase tracking-widest text-center">
            SecOps Control Portal Authentication
          </p>
        </div>

        {error && (
          <motion.div
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            className="mb-6 flex items-start gap-3 rounded-lg border border-red-500/25 bg-red-950/20 p-4 text-sm text-cyberRed"
          >
            <FiAlertTriangle className="text-lg flex-shrink-0 mt-0.5" />
            <div className="font-mono text-xs">{error}</div>
          </motion.div>
        )}

        <form onSubmit={handleSubmit} className="space-y-6">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 font-mono mb-2">
              Operator Username
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <FiUser className="text-base" />
              </span>
              <input
                type="text"
                required
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                className="w-full rounded-lg border border-cardBorder bg-[#05070C] py-3 pl-10 pr-4 text-sm text-white placeholder-gray-600 outline-none transition-all focus:border-cyberGreen focus:ring-1 focus:ring-cyberGreen"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-gray-500 font-mono mb-2">
              Security Access Password
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                <FiLock className="text-base" />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full rounded-lg border border-cardBorder bg-[#05070C] py-3 pl-10 pr-4 text-sm text-white placeholder-gray-600 outline-none transition-all focus:border-cyberGreen focus:ring-1 focus:ring-cyberGreen"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 rounded-lg bg-cyberGreen font-semibold text-darkBg shadow-glowGreen hover:bg-cyberGreen/90 transition-all font-sans text-sm tracking-widest uppercase flex items-center justify-center disabled:opacity-50"
          >
            {loading ? (
              <span className="h-5 w-5 animate-spin rounded-full border-2 border-darkBg border-t-transparent"></span>
            ) : (
              'Initiate Handshake'
            )}
          </button>
        </form>

      </motion.div>
    </div>
  );
};

export default Login;
