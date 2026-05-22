import React, { createContext, useContext, useState, useEffect } from 'react';
import { authApi } from '../services/api';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
  const [isAuthenticated, setIsAuthenticated] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  const verifyUser = async () => {
    const token = localStorage.getItem('jwt_token');
    if (!token) {
      setIsAuthenticated(false);
      setUser(null);
      setLoading(false);
      return;
    }

    try {
      const data = await authApi.verify();
      setIsAuthenticated(true);
      setUser(data.username);
    } catch (err) {
      console.error("Token verification failed:", err);
      // ONLY clear token and log out if the server explicitly returns 401 Unauthorized.
      // Transient network failures or aborted requests will NOT wipe out user credentials.
      if (err.response && err.response.status === 401) {
        authApi.logout();
        setIsAuthenticated(false);
        setUser(null);
      } else {
        // network issue - assume authenticated if valid token exists locally
        setIsAuthenticated(true);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    const runVerification = async () => {
      if (active) await verifyUser();
    };
    runVerification();
    return () => {
      active = false;
    };
  }, []);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const data = await authApi.login(username, password);
      setIsAuthenticated(true);
      setUser(username);
      return data;
    } catch (err) {
      setIsAuthenticated(false);
      setUser(null);
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const logout = () => {
    authApi.logout();
    setIsAuthenticated(false);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ isAuthenticated, user, loading, login, logout, verifyUser }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
