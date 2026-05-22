import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:8000/api';

// Create Axios Instance
const api = axios.create({
  baseURL: API_BASE_URL,
});

// Request Interceptor: Attach JWT token if stored
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('jwt_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Auth endpoints
export const authApi = {
  login: async (username, password) => {
    const response = await api.post('/auth/login', { username, password });
    if (response.data.access_token) {
      localStorage.setItem('jwt_token', response.data.access_token);
    }
    return response.data;
  },
  verify: async () => {
    const response = await api.get('/auth/verify');
    return response.data;
  },
  logout: () => {
    localStorage.removeItem('jwt_token');
  }
};

// Logs endpoints
export const logsApi = {
  getStats: async () => {
    const response = await api.get('/stats');
    return response.data;
  },
  getLogs: async (params = {}) => {
    const response = await api.get('/logs', { params });
    return response.data;
  },
  getThreats: async (limit = 100) => {
    const response = await api.get('/threats', { params: { limit } });
    return response.data;
  },
  uploadLogs: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  generateMockLogs: async (count = 50, scenario = null) => {
    const response = await api.post('/generate-mock', null, {
      params: { count, scenario }
    });
    return response.data;
  }
};

// Machine Learning endpoints
export const mlApi = {
  predictSingle: async (logLine, classifier = "isolation_forest") => {
    const response = await api.post('/predict', { log_line: logLine, classifier });
    return response.data;
  },
  getSummary: async () => {
    const response = await api.get('/predict/summary');
    return response.data;
  },
  retrainModel: async () => {
    const response = await api.post('/predict/retrain');
    return response.data;
  }
};

// Spark Metrics & Processing endpoints
export const sparkApi = {
  getMetrics: async () => {
    const response = await api.get('/spark/metrics');
    return response.data;
  },
  analyzeLogs: async (formData) => {
    const response = await api.post('/spark/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  simulateLogs: async (formData) => {
    const response = await api.post('/spark/simulate', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },
  exportCSV: async (records) => {
    const response = await api.post('/spark/export/csv', records, {
      responseType: 'blob',
    });
    return response.data;
  },
  exportJSON: async (records) => {
    const response = await api.post('/spark/export/json', records, {
      responseType: 'blob',
    });
    return response.data;
  }
};

// Advanced GeoMap endpoints
export const geomapApi = {
  getThreats: async (params = {}) => {
    const response = await api.get('/geomap-threats', { params });
    return response.data;
  },
  getTopCountries: async () => {
    const response = await api.get('/top-countries');
    return response.data;
  },
  getLiveAttacks: async (count = 5) => {
    const response = await api.get('/live-attacks', { params: { count } });
    return response.data;
  },
  processLogMap: async (file) => {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post('/process-log-map', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }
};

export default api;
