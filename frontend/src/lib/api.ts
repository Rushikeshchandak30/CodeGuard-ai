import axios from 'axios';
import { useAuthStore } from '../store/auth';

const BASE_URL = import.meta.env.VITE_API_URL || '';

export const api = axios.create({
  baseURL: BASE_URL,
  timeout: 30_000,
});

// Attach auth token to every request
api.interceptors.request.use((config) => {
  const token = useAuthStore.getState().token;
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Auto-logout on 401
api.interceptors.response.use(
  (r) => r,
  (err) => {
    if (err.response?.status === 401) {
      useAuthStore.getState().clearAuth();
      window.location.href = '/login';
    }
    return Promise.reject(err);
  }
);

// ─── Auth ─────────────────────────────────────────────────────────

export const authApi = {
  me: () => api.get('/api/auth/me'),
  apiKeys: () => api.get('/api/auth/api-keys'),
  createApiKey: (name: string) => api.post('/api/auth/api-keys', { name }),
  revokeApiKey: (id: string) => api.delete(`/api/auth/api-keys/${id}`),
  githubLoginUrl: () => `${BASE_URL}/api/auth/github`,
};

// ─── Scans ────────────────────────────────────────────────────────

export const scansApi = {
  list: (page = 1, limit = 20) =>
    api.get('/api/scans', { params: { page, limit } }),
  get: (id: string) => api.get(`/api/scans/${id}`),
  trends: () => api.get('/api/scans/trends/summary'),
};

// ─── GHIN ─────────────────────────────────────────────────────────

export const ghinApi = {
  stats: () => api.get('/api/ghin/stats'),
  packages: (page = 1, status?: string, ecosystem?: string) =>
    api.get('/api/ghin/packages', { params: { page, status, ecosystem } }),
  check: (ecosystem: string, name: string) =>
    api.get(`/api/ghin/check/${ecosystem}/${name}`),
  report: (data: { packageName: string; ecosystem: string; reportType: string; confidence: number }) =>
    api.post('/api/ghin/report', data),
};

// ─── Teams ────────────────────────────────────────────────────────

export const teamsApi = {
  list: () => api.get('/api/teams'),
  get: (slug: string) => api.get(`/api/teams/${slug}`),
  create: (data: { name: string; slug: string }) => api.post('/api/teams', data),
  invite: (slug: string, email: string, role: string) =>
    api.post(`/api/teams/${slug}/members`, { email, role }),
  stats: (slug: string) => api.get(`/api/teams/${slug}/stats`),
};

// ─── Admin ────────────────────────────────────────────────────────

export const adminApi = {
  stats: () => api.get('/api/admin/stats'),
  flags: () => api.get('/api/admin/flags'),
  setFlag: (flag: string, value: boolean) =>
    api.post('/api/admin/flags', { flag, value }),
  consolidate: () => api.post('/api/admin/ghin/consolidate'),
};
